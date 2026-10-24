/* wispd - the sensor's single-threaded, event-driven core.
 *
 * One epoll loop waits on a handful of descriptors and nothing else:
 *   - the exec/flow event source (eBPF ring buffer, or the proc connector)
 *   - an inotify fd for FIM and a separate one for inventory
 *   - a timerfd for slow housekeeping (rescans, heartbeat), one for exec
 *     coalescing and one for the CPU governor while it is shedding load
 *   - a signalfd for SIGHUP (reload) and SIGTERM/SIGINT (stop)
 *   - the console link (TLS socket, or its resolver's eventfd), when set
 * epoll_wait blocks with no timeout unless the console link has a retry or
 * deadline pending, so an idle host wakes the agent zero times per second
 * and consumes no measurable CPU.
 */
#include "wisp.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

static int open_inotify(const char *what)
{
	int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (fd < 0)
		logmsg("inotify for %s unavailable (%s): %s changes will not be seen live",
		       what, strerror(errno), what);
	return fd;
}

/* The FIM queue overflowed: events for watched paths were lost. Say so
 * loudly (rate-limited), because a missed change to /etc/shadow or
 * sudoers.d is exactly what FIM exists to catch. */
static void fim_gap(void)
{
	static uint64_t last;
	uint64_t now = now_ms();
	if (last && now - last < 60000)
		return;
	last = now;
	logmsg("fim: inotify queue overflowed; changes to watched paths may have been missed");
	struct proc dummy;
	memset(&dummy, 0, sizeof dummy);
	dummy.actor = ACTOR_UNKNOWN;
	scopy(dummy.comm, sizeof dummy.comm, "fim");
	scopy(dummy.actor_src, sizeof dummy.actor_src, "fim");
	out_alert("FIM-GAP", "T1562.001", "FIM event queue overflowed; watched-path changes may be missing",
	          SEV_HIGH, "alert", &dummy, NULL);
}

/* Drain one inotify instance. FIM and inventory each have their own, so a
 * flood of events in user-writable inventory directories can never evict a
 * FIM event from a shared queue. */
static void drain_inotify(int fd, int is_fim)
{
	char buf[8192] __attribute__((aligned(__alignof__(struct inotify_event))));
	ssize_t len;
	int overflow = 0;
	while ((len = read(fd, buf, sizeof buf)) > 0) {
		for (char *p = buf; p < buf + len;) {
			struct inotify_event *e = (struct inotify_event *)p;
			const char *name = e->len ? e->name : NULL;
			if (e->mask & IN_Q_OVERFLOW)
				overflow = 1;
			else if (is_fim)
				fim_on_event(e->wd, e->mask, name);
			else
				inventory_on_event(e->wd, e->mask, name);
			p += sizeof(struct inotify_event) + e->len;
		}
	}
	if (!overflow)
		return;
	if (is_fim) {
		fim_gap();
		fim_resync(); /* the dropped events may include IN_IGNORED */
	} else {
		logmsg("inventory: inotify queue overflowed; rescanning to resynchronise");
		inventory_scan();
	}
}

static int timer_open(void)
{
	int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	struct itimerspec its = {
		.it_interval = { .tv_sec = cfg.housekeeping },
		.it_value = { .tv_sec = cfg.housekeeping },
	};
	timerfd_settime(fd, 0, &its, NULL);
	return fd;
}

static void add_epoll(int ep, int fd, void *tag)
{
	struct epoll_event ev = { .events = EPOLLIN, .data.ptr = tag };
	epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
}

/* Register or update fd. A closed fd leaves epoll on its own, and its number
 * can be reused by the next descriptor, so MOD falls back to ADD and vice
 * versa. */
static void set_epoll(int ep, int fd, unsigned events, void *tag)
{
	struct epoll_event ev = { .events = events, .data.ptr = tag };
	if (epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev) != 0 && errno == ENOENT)
		epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
}

/* Reload every policy file in place: SIGHUP and the console's Reload policy
 * both come here, so they always apply the same thing. A file that cannot be
 * read keeps its current contents. Every proven-benign exec context is
 * forgotten: "never alerted" was relative to the old rules. */
void policy_reload(const char *why)
{
	int before = cfg_problems;
	int nr = rules_load(cfg.rules_path);
	int nc = catalog_load(cfg.catalog_path);
	int nn = netpolicy_load(cfg.netpolicy_path);
	int nf = fim_reload();
	char reason[96];
	snprintf(reason, sizeof reason, "policy reload (%s)", why);
	proc_benign_reset(reason);
	char probs[48] = "";
	if (cfg_problems > before)
		snprintf(probs, sizeof probs, "; %d problem(s), see above", cfg_problems - before);
	logmsg("reloaded: %d rules%s, catalog %s, %d network rules%s, %d fim paths%s (%s)%s",
	       rules_count(), nr < 0 ? " (kept: rules unreadable)" : "",
	       nc < 0 ? "unreadable (kept)" : "loaded",
	       netpolicy_count(), nn < 0 ? " (kept: unreadable)" : "",
	       fim_count(), nf < 0 ? " (kept)" : "", why, probs);
}

/* CPU governor driver. Evaluated from the exec-processing paths (whether or
 * not coalescing is on) at most every 250 ms while near the budget and every
 * 1 s otherwise; from a 1 s timer while it is shedding load, so coverage is
 * restored promptly after a storm even if no further exec arrives; and from
 * the housekeeping tick. The timer and housekeeping paths only evaluate a
 * window of at least 1 s with no exec-driven evaluation in it, so a quiet gap
 * between two coalescing drains is never mistaken for the end of a storm.
 * Nothing here runs on an idle host. */
enum { GOV_EXEC, GOV_TIMER };
static int gov_tfd = -1, gov_armed;
static void govern(int from)
{
	static int ramping;
	if (cfg.cpu_budget <= 0)
		return;
	uint64_t win = gov_cpu_window_ms();
	uint64_t min = from == GOV_EXEC && ramping ? 250 : 1000;
	if (win >= min) {
		double c = gov_cpu_sample();
		governor_tick(c, win);
		ramping = c > cfg.cpu_budget * 0.6;
	}
	/* While shedding, make sure a re-evaluation is due within 1 s even if no
	 * further exec arrives; touch the timer only when that need changes. */
	int need = governor_shedding();
	if (gov_tfd >= 0 && need != gov_armed) {
		struct itimerspec its = { .it_value = { .tv_sec = need ? 1 : 0 } };
		timerfd_settime(gov_tfd, 0, &its, NULL);
		gov_armed = need;
	}
}

/* Length of the next coalescing window. A drain that took more than a quarter
 * of the exec ring buffer means a storm of large records (long command lines
 * in a parallel build) that could overflow the ring before the next drain and
 * lose events, so the window shrinks in proportion; light drains let it grow
 * back to coalesce_ms. An ordinary storm (2000 exec/s of short command lines
 * fills about a tenth of it per 500 ms) never changes it, so the wakeup rate
 * stays as configured. */
static int coalesce_window(int base, int cur, double fill)
{
	if (fill > 0.25) {
		int lo = base < 10 ? base : 10, w = (int)(cur * (0.25 / fill));
		return w < lo ? lo : w;
	}
	if (fill < 0.1 && cur < base)
		return cur * 2 > base ? base : cur * 2;
	return cur;
}

static void arm_ms(int tfd, int ms)
{
	struct itimerspec its = { .it_value = { .tv_sec = ms / 1000, .tv_nsec = ms % 1000 * 1000000L } };
	timerfd_settime(tfd, 0, &its, NULL);
}

/* The kernel could not queue some exec records: say so (at most once per
 * housekeeping tick), since those execs were never evaluated. */
static void report_ring_lost(void)
{
	static uint64_t seen;
	uint64_t lost = proc_ring_lost();
	if (lost > seen) {
		logmsg("bpf: %llu exec events lost: ring buffer full (%llu in total)",
		       (unsigned long long)(lost - seen), (unsigned long long)lost);
		seen = lost;
	}
}

static void usage(FILE *o)
{
	fprintf(o,
	        "wispd %s -- Wisp endpoint sensor\n\n"
	        "Usage:\n"
	        "  wispd [-c CONFIG]                 run the sensor (default /etc/wisp/wisp.conf)\n"
	        "  wispd [-c CONFIG] --check-config  validate the config and every policy file, then exit\n"
	        "  wispd [-c CONFIG] --scan          one-shot inventory scan to the log, then exit\n"
	        "  wispd [-c CONFIG] --search F...   search this host's recorded events (forensics):\n"
	        "        key=value  q=text  since=ISO  until=ISO  tree=PID  limit=N\n"
	        "  wispd --version | --help\n\n"
	        "Signals: SIGHUP reloads rules, catalog, network policy and FIM paths;\n"
	        "         SIGTERM stops (the console is told goodbye).\n"
	        "Docs: docs/configuration.md, docs/policy.md, docs/operations.md\n",
	        WISP_VERSION);
}

/* --check-config: load everything the sensor would load, report every
 * problem with file:line, exit non-zero if anything is wrong. Safe to run on
 * a live host (it attaches nothing) and in CI against a policy repo. */
static int check_config(const char *conf)
{
	if (config_load(conf) < 0)
		cfg_problem(conf, 0, "cannot read config");
	int nr = rules_load(cfg.rules_path);
	if (nr < 0)
		cfg_problem(cfg.rules_path, 0, "cannot read rules");
	else if (nr == 0)
		cfg_problem(cfg.rules_path, 0, "no rules loaded");
	int nc = catalog_load(cfg.catalog_path);
	int nn = netpolicy_load(cfg.netpolicy_path);
	int ifd = inotify_init1(IN_CLOEXEC);
	int nf = ifd >= 0 ? fim_init(ifd, cfg.fim_path) : -1;
	if (ifd >= 0)
		close(ifd);
	if (cfg.console[0]) {
		const char *files[] = { cfg.cert, cfg.key, cfg.ca };
		const char *what[] = { "cert", "key", "ca" };
		for (int i = 0; i < 3; i++) {
			if (!files[i][0])
				cfg_problem(conf, 0, "console is set but '%s' is not", what[i]);
			else if (access(files[i], R_OK) != 0 && !(i == 1 && cfg.tpm))
				cfg_problem(files[i], 0, "%s not readable", what[i]);
		}
	}
	printf("config      %s\n", conf);
	printf("mode        %s, cpu budget %.3f%% (%s)\n", cfg.mode == MODE_ENFORCE ? "enforce" : "monitor",
	       cfg.cpu_budget, cfg.budget_mode ? "budget-first" : "security-first");
	printf("rules       %d  (%s)\n", nr < 0 ? 0 : nr, cfg.rules_path);
	printf("catalog     %s  (%s)\n", nc < 0 ? "none" : "loaded", cfg.catalog_path);
	printf("netpolicy   %d  (%s)\n", nn < 0 ? 0 : nn, cfg.netpolicy_path);
	printf("fim         %d watches  (%s)\n", nf < 0 ? 0 : nf, cfg.fim_path);
	printf("console     %s\n", cfg.console[0] ? cfg.console : "standalone");
	if (cfg_problems) {
		printf("\n%d problem(s) found -- see messages above\n", cfg_problems);
		return 1;
	}
	printf("\nOK\n");
	return 0;
}

int main(int argc, char **argv)
{
	const char *conf = "/etc/wisp/wisp.conf";
	int oneshot_inventory = 0, search_at = 0, check = 0;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-c") && i + 1 < argc)
			conf = argv[++i];
		else if (!strcmp(argv[i], "--scan"))
			oneshot_inventory = 1;
		else if (!strcmp(argv[i], "--check-config"))
			check = 1;
		else if (!strcmp(argv[i], "--search")) {
			search_at = i + 1; /* the remaining args are filters */
			break;
		} else if (!strcmp(argv[i], "--version")) {
			printf("wispd %s\n", WISP_VERSION);
			return 0;
		} else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(stdout);
			return 0;
		} else {
			fprintf(stderr, "wispd: unknown argument '%s'\n\n", argv[i]);
			usage(stderr);
			return 2;
		}
	}
	if (check)
		return check_config(conf);

	if (config_load(conf) < 0)
		logmsg("config %s not found, using defaults", conf);
	if (search_at)
		return forensics_search(argc - search_at, argv + search_at);
	out_init();
	anomaly_init();
	identity_init();
	telemetry_on = cfg.telemetry;
	if (rules_load(cfg.rules_path) < 0)
		logmsg("no rules at %s", cfg.rules_path);
	catalog_load(cfg.catalog_path);
	netpolicy_load(cfg.netpolicy_path);
	logmsg("wispd %s starting: %d rules, mode=%s", WISP_VERSION, rules_count(),
	       cfg.mode == MODE_ENFORCE ? "enforce" : "monitor");

	/* Signals arrive through a signalfd in the epoll set, so a SIGHUP or
	 * SIGTERM is acted on whenever it lands -- never lost because the loop
	 * happened to be busy rather than blocked in epoll_wait. */
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGTERM);
	sigprocmask(SIG_BLOCK, &sigs, NULL);
	int sigfd = signalfd(-1, &sigs, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sigfd < 0) {
		logmsg("FATAL: signalfd: %s", strerror(errno));
		return 1;
	}
	signal(SIGPIPE, SIG_IGN);

	if (oneshot_inventory) {
		/* A scan needs no event source: run it and exit. */
		int fd = open_inotify("inventory");
		inventory_init(fd);
		inventory_scan();
		out_flush();
		return 0;
	}

	int pfd = proc_open();
	if (pfd < 0) {
		logmsg("FATAL: cannot open the exec event source: %s", strerror(errno));
		return 1;
	}
	int fim_fd = open_inotify("FIM");
	if (fim_fd >= 0)
		fim_init(fim_fd, cfg.fim_path);
	int inv_fd = open_inotify("inventory");
	if (inv_fd >= 0)
		inventory_init(inv_fd);
	int tfd = timer_open();
	/* Dedicated one-shot timer for exec coalescing (see below). */
	int cotfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	gov_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);

	inventory_scan(); /* baseline at startup */
	/* Baselines for the CPU samplers, taken after startup work (BPF load,
	 * baseline scan) so it is not mistaken for load. */
	cpu_samplers_prime();

	int ep = epoll_create1(EPOLL_CLOEXEC);
	enum { TAG_PROC = 1, TAG_FIM, TAG_INV, TAG_TIMER, TAG_CONSOLE, TAG_COALESCE, TAG_GOV, TAG_SIGNAL };
	add_epoll(ep, pfd, (void *)TAG_PROC);
	if (fim_fd >= 0)
		add_epoll(ep, fim_fd, (void *)TAG_FIM);
	if (inv_fd >= 0)
		add_epoll(ep, inv_fd, (void *)TAG_INV);
	add_epoll(ep, tfd, (void *)TAG_TIMER);
	add_epoll(ep, cotfd, (void *)TAG_COALESCE);
	if (gov_tfd >= 0)
		add_epoll(ep, gov_tfd, (void *)TAG_GOV);
	add_epoll(ep, sigfd, (void *)TAG_SIGNAL);

	/* Exec coalescing: on a microVM every wakeup is an expensive vmexit, so
	 * under sustained exec load the dominant cost is the number of wakeups,
	 * not the work per event. When coalesce_ms>0 we process the first event
	 * of a burst immediately, then drop the event fd out of epoll and poll
	 * it from a timer every coalesce_ms, so one wakeup drains the whole
	 * window. An empty window re-arms the event fd and we go back to
	 * blocking in epoll -- so an idle host still has exactly zero wakeups. */
	const int coalesce = cfg.coalesce_ms > 0 ? cfg.coalesce_ms : 0;
	int window = coalesce; /* current window, <= coalesce (coalesce_window) */
	int batching = 0; /* 1 => event fd currently out of epoll, timer armed */
	int cfd_watched = -1;
	int want_stop = 0;

	unsigned cev_watched = 0, cgen_watched = console_fd_gen();
	struct epoll_event evs[16];
	while (!want_stop) {
		/* (re)arm the console descriptor as it resolves/connects/handshakes/
		 * drops, and whenever the event mask it needs changes. A socket that
		 * replaced a closed one often reuses its fd number (trying the next
		 * resolved address), so the generation is compared too: closing
		 * removed the old registration, and set_epoll() then re-adds it. */
		int cfd = console_fd();
		unsigned cev = console_events(), cgen = console_fd_gen();
		if (cfd != cfd_watched || cev != cev_watched || cgen != cgen_watched) {
			if (cfd_watched >= 0 && cfd_watched != cfd)
				epoll_ctl(ep, EPOLL_CTL_DEL, cfd_watched, NULL);
			if (cfd >= 0)
				set_epoll(ep, cfd, cev, (void *)TAG_CONSOLE);
			cfd_watched = cfd;
			cev_watched = cev;
			cgen_watched = cgen;
		}

		int n = epoll_wait(ep, evs, 16, console_timeout_ms());
		if (n < 0) {
			if (errno == EINTR)
				continue;
			logmsg("epoll_wait: %s", strerror(errno));
			break;
		}
		int saw_exec = 0;
		for (int i = 0; i < n; i++) {
			switch ((intptr_t)evs[i].data.ptr) {
			case TAG_SIGNAL: {
				struct signalfd_siginfo si;
				while (read(sigfd, &si, sizeof si) == sizeof si) {
					if (si.ssi_signo == SIGHUP)
						policy_reload("SIGHUP");
					else
						want_stop = 1;
				}
				break;
			}
			case TAG_PROC:
				saw_exec = 1;
				/* A real event woke us. Process the whole queued batch
				 * now; if coalescing is on, enter batching mode so the
				 * rest of this burst is drained by the timer, not by one
				 * wakeup each. */
				proc_handle(pfd);
				govern(GOV_EXEC);
				if (coalesce && !batching) {
					epoll_ctl(ep, EPOLL_CTL_DEL, pfd, NULL);
					arm_ms(cotfd, window);
					batching = 1;
				}
				break;
			case TAG_COALESCE: {
				uint64_t x;
				(void)!read(cotfd, &x, sizeof x);
				if (!batching)
					break;
				saw_exec = 1;
				int got = proc_handle(pfd); /* drain the window */
				govern(GOV_EXEC);
				if (got > 0) {
					window = coalesce_window(coalesce, window, proc_ring_fill());
					arm_ms(cotfd, window); /* stay batching */
				} else {
					add_epoll(ep, pfd, (void *)TAG_PROC); /* window empty: back to idle */
					batching = 0;
				}
				break;
			}
			case TAG_GOV: {
				uint64_t x;
				(void)!read(gov_tfd, &x, sizeof x);
				gov_armed = 0; /* one-shot: it has fired */
				govern(GOV_TIMER);
				break;
			}
			case TAG_FIM: drain_inotify(fim_fd, 1); break;
			case TAG_INV: drain_inotify(inv_fd, 0); break;
			case TAG_CONSOLE:
				console_on_readable();
				if (console_just_connected())
					inventory_scan(); /* replay baseline to the console */
				break;
			case TAG_TIMER: {
				uint64_t x;
				(void)!read(tfd, &x, sizeof x);
				static int ticks;
				anomaly_save();
				proc_benign_tick();
				report_ring_lost();
				govern(GOV_TIMER);
				out_heartbeat(proc_events(), out_alert_count(), self_cpu_pct(), self_rss_kb());
				if (cfg.inventory_interval > 0 &&
				    ++ticks * cfg.housekeeping >= cfg.inventory_interval) {
					ticks = 0;
					inventory_scan();
				}
				break;
			}
			}
		}
		if (saw_exec)
			out_flush();   /* one telemetry write() per drain cycle */
		console_tick();
	}

	anomaly_save();
	console_goodbye(cfg.ephemeral ? "ephemeral-exit" : "shutdown");
	logmsg("wispd stopping after %llu exec events", (unsigned long long)proc_events());
	out_flush();
	return 0;
}
