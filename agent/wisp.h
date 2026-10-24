/* Wisp - userspace fleet sensor.
 *
 * Design rule: the agent never polls in the hot path. Every wake-up is
 * caused by a kernel event that already passed an in-kernel filter
 * (classic BPF on the proc connector socket, inotify masks), so idle
 * CPU is ~0 and per-event cost is a handful of syscalls.
 */
#ifndef WISP_H
#define WISP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#ifndef WISP_VERSION
#define WISP_VERSION "dev" /* set from ../VERSION by the Makefile */
#endif

#define MAX_PATH   512
#define MAX_CMD    4096   /* captured command line (argv joined by spaces) */
/* Worst-case jesc() output for an n-byte input, plus the NUL: every byte can
 * become a 6-byte \u00XX escape. */
#define JESC_MAX(n) ((n) * 6 + 1)
#define MAX_ALT    16     /* comma alternatives per condition */
#define MAX_COND   8

enum sev { SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL };
enum action { ACT_IGNORE, ACT_ALERT, ACT_KILL, ACT_QUARANTINE };
enum mode { MODE_MONITOR, MODE_ENFORCE };

/* Who is ultimately behind a process. Inherited down the process tree. */
enum actor { ACTOR_UNKNOWN, ACTOR_HUMAN, ACTOR_AI, ACTOR_CODE, ACTOR_CI, ACTOR_SERVICE };

struct proc {
	pid_t pid, ppid;
	uid_t uid;
	int has_tty;
	int self_classified;      /* actor decided by this exec, not inherited */
	enum actor actor;
	char actor_src[40];      /* e.g. "claude", "npm", "sshd" */
	char comm[17];
	char pcomm[17];
	char exe[MAX_PATH];
	int cmd_truncated;       /* argv was longer than the captured MAX_CMD-1 bytes */
	char cmd[MAX_CMD];       /* argv joined by spaces */
	size_t cmdlen;
};

struct cond {
	int field;               /* F_* */
	int op;                  /* OP_* */
	int neg;
	int nalt;
	char *alt[MAX_ALT];
	size_t altlen[MAX_ALT];
	char *buf;               /* owns the alt[] strings (freed on reload) */
};

struct rule {
	char id[24];
	char mitre[24];
	char title[160];
	enum sev sev;
	enum action action;
	int enforce_override;    /* -1 inherit global mode, else enum mode */
	int ncond;
	struct cond c[MAX_COND];
};

struct config {
	char rules_path[MAX_PATH];
	char catalog_path[MAX_PATH];
	char fim_path[MAX_PATH];
	char netpolicy_path[MAX_PATH];
	char state_dir[MAX_PATH];
	char log_dir[MAX_PATH];
	enum mode mode;
	int telemetry;           /* write every exec to telemetry.jsonl */
	int inventory_interval;  /* seconds between full rescans */
	int housekeeping;        /* seconds between timer ticks */
	int coalesce_ms;         /* 0 = process each exec on its own wakeup;
	                          * >0 = after the first event, batch for this
	                          * many ms so one wakeup drains many (caps the
	                          * per-wakeup cost under sustained load) */
	double cpu_budget;       /* self-imposed CPU cap, % of one core, (0, 0.05] */
	int budget_mode;         /* 1 budget-first: shed early; 0 security-first:
	                          * shed only at the cap. Either way only exact
	                          * repeats of proven-benign execs are ever sampled
	                          * (see governor.c). */
	int tpm;                  /* load the OpenSSL tpm2 provider; mTLS key is TPM-resident */
	char console[256];       /* host:port, empty = standalone */
	char cert[MAX_PATH], key[MAX_PATH], ca[MAX_PATH];
	char slack_webhook[512];
	char group[64];
	int ephemeral;            /* short-lived runner/container: decommission on exit */
	int anomaly_learn;        /* first-seen learning window, seconds (-1 = off) */
};

extern struct config cfg;
extern char hostname[256];

/* util.c */
void   jstr(FILE *f, const char *key, const char *val, int comma);
size_t jesc(char *dst, size_t cap, const char *src);
size_t jesc_ex(char *dst, size_t cap, const char *src, int *truncated);
int    parse_long(const char *s, long lo, long hi, long *out);
int    parse_bool(const char *s, int *out);
size_t scopy(char *dst, size_t cap, const char *src);
ssize_t read_small(int dirfd, const char *path, char *buf, size_t cap);
const char *sev_name(enum sev s);
const char *actor_name(enum actor a);
const char *base_name(const char *p);
uint64_t now_ms(void);
void   logmsg(const char *fmt, ...);
extern int cfg_problems;
void   cfg_problem(const char *file, int line, const char *fmt, ...);
void   strip_comment(char *s);

/* config.c */
int  config_load(const char *path);

/* rules.c */
int  rules_load(const char *path);
void rules_eval(struct proc *p);
void rule_fire(const struct rule *r, struct proc *p);
int  rules_count(void);

/* proc.c */
int  proc_open(void);
int  proc_handle(int fd);
void proc_set_sampling(unsigned n);
uint64_t proc_sampled_drops(void);
void proc_benign_reset(const char *why); /* forget every proven-benign key */
void proc_benign_tick(void);             /* housekeeping: age the benign set */
double proc_ring_fill(void);     /* share of the event ring the last drain consumed */
uint64_t proc_ring_lost(void);   /* exec records lost to a full event ring */
void pipeline_run(struct proc *p);
extern int telemetry_on;      /* runtime telemetry gate (governor-controlled) */
void governor_tick(double cpu_pct, uint64_t window_ms); /* window of the cpu average */
int  governor_shedding(void);  /* 1 while telemetry is shed or sampling is on */
int  netpolicy_load(const char *path);
enum { NP_ALLOW, NP_DENY, NP_RATE };
int  netpolicy_check(uint32_t daddr, int dport, int actor, int is_v6, pid_t pid);
int  netpolicy_count(void);
void anomaly_init(void);
void anomaly_check(struct proc *p);
void anomaly_save(void);
uint64_t anomaly_count(void);
int  forensics_search(int argc, char **argv);
void ecosystem_note(const char *comm);
void ecosystem_json(char *out, size_t cap);
unsigned governor_sample_n(void);
int  proc_fill(pid_t pid, struct proc *p);
uint64_t proc_events(void);

/* actor.c */
void actor_resolve(struct proc *p);
void actor_forget(pid_t pid);
enum actor actor_cached(pid_t pid, char *src, size_t srclen);

/* catalog.c - package / extension / tool curation */
int  catalog_load(const char *path);
void catalog_check_exec(struct proc *p);
int  catalog_verdict(const char *kind, const char *name, const char *ver, char *why, size_t whylen);

/* inventory.c */
int  inventory_init(int inotify_fd);
void inventory_scan(void);
int  inventory_owns_wd(int wd);
void inventory_on_event(int wd, uint32_t mask, const char *name);
void inventory_dump(FILE *f);

/* fim.c */
int  fim_init(int inotify_fd, const char *path); /* load, or reload in place */
int  fim_reload(void);       /* re-read the fim.conf fim_init loaded; -1 = kept */
int  fim_count(void);
void fim_resync(void);       /* re-add every watch (after an inotify overflow) */
int  fim_owns_wd(int wd);
void fim_on_event(int wd, uint32_t mask, const char *name);

/* main.c: reload rules, catalog, network policy and FIM in place (SIGHUP and
 * the console's Reload policy both come here). why is logged. */
void policy_reload(const char *why);

/* respond.c */
int  respond_kill(pid_t pid, const char *why);  /* SIGKILL pid and every descendant */
/* As respond_kill, but only if pid still names the process that started at
 * start_ticks (field 22 of /proc/<pid>/stat; 0 = not known, no check). */
int  respond_kill_if(pid_t pid, unsigned long long start_ticks, const char *why);
/* Kill p's tree, then quarantine the executable it ran. *kill_rc gets the
 * kill result; on success dst is the quarantined copy, else err says why the
 * file was left in place. */
int  respond_quarantine(const struct proc *p, const char *why, int *kill_rc, char *dst, size_t dstlen,
                        char *err, size_t errlen);
int  respond_patch(pid_t pid, unsigned long addr, int kind, const char *why);
int  respond_unpatch(pid_t pid, unsigned long addr);

/* output.c */
void out_init(void);
void out_flow(pid_t pid, uid_t uid, const char *comm, enum actor a, const char *asrc,
              const char *dest, int dport, const char *verdict);
void out_alert(const char *rule, const char *mitre, const char *title, enum sev sev,
               const char *action, const struct proc *p, const char *extra_json);
void out_telemetry(const struct proc *p);
void out_heartbeat(uint64_t execs, uint64_t alerts, double cpu_pct, long rss_kb);
uint64_t out_alert_count(void);
uint64_t out_write_errors(void);
void out_audit(const char *event, const char *detail, const char *peer); /* local only */
void   identity_init(void);
const char *identity_id(void);
const char *identity_tier(void);
void out_inventory(const char *kind, const char *name, const char *ver,
                   const char *where, const char *change);
void out_flush(void);

/* console.c */
void console_tick(void);
int  console_fd(void);
unsigned console_fd_gen(void); /* changes when the socket is replaced: re-register */
int  console_just_connected(void);
unsigned console_events(void); /* EPOLLIN/EPOLLOUT mask the loop should watch */
void console_on_readable(void);
void console_send(const char *line, size_t len);
void console_goodbye(const char *reason);
uint64_t console_dropped_lines(void);
int  console_timeout_ms(void); /* ms until the link needs a tick, -1 = none */
int  console_addr_valid(const char *hostport); /* for --check-config */

/* selfstat */
double self_cpu_pct(void);
double gov_cpu_sample(void);
uint64_t gov_cpu_window_ms(void);
void   cpu_samplers_prime(void);
long   self_rss_kb(void);

#endif
