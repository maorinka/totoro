/* Console link: a single persistent TLS connection to the fleet console.
 * Alerts and inventory records are streamed up as newline-delimited JSON;
 * policy pushes (reload, mode change) come down the same socket.
 *
 * Everything here is non-blocking. The connection is a small state machine
 * (resolving -> connecting TCP -> TLS handshake -> up) driven entirely by the
 * main epoll loop, so a slow or dead console can never stall the sensor's
 * hot path:
 *   - name resolution runs on a short-lived helper thread that signals an
 *     eventfd (glibc's resolver blocks for timeout x attempts);
 *   - every connect + handshake has a deadline, and every resolved address
 *     is tried in turn;
 *   - the socket is watched for writability only while connect() is pending
 *     or OpenSSL actually wants to write, so a peer that accepts TCP and then
 *     stays silent costs nothing;
 *   - retries back off exponentially with jitter (5 s up to 5 min);
 *   - keepalive and TCP_USER_TIMEOUT detect a console that vanished without
 *     a RST.
 * The console is authenticated: its certificate must chain to `ca` AND name
 * the host (or IP) in `console =`. Without a loadable `ca` the sensor does not
 * connect at all. When no console is configured it is all inert and the
 * sensor runs fully standalone. Undelivered lines are dropped whole past a
 * bounded ring rather than growing memory without limit.
 */
#include "wisp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

enum state { ST_DOWN, ST_RESOLVING, ST_CONNECTING, ST_HANDSHAKE, ST_UP };

#define RETRY_MIN_MS    5000
#define RETRY_MAX_MS    300000
#define CONNECT_TMO_MS  10000   /* per address: TCP connect + TLS handshake */
#define MAX_ADDRS       8
#define CTL_LINE_MAX    4096

static SSL_CTX *ctx;
static SSL *ssl;
static int sfd = -1;
static enum state state;
static uint64_t next_try, deadline, retry_ms = RETRY_MIN_MS;
static int want_write;          /* last SSL call wanted to write */
static int no_ca_logged;

/* resolved addresses: the current attempt's, and the last good set as a
 * fallback when the resolver itself is failing */
struct addrs {
	struct sockaddr_storage a[MAX_ADDRS];
	socklen_t len[MAX_ADDRS];
	int n;
};
static struct addrs cur, good;
static int cur_i;

#define OUTBUF (256 * 1024)
static char obuf[OUTBUF];
static size_t ohead, otail;
static uint64_t n_dropped;

static char ibuf[CTL_LINE_MAX];
static size_t ilen;
static int idiscard;            /* skipping the rest of an over-long line */

static int enabled(void) { return cfg.console[0] != 0; }
uint64_t console_dropped_lines(void) { return n_dropped; }

/* ---- address parsing --------------------------------------------------- */

/* host:port, [v6]:port, [v6], bare v6 literal, or a bare host (port 8750). */
static int parse_hostport(const char *s, char *host, size_t hn, char *port, size_t pn)
{
	const char *h = s, *p = NULL;
	size_t hl;
	if (*s == '[') {
		const char *e = strchr(s, ']');
		if (!e)
			return -1;
		h = s + 1;
		hl = (size_t)(e - h);
		if (e[1] == ':')
			p = e + 2;
		else if (e[1])
			return -1;
	} else {
		const char *c = strchr(s, ':');
		if (c && strchr(c + 1, ':')) {
			hl = strlen(s);          /* two or more ':' -> IPv6 literal, no port */
		} else if (c) {
			hl = (size_t)(c - s);
			p = c + 1;
		} else {
			hl = strlen(s);
		}
	}
	if (!hl || hl >= hn)
		return -1;
	memcpy(host, h, hl);
	host[hl] = 0;
	if (!p)
		p = "8750";
	long v;
	if (parse_long(p, 1, 65535, &v) != 0)
		return -1;
	snprintf(port, pn, "%ld", v);
	return 0;
}

int console_addr_valid(const char *hostport)
{
	char h[256], p[16];
	return parse_hostport(hostport, h, sizeof h, p, sizeof p) == 0;
}

static int is_ip_literal(const char *host)
{
	unsigned char b[16];
	return inet_pton(AF_INET, host, b) == 1 || inet_pton(AF_INET6, host, b) == 1;
}

/* ---- state helpers ----------------------------------------------------- */

static int efd = -1;            /* resolver completion eventfd */
/* Bumped whenever the socket is closed. A new socket usually gets the same
 * fd number back (the lowest free one), and closing removed the old one from
 * the loop's epoll set, so the loop must re-register even though the number
 * and the event mask look unchanged. */
static unsigned fd_gen;

unsigned console_fd_gen(void) { return fd_gen; }

int console_fd(void)
{
	if (state == ST_RESOLVING)
		return efd;
	return state == ST_DOWN ? -1 : sfd;
}

int console_just_connected(void)
{
	static enum state last;
	int up = (state == ST_UP && last != ST_UP);
	last = state;
	return up;
}

/* Writability only when it is actually needed: connect() pending, OpenSSL
 * asked to write, or buffered output waiting to drain. Otherwise a silent
 * peer would make the level-triggered loop spin. */
unsigned console_events(void)
{
	switch (state) {
	case ST_RESOLVING: return EPOLLIN;
	case ST_CONNECTING: return EPOLLOUT;
	case ST_HANDSHAKE: return EPOLLIN | (want_write ? EPOLLOUT : 0);
	case ST_UP: return EPOLLIN | (want_write || ohead != otail ? EPOLLOUT : 0);
	default: return 0;
	}
}

/* Milliseconds until the link needs attention without any fd event (retry
 * time or an attempt deadline), or -1 for none. */
int console_timeout_ms(void)
{
	if (!enabled())
		return -1;
	uint64_t now = now_ms();
	uint64_t at = state == ST_DOWN ? (next_try ? next_try : now)
	              : (state == ST_CONNECTING || state == ST_HANDSHAKE) ? deadline : 0;
	if (!at)
		return -1;
	if (at <= now)
		return 0;
	uint64_t d = at - now;
	return d > 3600000 ? 3600000 : (int)d;
}

static void close_sock(void)
{
	if (ssl) {
		SSL_free(ssl);
		ssl = NULL;
	}
	if (sfd >= 0) {
		close(sfd);
		sfd = -1;
		fd_gen++;
	}
	want_write = 0;
}

/* Schedule the next attempt with exponential back-off and jitter, so a
 * restarted console is not hit by the whole fleet in lockstep. */
static void schedule_retry(void)
{
	uint32_t r = 0;
	if (getrandom(&r, sizeof r, GRND_NONBLOCK) != sizeof r)
		r = (uint32_t)now_ms() * 2654435761u;
	uint64_t wait = retry_ms / 2 + (uint64_t)r % (retry_ms / 2 + 1); /* [retry/2, retry] */
	next_try = now_ms() + wait;
	retry_ms = retry_ms * 2 > RETRY_MAX_MS ? RETRY_MAX_MS : retry_ms * 2;
}

static void drop(void)
{
	int was_up = state == ST_UP;
	close_sock();
	state = ST_DOWN;
	ohead = otail = 0;
	ilen = 0;
	idiscard = 0;
	if (was_up)
		retry_ms = RETRY_MIN_MS; /* a link that was up retries promptly */
	schedule_retry();
}

/* ---- TLS context ------------------------------------------------------- */

static void log_ssl_error(const char *what)
{
	unsigned long e = ERR_get_error();
	char buf[256] = "unknown error";
	if (e)
		ERR_error_string_n(e, buf, sizeof buf);
	ERR_clear_error();
	logmsg("console: %s: %s", what, buf);
}

static SSL_CTX *make_ctx(void)
{
	if (!cfg.ca[0]) {
		/* Fail closed: without a CA there is no way to authenticate the
		 * console, and the link carries every alert and accepts mode
		 * changes. Never connect unauthenticated. */
		if (!no_ca_logged++)
			logmsg("console: '%s' is set but 'ca' is not; refusing to connect to an "
			       "unauthenticated console (set ca = <console CA certificate>)", cfg.console);
		return NULL;
	}
	if (cfg.tpm) {
		/* Make the mTLS client key TPM-resident: the private key never
		 * leaves the TPM, which signs the handshake. Needs the tpm2 OpenSSL
		 * provider; TCTI comes from the environment (TPM2OPENSSL_TCTI). */
		static int loaded;
		static OSSL_PROVIDER *pdef, *ptpm;
		if (!loaded) {
			if (!pdef)
				pdef = OSSL_PROVIDER_load(NULL, "default");
			if (pdef && !ptpm)
				ptpm = OSSL_PROVIDER_load(NULL, "tpm2");
			if (!pdef || !ptpm) {
				log_ssl_error("cannot load the tpm2 OpenSSL provider (tpm = 1)");
				return NULL;
			}
			/* Prefer the default provider for all standard crypto (peer
			 * cert verification); the tpm2 provider is used only for the
			 * TPM-resident key it manages. Without this the tpm2 provider
			 * intercepts ECDSA/RSA verify and the handshake fails. */
			EVP_set_default_properties(NULL, "?provider=default");
			loaded = 1;
			logmsg("console: TPM2 provider loaded; mTLS key is TPM-resident");
		}
	}
	SSL_CTX *c = SSL_CTX_new(TLS_client_method());
	if (!c)
		return NULL;
	SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);
	if (SSL_CTX_load_verify_locations(c, cfg.ca, NULL) != 1) {
		log_ssl_error("cannot load ca");
		SSL_CTX_free(c);
		return NULL;
	}
	if (cfg.cert[0] && cfg.key[0]) {
		if (SSL_CTX_use_certificate_chain_file(c, cfg.cert) != 1)
			log_ssl_error("failed to load client cert");
		/* A TPM-resident key is a TSS2 blob loaded through the tpm2 provider's
		 * store. The socket software-TPM can throw a transient load error; a
		 * hardware TPM via /dev/tpmrm0 (kernel resource manager) does not. If
		 * the key fails to load we return NULL so the caller retries with a
		 * fresh context rather than caching a client-cert-less one. */
		if (SSL_CTX_use_PrivateKey_file(c, cfg.key, SSL_FILETYPE_PEM) != 1 ||
		    SSL_CTX_check_private_key(c) != 1) {
			ERR_clear_error();
			logmsg("console: client key load failed (%s); will retry",
			       cfg.tpm ? "TPM-resident" : cfg.key);
			SSL_CTX_free(c);
			return NULL;
		}
		logmsg("console: client identity loaded (%s)", cfg.tpm ? "TPM-resident" : "file");
	}
	SSL_CTX_set_verify(c, SSL_VERIFY_PEER, NULL);
	/* flush_buf() hands SSL_write the contiguous run at the ring's head,
	 * which may grow between a WANT_WRITE and the retry. */
	SSL_CTX_set_mode(c, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	return c;
}

/* ---- resolve ----------------------------------------------------------- */

struct resolve_job {
	char host[256], port[16];
	struct addrs out;
	int err;
	int efd;
};
static struct resolve_job job;
static pthread_t rthread;

static void *resolver(void *arg)
{
	struct resolve_job *j = arg;
	/* No AI_ADDRCONFIG: it hides 127.0.0.1 on hosts whose only IPv4 address is
	 * loopback (containers). Unusable families fail fast at connect and the
	 * next address is tried. */
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *res;
	j->out.n = 0;
	j->err = getaddrinfo(j->host, j->port, &hints, &res);
	if (!j->err) {
		for (struct addrinfo *ai = res; ai && j->out.n < MAX_ADDRS; ai = ai->ai_next) {
			if (ai->ai_addrlen > sizeof j->out.a[0])
				continue;
			memcpy(&j->out.a[j->out.n], ai->ai_addr, ai->ai_addrlen);
			j->out.len[j->out.n++] = ai->ai_addrlen;
		}
		freeaddrinfo(res);
	}
	uint64_t one = 1;
	(void)!write(j->efd, &one, sizeof one);
	return NULL;
}

static void start_resolve(void)
{
	if (!cfg.ca[0]) {
		(void)make_ctx(); /* logs the refusal once */
		next_try = now_ms() + RETRY_MAX_MS;
		return;
	}
	if (parse_hostport(cfg.console, job.host, sizeof job.host, job.port, sizeof job.port) != 0) {
		logmsg("console: cannot parse console address '%s'", cfg.console);
		schedule_retry();
		return;
	}
	if (efd < 0)
		efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (efd < 0) {
		logmsg("console: eventfd: %s", strerror(errno));
		schedule_retry();
		return;
	}
	job.efd = efd;
	/* The helper thread must never take the signals the main loop owns. */
	sigset_t all, old;
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &old);
	int rc = pthread_create(&rthread, NULL, resolver, &job);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	if (rc) {
		logmsg("console: cannot start resolver: %s", strerror(rc));
		schedule_retry();
		return;
	}
	state = ST_RESOLVING;
}

static void try_next_addr(void);

static void on_resolved(void)
{
	uint64_t x;
	if (read(efd, &x, sizeof x) != sizeof x)
		return;          /* spurious wake: the thread has not finished */
	pthread_join(rthread, NULL);
	if (job.err || !job.out.n) {
		const char *why = job.err ? gai_strerror(job.err) : "no usable address";
		if (good.n) {
			logmsg("console: cannot resolve %s (%s); using its last known address", job.host, why);
			cur = good;
		} else {
			logmsg("console: cannot resolve %s (%s); retrying", job.host, why);
			state = ST_DOWN;
			schedule_retry();
			return;
		}
	} else {
		cur = job.out;
	}
	cur_i = 0;
	try_next_addr();
}

/* ---- connect + handshake ----------------------------------------------- */

static void addr_str(const struct sockaddr_storage *a, char *out, size_t n)
{
	char ip[INET6_ADDRSTRLEN] = "?";
	int port = 0;
	if (a->ss_family == AF_INET) {
		const struct sockaddr_in *s4 = (const struct sockaddr_in *)a;
		inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip);
		port = ntohs(s4->sin_port);
		snprintf(out, n, "%s:%d", ip, port);
	} else if (a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)a;
		inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof ip);
		port = ntohs(s6->sin6_port);
		snprintf(out, n, "[%s]:%d", ip, port);
	} else {
		snprintf(out, n, "?");
	}
}

static void set_keepalive(int fd)
{
	int on = 1, idle = 60, intvl = 10, cnt = 6;
	unsigned int utmo = 120000; /* unacknowledged data for 2 min -> dead */
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
	setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &utmo, sizeof utmo);
}

/* Give up on the current address; move to the next, or back off. */
static void attempt_failed(const char *why)
{
	char a[64];
	addr_str(&cur.a[cur_i], a, sizeof a);
	close_sock();
	if (++cur_i < cur.n) {
		logmsg("console: %s (%s): %s; trying next address", cfg.console, a, why);
		try_next_addr();
		return;
	}
	state = ST_DOWN;
	schedule_retry();
	logmsg("console: %s (%s): %s; retrying in %llus", cfg.console, a, why,
	       (unsigned long long)((next_try - now_ms() + 999) / 1000));
}

static void pump_handshake(void);

static void try_next_addr(void)
{
	for (; cur_i < cur.n; cur_i++) {
		sfd = socket(cur.a[cur_i].ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (sfd < 0)
			continue;
		set_keepalive(sfd);
		deadline = now_ms() + CONNECT_TMO_MS;
		int rc = connect(sfd, (struct sockaddr *)&cur.a[cur_i], cur.len[cur_i]);
		if (rc == 0) {
			state = ST_HANDSHAKE;
			pump_handshake();
			return;
		}
		if (errno == EINPROGRESS) {
			state = ST_CONNECTING;
			return;
		}
		char why[96];
		snprintf(why, sizeof why, "connect: %s", strerror(errno));
		attempt_failed(why);
		return;
	}
	state = ST_DOWN;
	schedule_retry();
}

static void send_hello(void)
{
	char h[JESC_MAX(255)], g[JESC_MAX(63)], id[JESC_MAX(128)], tier[JESC_MAX(32)], ver[JESC_MAX(32)];
	jesc(h, sizeof h, hostname);
	jesc(g, sizeof g, cfg.group);
	jesc(id, sizeof id, identity_id());
	jesc(tier, sizeof tier, identity_tier());
	jesc(ver, sizeof ver, WISP_VERSION);
	char hello[sizeof h + sizeof g + sizeof id + sizeof tier + sizeof ver + 160];
	int n = snprintf(hello, sizeof hello,
	                 "{\"type\":\"hello\",\"host\":\"%s\",\"group\":\"%s\",\"version\":\"%s\","
	                 "\"host_id\":\"%s\",\"trust\":\"%s\",\"ephemeral\":%s}\n",
	                 h, g, ver, id, tier, cfg.ephemeral ? "true" : "false");
	if (n > 0 && (size_t)n < sizeof hello)
		console_send(hello, (size_t)n);
}

/* Advance the TLS handshake; non-blocking, resumes on the next epoll wake. */
static void pump_handshake(void)
{
	if (!ctx)
		ctx = make_ctx();
	if (!ctx) {          /* no ca, or key/cert load failed (e.g. transient TPM error) */
		close_sock();
		state = ST_DOWN;
		schedule_retry();
		return;
	}
	if (!ssl) {
		char host[256], port[16];
		if (parse_hostport(cfg.console, host, sizeof host, port, sizeof port) != 0) {
			attempt_failed("bad console address");
			return;
		}
		ssl = SSL_new(ctx);
		if (!ssl) {
			attempt_failed("SSL_new failed");
			return;
		}
		SSL_set_fd(ssl, sfd);
		/* Authenticate the console by name, not just by chain: the
		 * certificate must name exactly the host (or IP) in `console =`. */
		int ok;
		if (is_ip_literal(host)) {
			ok = X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host) == 1;
		} else {
			SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
			ok = SSL_set1_host(ssl, host) == 1 && SSL_set_tlsext_host_name(ssl, host) == 1;
		}
		if (!ok) {
			attempt_failed("cannot set the console name to verify");
			return;
		}
		SSL_set_connect_state(ssl);
	}
	ERR_clear_error();
	int r = SSL_do_handshake(ssl);
	if (r == 1) {
		state = ST_UP;
		want_write = 0;
		retry_ms = RETRY_MIN_MS;
		deadline = 0;
		good = cur;
		char a[64];
		addr_str(&cur.a[cur_i], a, sizeof a);
		logmsg("console: connected to %s (%s, %s)", cfg.console, a, SSL_get_version(ssl));
		send_hello(); /* may drop() the link if the write fails: last */
		return;
	}
	int e = SSL_get_error(ssl, r);
	if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
		want_write = e == SSL_ERROR_WANT_WRITE;
		return;
	}
	char why[384];
	long vr = SSL_get_verify_result(ssl);
	unsigned long ee = ERR_get_error();
	if (vr != X509_V_OK) {
		snprintf(why, sizeof why, "TLS handshake failed: console certificate rejected: %s",
		         X509_verify_cert_error_string(vr));
	} else if (ee) {
		char eb[256];
		ERR_error_string_n(ee, eb, sizeof eb);
		snprintf(why, sizeof why, "TLS handshake failed: %s", eb);
	} else if (e == SSL_ERROR_SYSCALL || e == SSL_ERROR_ZERO_RETURN) {
		snprintf(why, sizeof why, "TLS handshake failed: connection closed by peer");
	} else {
		snprintf(why, sizeof why, "TLS handshake failed (ssl error %d)", e);
	}
	ERR_clear_error();
	attempt_failed(why);
}

static void flush_buf(void)
{
	while (ohead != otail && state == ST_UP) {
		size_t chunk = (otail > ohead ? otail : OUTBUF) - ohead;
		ERR_clear_error();
		int n = SSL_write(ssl, obuf + ohead, (int)chunk);
		if (n <= 0) {
			int e = SSL_get_error(ssl, n);
			if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) {
				want_write = e == SSL_ERROR_WANT_WRITE;
				return;
			}
			logmsg("console: connection lost (write)");
			drop();
			return;
		}
		want_write = 0;
		ohead = (ohead + (size_t)n) % OUTBUF;
	}
}

/* Queue one complete line. A line that does not fit the free space is
 * dropped whole (and counted) -- never a prefix, which would fuse with the
 * next line into one unparseable record. Never blocks the hot path. */
void console_send(const char *line, size_t len)
{
	if (!enabled() || state != ST_UP || !len)
		return;
	size_t used = (otail + OUTBUF - ohead) % OUTBUF, free_ = OUTBUF - 1 - used;
	if (len > free_) {
		if (n_dropped++ % 1000 == 0)
			logmsg("console: link congested, dropping lines (%llu so far)",
			       (unsigned long long)n_dropped);
		return;
	}
	size_t first = OUTBUF - otail < len ? OUTBUF - otail : len;
	memcpy(obuf + otail, line, first);
	memcpy(obuf, line + first, len - first);
	otail = (otail + len) % OUTBUF;
	flush_buf();
}

/* ---- control channel --------------------------------------------------- */

static const char *mode_name(enum mode m) { return m == MODE_ENFORCE ? "enforce" : "monitor"; }

static void control_line(const char *l)
{
	/* Minimal control channel: one JSON command per line. */
	if (strstr(l, "\"reload\""))
		policy_reload("console"); /* exactly what SIGHUP applies */
	enum mode m = cfg.mode;
	if (strstr(l, "\"mode\":\"enforce\""))
		m = MODE_ENFORCE;
	else if (strstr(l, "\"mode\":\"monitor\""))
		m = MODE_MONITOR;
	if (m != cfg.mode) {
		char a[64] = "?";
		if (cur.n && cur_i < cur.n)
			addr_str(&cur.a[cur_i], a, sizeof a);
		logmsg("console: mode changed %s -> %s by console %s (%s)", mode_name(cfg.mode),
		       mode_name(m), cfg.console, a);
		char detail[160];
		snprintf(detail, sizeof detail, "%s -> %s", mode_name(cfg.mode), mode_name(m));
		out_audit("mode-change", detail, cfg.console);
		cfg.mode = m;
	}
}

static void read_control(void)
{
	char buf[2048];
	for (;;) {
		ERR_clear_error();
		int n = SSL_read(ssl, buf, sizeof buf);
		if (n <= 0) {
			int e = SSL_get_error(ssl, n);
			if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
				want_write = e == SSL_ERROR_WANT_WRITE;
				return;
			}
			logmsg("console: connection closed by the console");
			drop();
			return;
		}
		for (int i = 0; i < n; i++) {
			char c = buf[i];
			if (c == '\n') {
				if (!idiscard) {
					ibuf[ilen] = 0;
					control_line(ibuf);
				}
				ilen = 0;
				idiscard = 0;
			} else if (!idiscard) {
				if (ilen + 1 >= sizeof ibuf) {
					idiscard = 1; /* over-long line: ignore it whole */
					ilen = 0;
				} else {
					ibuf[ilen++] = c;
				}
			}
		}
		if (state != ST_UP)
			return;
	}
}

/* Called when epoll reports the console fd readable/writable. */
void console_on_readable(void)
{
	switch (state) {
	case ST_RESOLVING:
		on_resolved();
		return;
	case ST_CONNECTING: {
		int err = 0;
		socklen_t l = sizeof err;
		if (getsockopt(sfd, SOL_SOCKET, SO_ERROR, &err, &l) != 0)
			err = errno;
		if (err) {
			char why[96];
			snprintf(why, sizeof why, "connect: %s", strerror(err));
			attempt_failed(why);
			return;
		}
		state = ST_HANDSHAKE;
		pump_handshake();
		return;
	}
	case ST_HANDSHAKE:
		pump_handshake();
		return;
	case ST_UP:
		if (ohead != otail || want_write)
			flush_buf();
		if (state == ST_UP)
			read_control();
		return;
	default:
		return;
	}
}

/* Ephemeral sensor lifecycle: tell the console this host is going away so a
 * short-lived runner or container is decommissioned at once instead of
 * lingering as a "stale" host. Bounded wait (<= 1 s) to get the line out. */
void console_goodbye(const char *reason)
{
	if (!enabled() || state != ST_UP)
		return;
	char h[JESC_MAX(255)], r[JESC_MAX(64)];
	jesc(h, sizeof h, hostname);
	jesc(r, sizeof r, reason);
	char line[sizeof h + sizeof r + 64];
	int n = snprintf(line, sizeof line, "{\"type\":\"bye\",\"host\":\"%s\",\"reason\":\"%s\"}\n", h, r);
	if (n > 0 && (size_t)n < sizeof line)
		console_send(line, (size_t)n);
	for (int i = 0; i < 20 && ohead != otail && state == ST_UP; i++) {
		struct pollfd pf = { .fd = sfd, .events = POLLOUT };
		poll(&pf, 1, 50);
		flush_buf();
	}
	/* flush_buf() may have drop()ed the connection (peer gone) -- then ssl
	 * is already freed and NULL; only shut down a live session. */
	if (ssl && state == ST_UP)
		SSL_shutdown(ssl);
}

/* Retry and deadline handling; called after every loop iteration and when
 * the loop's console timeout expires. */
void console_tick(void)
{
	if (!enabled())
		return;
	uint64_t now = now_ms();
	if (state == ST_DOWN && now >= next_try)
		start_resolve();
	else if ((state == ST_CONNECTING || state == ST_HANDSHAKE) && deadline && now >= deadline)
		attempt_failed(state == ST_CONNECTING ? "connect timed out" : "TLS handshake timed out");
	else if (state == ST_UP && ohead != otail)
		flush_buf();
}
