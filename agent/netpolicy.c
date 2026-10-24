/* Network data-flow policy: attribute every outbound connection to an actor
 * and check it against policy. io.security's "API monitoring ... and in-app
 * data-flow and exposure control" / "realtime policy enforcement across
 * processes, APIs and data flows".
 *
 * netpolicy.conf, first match wins:
 *   allow|deny <cidr>|any [:port|:any] [actor=<actor>]
 *   limit      <cidr>|any [:port|:any] <N>/s|<N>/m [actor=<actor>]
 *
 * `limit` is API rate limiting: each process gets a token bucket of N new
 * connections per second (or minute) to the matching destination. Within
 * the limit the rule is transparent (evaluation continues, so a later deny
 * still applies); over it the flow is reported as NP_RATE and, in enforce
 * mode, corrected inline by the caller. The sensor sees TCP connects, so this
 * limits connection rate per process -- not individual requests multiplexed
 * over a kept-alive connection.
 * e.g.
 *   deny  any :22         actor=ai        # AI agents may not SSH out
 *   allow 10.0.0.0/8 :any                 # internal is fine
 *   deny  any :any        actor=ai        # default-deny egress for AI agents
 */
#include "wisp.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

struct netrule {
	int deny;
	int limit;            /* 1 = rate-limit rule (non-terminal) */
	double rate;          /* tokens per ms */
	double burst;         /* bucket size (= N) */
	uint32_t net, mask;   /* v4 only for policy; v6 is monitored, matched as "any" */
	int any_net;
	int port;             /* -1 = any */
	int actor;            /* -1 = any, else enum actor */
};

static struct netrule *rules;
static int nrules;

/* Per-(rule, pid) token buckets for `limit` rules: a small open-addressed
 * table with short linear probing. On a miss the least-recently-used slot in
 * the probe window is recycled, so two live pids that hash together do not
 * keep resetting each other to a full bucket (which would disable the limit
 * for both). Buckets are keyed by rule index, so netpolicy_load() clears the
 * table: indices are not stable across a policy reload. */
#define BUCKETS 512
#define PROBE 4
static struct bucket { int rule; pid_t pid; double tokens; uint64_t last; } bk[BUCKETS];


static int parse_actor(const char *s)
{
	for (int i = 0; i < 6; i++)
		if (!strcmp(s, actor_name(i)))
			return i;
	return -1;
}

int netpolicy_load(const char *path)
{
	FILE *f = fopen(path, "re");
	if (!f)
		return -1;
	struct netrule *nr = NULL;
	int n = 0, cap = 0;
	char line[256];
	int ln = 0;
	while (fgets(line, sizeof line, f)) {
		ln++;
		if (!strchr(line, '\n') && !feof(f)) {
			/* Never parse the pieces of an over-long line as rules. */
			cfg_problem(path, ln, "line longer than %zu bytes (skipped)", sizeof line - 2);
			int ch;
			while ((ch = fgetc(f)) != EOF && ch != '\n')
				;
			continue;
		}
		char *s = line;
		while (isspace((unsigned char)*s)) s++;
		strip_comment(s);
		if (!*s || *s == '#') continue;
		/* A malformed line is skipped and reported -- never reinterpreted
		 * (an unknown verb, actor or network must not widen an allow). */
		char verb[8], dest[64] = "", extra[64] = "", rate[32] = "";
		int k;
		if (!strncmp(s, "limit", 5)) {
			k = sscanf(s, "%7s %63s %31s %63s", verb, dest, rate, extra);
			if (k >= 1 && strcmp(verb, "limit")) {
				/* "limits", "limit2", ...: not a verb, and never an allow. */
				cfg_problem(path, ln, "unknown verb '%s' (allow, deny or limit)", verb);
				continue;
			}
			if (k < 3) { cfg_problem(path, ln, "want 'limit <dest>[:port] <N>/s|<N>/m [actor=]'"); continue; }
			k--; /* so `extra` is at the same index as for allow/deny */
		} else {
			k = sscanf(s, "%7s %63s %63s", verb, dest, extra);
			if (k < 2) { cfg_problem(path, ln, "want 'allow|deny <dest>[:port] [actor=]'"); continue; }
			if (strcmp(verb, "allow") && strcmp(verb, "deny")) {
				cfg_problem(path, ln, "unknown verb '%s' (allow, deny or limit)", verb);
				continue;
			}
		}
		if (n == cap) {
			int ncap = cap ? cap * 2 : 32;
			struct netrule *g = realloc(nr, ncap * sizeof *nr);
			if (!g) {
				cfg_problem(path, ln, "out of memory; keeping the current network policy");
				free(nr);
				fclose(f);
				return -1;
			}
			nr = g;
			cap = ncap;
		}
		struct netrule *r = &nr[n];
		memset(r, 0, sizeof *r);
		r->deny = !strcmp(verb, "deny");
		if (!strcmp(verb, "limit")) {
			char *sl = strchr(rate, '/');
			double nper = atof(rate);
			double per_ms = sl && sl[1] == 'm' ? 60000.0 : 1000.0;
			if (nper <= 0 || !sl || (sl[1] != 's' && sl[1] != 'm')) {
				cfg_problem(path, ln, "bad rate '%s' (want e.g. 10/s or 60/m)", rate);
				continue;
			}
			r->limit = 1;
			r->burst = nper;
			r->rate = nper / per_ms;
		}
		r->port = -1;
		r->actor = -1;
		/* split host[:port] */
		char *colon = strrchr(dest, ':');
		if (colon) {
			*colon = 0;
			if (strcmp(colon + 1, "any")) {
				char *end;
				long p = strtol(colon + 1, &end, 10);
				if (*end || p < 1 || p > 65535) {
					cfg_problem(path, ln, "bad port '%s'", colon + 1);
					continue;
				}
				r->port = (int)p;
			}
		}
		if (!strcmp(dest, "any") || !*dest) {
			r->any_net = 1;
		} else {
			char *slash = strchr(dest, '/');
			int bits = 32;
			if (slash) {
				*slash = 0;
				char *end;
				bits = (int)strtol(slash + 1, &end, 10);
				if (*end || bits < 0 || bits > 32) {
					cfg_problem(path, ln, "bad prefix length '/%s'", slash + 1);
					continue;
				}
			}
			struct in_addr a;
			if (!inet_aton(dest, &a)) {
				cfg_problem(path, ln, "bad IPv4 network '%s'", dest);
				continue;
			}
			r->net = ntohl(a.s_addr);
			r->mask = bits >= 32 ? 0xffffffffu : bits == 0 ? 0 : ~((1u << (32 - bits)) - 1);
			r->net &= r->mask;
		}
		if (k >= 3) {
			if (strncmp(extra, "actor=", 6)) {
				cfg_problem(path, ln, "unexpected '%s' (only actor=<actor> may follow)", extra);
				continue;
			}
			r->actor = parse_actor(extra + 6);
			if (r->actor < 0) {
				cfg_problem(path, ln, "unknown actor '%s' (human, ai, code, ci, service, unknown)", extra + 6);
				continue;
			}
		}
		n++;
	}
	fclose(f);
	free(rules);
	rules = nr;
	nrules = n;
	memset(bk, 0, sizeof bk); /* rule indices changed; see take_token() */
	return n;
}

static int take_token(int ri, const struct netrule *r, pid_t pid)
{
	unsigned h = ((unsigned)pid * 2654435761u) ^ (unsigned)ri * 40503u;
	uint64_t now = now_ms();
	struct bucket *b = NULL, *lru = NULL;
	for (int i = 0; i < PROBE; i++) {
		struct bucket *c = &bk[(h + i) % BUCKETS];
		if (c->last && c->rule == ri && c->pid == pid) { b = c; break; }
		if (!lru || c->last < lru->last)
			lru = c;
	}
	if (!b) {
		b = lru;
		b->rule = ri;
		b->pid = pid;
		b->tokens = r->burst;
		b->last = now;
	}
	b->tokens += (double)(now - b->last) * r->rate;
	if (b->tokens > r->burst)
		b->tokens = r->burst;
	b->last = now;
	if (b->tokens < 1.0)
		return 0;
	b->tokens -= 1.0;
	return 1;
}

/* Classify a flow: NP_ALLOW, NP_DENY, or NP_RATE (over a limit rule). daddr
 * is host byte order (v4); v6 flows are matched only by port/actor. */
int netpolicy_check(uint32_t daddr, int dport, int actor, int is_v6, pid_t pid)
{
	for (int i = 0; i < nrules; i++) {
		struct netrule *r = &rules[i];
		if (r->actor >= 0 && r->actor != actor) continue;
		if (r->port >= 0 && r->port != dport) continue;
		if (!r->any_net) {
			if (is_v6) continue;
			if ((daddr & r->mask) != r->net) continue;
		}
		if (r->limit) {
			if (!take_token(i, r, pid))
				return NP_RATE;
			continue; /* within limit: transparent */
		}
		return r->deny ? NP_DENY : NP_ALLOW;
	}
	return NP_ALLOW;
}

int netpolicy_count(void) { return nrules; }
