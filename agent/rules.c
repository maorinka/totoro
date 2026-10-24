/* Policy rule engine.
 *
 * rules.conf, one rule per line:
 *   <id> <severity> <action> <mitre|-> "<title>" [mode=monitor|enforce] <cond>...
 * cond:  [!]<field><op><value>[,<value>...]
 *   field: exe cmd comm pcomm actor src uid tty
 *   op:    =  equals   ^=  prefix   $=  suffix   *=  contains
 * All conditions must hold; comma alternatives are OR'ed.
 * Rules are first-match; action "ignore" is an allow-list entry.
 */
#include "wisp.h"

#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

enum { F_EXE, F_CMD, F_COMM, F_PCOMM, F_ACTOR, F_SRC, F_UID, F_TTY };
enum { OP_EQ, OP_PREFIX, OP_SUFFIX, OP_CONTAINS };

static struct rule *rules;
static int nrules;

int rules_count(void) { return nrules; }

static const char *fields[] = { "exe", "cmd", "comm", "pcomm", "actor", "src", "uid", "tty", NULL };

static int parse_sev(const char *s)
{
	static const char *n[] = { "info", "low", "medium", "high", "critical" };
	for (int i = 0; i < 5; i++)
		if (!strcmp(s, n[i]))
			return i;
	return -1;
}

static int parse_action(const char *s)
{
	if (!strcmp(s, "ignore")) return ACT_IGNORE;
	if (!strcmp(s, "alert")) return ACT_ALERT;
	if (!strcmp(s, "kill")) return ACT_KILL;
	if (!strcmp(s, "quarantine")) return ACT_QUARANTINE;
	return -1;
}

/* Tokenizer honoring double quotes. Mutates s. */
static char *next_tok(char **s)
{
	char *p = *s;
	while (isspace((unsigned char)*p))
		p++;
	if (!*p)
		return NULL;
	char *start = p, *w = p;
	int q = 0;
	for (; *p; p++) {
		if (*p == '"') {
			q = !q;
			continue;
		}
		if (!q && isspace((unsigned char)*p))
			break;
		*w++ = *p;
	}
	if (*p)
		p++;
	*w = 0;
	*s = p;
	return start;
}

static int parse_cond(char *t, struct cond *c)
{
	memset(c, 0, sizeof *c);
	if (*t == '!') {
		c->neg = 1;
		t++;
	}
	char *op = strpbrk(t, "=^$*");
	if (!op)
		return -1;
	char *val;
	if (*op == '=') {
		c->op = OP_EQ;
		val = op + 1;
	} else if (op[1] == '=') {
		c->op = *op == '^' ? OP_PREFIX : *op == '$' ? OP_SUFFIX : OP_CONTAINS;
		val = op + 2;
	} else {
		return -1;
	}
	*op = 0;
	c->field = -1;
	for (int i = 0; fields[i]; i++)
		if (!strcmp(t, fields[i]))
			c->field = i;
	if (c->field < 0)
		return -1;
	c->buf = strdup(val);
	if (!c->buf)
		return -1;
	char *save, *v = strtok_r(c->buf, ",", &save);
	for (; v && c->nalt < MAX_ALT; v = strtok_r(NULL, ",", &save)) {
		c->alt[c->nalt] = v;
		c->altlen[c->nalt++] = strlen(v);
	}
	if (!c->nalt || v) { /* no value, or more alternatives than MAX_ALT */
		free(c->buf);
		c->buf = NULL;
		return -1;
	}
	return 0;
}

static void free_conds(struct rule *r)
{
	for (int j = 0; j < r->ncond; j++) {
		free(r->c[j].buf);
		r->c[j].buf = NULL;
	}
	r->ncond = 0;
}

static void free_rules(struct rule *rs, int n)
{
	for (int i = 0; i < n; i++)
		free_conds(&rs[i]);
	free(rs);
}

int rules_load(const char *path)
{
	FILE *f = fopen(path, "re");
	if (!f)
		return -1;
	struct rule *nr = NULL;
	int n = 0, cap = 0, lineno = 0;
	char line[2048];
	while (fgets(line, sizeof line, f)) {
		lineno++;
		if (!strchr(line, '\n') && !feof(f)) {
			/* Never parse the pieces of an over-long line as rules. */
			cfg_problem(path, lineno, "line longer than %zu bytes (skipped)", sizeof line - 2);
			int ch;
			while ((ch = fgetc(f)) != EOF && ch != '\n')
				;
			continue;
		}
		char *s = line, *t;
		while (isspace((unsigned char)*s))
			s++;
		if (!*s || *s == '#')
			continue;
		if (n == cap) {
			int ncap = cap ? cap * 2 : 64;
			struct rule *g = realloc(nr, ncap * sizeof *nr);
			if (!g) {
				cfg_problem(path, lineno, "out of memory; keeping the current rules");
				free_rules(nr, n);
				fclose(f);
				return -1;
			}
			nr = g;
			cap = ncap;
		}
		struct rule *r = &nr[n];
		memset(r, 0, sizeof *r);
		r->enforce_override = -1;
		char *id = next_tok(&s), *sev = next_tok(&s), *act = next_tok(&s);
		char *mitre = next_tok(&s), *title = next_tok(&s);
		if (!title || parse_sev(sev) < 0 || parse_action(act) < 0) {
			cfg_problem(path, lineno, "malformed rule (want: <id> <severity> <action> <mitre|-> \"<title>\" <cond>...)");
			continue;
		}
		snprintf(r->id, sizeof r->id, "%s", id);
		snprintf(r->mitre, sizeof r->mitre, "%s", strcmp(mitre, "-") ? mitre : "");
		snprintf(r->title, sizeof r->title, "%s", title);
		r->sev = parse_sev(sev);
		r->action = parse_action(act);
		int bad = 0;
		while ((t = next_tok(&s))) {
			if (!strncmp(t, "mode=", 5)) {
				/* Exactly monitor or enforce: a typo must not quietly
				 * turn a blocking rule into a report-only one. */
				if (!strcmp(t + 5, "enforce"))
					r->enforce_override = MODE_ENFORCE;
				else if (!strcmp(t + 5, "monitor"))
					r->enforce_override = MODE_MONITOR;
				else {
					cfg_problem(path, lineno, "unknown mode '%s' (monitor or enforce; rule skipped)", t + 5);
					bad = 1;
					break;
				}
				continue;
			}
			if (r->ncond == MAX_COND) {
				cfg_problem(path, lineno, "more than %d conditions (rule skipped)", MAX_COND);
				bad = 1;
				break;
			}
			char shown[128];
			snprintf(shown, sizeof shown, "%s", t); /* parse_cond cuts t */
			if (parse_cond(t, &r->c[r->ncond]) < 0) {
				cfg_problem(path, lineno, "bad condition '%s' (want [!]field op value[,value...], "
				            "at most %d values)", shown, MAX_ALT);
				bad = 1;
				break;
			}
			r->ncond++;
		}
		if (!bad && !r->ncond)
			cfg_problem(path, lineno, "rule %s has no conditions (skipped)", r->id);
		if (bad || !r->ncond)
			free_conds(r);
		if (!bad && r->ncond) {
			/* Reorder conditions cheap-first so a rule bails on a short
			 * integer/comm check before scanning the long cmd/exe. Fields:
			 * tty/uid/actor/src/comm are cheap; pcomm triggers a /proc read;
			 * exe/cmd are long-string contains. Insertion sort (<=8 conds). */
			static const int rank[] = {
				[F_TTY] = 0, [F_UID] = 0, [F_ACTOR] = 1, [F_SRC] = 1,
				[F_COMM] = 2, [F_PCOMM] = 4, [F_EXE] = 5, [F_CMD] = 6,
			};
			for (int a = 1; a < r->ncond; a++) {
				struct cond tmp = r->c[a];
				int b = a - 1;
				while (b >= 0 && rank[r->c[b].field] > rank[tmp.field]) {
					r->c[b + 1] = r->c[b];
					b--;
				}
				r->c[b + 1] = tmp;
			}
			n++;
		}
	}
	fclose(f);
	free_rules(rules, nrules);
	rules = nr;
	nrules = n;
	return n;
}

static void load_pcomm(struct proc *p)
{
	if (p->pcomm[0] || !p->ppid)
		return;
	char path[32];
	snprintf(path, sizeof path, "/proc/%d/comm", p->ppid);
	ssize_t n = read_small(AT_FDCWD, path, p->pcomm, sizeof p->pcomm);
	if (n > 0 && p->pcomm[n - 1] == '\n')
		p->pcomm[n - 1] = 0;
	if (!p->pcomm[0])
		strcpy(p->pcomm, "?");
}

static int match1(const char *s, size_t sl, const char *v, size_t vl, int op)
{
	switch (op) {
	case OP_EQ: return sl == vl && !memcmp(s, v, vl);
	case OP_PREFIX: return sl >= vl && !memcmp(s, v, vl);
	case OP_SUFFIX: return sl >= vl && !memcmp(s + sl - vl, v, vl);
	default: return memmem(s, sl, v, vl) != NULL;
	}
}

static int cond_holds(const struct cond *c, struct proc *p)
{
	char tmp[24];
	const char *s;
	switch (c->field) {
	case F_EXE: s = p->exe; break;
	case F_CMD: s = p->cmd; break;
	case F_COMM: s = p->comm; break;
	case F_PCOMM: load_pcomm(p); s = p->pcomm; break;
	case F_ACTOR: s = actor_name(p->actor); break;
	case F_SRC: s = p->actor_src; break;
	case F_UID: snprintf(tmp, sizeof tmp, "%u", p->uid); s = tmp; break;
	default: s = p->has_tty ? "yes" : "no"; break;
	}
	size_t sl = c->field == F_CMD ? p->cmdlen : strlen(s);
	int hit = 0;
	for (int i = 0; i < c->nalt && !hit; i++)
		hit = match1(s, sl, c->alt[i], c->altlen[i], c->op);
	return hit != c->neg;
}

/* Apply a rule's action honoring global / per-rule mode. */
void rule_fire(const struct rule *r, struct proc *p)
{
	int mode = r->enforce_override >= 0 ? r->enforce_override : (int)cfg.mode;
	const char *done = "alert";
	char extra[JESC_MAX(MAX_PATH + 64) + 32] = "";
	if (mode == MODE_ENFORCE && r->action >= ACT_KILL) {
		if (r->action == ACT_QUARANTINE && p->exe[0]) {
			char dst[MAX_PATH + 64], err[MAX_PATH + 64], e1[JESC_MAX(MAX_PATH + 64)];
			int krc = -1;
			if (respond_quarantine(p, r->id, &krc, dst, sizeof dst, err, sizeof err) == 0) {
				jesc(e1, sizeof e1, dst);
				snprintf(extra, sizeof extra, "\"quarantined\":\"%s\"", e1);
				done = "quarantine";
			} else {
				/* Additive field: why the file was left in place. */
				jesc(e1, sizeof e1, err);
				snprintf(extra, sizeof extra, "\"quarantine_error\":\"%s\"", e1);
				done = krc == 0 ? "kill" : "kill-failed";
			}
		} else {
			done = respond_kill(p->pid, p->start, r->id) == 0 ? "kill" : "kill-failed";
		}
	} else if (r->action >= ACT_KILL) {
		done = "would-block"; /* monitor mode: report what enforce would do */
	}
	out_alert(r->id, r->mitre, r->title, r->sev, done, p, extra[0] ? extra : NULL);
}

void rules_eval(struct proc *p)
{
	for (int i = 0; i < nrules; i++) {
		struct rule *r = &rules[i];
		int ok = 1;
		for (int j = 0; j < r->ncond && ok; j++)
			ok = cond_holds(&r->c[j], p);
		if (!ok)
			continue;
		if (r->action != ACT_IGNORE)
			rule_fire(r, p);
		return;
	}
}
