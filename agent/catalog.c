/* Curated catalog: which packages, IDE extensions, AI tools and MCP
 * servers are sanctioned on the fleet.
 *
 * catalog.conf:
 *   default <kind> allow|deny          # deny = allow-list mode for that kind
 *   <kind> <name> allow|deny [version] # version pins an allowed package
 * kinds: npm pip (checked when a package manager runs), vsx (IDE
 * extensions, checked on discovery by inventory.c), ai (AI tools, checked
 * when one starts)
 *
 * Install-time enforcement: when `npm install X` / `pip install X` execs,
 * the requested packages are checked before the package manager has even
 * resolved them; in enforce mode the installer is killed.
 */
#include "wisp.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

struct entry {
	char kind[8];
	char name[128];
	char ver[48];
	int deny;
};

static struct entry *ents;
static int nents;
static struct { char kind[8]; int deny; } defaults[8];
static int ndefaults;

int catalog_load(const char *path)
{
	FILE *f = fopen(path, "re");
	if (!f)
		return -1;
	struct entry *ne = NULL;
	int n = 0, cap = 0, nd = 0;
	struct { char kind[8]; int deny; } nds[8];
	char line[512], a[16], b[160], c[16], d[64];
	int ln = 0;
	while (fgets(line, sizeof line, f)) {
		ln++;
		if (!strchr(line, '\n') && !feof(f)) {
			cfg_problem(path, ln, "line longer than %zu bytes (skipped)", sizeof line - 2);
			int ch;
			while ((ch = fgetc(f)) != EOF && ch != '\n')
				;
			continue;
		}
		char *s = line;
		while (isspace((unsigned char)*s))
			s++;
		strip_comment(s);
		if (!*s || *s == '#')
			continue;
		d[0] = 0;
		int k = sscanf(s, "%15s %159s %15s %63s", a, b, c, d);
		if (!strcmp(a, "default") && k >= 3) {
			if (strcmp(c, "allow") && strcmp(c, "deny")) {
				cfg_problem(path, ln, "default must be allow or deny, got '%s'", c);
				continue;
			}
			if (nd == 8) {
				cfg_problem(path, ln, "more than 8 default lines (skipped)");
				continue;
			}
			snprintf(nds[nd].kind, sizeof nds[nd].kind, "%s", b);
			nds[nd++].deny = !strcmp(c, "deny");
			continue;
		}
		if (k < 3) {
			cfg_problem(path, ln, "want '<kind> <name> allow|deny [version]'");
			continue;
		}
		if (strcmp(c, "allow") && strcmp(c, "deny")) {
			cfg_problem(path, ln, "verdict must be allow or deny, got '%s' (line skipped)", c);
			continue;
		}
		if (n == cap) {
			int ncap = cap ? cap * 2 : 128;
			struct entry *g = realloc(ne, ncap * sizeof *ne);
			if (!g) {
				cfg_problem(path, ln, "out of memory; keeping the current catalog");
				free(ne);
				fclose(f);
				return -1;
			}
			ne = g;
			cap = ncap;
		}
		snprintf(ne[n].kind, sizeof ne[n].kind, "%s", a);
		snprintf(ne[n].name, sizeof ne[n].name, "%s", b);
		snprintf(ne[n].ver, sizeof ne[n].ver, "%s", k >= 4 ? d : "");
		ne[n].deny = !strcmp(c, "deny");
		n++;
	}
	fclose(f);
	free(ents);
	ents = ne;
	nents = n;
	memcpy(defaults, nds, sizeof nds);
	ndefaults = nd;
	return n;
}

/* 0 = allowed, 1 = violates catalog. */
int catalog_verdict(const char *kind, const char *name, const char *ver, char *why, size_t whylen)
{
	for (int i = 0; i < nents; i++) {
		struct entry *e = &ents[i];
		if (strcmp(e->kind, kind) || strcasecmp(e->name, name))
			continue;
		if (e->deny) {
			snprintf(why, whylen, "%s package '%s' is denied by catalog", kind, name);
			return 1;
		}
		if (e->ver[0] && strcmp(e->ver, "*") && ver && *ver && strcmp(e->ver, ver)) {
			snprintf(why, whylen, "%s '%s' pinned to %s, got %s", kind, name, e->ver, ver);
			return 1;
		}
		return 0;
	}
	for (int i = 0; i < ndefaults; i++)
		if (!strcmp(defaults[i].kind, kind) && defaults[i].deny) {
			snprintf(why, whylen, "%s '%s' is not in the curated catalog", kind, name);
			return 1;
		}
	return 0;
}

static void violation(struct proc *p, const char *kind, const char *why)
{
	struct rule r = { .sev = SEV_HIGH, .action = ACT_KILL, .enforce_override = -1 };
	snprintf(r.id, sizeof r.id, "CAT-%s", kind);
	snprintf(r.mitre, sizeof r.mitre, "%s", !strcmp(kind, "ai") ? "" : "T1195.001");
	snprintf(r.title, sizeof r.title, "%s", why);
	for (char *c = r.id; *c; c++)
		*c = toupper((unsigned char)*c);
	rule_fire(&r, p);
}

static int is_pm(const char *c, const char *const *l)
{
	for (; *l; l++)
		if (!strcmp(c, *l))
			return 1;
	return 0;
}

/* Split "name@ver" (npm, scoped aware) or "name==ver" (pip). */
static void split_spec(const char *kind, char *tok, char **ver)
{
	*ver = NULL;
	if (!strcmp(kind, "npm")) {
		char *at = strchr(tok + (*tok == '@'), '@');
		if (at) {
			*at = 0;
			*ver = at + 1;
		}
	} else {
		char *eq = strstr(tok, "==");
		if (eq) {
			*eq = 0;
			*ver = eq + 2;
		} else {
			tok[strcspn(tok, "<>=!~[;")] = 0;
		}
	}
}

void catalog_check_exec(struct proc *p)
{
	static const char *const npm[] = { "npm", "yarn", "pnpm", "bun", NULL };
	static const char *const pip[] = { "pip", "pip3", "uv", "pipx", "poetry", NULL };
	char why[256];

	/* Shadow AI: an AI tool starting up on its own (not a child of one). */
	if (p->actor == ACTOR_AI && p->self_classified) {
		if (catalog_verdict("ai", p->actor_src, NULL, why, sizeof why))
			violation(p, "ai", why);
		return;
	}

	const char *kind = NULL;
	const char *b = base_name(p->exe);
	if (is_pm(p->comm, npm) || is_pm(b, npm) || strstr(p->cmd, "npm-cli.js"))
		kind = "npm";
	else if (is_pm(p->comm, pip) || is_pm(b, pip) || strstr(p->cmd, "-m pip"))
		kind = "pip";
	if (!kind)
		return;

	char cmd[MAX_CMD], *save, *t;
	snprintf(cmd, sizeof cmd, "%s", p->cmd);
	int seen_verb = 0, skip_next = 0;
	for (t = strtok_r(cmd, " ", &save); t; t = strtok_r(NULL, " ", &save)) {
		if (!seen_verb) {
			if (!strcmp(t, "install") || !strcmp(t, "i") || !strcmp(t, "add"))
				seen_verb = 1;
			continue;
		}
		if (skip_next) {
			skip_next = 0;
			continue;
		}
		if (*t == '-') {
			/* options that take an argument */
			if (!strcmp(t, "-r") || !strcmp(t, "--requirement") || !strcmp(t, "-c") ||
			    !strcmp(t, "--prefix") || !strcmp(t, "-t") || !strcmp(t, "--target") ||
			    !strcmp(t, "-i") || !strcmp(t, "--index-url") || !strcmp(t, "--registry"))
				skip_next = 1;
			continue;
		}
		if (strchr(t, '/') && *t != '@')
			continue; /* local path / git url */
		char *ver;
		split_spec(kind, t, &ver);
		if (*t && catalog_verdict(kind, t, ver, why, sizeof why)) {
			violation(p, kind, why);
			return;
		}
	}
}
