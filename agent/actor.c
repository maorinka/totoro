/* Actor attribution: is a process ultimately driven by a human, an AI
 * agent, package/install code, CI, or a background service?
 *
 * Each exec is classified on its own merits; if that is inconclusive it
 * inherits the parent's verdict. Verdicts are cached per pid so the common
 * case is one hash lookup. Only a cold miss walks /proc upward.
 */
#include "wisp.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define CACHE_BITS 13
#define CACHE_SIZE (1u << CACHE_BITS)

struct centry {
	pid_t pid;
	uint8_t actor;
	char comm[17];
	char src[26];
};
static struct centry cache[CACHE_SIZE];

static struct centry *slot(pid_t pid) { return &cache[(uint32_t)pid & (CACHE_SIZE - 1)]; }

void actor_forget(pid_t pid)
{
	struct centry *e = slot(pid);
	if (e->pid == pid)
		e->pid = 0;
}

static const char *const ai_bins[] = {
	"claude", "codex", "gemini", "aider", "cursor-agent", "goose", "opencode",
	"openclaw", "hermes", "amp", "copilot", "ollama", "lms", "llama-server",
	"continue", "cline", "windsurf", NULL,
};
/* AI CLIs shipped as node/python packages show up as an interpreter. */
static const char *const ai_markers[] = {
	"@anthropic-ai/claude-code", "@openai/codex", "@google/gemini-cli",
	"/bin/aider", "aider.main", "goose", "opencode", "openclaw", "@sourcegraph/amp",
	"mcp-server", "modelcontextprotocol", NULL,
};
static const char *const interps[] = {
	"node", "bun", "deno", "python", "python3", "uv", "uvx", "npx", NULL,
};
static const char *const pkg_mgrs[] = {
	"npm", "npx", "yarn", "pnpm", "bun", "pip", "pip3", "uv", "poetry", "pipx", "cargo", "gem", NULL,
};
static const char *const ci_bins[] = {
	"Runner.Worker", "Runner.Listene", "gitlab-runner", "buildkite-agent", "circleci-agent",
	"jenkins-agent", "teamcity-agent", "drone-runner", NULL,
};
static const char *const human_roots[] = {
	"sshd", "sshd-session", "login", "gnome-terminal-", "konsole", "xterm", "alacritty", "kitty",
	"wezterm-gui", "foot", "tilix", "Terminal", "iTerm2", "tmux: server", "screen", NULL,
};

/* Category bits a binary name can carry. A name may be in several lists
 * (e.g. "bun" is both an interpreter and a package manager). */
enum { C_AI = 1, C_INTERP = 2, C_PKG = 4, C_CI = 8, C_HUMAN = 16 };

/* Init-time hash set: name -> category bits. Replaces the ~50 strcmp/strstr
 * linear scans classify() used to do per exec with a single lookup, which
 * is the bulk of the per-event cost on a busy host. */
#define NAMEHASH_BITS 9
#define NAMEHASH (1u << NAMEHASH_BITS)
struct nh { const char *name; uint8_t cat; };
static struct nh namehash[NAMEHASH];
static int namehash_ready;

static uint32_t fnv1a(const char *s)
{
	uint32_t h = 2166136261u;
	for (; *s; s++)
		h = (h ^ (unsigned char)*s) * 16777619u;
	return h;
}

static void nh_insert(const char *name, uint8_t cat)
{
	uint32_t i = fnv1a(name) & (NAMEHASH - 1);
	for (; namehash[i].name; i = (i + 1) & (NAMEHASH - 1))
		if (!strcmp(namehash[i].name, name)) {
			namehash[i].cat |= cat;
			return;
		}
	namehash[i].name = name;
	namehash[i].cat = cat;
}

static uint8_t nh_lookup(const char *name)
{
	if (!*name)
		return 0;
	uint32_t i = fnv1a(name) & (NAMEHASH - 1);
	for (; namehash[i].name; i = (i + 1) & (NAMEHASH - 1))
		if (!strcmp(namehash[i].name, name))
			return namehash[i].cat;
	return 0;
}

static void namehash_init(void)
{
	for (const char *const *p = ai_bins; *p; p++) nh_insert(*p, C_AI);
	for (const char *const *p = interps; *p; p++) nh_insert(*p, C_INTERP);
	for (const char *const *p = pkg_mgrs; *p; p++) nh_insert(*p, C_PKG);
	for (const char *const *p = ci_bins; *p; p++) nh_insert(*p, C_CI);
	for (const char *const *p = human_roots; *p; p++) nh_insert(*p, C_HUMAN);
	namehash_ready = 1;
}

static int is_install(const char *cmd)
{
	return strstr(cmd, " install") || strstr(cmd, " add ") || strstr(cmd, " ci") ||
	       strstr(cmd, " i ") || strstr(cmd, " sync") || strstr(cmd, " update");
}

/* Classify one process from its own identity. Returns ACTOR_UNKNOWN if
 * nothing about it is decisive. */
static enum actor classify(const char *comm, const char *exe, const char *cmd, char *src, size_t srclen)
{
	if (!namehash_ready)
		namehash_init();

	const char *b = exe && *exe ? base_name(exe) : comm;
	char name[64];
	scopy(name, sizeof name, b);
	char *sp = strstr(name, " (deleted)");
	if (sp)
		*sp = 0;

	uint8_t cn = nh_lookup(name), cc = nh_lookup(comm), cat = cn | cc;

	if (cat & C_AI) {
		scopy(src, srclen, (cn & C_AI) ? name : comm);
		return ACTOR_AI;
	}
	if ((cat & C_INTERP) || !strncmp(name, "python", 6)) {
		for (const char *const *m = ai_markers; *m; m++)
			if (strstr(cmd, *m)) {
				scopy(src, srclen, base_name(*m));
				return ACTOR_AI;
			}
	}
	if (((cat & C_PKG) || strstr(cmd, "npm-cli.js") || strstr(cmd, "-m pip")) && is_install(cmd)) {
		snprintf(src, srclen, "%s-install", (cc & C_PKG) ? comm : "pkg");
		return ACTOR_CODE;
	}
	if (cat & C_CI) {
		scopy(src, srclen, comm);
		return ACTOR_CI;
	}
	if (cc & C_HUMAN) {
		scopy(src, srclen, comm);
		return ACTOR_HUMAN;
	}
	return ACTOR_UNKNOWN;
}

/* Cold path: walk ancestors through /proc until something decides. */
static enum actor walk(pid_t pid, int tty, char *src, size_t srclen)
{
	char path[48], buf[1024], cmd[512];
	for (int depth = 0; pid > 1 && depth < 24; depth++) {
		struct centry *e = slot(pid);
		if (e->pid == pid) {
			scopy(src, srclen, e->src);
			return e->actor;
		}
		snprintf(path, sizeof path, "/proc/%d/stat", pid);
		if (read_small(AT_FDCWD, path, buf, sizeof buf) <= 0)
			break;
		char *l = strchr(buf, '('), *r = strrchr(buf, ')');
		if (!l || !r)
			break;
		char comm[17] = "";
		size_t n = r - l - 1 > 16 ? 16 : r - l - 1;
		memcpy(comm, l + 1, n);
		comm[n] = 0;
		int ppid = 0, t = 0;
		char st;
		sscanf(r + 2, "%c %d %*d %*d %d", &st, &ppid, &t);
		tty |= t != 0;

		snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
		ssize_t cl = read_small(AT_FDCWD, path, cmd, sizeof cmd);
		for (ssize_t i = 0; i < cl; i++)
			if (!cmd[i])
				cmd[i] = ' ';
		if (cl < 0)
			cmd[0] = 0;

		enum actor a = classify(comm, NULL, cmd, src, srclen);
		if (a != ACTOR_UNKNOWN) {
			struct centry *c = slot(pid);
			c->pid = pid;
			c->actor = a;
			scopy(c->comm, sizeof c->comm, comm);
			scopy(c->src, sizeof c->src, src);
			return a;
		}
		pid = ppid;
	}
	scopy(src, srclen, tty ? "tty" : "system");
	return tty ? ACTOR_HUMAN : ACTOR_SERVICE;
}

void actor_resolve(struct proc *p)
{
	char src[32] = "";
	struct centry *pe = slot(p->ppid);
	int phit = p->ppid && pe->pid == p->ppid;
	if (phit)
		scopy(p->pcomm, sizeof p->pcomm, pe->comm);
	enum actor a = classify(p->comm, p->exe, p->cmd, src, sizeof src);
	p->self_classified = a != ACTOR_UNKNOWN;
	if (a == ACTOR_UNKNOWN) {
		if (phit) {
			a = pe->actor;
			scopy(src, sizeof src, pe->src);
		} else {
			a = walk(p->ppid, p->has_tty, src, sizeof src);
		}
	}
	p->actor = a;
	scopy(p->actor_src, sizeof p->actor_src, src);

	struct centry *e = slot(p->pid);
	e->pid = p->pid;
	e->actor = a;
	scopy(e->comm, sizeof e->comm, p->comm);
	scopy(e->src, sizeof e->src, src);
}

/* Look up the cached actor for a pid (used to attribute network flows to the
 * process that opened them, without re-walking /proc). */
enum actor actor_cached(pid_t pid, char *src, size_t srclen)
{
	struct centry *e = slot(pid);
	if (e->pid == pid) {
		if (src) snprintf(src, srclen, "%s", e->src);
		return e->actor;
	}
	if (src) snprintf(src, srclen, "%s", "unknown");
	return ACTOR_UNKNOWN;
}
