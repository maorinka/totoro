#include "wisp.h"
#include <string.h>

/* Which package-ecosystem runtimes have been seen executing on this host.
 * Used by the console's vulnerability engine to tell a *reachable* vulnerable
 * package (its runtime is active) from a merely *dormant* one. */
static unsigned seen_mask;
enum { E_NODE = 1, E_PY = 2, E_RUBY = 4, E_GO = 8, E_JAVA = 16, E_RUST = 32 };

void ecosystem_note(const char *comm)
{
	if (!strcmp(comm, "node") || !strcmp(comm, "bun") || !strcmp(comm, "deno"))
		seen_mask |= E_NODE;
	else if (!strncmp(comm, "python", 6) || !strcmp(comm, "uv") || !strcmp(comm, "uvx"))
		seen_mask |= E_PY;
	else if (!strcmp(comm, "ruby") || !strcmp(comm, "gem"))
		seen_mask |= E_RUBY;
	else if (!strcmp(comm, "java") || !strcmp(comm, "scala"))
		seen_mask |= E_JAVA;
	else if (!strcmp(comm, "ruby"))
		seen_mask |= E_RUBY;
}

/* JSON-array fragment of active ecosystems, for the heartbeat. */
void ecosystem_json(char *out, size_t cap)
{
	const struct { unsigned bit; const char *name; } m[] = {
		{ E_NODE, "npm" }, { E_PY, "pip" }, { E_RUBY, "gem" },
		{ E_GO, "go" }, { E_JAVA, "maven" }, { E_RUST, "cargo" },
	};
	size_t n = 0;
	n += (size_t)snprintf(out + n, cap - n, "[");
	int first = 1;
	for (size_t i = 0; i < sizeof m / sizeof m[0]; i++)
		if (seen_mask & m[i].bit) {
			n += (size_t)snprintf(out + n, cap - n, "%s\"%s\"", first ? "" : ",", m[i].name);
			first = 0;
		}
	snprintf(out + n, cap - n, "]");
}
