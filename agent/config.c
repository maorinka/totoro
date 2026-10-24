#include "wisp.h"

#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

struct config cfg = {
	.rules_path = "/etc/wisp/rules.conf",
	.catalog_path = "/etc/wisp/catalog.conf",
	.fim_path = "/etc/wisp/fim.conf",
	.netpolicy_path = "/etc/wisp/netpolicy.conf",
	.state_dir = "/var/lib/wisp",
	.log_dir = "/var/log/wisp",
	.mode = MODE_MONITOR,
	.telemetry = 1,
	.inventory_interval = 86400,
	.housekeeping = 60,
	.cpu_budget = 0.05,
	.budget_mode = 1,
	.group = "default",
	.anomaly_learn = 3600,
};

static char *trim(char *s)
{
	while (isspace((unsigned char)*s))
		s++;
	char *e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = 0;
	return s;
}

/* String keys: the value must fit the field; an over-long value is reported
 * and the default kept (a silently cut path or console address is worse). */
#define SETSTR(k, field)                                                                   \
	if (!strcmp(key, k)) {                                                             \
		if (strlen(val) >= sizeof cfg.field)                                       \
			cfg_problem(path, ln, "%s is too long (max %zu bytes); keeping default", k, \
			            sizeof cfg.field - 1);                                         \
		else                                                                       \
			snprintf(cfg.field, sizeof cfg.field, "%s", val);                    \
		continue;                                                                  \
	}
/* Integer keys: the whole value must be an integer in [lo, hi]; anything else
 * is reported (so --check-config fails) and the default is kept. */
#define SETINT(k, field, lo, hi)                                                           \
	if (!strcmp(key, k)) {                                                             \
		long v_;                                                                   \
		if (parse_long(val, lo, hi, &v_) == 0)                                     \
			cfg.field = (int)v_;                                               \
		else                                                                       \
			cfg_problem(path, ln, "%s must be an integer in [%ld, %ld], got '%s'; keeping %d", \
			            k, (long)(lo), (long)(hi), val, cfg.field);                \
		continue;                                                                  \
	}
/* Boolean keys: 1/0, yes/no, true/false, on/off. */
#define SETBOOL(k, field)                                                                  \
	if (!strcmp(key, k)) {                                                             \
		int b_;                                                                    \
		if (parse_bool(val, &b_) == 0)                                             \
			cfg.field = b_;                                                    \
		else                                                                       \
			cfg_problem(path, ln, "%s must be 0/1 (or yes/no, true/false, on/off), got '%s'; keeping %d", \
			            k, val, cfg.field);                                        \
		continue;                                                                  \
	}

/* Limits. housekeeping is also the heartbeat interval: the console marks a
 * host stale after 3 minutes without one and drops an idle ingest connection
 * after 10, so the tick must stay well inside the stale window. */
#define HOUSEKEEPING_MIN 5
#define HOUSEKEEPING_MAX 120
#define CPU_BUDGET_MAX   0.05

int config_load(const char *path)
{
	FILE *f = fopen(path, "re");
	if (!f)
		return -1;
	char line[1024];
	int ln = 0;
	while (fgets(line, sizeof line, f)) {
		ln++;
		strip_comment(line);
		char *s = trim(line);
		if (!*s || *s == '#')
			continue;
		char *eq = strchr(s, '=');
		if (!eq) {
			cfg_problem(path, ln, "expected 'key = value'");
			continue;
		}
		*eq = 0;
		char *key = trim(s), *val = trim(eq + 1);
		SETSTR("rules", rules_path);
		SETSTR("catalog", catalog_path);
		SETSTR("fim", fim_path);
		SETSTR("netpolicy", netpolicy_path);
		SETSTR("state_dir", state_dir);
		SETSTR("log_dir", log_dir);
		SETSTR("console", console);
		SETSTR("cert", cert);
		SETSTR("key", key);
		SETSTR("ca", ca);
		SETSTR("slack_webhook", slack_webhook);
		SETSTR("group", group);
		SETBOOL("telemetry", telemetry);
		SETINT("inventory_interval", inventory_interval, 0, 31536000);
		SETINT("housekeeping", housekeeping, HOUSEKEEPING_MIN, HOUSEKEEPING_MAX);
		SETINT("coalesce_ms", coalesce_ms, 0, 5000);
		if (!strcmp(key, "cpu_budget")) {
			/* The CPU budget is an unconditional product invariant: anything
			 * that is not a finite number in (0, 0.05] is reported and the
			 * default cap kept, so no configuration runs the sensor uncapped
			 * (NaN would otherwise defeat every comparison). */
			char *end;
			double v = strtod(val, &end);
			if (end == val || *end || !isfinite(v) || v <= 0 || v > CPU_BUDGET_MAX)
				cfg_problem(path, ln, "cpu_budget must be a number in (0, %.2f], got '%s'; keeping %.4f",
				            CPU_BUDGET_MAX, val, cfg.cpu_budget);
			else
				cfg.cpu_budget = v;
			continue;
		}
		if (!strcmp(key, "budget_mode")) {
			if (!strcmp(val, "budget-first"))
				cfg.budget_mode = 1;
			else if (!strcmp(val, "security-first"))
				cfg.budget_mode = 0;
			else
				cfg_problem(path, ln, "budget_mode must be budget-first or security-first; keeping %s",
				            cfg.budget_mode ? "budget-first" : "security-first");
			continue;
		}
		SETBOOL("tpm", tpm);
		SETINT("anomaly_learn", anomaly_learn, -1, 31536000);
		SETBOOL("ephemeral", ephemeral);
		if (!strcmp(key, "mode")) {
			if (strcmp(val, "enforce") && strcmp(val, "monitor"))
				cfg_problem(path, ln, "mode must be monitor or enforce (staying in monitor)");
			cfg.mode = !strcmp(val, "enforce") ? MODE_ENFORCE : MODE_MONITOR;
			continue;
		}
		cfg_problem(path, ln, "unknown key '%s'", key);
	}
	fclose(f);
	if (cfg.console[0] && !console_addr_valid(cfg.console))
		cfg_problem(path, 0, "console '%s' is not host:port, [ipv6]:port, or a host name", cfg.console);
	return 0;
}
