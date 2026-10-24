// wisp-console: the fleet console for the Wisp sensor.
//
// Accepts newline-delimited JSON from sensors over mutual TLS, keeps a bounded
// in-memory view of hosts, alerts and inventory, journals every security-
// relevant event to disk (replayed at start, so a restart loses nothing), and
// serves the web console plus a JSON API. High-severity alerts can be posted
// to a Slack webhook.
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <deque>
#include <iostream>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/opensslv.h>
#include <pthread.h>
#include <set>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "assets.hpp"
#include "console.hpp"
#include "http.hpp"
#include "util.hpp"

#ifndef WISP_VERSION
#define WISP_VERSION "dev"
#endif

namespace wisp {

using namespace std::chrono;

static const auto started = steady_clock::now();

// ---- flags ------------------------------------------------------------------

struct FlagDef {
	const char *name, *def, *help;
	bool boolean;
};

static const FlagDef FLAGS[] = {
    {"listen", ":8750", "sensor ingest address (mutual TLS)", false},
    {"http", "127.0.0.1:8080", "web console + API address", false},
    {"cert", "", "ingest server certificate (PEM)", false},
    {"key", "", "ingest server private key (PEM)", false},
    {"client-ca", "", "CA that signs sensor client certificates (required outside -dev)", false},
    {"http-cert", "", "serve the web console over HTTPS with this certificate", false},
    {"http-key", "", "private key for -http-cert", false},
    {"state-dir", ".", "directory for the journal and vault (relative paths below resolve here)", false},
    {"vulndb", "", "vulnerability database JSON (default: the copy bundled in the binary)", false},
    {"roles", "", "RBAC tokens file (required outside -dev; see -gen-token)", false},
    {"vault", "vault.json", "encrypted secrets vault store", false},
    {"events", "events.jsonl", "event journal (append-only JSONL, replayed at start)", false},
    {"journal-max-mb", "256", "rotate the journal past this size (one previous segment kept; 0: never rotate)", false},
    {"max-sensors", "16384", "most concurrent sensor connections (each holds a thread; keep TasksMax above this)", false},
    {"max-hosts", "100000", "most hosts (not retired) the console tracks; hellos for new hosts past it are refused", false},
    {"max-hosts-per-cert", "0",
     "most hosts one sensor client certificate may speak for (0: no limit; set it when every sensor has its own "
     "certificate)",
     false},
    {"http-local-proxy", "false",
     "a reverse proxy on this machine carries every user: exempt loopback clients from the per-client HTTP "
     "connection limit (never trusts X-Forwarded-For)",
     true},
    {"stale-after", "3m0s", "mark a host stale after this long without contact", false},
    {"decommission-after", "168h0m0s", "retire a silent persistent host after this long (0: never)", false},
    {"slack", "", "Slack webhook for high/critical alerts (default $WISP_SLACK_WEBHOOK)", false},
    {"analysis-interval", "1m0s", "how often the analysis engine looks for new suggestions", false},
    {"ai", "true", "enable the AI assistant when an API key is available", true},
    {"ai-key-file", "", "file holding the Claude API key (else the vault secret anthropic/api-key, else $ANTHROPIC_API_KEY)", false},
    {"ai-model", "claude-opus-5-5", "Claude model for the AI assistant", false},
    {"ai-effort", "high", "reasoning effort: low, medium, high, xhigh or max", false},
    {"ai-url", "https://api.anthropic.com", "Claude API base URL (a gateway or proxy that speaks the same API)", false},
    {"ai-ca", "", "extra CA certificate (PEM) to trust for -ai-url, e.g. a TLS-inspecting proxy", false},
    {"ai-max-per-hour", "60", "cap on AI requests per hour", false},
    {"ai-fallback", "true", "let the API retry a declined request on its recommended fallback model", true},
    {"dev", "false", "development mode: no auth, plaintext ingest allowed. NEVER in production", true},
    {"gen-token", "", "print a new API token for <role>[:<name>] and the roles.conf line, then exit", false},
    {"version", "false", "print version and exit", true},
};

static void usage(std::ostream &o) {
	o << "wisp-console " << WISP_VERSION << " -- Wisp fleet console\n\nUsage:\n  wisp-console [flags]\n"
	  << "  wisp-console -gen-token <role>[:<name>]\n\nFlags:\n";
	for (auto &f : FLAGS) {
		o << "  -" << f.name << (f.boolean ? "" : " value") << "\n    \t" << f.help;
		if (!f.boolean && *f.def)
			o << " (default \"" << f.def << "\")";
		if (f.boolean && std::string(f.def) == "true")
			o << " (default true)";
		o << "\n";
	}
	o << "\nEnvironment: WISP_SLACK_WEBHOOK, WISP_VAULT_KEY, WISP_VAULT_KEY_FILE, ANTHROPIC_API_KEY, HTTPS_PROXY.\n"
	  << "Docs: docs/console.md, docs/configuration.md\n";
}

namespace {
struct FlagExit {
	int code;
};
}  // namespace

static void parse_flags_or_throw(int argc, char **argv, Config &c, std::ostream &out, std::ostream &err) {
	std::map<std::string, std::string> v;
	for (auto &f : FLAGS)
		v[f.name] = f.def;
	if (const char *s = getenv("WISP_SLACK_WEBHOOK"))
		v["slack"] = s;
	std::set<std::string> given;
	for (int i = 1; i < argc; i++) {
		std::string a = argv[i];
		if (a == "--" || a.size() < 2 || a[0] != '-') {
			// The first non-flag ends flag parsing (Go semantics). wisp-console
			// takes no arguments, so anything left is a mistake that would
			// otherwise silently drop every flag after it.
			int first = a == "--" ? i + 1 : i;
			if (first < argc) {
				err << "unexpected argument \"" << argv[first]
				    << "\": wisp-console takes only flags (flags after it would be ignored)\n";
				usage(err);
				throw FlagExit{2};
			}
			break;
		}
		std::string name = a.substr(a[1] == '-' ? 2 : 1), val;
		bool has_val = false;
		if (auto eq = name.find('='); eq != std::string::npos) {
			val = name.substr(eq + 1);
			name = name.substr(0, eq);
			has_val = true;
		}
		if (name == "h" || name == "help") {
			usage(out);
			throw FlagExit{0};
		}
		const FlagDef *def = nullptr;
		for (auto &f : FLAGS)
			if (name == f.name)
				def = &f;
		if (!def) {
			err << "flag provided but not defined: -" << name << "\n";
			usage(err);
			throw FlagExit{2};
		}
		if (def->boolean) {
			if (!has_val)
				val = "true";
			if (val != "true" && val != "false" && val != "1" && val != "0") {
				err << "invalid boolean value \"" << val << "\" for -" << name << "\n";
				throw FlagExit{2};
			}
			val = (val == "true" || val == "1") ? "true" : "false";
		} else if (!has_val) {
			if (i + 1 >= argc) {
				err << "flag needs an argument: -" << name << "\n";
				usage(err);
				throw FlagExit{2};
			}
			val = argv[++i];
		}
		v[name] = val;
		given.insert(name);
	}
	c = Config{};
	c.ingest_addr = v["listen"];
	c.http_addr = v["http"];
	c.cert = v["cert"];
	c.key = v["key"];
	c.client_ca = v["client-ca"];
	c.http_cert = v["http-cert"];
	c.http_key = v["http-key"];
	c.state_dir = v["state-dir"];
	c.vulndb = v["vulndb"];
	c.roles = v["roles"];
	c.vault = v["vault"];
	c.journal = v["events"];
	c.slack = v["slack"];
	c.dev = v["dev"] == "true";
	c.gen_token = v["gen-token"];
	c.show_version = v["version"] == "true";
	c.listen_set = given.count("listen") > 0;
	// Whole-string decimal integers in [lo, hi]; "10GB" or "-5" is an error, not 10 or -5.
	auto integer = [&](const char *k, long long lo, long long hi, const char *want) {
		const std::string &s = v[k];
		long long n = 0;
		bool ok = !s.empty() && s.size() <= 12 && s.find_first_not_of("0123456789") == std::string::npos;
		if (ok) {
			n = std::stoll(s);
			ok = n >= lo && n <= hi;
		}
		if (!ok) {
			err << "invalid value \"" << s << "\" for -" << k << ": want " << want << "\n";
			throw FlagExit{2};
		}
		return (int)n;
	};
	c.journal_max_mb = integer("journal-max-mb", 0, 1 << 20, "an integer number of MiB from 0 (never rotate) to 1048576");
	c.max_sensors = integer("max-sensors", 1, 1000000, "an integer from 1 to 1000000");
	c.max_hosts = integer("max-hosts", 1, 10000000, "an integer from 1 to 10000000");
	c.max_hosts_per_cert = integer("max-hosts-per-cert", 0, 10000000, "an integer from 0 (no limit) to 10000000");
	c.http_proxy_local = v["http-local-proxy"] == "true";
	auto dur = [&](const char *k) {
		auto d = parse_duration(v[k]);
		if (!d) {
			err << "invalid value \"" << v[k] << "\" for flag -" << k << ": invalid duration\n";
			throw FlagExit{2};
		}
		return *d;
	};
	c.stale_after = dur("stale-after");
	c.decom_after = dur("decommission-after");
	c.analysis_interval = dur("analysis-interval");
	if (c.stale_after <= nanoseconds(0)) {
		err << "invalid value \"" << v["stale-after"] << "\" for flag -stale-after: must be > 0\n";
		throw FlagExit{2};
	}
	if (c.decom_after != nanoseconds(0) && c.decom_after < c.stale_after) {
		err << "invalid value \"" << v["decommission-after"]
		    << "\" for flag -decommission-after: must be 0 (never) or at least -stale-after\n";
		throw FlagExit{2};
	}
	c.ai = v["ai"] == "true";
	c.ai_fallback = v["ai-fallback"] == "true";
	c.ai_key_file = v["ai-key-file"];
	c.ai_model = v["ai-model"];
	c.ai_effort = v["ai-effort"];
	c.ai_url = v["ai-url"];
	c.ai_ca = v["ai-ca"];
	c.ai_max_per_hour = integer("ai-max-per-hour", 0, 1000000, "an integer >= 0");
	static const std::set<std::string> efforts = {"low", "medium", "high", "xhigh", "max"};
	if (!efforts.count(c.ai_effort)) {
		err << "invalid value \"" << c.ai_effort << "\" for -ai-effort: want low, medium, high, xhigh or max\n";
		throw FlagExit{2};
	}
	// Half a TLS configuration would silently fall back to plaintext.
	auto pair = [&](const char *a, const char *b) {
		if (v[a].empty() != v[b].empty()) {
			err << "-" << (v[a].empty() ? a : b) << " is required with -" << (v[a].empty() ? b : a) << "\n";
			throw FlagExit{2};
		}
	};
	pair("http-cert", "http-key");
	pair("cert", "key");
	// Both are only ever reached over HTTPS: refuse now rather than fail every request later.
	if (!c.slack.empty() && c.slack.rfind("https://", 0) != 0) {
		err << "invalid -slack (or $WISP_SLACK_WEBHOOK): the webhook must be an https:// URL\n";
		throw FlagExit{2};
	}
	if (c.ai_url.rfind("https://", 0) != 0) {
		err << "invalid value \"" << c.ai_url << "\" for -ai-url: want an https:// URL\n";
		throw FlagExit{2};
	}
}

int parse_flags(int argc, char **argv, Config &c, std::ostream &out, std::ostream &err) {
	try {
		parse_flags_or_throw(argc, argv, c, out, err);
		return -1;
	} catch (const FlagExit &e) {
		return e.code;
	}
}

Config parse_flags(int argc, char **argv) {
	Config c;
	if (int code = parse_flags(argc, argv, c, std::cout, std::cerr); code >= 0)
		exit(code);
	return c;
}

std::string Config::in_state(const std::string &p) const {
	if (p.empty() || p[0] == '/')
		return p;
	return state_dir + "/" + p;
}

// ---- HTTP surface ---------------------------------------------------------------

static void write_json(Response &r, const json &j, int status = 200) {
	r.status = status;
	r.set("Content-Type", "application/json");
	r.set("Cache-Control", "no-store");
	// A string that is not UTF-8 (a decoded query value echoed back, text
	// cut mid-character) is sent with U+FFFD rather than throwing and leaving
	// the request unanswered.
	r.body = j.dump(-1, ' ', false, json::error_handler_t::replace) + "\n";
}

static void write_err(Response &r, int code, const std::string &msg) { write_json(r, {{"error", msg}}, code); }

static void method_not_allowed(Response &r, const std::string &allow) {
	r.set("Allow", allow);
	write_err(r, 405, "method not allowed");
}

static std::string qfirst(const Request &req, const std::string &k) {
	auto it = req.query.find(k);
	return it == req.query.end() || it->second.empty() ? std::string() : it->second.front();
}

// Request text for a log line: control bytes (a %00 would cut the line
// short) as '?', and bounded.
static std::string printable(const std::string &s, size_t max = 512) {
	std::string out = s.substr(0, max);
	for (auto &c : out)
		if ((unsigned char)c < 0x20 || c == 0x7f)
			c = '?';
	return s.size() > max ? out + "..." : out;
}

// An operator action that changes or reveals state outside the store's own
// records (single-host push, vault write or listing): journaled as a console
// record so the audit trail survives in the journal, not only in stderr.
static void audit(Store &st, json rec) {
	rec["type"] = "audit";
	rec["host"] = "console";  // never a fleet host: replay leaves no trace in host state
	std::string op = rec.value("op", "?");
	try {
		st.record_console(std::move(rec));  // dumped with U+FFFD for any non-UTF-8 text
	} catch (const std::exception &e) {
		logf("audit: could not journal %s: %s", op.c_str(), e.what());
	}
}

// Authorise against a minimum role; on failure writes 401/403 and returns false.
static bool authorize(Store &st, const Request &req, Response &r, const std::string &min, std::string &role,
                      std::string &user) {
	auto [ro, name] = st.rbac.identify(req.header("authorization"));
	if (ro.empty()) {
		r.set("WWW-Authenticate", "Bearer realm=\"wisp\"");
		write_err(r, 401, "authentication required");
		return false;
	}
	if (role_rank(ro) < role_rank(min)) {
		write_err(r, 403, "requires role " + min);
		return false;
	}
	role = ro;
	user = name;
	r.set("X-Wisp-Role", role);
	r.set("X-Wisp-User", user);
	return true;
}

static void serve_static(const Request &req, Response &r) {
	std::string path = req.path;
	if (path != "/" && path.rfind("/assets/", 0) != 0)
		path = "/";  // single-page app: client-side routes serve the app shell
	const Asset *a = find_asset(path == "/" ? "web/index.html" : "web" + path);
	if (!a) {
		r.status = 404;
		r.set("Content-Type", "text/plain; charset=utf-8");
		r.body = "404 page not found\n";
		return;
	}
	r.set("Content-Type", a->mime);
	if (path == "/")
		r.set("Cache-Control", "no-cache");
	r.body.assign(a->data, a->size);
}

static bool route_analysis(App &app, const Request &req, Response &r);

static void route(App &app, const Request &req, Response &r) {
	Store &st = app.store;
	const std::string &p = req.path;
	if (p.rfind("/api/", 0) != 0 && req.method != "GET" && req.method != "HEAD")
		return method_not_allowed(r, "GET, HEAD");  // the web app and probes are read-only
	if (p == "/healthz") {
		r.body = "ok\n";
		return;
	}
	if (p == "/readyz") {
		if (!st.ready || !st.journal_ok()) {  // ready means serving with the journal writable
			r.status = 503;
			r.set("X-Content-Type-Options", "nosniff");
			r.body = "not ready\n";
		} else {
			r.body = "ready\n";
		}
		return;
	}
	if (p.rfind("/api/", 0) != 0) {
		serve_static(req, r);
		return;
	}
	// Decoded query values reach JSON responses and journal records, which
	// must be UTF-8: refuse anything else up front.
	for (auto &[k, vals] : req.query) {
		bool ok = valid_utf8(k);
		for (auto &v : vals)
			ok = ok && valid_utf8(v);
		if (!ok)
			return write_err(r, 400, "query parameters must be UTF-8 text");
	}
	std::string role, user;
	auto get_only = [&](const char *min) {
		if (req.method != "GET") {
			method_not_allowed(r, "GET");
			return false;
		}
		return authorize(st, req, r, min, role, user);
	};

	// Public: tells the sign-in page whether a token is needed. Nothing else.
	if (p == "/api/session") {
		if (req.method != "GET")
			return method_not_allowed(r, "GET");
		return write_json(r, {{"auth", st.rbac.enabled()}});
	}
	if (p == "/api/version") {
		if (!get_only("viewer"))
			return;
		auto up = duration_cast<seconds>(steady_clock::now() - started).count();
		return write_json(r, {{"version", WISP_VERSION},
		                      {"runtime", std::string("C++ / ") + OPENSSL_VERSION_TEXT},
		                      {"uptime_s", up},
		                      {"auth", st.rbac.enabled()}});
	}
	if (p == "/api/me") {
		if (!get_only("viewer"))
			return;
		return write_json(r, {{"role", role}, {"name", user}});
	}
	if (p == "/api/summary") {
		if (!get_only("viewer"))
			return;
		json sum = st.summary();
		if (app.analyst) {
			// Every incident not resolved (open or acknowledged, as the
			// Incidents page lists them), uncapped, by priority.
			json by = {{"P1", 0}, {"P2", 0}, {"P3", 0}, {"P4", 0}};
			int total = 0;
			for (auto &inc : app.analyst->incidents()) {
				if (inc.status == "resolved")
					continue;
				total++;
				if (by.contains(inc.priority))
					by[inc.priority] = by[inc.priority].get<int>() + 1;
			}
			sum["incidents_open"] = {{"total", total}, {"by_priority", by}};
		}
		return write_json(r, sum);
	}
	if (p == "/api/hosts") {
		if (!get_only("viewer"))
			return;
		return write_json(r, st.host_list(qfirst(req, "state"), qfirst(req, "group")));
	}
	if (p == "/api/hosts/detail") {
		if (!get_only("viewer"))
			return;
		auto d = st.host_detail(qfirst(req, "name"));
		return d ? write_json(r, *d) : write_err(r, 404, "no such host");
	}
	if (p == "/api/alerts") {
		if (!get_only("viewer"))
			return;
		return write_json(r, st.alert_list(req.query));
	}
	if (p == "/api/alerts/triage") {
		if (req.method != "POST")
			return method_not_allowed(r, "POST");
		if (!authorize(st, req, r, "operator", role, user))
			return;
		json body;
		try {
			body = json::parse(req.body);
		} catch (...) {
		}
		if (!body.is_object())
			return write_err(r, 400, "body must be JSON {id, status, note}");
		auto s = [&](const char *k) {  // Go's decoder matched field names case-insensitively
			for (auto &[name, v] : body.items())
				if (strcasecmp(name.c_str(), k) == 0 && v.is_string())
					return v.get<std::string>();
			return std::string();
		};
		try {
			return write_json(r, st.triage(s("id"), s("status"), s("note"), user));
		} catch (const std::invalid_argument &e) {
			return write_err(r, 400, e.what());
		}
	}
	if (p == "/api/vulns") {
		if (!get_only("viewer"))
			return;
		return write_json(r, st.vulns_json());
	}
	if (p == "/api/inventory") {
		if (!get_only("viewer"))
			return;
		return write_json(r, st.inventory_json(qfirst(req, "host")));
	}
	if (p == "/api/events") {
		if (!get_only("viewer"))
			return;
		return write_json(r, st.search_events(req.query));
	}
	if (p == "/api/posture") {
		if (!get_only("viewer"))
			return;
		return write_json(r, st.posture_json());
	}
	// Rollout history is readable by any viewer (it is the audit trail);
	// starting a rollout needs deployer.
	if (p == "/api/policy/rollout") {
		if (!authorize(st, req, r, "viewer", role, user))
			return;
		if (req.method == "POST" && role_rank(role) < role_rank("deployer"))
			return write_err(r, 403, "requires role deployer");
		if (req.method == "GET")
			return write_json(r, st.rollouts_json());
		if (req.method != "POST") {
			r.set("Allow", "GET, POST");
			return write_err(r, 405, "GET for history, POST to start a rollout");
		}
		int pct = 0;
		try {
			pct = std::stoi(qfirst(req, "percent"));
		} catch (...) {
		}
		try {
			Rollout ro = st.rollout(qfirst(req, "action"), qfirst(req, "group"), pct, user);
			return write_json(r, rollout_to_json(ro));
		} catch (const std::invalid_argument &e) {
			return write_err(r, 400, e.what());
		}
	}
	// Single-host push (operator+): approve & push a rule reload or a mode
	// change to one agent -- "we suggest, you approve, we solve".
	if (p == "/api/policy/push") {
		if (req.method != "POST")
			return method_not_allowed(r, "POST");
		if (!authorize(st, req, r, "operator", role, user))
			return;
		const std::string host = qfirst(req, "host"), action = qfirst(req, "action");
		auto cmd = control_commands().find(action);
		if (cmd == control_commands().end())
			return write_err(r, 400, "action must be reload, enforce or monitor");
		bool delivered = st.push_control(host, cmd->second);
		logf("policy push host=%s action=%s delivered=%s by=%s", printable(host).c_str(), action.c_str(),
		     delivered ? "true" : "false", user.c_str());
		audit(st, {{"op", "policy_push"}, {"target", host}, {"command", action}, {"delivered", delivered}, {"by", user}});
		return write_json(r, {{"host", host}, {"action", action}, {"delivered", delivered}});
	}
	// Secrets vault: list/read (operator+, audited), write (admin).
	if (p == "/api/vault") {
		if (!authorize(st, req, r, "operator", role, user))
			return;
		const std::string key = qfirst(req, "key");
		if (req.method == "GET") {
			if (key.empty()) {
				audit(st, {{"op", "vault_list"}, {"by", user}});
				return write_json(r, {{"keys", st.vault->keys()}});
			}
			bool undecryptable = false;
			auto val = st.vault->get(key, &undecryptable);
			if (!val)
				return undecryptable ? write_err(r, 500, "secret cannot be decrypted (wrong vault key or tampered entry)")
				                     : write_err(r, 404, "not found");
			if (!valid_utf8(*val))  // stored before writes were checked; JSON cannot carry it
				return write_err(r, 500, "secret is not UTF-8 text and cannot be returned as JSON");
			st.audit_secret_access(key, user);
			return write_json(r, {{"key", key}, {"value", *val}});
		}
		if (req.method == "PUT" || req.method == "POST") {
			if (role_rank(role) < role_rank("admin"))
				return write_err(r, 403, "requires role admin");
			if (std::string why = Vault::check(key, req.body); !why.empty())
				return write_err(r, 400, why);
			std::string err;
			if (!st.vault->set(key, req.body, &err)) {
				logf("vault: write %s: %s", printable(key).c_str(), err.c_str());
				return write_err(r, 500, "could not store secret");
			}
			audit(st, {{"op", "vault_write"}, {"key", key}, {"by", user}});  // the name only, never the value
			return write_json(r, {{"key", key}, {"stored", true}});
		}
		return write_err(r, 405, "GET or PUT");
	}
	if (route_analysis(app, req, r))
		return;
	write_err(r, 404, "no such API endpoint");
}

static json body_json(const Request &req) {
	try {
		auto j = json::parse(req.body);
		if (j.is_object())
			return j;
	} catch (...) {
	}
	return json();
}

static std::string jfield(const json &j, const char *k) {
	auto it = j.find(k);
	return it != j.end() && it->is_string() ? it->get<std::string>() : std::string();
}

// Incidents, fleet health, rule review, suggestions and the AI assistant.
// Returns false when the path is not one of these.
static bool route_analysis(App &app, const Request &req, Response &r) {
	const std::string &p = req.path;
	if (p.rfind("/api/incidents", 0) != 0 && p.rfind("/api/analysis/", 0) != 0 &&
	    p.rfind("/api/suggestions", 0) != 0 && p.rfind("/api/ai/", 0) != 0)
		return false;
	Store &st = app.store;
	std::string role, user;
	auto need = [&](const char *method, const char *min) {
		if (req.method != method) {
			method_not_allowed(r, method);
			return false;
		}
		return authorize(st, req, r, min, role, user);
	};
	if (!app.analyst) {
		write_err(r, 404, "analysis is not enabled on this console");
		return true;
	}
	Analyst &an = *app.analyst;
	if (p == "/api/incidents") {
		if (need("GET", "viewer"))
			write_json(r, an.incidents_json(req.query));
		return true;
	}
	if (p == "/api/incidents/detail") {
		if (!need("GET", "viewer"))
			return true;
		auto inc = an.incident(qfirst(req, "id"));
		inc ? write_json(r, an.incident_json(*inc, true)) : write_err(r, 404, "no such incident");
		return true;
	}
	if (p == "/api/incidents/triage") {
		if (!need("POST", "operator"))
			return true;
		// alert_ids: the alerts the operator was shown. Only those are triaged
		// (alerts that joined the incident since keep their status, counted in
		// "skipped"); when none of them is in the incident any more, nothing is
		// changed and the answer is 409. Without alert_ids (older clients)
		// every alert in the incident is triaged.
		json b = body_json(req);
		std::vector<std::string> shown;
		bool has_shown = false;
		if (auto it = b.find("alert_ids"); it != b.end() && !it->is_null()) {
			bool ok = it->is_array() && !it->empty() && it->size() <= 100000;
			for (size_t i = 0; ok && i < it->size(); i++)
				ok = (*it)[i].is_string();
			if (!ok) {
				write_err(r, 400, "alert_ids must be a non-empty array of the alert ids you were shown");
				return true;
			}
			for (auto &x : *it)
				shown.push_back(x.get<std::string>());
			has_shown = true;
		}
		try {
			json res = an.triage_incident(jfield(b, "id"), jfield(b, "status"), jfield(b, "note"), user,
			                              has_shown ? &shown : nullptr);
			if (has_shown && res.value("updated", 0) == 0) {
				res["error"] = "the incident changed since it was shown (none of the alerts you saw are in it any "
				               "more); reload it and triage again";
				write_json(r, res, 409);
			} else {
				write_json(r, res);
			}
		} catch (const std::invalid_argument &e) {
			write_err(r, 400, e.what());
		}
		return true;
	}
	if (p == "/api/analysis/health") {
		if (need("GET", "viewer"))
			write_json(r, an.health_json());
		return true;
	}
	if (p == "/api/analysis/rules") {
		if (need("GET", "viewer"))
			write_json(r, an.rules_json());
		return true;
	}
	if (p == "/api/analysis/run") {
		if (need("POST", "operator"))
			write_json(r, {{"proposed", an.run()}});
		return true;
	}
	if (p == "/api/suggestions") {
		if (!need("GET", "viewer"))
			return true;
		// Paginated, newest first: limit (default 500, at most 1000) and
		// offset. X-Total-Count is the number matching the status filter, and
		// X-Next-Offset is set while there are more.
		// can_approve: whether the caller's role may decide it (approval_role(),
		// reported as required_role), whatever its status, so the UI offers
		// only what the route accepts.
		auto num = [&](const char *k, long dflt, long lo, long hi, long *out) {
			std::string v = qfirst(req, k);
			if (v.empty()) {
				*out = dflt;
				return true;
			}
			if (v.size() > 9 || v.find_first_not_of("0123456789") != std::string::npos)
				return false;
			*out = std::stol(v);
			return *out >= lo && *out <= hi;
		};
		long limit = 0, offset = 0;
		if (!num("limit", 500, 1, 1000, &limit) || !num("offset", 0, 0, 100000000, &offset)) {
			write_err(r, 400, "limit must be 1..1000 and offset a non-negative integer");
			return true;
		}
		size_t total = 0;
		json list = an.suggestions_json(qfirst(req, "status"), (size_t)limit, (size_t)offset, &total);
		for (auto &j : list) {
			std::string min_role = j.contains("required_role") && j["required_role"].is_string()
			                           ? j["required_role"].get<std::string>()
			                           : "admin";
			j["can_approve"] = role_rank(role) >= role_rank(min_role);
		}
		r.set("X-Total-Count", std::to_string(total));
		if ((size_t)offset + list.size() < total)
			r.set("X-Next-Offset", std::to_string((size_t)offset + list.size()));
		write_json(r, list);
		return true;
	}
	if (p == "/api/suggestions/decide") {
		// The lowest role any suggestion needs; the suggestion itself decides
		// the rest (below).
		if (!need("POST", "deployer"))
			return true;
		json b = body_json(req);
		std::string d = jfield(b, "decision");
		if (d != "approve" && d != "reject") {
			write_err(r, 400, "body must be JSON {id, decision: approve|reject, note}");
			return true;
		}
		// approval_role(): what the action stands in for, and never less than
		// operator for an AI-proposed one (AI text is shaped by telemetry an
		// attacker can write, so a deployer automation token can never approve
		// an AI rollout). Checked here first so a refused caller changes nothing.
		if (auto sg = an.suggestion(jfield(b, "id"))) {
			std::string min = approval_role(*sg);
			if (role_rank(role) < role_rank(min)) {
				write_err(r, 403, "this suggestion needs the " + min + " role");
				return true;
			}
		}
		try {
			Suggestion s = an.decide(jfield(b, "id"), d == "approve", user, role, jfield(b, "note"));
			write_json(r, suggestion_to_json(s));
		} catch (const std::domain_error &e) {
			write_err(r, 403, e.what());
		} catch (const std::invalid_argument &e) {
			write_err(r, 400, e.what());
		}
		return true;
	}
	// AI assistant
	if (p == "/api/ai/status") {
		if (!need("GET", "viewer"))
			return true;
		write_json(r, app.ai ? app.ai->status_json() : json{{"enabled", false}, {"reason", app.ai_off}});
		return true;
	}
	if (p == "/api/ai/jobs") {
		if (!need("GET", "operator"))
			return true;
		if (!app.ai)
			write_json(r, json::array());
		else if (std::string id = qfirst(req, "id"); !id.empty()) {
			auto j = app.ai->job(id);
			j ? write_json(r, *j) : write_err(r, 404, "no such job");
		} else
			write_json(r, app.ai->jobs_json());
		return true;
	}
	if (p == "/api/ai/triage" || p == "/api/ai/curate" || p == "/api/ai/ask") {
		if (!need("POST", "operator"))
			return true;
		if (!app.ai) {
			write_err(r, 503, "the AI assistant is unavailable: " + app.ai_off);
			return true;
		}
		json b = body_json(req);
		std::string kind = p.substr(8);
		std::string target = jfield(b, kind == "triage" ? "incident" : kind == "curate" ? "rule" : "question");
		try {
			write_json(r, app.ai->submit(kind, target, user), 202);
		} catch (const std::invalid_argument &e) {
			write_err(r, 400, e.what());
		} catch (const std::runtime_error &e) {
			write_err(r, app.ai->configured() ? 429 : 503, e.what());
		}
		return true;
	}
	write_err(r, 404, "no such API endpoint");
	return true;
}

void handle(Store &st, const Request &req, Response &r) {
	App app{st};
	handle(app, req, r);
}

void handle(App &app, const Request &req, Response &r) {
	security_headers(r, req.tls);
	auto t0 = steady_clock::now();
	route(app, req, r);
	// Access log: every change, every refusal, and every vault request
	// (reads and listings included), with the key name but never a value.
	bool vault = req.path == "/api/vault";
	if (req.path.rfind("/api/", 0) == 0 && (req.method != "GET" || r.status >= 400 || vault)) {
		auto ms = duration_cast<milliseconds>(steady_clock::now() - t0);
		std::string key = vault ? qfirst(req, "key") : "";
		logf("api %s %s -> %d (%s) user=%s%s", printable(req.method, 32).c_str(), printable(req.path).c_str(), r.status,
		     fmt_duration(ms).c_str(), r.get("X-Wisp-User").c_str(),
		     vault ? (" key=" + (key.empty() ? std::string("(list)") : printable(key, 256))).c_str() : "");
	}
}

bool precheck(App &app, const Request &req, Response &r) {
	// Static paths, probes and /api/session never read a body: answer now.
	if (req.path.rfind("/api/", 0) != 0 || req.path == "/api/session") {
		handle(app, req, r);
		return false;
	}
	Store &st = app.store;
	if (!st.rbac.enabled() || !st.rbac.identify(req.header("authorization")).first.empty())
		return true;  // authenticated (or -dev): read the body and route as usual
	// Unauthenticated: every API route refuses before it looks at a body
	// (401, or 404/405 for a path or method that does not exist).
	handle(app, req, r);
	return false;
}

// ---- sensor ingest --------------------------------------------------------------

namespace {

// A sensor's TLS connection as a SensorLink: control lines are written with a
// 5 s deadline; the stream's internal lock keeps them from interleaving with
// each other and from racing the reader on the same SSL object.
//
// "Delivered" means written to a connection the sensor is demonstrably
// using. Half-open links (a laptop that slept, a partition) are dropped by
// TCP keepalive and TCP_USER_TIMEOUT within about two minutes, before the
// host shows as stale (tune_sensor_socket); a link whose sensor has sent
// nothing for longer than -stale-after -- exactly when the Hosts page turns
// it Stale -- is reported as not delivered: its process is hung or gone, and
// the bytes would only reach the socket buffer. (The store refuses pushes to
// a stale host too, on the same clock.) A write that fails or times out ends the connection
// (Stream::write_all), so the sensor reconnects and nothing half-written can
// be mistaken for a later command.
class SensorConn : public SensorLink {
public:
	SensorConn(std::shared_ptr<Stream> s, nanoseconds stale)
	    : s_(std::move(s)), silent_limit_(stale.count()) {
		touch();
	}
	bool send(const std::string &line) override {
		std::lock_guard g(write_mu_);
		if (now_ns() - last_rx_.load() > silent_limit_)
			return false;
		if (s_->write_all(line + "\n", after(seconds(5))))
			return true;
		s_->shutdown();  // the reader ends the connection; the sensor reconnects
		return false;
	}
	void shutdown() override { s_->shutdown(); }
	void touch() { last_rx_ = now_ns(); }

private:
	static long long now_ns() { return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count(); }
	std::shared_ptr<Stream> s_;
	long long silent_limit_;  // ns
	std::atomic<long long> last_rx_{0};
	std::mutex write_mu_;
};

// A sensor sends nothing (not even a heartbeat) for this long: drop it.
constexpr auto INGEST_IDLE = minutes(10);
std::string source_of(const std::string &peer) { return peer.substr(0, peer.rfind(':')); }

// Half-open links (a peer that vanished without FIN or RST) are found by the
// kernel within about two minutes instead of the 10-minute read timeout.
void tune_sensor_socket(int fd) {
	int on = 1, idle = 60, intvl = 15, cnt = 4;
	unsigned int user_timeout_ms = 120000;
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
	setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms, sizeof user_timeout_ms);
}

}  // namespace

// At most one log line per source and reason per minute, so a scanner or a
// misconfigured fleet cannot flood the log.
bool IngestServer::log_allow(const std::string &key) {
	std::lock_guard g(log_mu_);
	auto now = steady_clock::now();
	if (log_last_.size() > 4096) {
		for (auto it = log_last_.begin(); it != log_last_.end();)
			it = now - it->second > minutes(1) ? log_last_.erase(it) : std::next(it);
		if (log_last_.size() > 4096)
			log_last_.clear();
	}
	auto [it, fresh] = log_last_.try_emplace(key, now);
	if (!fresh && now - it->second < minutes(1)) {
		suppressed_++;
		return false;
	}
	it->second = now;
	return true;
}

std::string IngestServer::suppressed_note() {
	std::lock_guard g(log_mu_);
	if (!suppressed_)
		return "";
	std::string s = " (" + std::to_string(suppressed_) + " similar line(s) suppressed)";
	suppressed_ = 0;
	return s;
}

void IngestServer::refuse(const std::string &why) {
	shed_++;
	auto now = steady_clock::now();
	if (shed_logged_ == steady_clock::time_point{} || now - shed_logged_ > seconds(10)) {
		logf("ingest: refusing connections: %s (%llu refused since the last report)", why.c_str(), shed_);
		shed_ = 0;
		shed_logged_ = now;
	}
}

void IngestServer::shutdown_all() {
	std::lock_guard g(mu_);
	stopping_ = true;
	for (auto *s : live_)
		s->shutdown();
}

bool IngestServer::serve(Listener &ln) {
	for (;;) {
		int fd = ln.accept_fd();
		if (fd < 0)
			return ln.closed();  // a failure was logged by the listener
		if (total_ >= max_conns_) {
			::close(fd);
			refuse(std::to_string(max_conns_) + " connections open (-max-sensors)");
			continue;
		}
		if (unbound_ >= max_unbound) {
			::close(fd);
			refuse(std::to_string(max_unbound) + " connections are still in the TLS handshake or have not sent a hello");
			continue;
		}
		tune_sensor_socket(fd);
		total_++;
		unbound_++;
		try {
			std::thread([this, fd] {
				try {
					connection(fd);
				} catch (const std::exception &e) {
					logf("ingest: %s", e.what());
				}
				total_--;
			}).detach();
		} catch (const std::exception &e) {
			// No thread (TasksMax, RLIMIT_NPROC, memory): refuse this
			// connection and keep serving the ones we have.
			total_--;
			unbound_--;
			::close(fd);
			refuse(std::string("cannot start a connection thread: ") + e.what());
			std::this_thread::sleep_for(milliseconds(100));
		}
	}
}

void IngestServer::connection(int fd) {
	Store &st = st_;
	bool bound = false;
	struct Unbound {  // serve() counted this connection as unbound
		std::atomic<int> &n;
		bool &bound;
		~Unbound() {
			if (!bound)
				n--;
		}
	} unbound_guard{unbound_, bound};
	const std::string peer = peer_address(fd);
	auto stream = std::make_shared<Stream>(fd, tls_);  // owns fd from here, even if it throws
	struct Registered {
		IngestServer &srv;
		Stream *s;
		Registered(IngestServer &v, Stream *st) : srv(v), s(st) {
			std::lock_guard g(srv.mu_);
			srv.live_.insert(s);
			if (srv.stopping_)
				s->shutdown();
		}
		~Registered() {
			std::lock_guard g(srv.mu_);
			srv.live_.erase(s);
		}
	} reg{*this, stream.get()};
	std::string why;
	if (!stream->handshake(after(seconds(10)), &why)) {
		// Failed mutual TLS is a security signal and the first thing to check
		// when a sensor cannot connect (wrong CA, expired or missing cert).
		if (!stream->dead() && log_allow("tls " + source_of(peer)))
			logf("ingest: TLS handshake with %s failed: %s%s", peer.c_str(), why.c_str(), suppressed_note().c_str());
		return;
	}
	auto conn = std::make_shared<SensorConn>(stream, st.stale_after);
	SensorSession session{"", conn};
	// The session speaks with the client certificate's identity: the store
	// records it per host and never hands a host's control lines to a
	// connection that authenticated with a different certificate.
	stream->peer_cert(&session.cert_fp, &session.cert_name);
	struct Closed {  // on every exit path, exceptions included: the store must forget this link
		Store &st;
		SensorSession &s;
		~Closed() {
			try {
				st.sensor_closed(s);
			} catch (const std::exception &e) {
				logf("ingest: %s", e.what());
			}
		}
	} closed{st, session};
	const auto hello_by = steady_clock::now() + hello_wait;
	// Lines longer than the store accepts are refused there (counted and
	// logged); the bytes of one are never buffered past that limit here: the
	// rest of it is skipped up to its newline.
	const size_t max_line = st.sensor_max_line;
	std::string buf;
	size_t scanned = 0;  // bytes of buf already searched for a newline
	bool skipping = false;
	char chunk[16384];
	for (;;) {
		Deadline dl = after(INGEST_IDLE);
		if (!bound)
			dl = std::min(dl, hello_by);
		long n = stream->read_some(chunk, sizeof chunk, dl);
		if (n <= 0) {
			if (n == -2 && !bound && log_allow("hello " + source_of(peer)))
				logf("ingest: %s sent no hello within %s; closing%s", peer.c_str(), fmt_duration(hello_wait).c_str(),
				     suppressed_note().c_str());
			break;
		}
		conn->touch();
		buf.append(chunk, (size_t)n);
		size_t start = 0, nl, from = scanned;
		while ((nl = buf.find('\n', from)) != std::string::npos) {
			if (skipping) {
				skipping = false;  // the end of an oversized line
			} else {
				size_t len = nl - start;
				if (len && buf[nl - 1] == '\r')
					len--;
				if (len)
					st.sensor_line(session, buf.substr(start, len));
			}
			start = from = nl + 1;
		}
		buf.erase(0, start);
		if (skipping) {
			buf.clear();
		} else if (buf.size() > max_line) {
			st.sensor_line(session, buf);  // refused as too long: counted and logged by the store
			buf.clear();
			skipping = true;
		}
		scanned = buf.size();
		if (!bound && !session.host.empty()) {
			bound = true;
			unbound_--;
		}
	}
}

static bool loopback_host(std::string host) {
	if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
		host = host.substr(1, host.size() - 2);
	struct in_addr a {};
	return host == "localhost" || host == "::1" ||
	       (inet_pton(AF_INET, host.c_str(), &a) == 1 && (ntohl(a.s_addr) >> 24) == 127);
}

static std::string addr_host(const std::string &addr) { return addr.substr(0, addr.rfind(':')); }

static std::unique_ptr<Listener> listen_ingest(const Config &c, SSLCtxPtr &ctx) {
	if (c.cert.empty() || c.key.empty()) {
		if (!c.dev)
			throw std::runtime_error("sensor ingest requires -cert and -key (use -dev for a plaintext local demo)");
		std::string addr = c.ingest_addr;
		if (!c.listen_set && !loopback_host(addr_host(addr)))
			addr = "127.0.0.1" + addr.substr(addr.rfind(':'));  // plaintext: local only unless asked
		logf("WARNING: sensor ingest on %s is PLAINTEXT (-dev); never use this in production%s", addr.c_str(),
		     c.listen_set ? "" : " (loopback only; pass -listen to choose an address)");
		return std::make_unique<Listener>(addr);
	}
	if (c.client_ca.empty() && !c.dev)
		throw std::runtime_error("sensor ingest requires -client-ca (mutual TLS) outside -dev");
	ctx = make_server_ctx(c.cert, c.key, c.client_ca);
	auto ln = std::make_unique<Listener>(c.ingest_addr);
	logf("sensor ingest (TLS, mtls=%s) on %s", c.client_ca.empty() ? "false" : "true", c.ingest_addr.c_str());
	return ln;
}

// ---- Slack ----------------------------------------------------------------------

// Slack mrkdwn treats & < > as control characters (<!channel>, <@U123>,
// <https://x|label>), so they must be sent as entities; a backtick would end
// the code span around the command line; a newline would break the layout.
static std::string slack_field(const std::string &s, size_t max) {
	std::string out;
	size_t i = 0;
	for (; i < s.size(); i++) {
		unsigned char c = (unsigned char)s[i];
		if (i >= max && (c & 0xC0) != 0x80) {  // cut on a character boundary
			out += "\xe2\x80\xa6";             // …
			break;
		}
		if (c == '&') out += "&amp;";
		else if (c == '<') out += "&lt;";
		else if (c == '>') out += "&gt;";
		else if (c == '`') out += '\'';
		else if (c < 0x20 || c == 0x7f) out += ' ';
		else out += (char)c;
	}
	return out;
}

std::string slack_alert_text(const Event &e) {
	return "*" + slack_field(e.severity, 16) + "* `" + slack_field(e.rule, 100) + "` on *" + slack_field(e.host, 255) +
	       "* \xe2\x80\x94 " + slack_field(e.title, 300) + "\n> actor=" + slack_field(e.actor, 64) + "/" +
	       slack_field(e.actor_src, 64) + " action=" + slack_field(e.action, 32) + "\n> `" + slack_field(e.cmd, 1000) +
	       "`";
}

namespace {

// One sender thread with a bounded queue: an alert storm costs a counter,
// not a thread and a TLS handshake per alert. Posts at most about one
// message a second (several alerts each), honours 429 Retry-After, and logs
// failed deliveries (rate-limited; never the webhook URL, which is a secret).
class SlackNotifier {
public:
	explicit SlackNotifier(std::string url) : url_(std::move(url)) { th_ = std::thread([this] { loop(); }); }
	~SlackNotifier() { stop(); }
	void enqueue(const Event &e) noexcept {
		try {
			std::string line = slack_alert_text(e);
			std::lock_guard g(mu_);
			if (stop_)
				return;
			if (q_.size() >= MAX_QUEUE) {
				dropped_++;
				return;
			}
			q_.push_back(std::move(line));
			cv_.notify_one();
		} catch (...) {
			// never let a notification failure unwind sensor ingest
		}
	}
	void stop() {
		{
			std::lock_guard g(mu_);
			stop_ = true;
		}
		cancel_ = true;
		cv_.notify_all();
		if (th_.joinable())
			th_.join();
	}

private:
	static constexpr size_t MAX_QUEUE = 200, PER_MESSAGE = 10;

	void report(const std::string &what) {
		auto now = steady_clock::now();
		failures_++;
		if (reported_ == steady_clock::time_point{} || now - reported_ > minutes(1)) {
			logf("slack: delivery failed: %s (%llu failure(s) since the last report)", what.c_str(), failures_);
			failures_ = 0;
			reported_ = now;
		}
	}
	// Waits up to d unless stopping; false when stopping.
	bool pause(nanoseconds d) {
		std::unique_lock lk(mu_);
		return !cv_.wait_for(lk, d, [&] { return stop_; });
	}
	void post(const std::string &text) {
		std::string body = json{{"text", text}, {"unfurl_links", false}, {"unfurl_media", false}}.dump(
		    -1, ' ', false, json::error_handler_t::replace);
		for (int attempt = 0; attempt < 3; attempt++) {
			auto r = https_request("POST", url_, {{"Content-Type", "application/json"}}, body, seconds(10), "", &cancel_);
			if (r.status >= 200 && r.status < 300)
				return;
			if (cancel_)
				return;
			if (r.status == 429) {
				long long wait = 30;
				if (auto it = r.headers.find("retry-after"); it != r.headers.end() && !it->second.empty() &&
				                                            it->second.size() < 6 &&
				                                            it->second.find_first_not_of("0123456789") == std::string::npos)
					wait = std::stoll(it->second);
				wait = std::clamp<long long>(wait, 1, 300);
				report("rate limited by Slack (429); retrying in " + std::to_string(wait) + "s");
				if (!pause(seconds(wait)))
					return;
				continue;
			}
			report(r.status < 0 ? r.error
			                    : "HTTP " + std::to_string(r.status) + " " + log_escape(r.body.substr(0, 120)));
			return;
		}
	}
	void loop() {
		std::unique_lock lk(mu_);
		for (;;) {
			cv_.wait(lk, [&] { return stop_ || !q_.empty(); });
			if (stop_)
				break;
			std::string text;
			for (size_t n = 0; n < PER_MESSAGE && !q_.empty(); n++) {
				text += (n ? "\n\n" : "") + q_.front();
				q_.pop_front();
			}
			if (dropped_) {
				text += "\n\n_" + std::to_string(dropped_) +
				        " more high/critical alert(s) were not posted to Slack (too many at once); see the console._";
				dropped_ = 0;
			}
			lk.unlock();
			post(text);
			lk.lock();
			if (cv_.wait_for(lk, seconds(1), [&] { return stop_; }))  // about one message a second
				break;
		}
		if (size_t left = q_.size() + dropped_)
			logf("slack: %zu queued notification(s) not sent at shutdown", left);
	}

	std::string url_;
	std::mutex mu_;
	std::condition_variable cv_;
	std::deque<std::string> q_;
	size_t dropped_ = 0;
	bool stop_ = false;
	std::atomic<bool> cancel_{false};
	steady_clock::time_point reported_{};  // sender thread only
	unsigned long long failures_ = 0;
	std::thread th_;  // last: starts once everything above is constructed
};

}  // namespace

// ---- run ------------------------------------------------------------------------

bool read_ai_key_file(const std::string &path, std::string *key, std::string *why) {
	auto k = read_file(path);
	if (!k || trim(*k).empty()) {
		*why = "-ai-key-file " + path + " is unreadable or empty; the AI assistant is unavailable";
		return false;
	}
	*key = trim(*k);
	return true;
}

static void reload_roles(Store &st, const Config &c) {
	if (c.roles.empty()) {
		logf("SIGHUP: no -roles file to reload (-dev without -roles: authentication stays off)");
		return;
	}
	try {
		st.rbac.reload();
		logf("roles: reloaded %s (%zu token(s))", st.rbac.path().c_str(), st.rbac.size());
		for (auto &w : st.rbac.warnings())
			logf("WARNING: roles: %s", w.c_str());
	} catch (const std::exception &e) {
		logf("roles: reload failed, the previous tokens stay in force: %s", e.what());
	}
}

int run(const Config &c) {
	if (c.show_version) {
		std::cout << "wisp-console " << WISP_VERSION << " (C++, " << OPENSSL_VERSION_TEXT << ")\n";
		return 0;
	}
	if (!c.gen_token.empty()) {
		std::string role = c.gen_token, name;
		if (auto col = role.find(':'); col != std::string::npos) {
			name = role.substr(col + 1);
			role = role.substr(0, col);
		}
		if (role_rank(role) == 0) {
			logf("wisp-console: -gen-token: role must be viewer, deployer, operator or admin");
			return 1;
		}
		if (name.empty())
			name = role;
		auto [tok, line] = gen_token(role, name);
		std::cout << "token (give to the user; shown once):\n  " << tok
		          << "\n\nroles.conf line (store this; it holds only the hash):\n  " << line << "\n";
		return 0;
	}
	// Signals are handled by one dedicated thread; block them everywhere else.
	// SIGHUP re-reads roles.conf (by default it would kill the process).
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &sigs, nullptr);
	signal(SIGPIPE, SIG_IGN);

	try {
		std::string acc;  // create every missing component, like mkdir -p
		for (size_t i = 0; i <= c.state_dir.size(); i++) {
			if (i == c.state_dir.size() || c.state_dir[i] == '/') {
				acc = c.state_dir.substr(0, i);
				if (!acc.empty() && mkdir(acc.c_str(), 0700) != 0 && errno != EEXIST)
					throw std::runtime_error("state dir: " + std::string(strerror(errno)));
			}
		}

		Store st(c.slack);
		st.stale_after = c.stale_after;
		st.decom_after = c.decom_after;
		st.journal_max = (long long)c.journal_max_mb << 20;
		st.max_hosts = (size_t)c.max_hosts;
		st.max_hosts_per_cert = (size_t)c.max_hosts_per_cert;
		st.vulndb = VulnDB::load(c.vulndb);
		if (c.roles.empty() && !c.dev)
			throw std::runtime_error(
			    "no -roles file: refusing to serve an unauthenticated console (create one with -gen-token, or pass "
			    "-dev for a local demo)");
		st.rbac = RBAC::load(c.roles);
		for (auto &w : st.rbac.warnings())
			logf("WARNING: roles: %s", w.c_str());
		if (!st.rbac.enabled()) {
			// Every request is admin (vault reads included): never off this machine.
			if (!loopback_host(addr_host(c.http_addr)))
				throw std::runtime_error("-dev without -roles serves an unauthenticated admin API: refusing to listen on " +
				                         c.http_addr + " (bind -http to 127.0.0.1, or pass -roles)");
			logf("WARNING: -dev: API authentication is DISABLED; every request is admin");
		}
		st.vault = Vault::open(c.in_state(c.vault));
		Analyst analyst(st);
		st.replay_hook = [&analyst](const json &rec) { analyst.replay(rec); };
		// Rejections and recent approvals hold back repeat proposals: they must
		// outlive the journal segment that recorded them. (Analyst::carry_forward
		// takes only the analyst's own lock and never calls into the store.)
		st.carry_hook = [&analyst] { return analyst.carry_forward(); };
		st.open_journal(c.in_state(c.journal));
		std::unique_ptr<Assistant> assistant;
		std::string ai_off = "disabled with -ai=false";
		bool ai_on = c.ai;
		AiConfig ac;
		if (ai_on && !c.ai_key_file.empty()) {
			// An optional feature must not keep the console (and the fleet's
			// telemetry) down: an unusable key file only turns the assistant off.
			if (!read_ai_key_file(c.ai_key_file, &ac.api_key, &ai_off)) {
				logf("ERROR: %s (fix the file and restart the console)", ai_off.c_str());
				ai_on = false;
			}
		}
		if (ai_on) {
			// Key order (as documented): -ai-key-file, else the vault secret
			// anthropic/api-key (read on every request, so a rotation there
			// takes effect at once), else $ANTHROPIC_API_KEY.
			if (const char *k = getenv("ANTHROPIC_API_KEY"); k && *k)
				ac.env_key = trim(k);
			ac.base_url = c.ai_url;
			ac.model = c.ai_model;
			ac.effort = c.ai_effort;
			ac.ca_file = c.ai_ca;
			ac.fallback = c.ai_fallback;
			ac.max_per_hour = c.ai_max_per_hour;
			assistant = std::make_unique<Assistant>(st, analyst, ac);
			logf("AI assistant: %s (model %s)",
			     assistant->configured() ? "enabled" : "off until an API key is configured", c.ai_model.c_str());
		}
		App app{st, &analyst, assistant.get(), ai_off};
		std::unique_ptr<SlackNotifier> slack;
		if (!c.slack.empty()) {
			slack = std::make_unique<SlackNotifier>(c.slack);
			st.notify = [n = slack.get()](const Event &e) { n->enqueue(e); };
		}

		SSLCtxPtr ingest_ctx;
		auto ingest = listen_ingest(c, ingest_ctx);
		SSLCtxPtr http_ctx;
		if (!c.http_cert.empty())
			http_ctx = make_server_ctx(c.http_cert, c.http_key, "");
		auto http_ln = std::make_unique<Listener>(c.http_addr);
		HttpServer srv([&app](const Request &rq, Response &rs) { handle(app, rq, rs); }, http_ctx.get());
		srv.precheck = [&app](const Request &rq, Response &rs) { return precheck(app, rq, rs); };
		srv.exempt_loopback = c.http_proxy_local;

		IngestServer ing(st, ingest_ctx.get(), c.max_sensors);
		std::mutex stop_mu;
		std::condition_variable stop_cv;
		bool stop = false;
		std::atomic<bool> stopping{false}, failed{false}, sig_done{false};
		// Idempotent: stop accepting on both listeners (serve() then returns).
		auto begin_stop = [&] {
			if (stopping.exchange(true))
				return;
			st.ready = false;
			ingest->close();
			http_ln->close();
		};
		std::thread ingest_thread, reaper, analysis_thread, sig_thread;
		// Every exit path, an exception included, stops and joins the threads
		// above before their objects go out of scope (a joinable std::thread
		// destroyed during unwinding would std::terminate the console), then
		// wakes every connection and waits for its thread. Returns the number
		// of connection threads still running.
		auto shutdown = [&]() -> int {
			begin_stop();
			if (ingest_thread.joinable())
				ingest_thread.join();
			// Sensors: the store journals connected hosts as disconnected by the
			// shutdown and stops rollout pushes; every ingest stream (handshaking,
			// pre-hello and superseded ones too) is woken.
			st.shutdown_links();
			ing.shutdown_all();
			{
				std::lock_guard g(stop_mu);
				stop = true;
			}
			stop_cv.notify_all();
			if (reaper.joinable())
				reaper.join();
			if (analysis_thread.joinable())
				analysis_thread.join();
			if (assistant)
				assistant->stop();
			if (slack)
				slack->stop();
			int left = srv.abort_connections(seconds(3));
			for (int i = 0; i < 150 && ing.active() > 0; i++)  // let sensor threads unwind (<= 3 s)
				std::this_thread::sleep_for(milliseconds(20));
			if (sig_thread.joinable()) {
				if (!sig_done)
					pthread_kill(sig_thread.native_handle(), SIGTERM);
				sig_thread.join();
			}
			st.close_journal();
			return left + ing.active();
		};
		// Threads that outlived shutdown() still reference the store, the
		// server and the analyst: leave without running destructors (the
		// journal is already fsynced and closed).
		auto finish = [&](int left, int code) {
			if (left > 0) {
				logf("%d connection thread(s) still running at exit; exiting without cleanup", left);
				fflush(stderr);
				_exit(code);
			}
			return code;
		};

		try {
			ingest_thread = std::thread([&] {
				if (!ing.serve(*ingest) && !stopping) {
					logf("sensor ingest stopped accepting connections; shutting down (exit 1) so the service "
					     "manager restarts the console");
					failed = true;
					begin_stop();
				}
			});
			reaper = std::thread([&] {
				std::unique_lock lk(stop_mu);
				while (!stop_cv.wait_for(lk, seconds(15), [&] { return stop; })) {
					lk.unlock();
					try {
						st.reap();
					} catch (const std::exception &e) {
						logf("reaper: %s", e.what());
					}
					lk.lock();
				}
			});
			analysis_thread = std::thread([&] {
				std::unique_lock lk(stop_mu);
				auto every = std::max<nanoseconds>(c.analysis_interval, seconds(5));
				while (!stop_cv.wait_for(lk, every, [&] { return stop; })) {
					lk.unlock();
					try {
						analyst.run();
					} catch (const std::exception &e) {
						logf("analysis: %s", e.what());
					}
					lk.lock();
				}
			});
			sig_thread = std::thread([&] {
				for (;;) {
					int s = 0;
					if (sigwait(&sigs, &s) != 0)
						continue;
					if (s == SIGHUP) {
						reload_roles(st, c);
						continue;
					}
					if (!stopping)
						logf("shutting down (%s)", s == SIGINT ? "SIGINT" : "SIGTERM");
					begin_stop();
					break;
				}
				sig_done = true;
			});

			std::string host = addr_host(c.http_addr);
			if (http_ctx)
				logf("web console + API on https://%s (version %s)", c.http_addr.c_str(), WISP_VERSION);
			else {
				if (!loopback_host(host))
					logf("WARNING: web console is plain HTTP on %s; use -http-cert or a TLS-terminating proxy",
					     c.http_addr.c_str());
				logf("web console + API on http://%s (version %s)", c.http_addr.c_str(), WISP_VERSION);
			}
			st.ready = true;
			srv.serve(*http_ln, seconds(10));  // returns once the listener is closed (or fails)
			if (!stopping && !http_ln->closed()) {
				logf("web listener stopped accepting connections; shutting down (exit 1) so the service manager "
				     "restarts the console");
				failed = true;
			}
		} catch (const std::exception &e) {
			logf("wisp-console: %s", e.what());
			return finish(shutdown(), 1);
		}
		int left = shutdown();
		return finish(left, failed ? 1 : 0);
	} catch (const std::exception &e) {
		logf("wisp-console: %s", e.what());
		return 1;
	}
}

}  // namespace wisp

#ifndef WISP_NO_MAIN
int main(int argc, char **argv) { return wisp::run(wisp::parse_flags(argc, argv)); }
#endif
