// Unit tests for wisp-console. Built with sanitizers (make test / make tsan).
// Covers every case of the original Go test suite plus the C++-specific
// risks: HTTP parsing and limits, keep-alive, and concurrent sensor I/O.
#include <algorithm>
#include <csignal>
#include <openssl/ssl.h>
#include <sstream>
#include <sys/resource.h>

#include "harness.hpp"

// ---- RBAC ----------------------------------------------------------------------

TEST(RBACHashedAndPlainTokens) {
	Env e;
	CHECK_EQ(e.req("GET", "/api/me").status, 401);
	CHECK_EQ(e.req("GET", "/api/me", "wrong-token-0123456789").status, 401);
	auto r = e.req("GET", "/api/me", TOK_VIEWER);  // stored only as sha256
	CHECK_EQ(r.status, 200);
	CHECK_EQ(body_json(r)["name"].get<std::string>(), std::string("vic"));
	CHECK_EQ(e.req("GET", "/api/me", TOK_ADMIN).status, 200);
	CHECK(e.req("GET", "/api/me").get("WWW-Authenticate").find("Bearer") == 0);
}

TEST(RBACRejectsBadRolesFile) {
	TempDir d;
	std::vector<std::pair<std::string, std::string>> bad = {{"short", "abc viewer\n"},
	                                                        {"badrole", "a-long-enough-token-xyz root\n"},
	                                                        {"badhash", "sha256:zz viewer\n"},
	                                                        {"empty", "# nothing\n"}};
	for (auto &[name, body] : bad) {
		std::string p = d.path + "/" + name, err;
		write_file_atomic(p, body, 0600, &err);
		bool threw = false;
		try {
			RBAC::load(p);
		} catch (const std::exception &) {
			threw = true;
		}
		CHECK(threw);
	}
	bool threw = false;
	try {
		RBAC::load(d.path + "/missing");
	} catch (const std::exception &) {
		threw = true;
	}
	CHECK(threw);
}

TEST(RoleEnforcement) {
	Env e;
	CHECK_EQ(e.req("POST", "/api/alerts/triage", TOK_VIEWER, "{}").status, 403);
	CHECK_EQ(e.req("POST", "/api/policy/rollout?action=reload&percent=10", TOK_VIEWER).status, 403);
	CHECK_EQ(e.req("POST", "/api/policy/rollout?action=reload&percent=10", TOK_DEPLOYER).status, 200);
	CHECK_EQ(e.req("GET", "/api/policy/rollout", TOK_VIEWER).status, 200);  // history is viewer-readable
	CHECK_EQ(e.req("POST", "/api/policy/push?host=x&action=reload", TOK_DEPLOYER).status, 403);
	CHECK_EQ(e.req("PUT", "/api/vault?key=db", TOK_OPERATOR, "s3cret").status, 403);
}

// ---- HTTP surface ----------------------------------------------------------------

TEST(MutationsRequirePOST) {
	Env e;
	for (auto p : {"/api/policy/push?host=h&action=enforce", "/api/alerts/triage"})
		CHECK_EQ(e.req("GET", p, TOK_ADMIN).status, 405);
	e.send({{"type", "hello"}, {"host", "web-1"}, {"group", "prod"}, {"host_id", "id1"}});
	e.req("GET", "/api/policy/rollout?action=enforce&percent=100", TOK_ADMIN);
	CHECK_EQ(e.st.rollout_count(), (size_t)0);  // GET never mutates
}

TEST(SecurityHeadersHealthAndSPA) {
	Env e;
	auto r = e.req("GET", "/");
	CHECK_EQ(r.status, 200);
	CHECK(r.get("Content-Security-Policy").find("default-src 'self'") != std::string::npos);
	CHECK_EQ(r.get("X-Frame-Options"), std::string("DENY"));
	CHECK_EQ(r.get("X-Content-Type-Options"), std::string("nosniff"));
	CHECK(r.body.find("<!doctype html>") != std::string::npos);
	auto spa = e.req("GET", "/alerts");  // client-side route -> app shell
	CHECK(spa.status == 200 && spa.body.find("<!doctype html>") != std::string::npos);
	CHECK_EQ(e.req("GET", "/assets/app.js").get("Content-Type"), std::string("text/javascript; charset=utf-8"));
	CHECK_EQ(e.req("GET", "/assets/nope.js").status, 404);
	CHECK_EQ(e.req("GET", "/api/nope", TOK_ADMIN).status, 404);
	CHECK_EQ(e.req("GET", "/healthz").status, 200);
	e.st.ready = false;
	CHECK_EQ(e.req("GET", "/readyz").status, 503);
	CHECK_EQ(body_json(e.req("GET", "/api/session"))["auth"].get<bool>(), true);
}

// ---- HTTP transport (real sockets) ------------------------------------------------

struct LiveServer {
	Env env;
	Listener ln{"127.0.0.1:0"};
	HttpServer srv{[this](const Request &rq, Response &rs) { handle(env.st, rq, rs); }, nullptr};
	bool configured = [this] {  // as run() wires it, before serving starts
		srv.precheck = [this](const Request &rq, Response &rs) {
			App app{env.st};
			return precheck(app, rq, rs);
		};
		return true;
	}();
	std::thread th{[this] { srv.serve(ln, std::chrono::seconds(2)); }};
	~LiveServer() {
		ln.close();
		th.join();
	}
	// Send raw bytes, read until the server closes or `want` responses arrived.
	std::string exchange(const std::string &raw, int want = 1) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in a {};
		a.sin_family = AF_INET;
		a.sin_port = htons((uint16_t)ln.port());
		inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
		connect(fd, (struct sockaddr *)&a, sizeof a);
		struct timeval tv = {3, 0};
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
		size_t off = 0;
		while (off < raw.size()) {
			ssize_t w = ::send(fd, raw.data() + off, raw.size() - off, MSG_NOSIGNAL);
			if (w <= 0)
				break;
			off += (size_t)w;
		}
		std::string out;
		char buf[65536];
		for (;;) {
			ssize_t n = recv(fd, buf, sizeof buf, 0);
			if (n <= 0)
				break;
			out.append(buf, (size_t)n);
			size_t count = 0, p = 0;
			while ((p = out.find("HTTP/1.1 ", p)) != std::string::npos) {
				count++;
				p++;
			}
			if ((int)count >= want && out.find("\r\n\r\n") != std::string::npos) {
				// stop once the last response's body is complete
				size_t last = out.rfind("HTTP/1.1 ");
				size_t he = out.find("\r\n\r\n", last);
				size_t cl = out.find("Content-Length: ", last);
				if (he != std::string::npos && cl != std::string::npos && cl < he) {
					size_t len = std::stoul(out.substr(cl + 16));
					if (out.size() >= he + 4 + len)
						break;
				}
			}
		}
		close(fd);
		return out;
	}
};

TEST(HttpBodyLimitAndHeaders) {
	LiveServer s;
	std::string big = "PUT /api/vault?key=big HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOK_ADMIN +
	                  "\r\nContent-Length: " + std::to_string(2 << 20) + "\r\n\r\n";
	CHECK(s.exchange(big).rfind("HTTP/1.1 413", 0) == 0);  // refused before reading 2 MiB
	std::string huge = "GET / HTTP/1.1\r\nHost: x\r\nX-Pad: " + std::string(70000, 'a') + "\r\n\r\n";
	CHECK(s.exchange(huge).rfind("HTTP/1.1 431", 0) == 0);
	CHECK(s.exchange("GARBAGE\r\n\r\n").rfind("HTTP/1.1 400", 0) == 0);
	CHECK(s.exchange("POST /api/alerts/triage HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	          .rfind("HTTP/1.1 501", 0) == 0);
}

TEST(HttpKeepAliveAndQueryDecoding) {
	LiveServer s;
	s.env.send({{"type", "hello"}, {"host", "web 1"}, {"group", "prod"}});
	std::string two = "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"
	                  "GET /api/hosts?group=pr%6Fd&state= HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " +
	                  TOK_VIEWER + "\r\nConnection: close\r\n\r\n";
	std::string out = s.exchange(two, 2);
	CHECK(out.rfind("HTTP/1.1 200", 0) == 0);
	CHECK(out.find("ok\n") != std::string::npos);
	CHECK(out.find("\"web 1\"") != std::string::npos);  // %6F decoded: group=prod matched
	CHECK(out.find("Connection: close") != std::string::npos);
	auto q = parse_query("a=1+2&b=%2F%zz&a=3&flag");
	CHECK_EQ(q["a"].size(), (size_t)2);
	CHECK_EQ(q["a"][0], std::string("1 2"));
	CHECK_EQ(q["b"][0], std::string("/%zz"));
	CHECK(q.count("flag") == 1);
	std::string head = s.exchange("HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
	CHECK(head.rfind("HTTP/1.1 200", 0) == 0 && head.find("<!doctype") == std::string::npos);
}

// ---- ingest, triage, journal --------------------------------------------------------

TEST(SensorCannotForgeConsoleFields) {
	Env e;
	SensorSession s{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(s, R"({"type":"hello","host":"h1","host_id":"x"})");
	e.st.sensor_line(s, R"({"type":"alert","host":"h1","rule":"X","severity":"high","id":"forged","status":"resolved","note":"pwned","by":"admin"})");
	auto a = e.st.alert_list({})[0];
	CHECK(a["id"] != "forged");
	CHECK_EQ(a["status"].get<std::string>(), std::string("open"));
	CHECK(!a.contains("note"));
	auto j = read_file(e.st.journal_path()).value_or("");
	CHECK(j.find("pwned") == std::string::npos && j.find("forged") == std::string::npos);
}

TEST(SensorMustHelloFirstAndSpeakForOneHost) {
	Env e;
	SensorSession s{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(s, R"({"type":"alert","host":"victim","rule":"X","severity":"high"})");  // before hello
	CHECK_EQ(e.st.alert_list({}).size(), (size_t)0);
	e.st.sensor_line(s, R"({"type":"hello","host":"h1"})");
	e.st.sensor_line(s, R"({"type":"alert","host":"victim","rule":"X","severity":"high"})");  // other host
	e.st.sensor_line(s, R"({"type":"triage","host":"h1","id":"A1","status":"resolved"})");   // console-only type
	e.st.sensor_line(s, R"({"type":"hello","host":"console"})");                             // reserved name
	e.st.sensor_line(s, "{not json");
	CHECK_EQ(e.st.alert_list({}).size(), (size_t)0);
	e.st.sensor_line(s, R"({"type":"alert","host":"h1","rule":"OK","severity":"low"})");
	CHECK_EQ(e.st.alert_list({}).size(), (size_t)1);
}

TEST(TriageAndReplay) {
	Env e;
	SensorSession s{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(s, R"({"type":"hello","host":"web-1","group":"prod","host_id":"id1"})");  // no ts: stamped
	e.send({{"ts", now_ts()}, {"type", "alert"}, {"host", "web-1"}, {"rule", "CRED-001"}, {"severity", "high"}});
	std::string id = e.st.alert_list({})[0]["id"];
	bool threw = false;
	try {
		e.st.triage(id, "bogus", "", "olive");
	} catch (const std::invalid_argument &) {
		threw = true;
	}
	CHECK(threw);
	e.st.triage(id, "resolved", "rotated the key", "olive");
	e.st.rollout("monitor", "prod", 100, "dee");
	std::string path = e.st.journal_path();
	e.st.close_journal();

	Store st2;
	st2.vulndb = VulnDB::load("");
	st2.open_journal(path);
	auto got = st2.alert_list({});
	CHECK_EQ(got.size(), (size_t)1);
	CHECK_EQ(got[0]["status"].get<std::string>(), std::string("resolved"));
	CHECK_EQ(got[0]["note"].get<std::string>(), std::string("rotated the key"));
	CHECK_EQ(got[0]["triaged_by"].get<std::string>(), std::string("olive"));
	auto h = st2.host_snapshot("web-1");
	CHECK(h && h->group == "prod" && h->host_id == "id1");
	CHECK(h && fmt_rfc3339(h->first_seen).rfind("20", 0) == 0);  // a real timestamp, not year 1
	CHECK_EQ(st2.rollouts_json().size(), (size_t)1);
	CHECK_EQ(st2.rollouts_json()[0]["by"].get<std::string>(), std::string("dee"));
	st2.close_journal();
}

TEST(JournalRotation) {
	Env e;
	e.st.journal_max = 2048;
	for (int i = 0; i < 60; i++)
		e.send({{"ts", now_ts()}, {"type", "alert"}, {"host", "h"}, {"rule", "R"}, {"severity", "low"},
		        {"title", std::string(50, 'x')}});
	CHECK(fs::exists(e.st.journal_path() + ".1"));
	CHECK(fs::file_size(e.st.journal_path()) <= 4096);
}

TEST(HostIdentityMismatchAlerts) {
	Env e;
	e.send({{"type", "hello"}, {"host", "db-1"}, {"host_id", "tpm-aaa"}});
	e.send({{"type", "hello"}, {"host", "db-1"}, {"host_id", "tpm-bbb"}});
	auto a = e.st.alert_list({{"rule", {"HOST-ID-MISMATCH"}}});
	CHECK_EQ(a.size(), (size_t)1);
	CHECK(a.size() == 1 && a[0]["host"] == "db-1");
}

TEST(Lifecycle) {
	Env e;
	e.st.stale_after = std::chrono::milliseconds(50);
	auto ci = std::make_shared<FakeLink>(), web = std::make_shared<FakeLink>();
	SensorSession sci{"", ci}, sweb{"", web};
	e.st.sensor_line(sci, R"({"type":"hello","host":"ci-1","ephemeral":true})");
	e.st.sensor_line(sweb, R"({"type":"hello","host":"web-1"})");
	CHECK(e.st.host_snapshot("ci-1")->connected);
	e.st.sensor_line(sci, R"({"type":"bye","host":"ci-1","reason":"ephemeral-exit"})");
	e.st.sensor_line(sweb, R"({"type":"bye","host":"web-1","reason":"shutdown"})");
	e.st.sensor_closed(sweb);  // the agent closes its connection after the bye
	auto d = e.st.host_list("decommissioned", "");
	CHECK(d.size() == 1 && d[0]["name"] == "ci-1" && d[0]["decommissioned"] == "ephemeral-exit");
	CHECK(ci->down);  // its connection was shut down
	std::this_thread::sleep_for(std::chrono::milliseconds(80));
	auto stale = e.st.host_list("stale", "");
	CHECK(stale.size() == 1 && stale[0]["name"] == "web-1");  // persistent: stale, not retired
	SensorSession again{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(again, R"({"type":"hello","host":"ci-1","ephemeral":true})");
	CHECK_EQ(e.st.host_list("decommissioned", "").size(), (size_t)0);
	e.st.sensor_closed(again);  // an ephemeral host dropping its connection is retired
	CHECK_EQ(e.st.host_list("decommissioned", "").size(), (size_t)1);
	e.st.decom_after = std::chrono::milliseconds(10);
	e.st.reap();
	CHECK_EQ(e.st.host_list("decommissioned", "").size(), (size_t)2);
	CHECK(e.st.host_list("decommissioned", "")[1]["decommissioned"].get<std::string>().rfind("silent for", 0) == 0);
}

TEST(RolloutCohortsNestAndPushReachesHosts) {
	Env e;
	std::map<std::string, std::shared_ptr<FakeLink>> links;
	for (int i = 0; i < 50; i++) {
		std::string name = "h" + std::to_string(i);
		links[name] = std::make_shared<FakeLink>();
		SensorSession s{"", links[name]};
		e.st.sensor_line(s, json({{"type", "hello"}, {"host", name}, {"group", "prod"}}).dump());
	}
	e.send({{"type", "hello"}, {"host", "other"}, {"group", "dev"}});
	std::set<std::string> prev;
	for (int p : {5, 25, 60, 100}) {
		Rollout r = e.st.rollout("reload", "prod", p, "t");
		std::set<std::string> cur(r.cohort.begin(), r.cohort.end());
		CHECK(!cur.count("other"));
		for (auto &h : prev)
			CHECK(cur.count(h));  // earlier stages stay in
		prev = cur;
		CHECK_EQ(r.failed.size(), (size_t)0);
	}
	CHECK_EQ(prev.size(), (size_t)50);
	CHECK_EQ(links["h0"]->sent.size(), (size_t)(bucket("h0") < 5 ? 4 : bucket("h0") < 25 ? 3 : bucket("h0") < 60 ? 2 : 1));
	CHECK_EQ(links["h0"]->sent.back(), std::string(R"({"reload":true})"));
	for (auto bad : {0, 101}) {
		bool threw = false;
		try {
			e.st.rollout("reload", "prod", bad, "t");
		} catch (const std::invalid_argument &) {
			threw = true;
		}
		CHECK(threw);
	}
	bool threw = false;
	try {
		e.st.rollout("rm -rf", "prod", 10, "t");
	} catch (const std::invalid_argument &) {
		threw = true;
	}
	CHECK(threw);
}

TEST(BucketMatchesGoAndUI) {
	// FNV-1a 32 mod 100, computed independently (Python) -- the Go console,
	// this console and the web UI's preview must all agree.
	CHECK_EQ(bucket("web-01"), 23);
	CHECK_EQ(bucket("db-03"), 63);
	CHECK_EQ(bucket("ci-runner-05"), 82);
	CHECK_EQ(bucket("vm"), 60);
	CHECK_EQ(bucket("\xc3\xbc-host"), 7);  // UTF-8 "ü-host"
}

TEST(SummaryAndAlertFilters) {
	Env e;
	e.send({{"type", "hello"}, {"host", "a"}, {"group", "prod"}});
	e.send({{"ts", now_ts()}, {"type", "alert"}, {"host", "a"}, {"rule", "R1"}, {"severity", "critical"}, {"actor", "ai"}});
	e.send({{"ts", now_ts()}, {"type", "alert"}, {"host", "a"}, {"rule", "R2"}, {"severity", "low"}});
	CHECK_EQ(e.st.alert_list({{"status", {"all"}}}).size(), (size_t)2);
	auto hi = e.st.alert_list({{"severity", {"high"}}});
	CHECK(hi.size() == 1 && hi[0]["rule"] == "R1");
	CHECK_EQ(e.st.alert_list({{"q", {"r2"}}}).size(), (size_t)1);  // case-insensitive text
	auto sm = e.st.summary();
	CHECK_EQ(sm["alerts"]["open_total"].get<int>(), 2);
	CHECK_EQ(sm["alerts"]["last_24h"].get<int>(), 2);
	CHECK_EQ(sm["alerts"]["ai_actor_alerts_24h"].get<int>(), 1);
	CHECK_EQ(sm["alerts"]["hourly_24h"][23].get<int>(), 2);
	CHECK_EQ(sm["hosts"]["live"].get<int>(), 1);
	CHECK_EQ(sm["hosts"]["groups"]["prod"].get<int>(), 1);
}

TEST(EventSearch) {
	Env e;
	e.send({{"ts", "2026-01-01T10:00:00.000Z"}, {"type", "alert"}, {"host", "a"}, {"rule", "R1"}, {"pid", 4242},
	        {"severity", "low"}, {"cmd", "cat id_rsa"}});
	e.send({{"ts", "2026-01-01T11:00:00.000Z"}, {"type", "inventory"}, {"host", "b"}, {"kind", "npm"}, {"name", "x"}});
	CHECK_EQ(e.st.search_events({{"pid", {"4242"}}}).size(), (size_t)1);  // numeric field as text
	CHECK_EQ(e.st.search_events({{"q", {"id_rsa"}}}).size(), (size_t)1);
	CHECK_EQ(e.st.search_events({{"since", {"2026-01-01T10:30"}}}).size(), (size_t)1);
	CHECK_EQ(e.st.search_events({{"until", {"2026-01-01T10:30"}}}).size(), (size_t)1);
	auto newest = e.st.search_events({});
	CHECK(newest.size() == 2 && newest[0]["type"] == "inventory");  // newest first
}

// ---- vault ------------------------------------------------------------------------

TEST(Vault) {
	TempDir d;
	std::string p = d.path + "/vault.json", err;
	auto v = Vault::open(p);
	CHECK(v->set("db/password", "hunter2", &err));
	auto raw = read_file(p).value_or("");
	CHECK(raw.find("hunter2") == std::string::npos);
	auto v2 = Vault::open(p);
	CHECK_EQ(v2->get("db/password").value_or("?"), std::string("hunter2"));
	// ciphertext is bound to its name: moving it to another name fails
	auto items = json::parse(raw);
	items["other"] = items["db/password"];
	write_file_atomic(p, items.dump(), 0600, &err);
	CHECK(!Vault::open(p)->get("other"));
	// corrupt store is an error, not an empty vault
	write_file_atomic(p, "{not json", 0600, &err);
	bool threw = false;
	try {
		Vault::open(p);
	} catch (const std::exception &) {
		threw = true;
	}
	CHECK(threw);
	// a store without its key refuses rather than minting a new key
	write_file_atomic(p, raw, 0600, &err);
	fs::remove(p + ".key");
	threw = false;
	try {
		Vault::open(p);
	} catch (const std::exception &) {
		threw = true;
	}
	CHECK(threw);
}

TEST(VaultReadsVaultWrittenByGoConsole) {
	// tests/fixtures/go-vault.json was written by the Go console with
	// WISP_VAULT_KEY="test-only fixture key, not a secret".
	TempDir d;
	std::string err;
	auto fixture = read_file("tests/fixtures/go-vault.json");
	CHECK(fixture.has_value());
	if (!fixture)
		return;
	write_file_atomic(d.path + "/vault.json", *fixture, 0600, &err);
	setenv("WISP_VAULT_KEY", "test-only fixture key, not a secret", 1);
	auto v = Vault::open(d.path + "/vault.json");
	unsetenv("WISP_VAULT_KEY");
	CHECK_EQ(v->get("db/password").value_or("?"), std::string("hunter2 \xe2\x80\x94 \xc3\xbc" "n" "\xc3\xaf" "code \xe2\x9c\x93"));
	CHECK_EQ(v->get("empty").value_or("?"), std::string(""));
	auto keys = v->keys();
	CHECK(keys.size() == 2 && keys[0] == "db/password");
}

TEST(VaultReadIsAuditedWithReaderName) {
	Env e;
	CHECK_EQ(e.req("PUT", "/api/vault?key=api", TOK_ADMIN, "k").status, 200);
	auto r = e.req("GET", "/api/vault?key=api", TOK_OPERATOR);
	CHECK_EQ(r.status, 200);
	CHECK_EQ(body_json(r)["value"].get<std::string>(), std::string("k"));
	auto a = e.st.alert_list({{"rule", {"VAULT-ACCESS"}}});
	CHECK(a.size() == 1 && a[0]["title"].get<std::string>().find("Olive Ortega") != std::string::npos);
}

// ---- vulnerabilities ------------------------------------------------------------------

TEST(VulnDB) {
	auto db = VulnDB::load("");
	CHECK(!db.list.empty());
	bool threw = false;
	try {
		VulnDB::load("/nonexistent/vulndb.json");
	} catch (const std::exception &) {
		threw = true;
	}
	CHECK(threw);
	CHECK(ver_less("4.17.15", "4.17.21") && !ver_less("4.17.21", "4.17.21") && ver_less("1.2", "1.10"));
	CHECK(ver_less("1.2.5-beta", "1.2.6"));
}

TEST(VulnTiers) {
	Env e;
	auto inv = [&](const char *host, const char *eco, const char *name, const char *ver) {
		e.send({{"ts", now_ts()}, {"type", "inventory"}, {"host", host}, {"kind", eco}, {"name", name},
		        {"version", ver}, {"change", "present"}});
	};
	e.send({{"type", "hello"}, {"host", "runs-node"}});
	e.send({{"type", "heartbeat"}, {"host", "runs-node"}, {"runtimes", {"npm"}}});
	e.send({{"type", "hello"}, {"host", "idle"}});
	e.send({{"type", "hello"}, {"host", "owned"}});
	inv("runs-node", "npm", "minimist", "1.2.5");
	inv("idle", "npm", "minimist", "1.2.5");
	inv("idle", "npm", "lodash", "");
	inv("owned", "npm", "event-stream", "3.3.6");
	e.send({{"ts", now_ts()}, {"type", "alert"}, {"host", "owned"}, {"rule", "CAT-NPM"}, {"severity", "high"},
	        {"cmd", "npm install event-stream@3.3.6"}});
	std::map<std::string, std::string> got;
	for (auto &f : e.st.vuln_findings())
		got[f.host + "/" + f.name] = f.tier;
	CHECK_EQ(got["runs-node/minimist"], std::string("reachable"));
	CHECK_EQ(got["idle/minimist"], std::string("dormant"));
	CHECK_EQ(got["idle/lodash"], std::string("theoretical"));
	CHECK_EQ(got["owned/event-stream"], std::string("exploited"));
	for (auto &[_k, t] : got)
		CHECK(t != "vulnerable");
}

TEST(PostureScoring) {
	Env e;
	e.send({{"type", "hello"}, {"host", "good"}, {"host_id", "a"}, {"trust", "tpm"}});
	e.send({{"type", "heartbeat"}, {"host", "good"}, {"mode", "enforce"}});
	e.send({{"type", "hello"}, {"host", "bad"}, {"host_id", "b"}, {"trust", "generated"}});
	e.send({{"type", "heartbeat"}, {"host", "bad"}, {"mode", "monitor"}});
	e.send({{"ts", now_ts()}, {"type", "alert"}, {"host", "bad"}, {"rule", "CAT-NPM"}, {"severity", "critical"}});
	e.send({{"type", "hello"}, {"host", "unknown-mode"}, {"host_id", "c"}, {"trust", "tpm"}});
	auto p = e.st.posture_json();
	std::map<std::string, json> by;
	for (auto &h : p["hosts"])
		by[h["host"]] = h;
	CHECK_EQ(by["good"]["score"].get<int>(), 100);
	CHECK_EQ(by["unknown-mode"]["score"].get<int>(), 100);  // unknown mode is not scored as monitor
	CHECK_EQ(by["bad"]["score"].get<int>(), 100 - 4 - 8 - 10 - 5);
	CHECK_EQ(p["hosts"][0]["host"].get<std::string>(), std::string("bad"));  // weakest first
	CHECK_EQ(by["bad"]["findings"][1].get<std::string>(), std::string("1 critical severity alert"));
}

// ---- helpers ------------------------------------------------------------------------

TEST(TimeAndDurations) {
	CHECK_EQ(fmt_duration(std::chrono::hours(168)), std::string("168h0m0s"));
	CHECK_EQ(fmt_duration(std::chrono::minutes(3)), std::string("3m0s"));
	CHECK_EQ(fmt_duration(std::chrono::seconds(5)), std::string("5s"));
	CHECK(parse_duration("1h30m") == std::chrono::nanoseconds(std::chrono::minutes(90)));
	CHECK(parse_duration("250ms") == std::chrono::nanoseconds(std::chrono::milliseconds(250)));
	CHECK(!parse_duration("5 minutes"));
	auto t = parse_ts("2026-10-21T20:40:43.123Z");
	CHECK_EQ(fmt_ts_ms(t), std::string("2026-10-21T20:40:43.123Z"));
	CHECK_EQ(fmt_ts_ms(parse_ts("2026-10-21T22:40:43.123+02:00")), std::string("2026-10-21T20:40:43.123Z"));
	CHECK(is_zero(parse_ts("yesterday")));
	CHECK_EQ(fmt_rfc3339(TimePoint{}), std::string("0001-01-01T00:00:00Z"));
	CHECK_EQ(base64_decode(base64_encode("any carnal pleas")).value_or("?"), std::string("any carnal pleas"));
	CHECK(!base64_decode("abc"));
}

TEST(ConcurrentIngestPushAndReads) {
	// Many sensors, pushes, rollouts and reads at once. Meaningful under
	// `make tsan`; under ASan it checks for memory errors in the same paths.
	Env e;
	std::vector<std::shared_ptr<FakeLink>> links;
	std::vector<std::thread> th;
	for (int i = 0; i < 8; i++)  // all links exist before any thread reads them
		links.push_back(std::make_shared<FakeLink>());
	for (int i = 0; i < 8; i++) {
		th.emplace_back([&, i] {
			SensorSession s{"", links[i]};
			std::string host = "c" + std::to_string(i);
			e.st.sensor_line(s, json({{"type", "hello"}, {"host", host}, {"group", "g"}, {"ephemeral", i % 2 == 0}}).dump());
			for (int k = 0; k < 200; k++)
				e.st.sensor_line(s, json({{"ts", now_ts()}, {"type", "alert"}, {"host", host}, {"rule", "R"},
				                          {"severity", k % 2 ? "high" : "low"}})
				                        .dump());
			e.st.sensor_closed(s);
		});
	}
	th.emplace_back([&] {
		for (int k = 0; k < 20; k++) {
			e.st.rollout("reload", "g", 100, "t");
			e.st.push_control("c1", R"({"reload":true})");
		}
	});
	th.emplace_back([&] {
		for (int k = 0; k < 40; k++) {
			e.st.summary();
			e.st.posture_json();
			e.st.host_list("all", "");
			e.st.search_events({{"q", {"R"}}});
		}
	});
	for (auto &t : th)
		t.join();
	CHECK_EQ(e.st.alert_list({{"limit", {"5000"}}, {"status", {"all"}}}).size(), (size_t)1600);
	CHECK_EQ(e.st.host_list("decommissioned", "").size(), (size_t)4);  // the ephemeral half
}

// ---- data-layer hardening (release review) -------------------------------------

static std::string write_tmp(const TempDir &d, const std::string &name, const std::string &body) {
	std::string p = d.path + "/" + name, err;
	write_file_atomic(p, body, 0600, &err);
	return p;
}

static bool load_throws(const std::string &p, const std::string &needle = "") {
	try {
		RBAC::load(p);
	} catch (const std::exception &ex) {
		return needle.empty() || std::string(ex.what()).find(needle) != std::string::npos;
	}
	return false;
}

TEST(RBACRefusesPlaceholderAndDuplicateTokens) {
	TempDir d;
	// The shipped template's lines must never authenticate.
	CHECK(load_throws(write_tmp(d, "tpl", "CHANGE-ME-admin-token admin\n"), "placeholder"));
	CHECK(load_throws(write_tmp(d, "tpl2", "sha256:" + hexsha(TOK_VIEWER) + " viewer\nchangeme-operator-token-x operator\n"),
	                  ":2: placeholder"));
	// One token on two lines: refused (the last line no longer silently wins).
	CHECK(load_throws(write_tmp(d, "dup", TOK_ADMIN + " admin ada\nsha256:" + hexsha(TOK_ADMIN) + " viewer ada\n"),
	                  "already defined on line 1"));
	// The same display name on two tokens is fine (rotation).
	auto ok = RBAC::load(write_tmp(d, "rot", TOK_VIEWER + " viewer vic\nsha256:" + hexsha(TOK_ADMIN) + " viewer vic\n"));
	CHECK_EQ(ok.size(), (size_t)2);
	CHECK_EQ(ok.warnings().size(), (size_t)1);  // one plaintext token on disk
	CHECK(ok.warnings()[0].find(TOK_VIEWER) == std::string::npos);  // never the token itself
}

TEST(RBACReloadSwapsAtomically) {
	TempDir d;
	std::string p = write_tmp(d, "roles", "sha256:" + hexsha(TOK_VIEWER) + " viewer vic\n");
	auto r = RBAC::load(p);
	CHECK_EQ(r.identify("Bearer " + TOK_VIEWER).first, std::string("viewer"));
	write_tmp(d, "roles", "sha256:" + hexsha(TOK_ADMIN) + " admin ada\n");
	std::atomic<bool> stop{false};
	std::atomic<int> bad{0};
	std::thread reader([&] {
		while (!stop) {  // each answer comes whole from the old or the new table (and TSan sees no race)
			auto a = r.identify("Bearer " + TOK_ADMIN), v = r.identify("Bearer " + TOK_VIEWER);
			if (!(a.first.empty() && a.second.empty()) && !(a.first == "admin" && a.second == "ada"))
				bad++;
			if (!(v.first.empty() && v.second.empty()) && !(v.first == "viewer" && v.second == "vic"))
				bad++;
		}
	});
	for (int i = 0; i < 50; i++)
		r.reload();
	stop = true;
	reader.join();
	CHECK_EQ(bad.load(), 0);
	CHECK_EQ(r.identify("Bearer " + TOK_ADMIN).first, std::string("admin"));
	// A broken file keeps the current table in force.
	write_tmp(d, "roles", "garbage\n");
	bool threw = false;
	try {
		r.reload();
	} catch (const std::exception &) {
		threw = true;
	}
	CHECK(threw);
	CHECK_EQ(r.identify("Bearer " + TOK_ADMIN).first, std::string("admin"));
}

TEST(HostIdentityCannotBeBlankedOrDowngraded) {
	Env e;
	auto real = std::make_shared<FakeLink>(), imp = std::make_shared<FakeLink>(), imp2 = std::make_shared<FakeLink>();
	SensorSession sr{"", real}, si{"", imp}, si2{"", imp2};
	e.st.sensor_line(sr, R"({"type":"hello","host":"db-1","host_id":"tpm-aaa","trust":"tpm","group":"prod"})");
	// An id-less hello: alert, and the recorded identity survives.
	e.st.sensor_line(si, R"({"type":"hello","host":"db-1"})");
	auto h = e.st.host_snapshot("db-1");
	CHECK(h && h->host_id == "tpm-aaa" && h->trust == "tpm");
	CHECK_EQ(e.st.alert_list({{"rule", {"HOST-ID-MISMATCH"}}}).size(), (size_t)1);
	// A different id while the original sensor is connected: alert, identity
	// kept, and control lines still go to the original.
	e.st.sensor_line(si2, R"({"type":"hello","host":"db-1","host_id":"evil","trust":"tpm"})");
	CHECK_EQ(e.st.alert_list({{"rule", {"HOST-ID-MISMATCH"}}}).size(), (size_t)2);
	CHECK_EQ(e.st.host_snapshot("db-1")->host_id, std::string("tpm-aaa"));
	CHECK(e.st.push_control("db-1", R"({"mode":"monitor"})"));
	CHECK_EQ(real->sent.size(), (size_t)1);
	CHECK(imp->sent.empty() && imp2->sent.empty());
	CHECK(!e.st.posture().second.empty());  // still scored: not turned into a "non-sensor entry"
	// The same id with weaker trust is flagged too.
	SensorSession s3{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(s3, R"({"type":"hello","host":"db-1","host_id":"tpm-aaa","trust":"machine-id"})");
	CHECK_EQ(e.st.alert_list({{"rule", {"HOST-ID-MISMATCH"}}}).size(), (size_t)3);
	CHECK_EQ(e.st.host_snapshot("db-1")->trust, std::string("tpm"));
	// ...and a non-controlling connection cannot retire a host with a bye.
	auto runner = std::make_shared<FakeLink>();
	SensorSession sc{"", runner}, sc2{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(sc, R"({"type":"hello","host":"ci-1","host_id":"c","trust":"tpm","ephemeral":true})");
	e.st.sensor_line(sc2, R"({"type":"hello","host":"ci-1"})");
	e.st.sensor_line(sc2, R"({"type":"bye","host":"ci-1","reason":"ephemeral-exit"})");
	CHECK(e.st.host_snapshot("ci-1")->decommissioned.empty());
	CHECK(!runner->down);
	e.st.sensor_line(sc, R"({"type":"bye","host":"ci-1","reason":"ephemeral-exit"})");
	CHECK(!e.st.host_snapshot("ci-1")->decommissioned.empty());
	// The decision replays: a restart does not adopt the refused identity.
	std::string path = e.st.journal_path();
	Store st2;
	st2.open_journal(path);
	CHECK_EQ(st2.host_snapshot("db-1")->host_id, std::string("tpm-aaa"));
	st2.close_journal();
	// Once the original is gone (re-imaged), a new identity is recorded (and flagged).
	e.st.sensor_closed(sr);
	SensorSession s4{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(s4, R"({"type":"hello","host":"db-1","host_id":"tpm-new","trust":"tpm"})");
	CHECK_EQ(e.st.host_snapshot("db-1")->host_id, std::string("tpm-new"));
	CHECK_EQ(e.st.alert_list({{"rule", {"HOST-ID-MISMATCH"}}, {"host", {"db-1"}}}).size(), (size_t)4);
}

TEST(ConnectionCannotChangeHostAndDuplicatesKeepControl) {
	Env e;
	auto victim = std::make_shared<FakeLink>(), attacker = std::make_shared<FakeLink>();
	SensorSession sv{"", victim}, sa{"", attacker};
	e.st.sensor_line(sv, R"({"type":"hello","host":"web-9","host_id":"v"})");
	e.st.sensor_line(sa, R"({"type":"hello","host":"laptop-1","host_id":"l"})");
	e.st.sensor_line(sa, R"({"type":"hello","host":"web-9","host_id":"v"})");  // rebinding: dropped
	e.st.sensor_line(sa, R"({"type":"alert","host":"web-9","rule":"FORGED","severity":"high"})");
	CHECK_EQ(e.st.alert_list({{"rule", {"FORGED"}}}).size(), (size_t)0);
	CHECK(e.st.push_control("web-9", "x"));
	CHECK(victim->sent.size() == 1 && attacker->sent.empty());
	e.st.sensor_closed(sa);
	CHECK(!e.st.host_snapshot("laptop-1")->connected);  // no stale "connected" host left behind
	CHECK(!e.st.push_control("laptop-1", "x"));
	// Two live connections for one host: the newer one closing leaves the
	// older one connected and in control.
	auto second = std::make_shared<FakeLink>();
	SensorSession s2{"", second};
	e.st.sensor_line(s2, R"({"type":"hello","host":"web-9","host_id":"v"})");
	CHECK(e.st.push_control("web-9", "y") && second->sent.size() == 1);
	e.st.sensor_closed(s2);
	CHECK(e.st.host_snapshot("web-9")->connected);
	CHECK(e.st.push_control("web-9", "z"));
	CHECK_EQ(victim->sent.size(), (size_t)2);
}

TEST(ShutdownDoesNotDecommissionEphemeralHosts) {
	Env e;
	SensorSession s{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(s, R"({"type":"hello","host":"ci-runner-7","ephemeral":true})");
	e.st.shutdown_links();
	e.st.sensor_closed(s);  // the reader thread unwinding
	CHECK_EQ(e.st.host_list("decommissioned", "").size(), (size_t)0);
	auto j = read_file(e.st.journal_path()).value_or("");
	CHECK(j.find("console shutdown") != std::string::npos && j.find("decommissioned") == std::string::npos);
}

TEST(ReplayUsesReceiptTimeNotSensorClock) {
	TempDir d;
	std::string path = d.path + "/events.jsonl";
	{
		Store st;
		st.open_journal(path);
		SensorSession s{"", std::make_shared<FakeLink>()};
		st.sensor_line(s, R"({"type":"hello","host":"skew","host_id":"x"})");
		st.sensor_line(s, R"({"ts":"2200-01-01T00:00:00.000Z","type":"inventory","host":"skew","kind":"npm","name":"a","change":"present"})");
		st.sensor_line(s, R"({"ts":"2001-01-01T00:00:00.000Z","type":"alert","host":"skew","rule":"R","severity":"low"})");
		// a sensor cannot supply the receipt time or provenance itself
		st.sensor_line(s, R"({"ts":"2026-01-01T00:00:00.000Z","type":"alert","host":"skew","rule":"R2","rx_ts":"2200-01-01T00:00:00.000Z","src":"console"})");
		st.close_journal();
	}
	auto j = read_file(path).value_or("");
	CHECK(j.find("\"rx_ts\":\"2200") == std::string::npos);  // the forged receipt time was stripped
	CHECK(j.find("\"rule\":\"R2\",\"rx_ts\":\"20") != std::string::npos);  // and the console's own stamped
	CHECK(j.find("\"rule\":\"R2\",\"rx_ts\"") != std::string::npos && j.find("R2\",\"rx_ts\":\"2200") == std::string::npos);
	for (auto &l : {std::string("\"rule\":\"R2\"")}) {
		auto at = j.find(l);
		auto eol = j.find('\n', at);
		CHECK(at != std::string::npos && j.substr(at, eol - at).find("\"src\"") == std::string::npos);
	}
	Store st2;
	st2.stale_after = std::chrono::minutes(3);
	st2.open_journal(path);
	auto h = st2.host_snapshot("skew");
	CHECK(h && h->last_seen <= Clock::now() && h->last_seen > Clock::now() - std::chrono::minutes(5));
	CHECK(h && h->first_seen > Clock::now() - std::chrono::minutes(5));  // not 2001
	st2.close_journal();
	// An older journal (no receipt times): a sensor ts is clamped to the file's mtime.
	TempDir d2;
	std::string old = write_tmp(d2, "events.jsonl",
	                            R"({"ts":"2200-01-01T00:00:00.000Z","type":"hello","host":"old","host_id":"y"})" "\n");
	Store st3;
	st3.open_journal(old);
	CHECK(st3.host_snapshot("old")->last_seen <= Clock::now());
	st3.close_journal();
	// parse_ts: ranges checked, no wrap-around past 2262
	CHECK(is_zero(parse_ts("2026-13-45T99:99:99Z")));
	CHECK(is_zero(parse_ts("2026-02-30T00:00:00Z")));
	CHECK(is_zero(parse_ts("2300-01-01T00:00:00Z")));
	CHECK(!is_zero(parse_ts("2024-02-29T23:59:59Z")));
	CHECK(is_zero(parse_ts("2026-01-01T00:00:00+25:00")));
}

TEST(ReapSparesConnectedAndJustRestartedHosts) {
	Env e;
	e.st.decom_after = std::chrono::milliseconds(1);
	SensorSession s{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(s, R"({"type":"hello","host":"db-1","host_id":"x"})");
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	e.st.reap();  // silent past the limit, but connected: never reaped
	CHECK_EQ(e.st.host_list("decommissioned", "").size(), (size_t)0);
	e.st.sensor_closed(s);
	std::string path = e.st.journal_path();
	// A quiet host whose only record is days old, replayed after a restart:
	// it gets the grace period to reconnect before it can be reaped.
	TempDir d;
	std::string old = write_tmp(d, "events.jsonl",
	                            json{{"ts", fmt_ts_ms(Clock::now() - std::chrono::hours(24 * 10))},
	                                 {"type", "hello"}, {"host", "quiet"}, {"host_id", "q"}}
	                                    .dump() +
	                                "\n");
	Store st;
	st.open_journal(old);
	st.reap();
	CHECK_EQ(st.host_list("decommissioned", "").size(), (size_t)0);
	st.reap_grace = std::chrono::nanoseconds(0);
	st.reap();
	CHECK_EQ(st.host_list("decommissioned", "").size(), (size_t)1);
	st.decom_after = std::chrono::nanoseconds(0);  // 0 disables reaping
	st.close_journal();
	// A clean close journals the disconnect time, so replay knows it.
	auto j = read_file(path).value_or("");
	CHECK(j.find("\"change\":\"disconnected\"") != std::string::npos);
}

TEST(JournalTornTailIsRepaired) {
	TempDir d;
	std::string path = write_tmp(d, "events.jsonl",
	                             R"({"ts":"2026-01-01T00:00:00.000Z","type":"hello","host":"web-1"})" "\n"
	                             R"({"ts":"2026-01-01T00:00:01.000Z","type":"alert","host":"web-1","severity":"hi)");
	{
		Store st;
		st.open_journal(path);
		st.ingest(event_from_json({{"type", "hello"}, {"host", "web-2"}}), R"({"type":"hello","host":"web-2"})");
		st.close_journal();
	}
	Store st2;
	st2.open_journal(path);
	CHECK(st2.host_snapshot("web-1").has_value());
	CHECK(st2.host_snapshot("web-2").has_value());  // not glued onto the torn line
	st2.close_journal();
}

TEST(JournalRotationFailureKeepsPersisting) {
	TempDir d;
	Store st;
	st.journal_max = 1024;
	st.rotate_retry = std::chrono::nanoseconds(0);
	st.open_journal(d.path + "/events.jsonl");
	auto alert = [&](int i) {
		std::string raw = json{{"ts", now_ts()}, {"type", "alert"}, {"host", "h"}, {"rule", "R" + std::to_string(i)},
		                       {"severity", "low"}, {"title", std::string(100, 'x')}}
		                      .dump();
		st.ingest(event_from_json(json::parse(raw)), raw);
	};
	// Exhaust file descriptors so the new segment cannot be opened.
	int lowest = dup(0);
	close(lowest);
	struct rlimit old {};
	getrlimit(RLIMIT_NOFILE, &old);
	struct rlimit tight = old;
	tight.rlim_cur = (rlim_t)lowest;
	setrlimit(RLIMIT_NOFILE, &tight);
	for (int i = 0; i < 12; i++)
		alert(i);
	auto h = st.journal_health();
	setrlimit(RLIMIT_NOFILE, &old);
	CHECK(h.rotate_pending && h.ok);  // still persisting: into the .1 segment
	CHECK(st.journal_ok());
	alert(99);  // descriptors available again: the new segment opens
	CHECK(!st.journal_health().rotate_pending);
	st.close_journal();
	Store st2;
	st2.open_journal(d.path + "/events.jsonl");
	CHECK_EQ(st2.alert_list({{"limit", {"100"}}}).size(), (size_t)13);  // nothing went memory-only
	st2.close_journal();
	CHECK(!body_json(Env().req("GET", "/api/summary", TOK_VIEWER))["journal"]["ok"].is_null());
}

TEST(LargeConsoleRecordsReplay) {
	Env e;
	std::string big(1500000, 'x');  // e.g. a rollout record for a 30,000-host cohort
	e.st.record_console({{"type", "suggestion"}, {"id", "S1"}, {"title", big}});
	std::string path = e.st.journal_path();
	Store st2;
	size_t got = 0;
	st2.replay_hook = [&](const json &r) { got = r["title"].get<std::string>().size(); };
	st2.open_journal(path);
	CHECK_EQ(got, big.size());
	st2.close_journal();
	// Sensors cannot send lines anywhere near that size.
	SensorSession s{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(s, R"({"type":"hello","host":"h"})");
	e.st.sensor_line(s, json{{"type", "alert"}, {"host", "h"}, {"rule", "BIG"}, {"cmd", std::string(128 << 10, 'a')}}.dump());
	CHECK_EQ(e.st.alert_list({{"rule", {"BIG"}}}).size(), (size_t)0);
	CHECK_EQ(e.st.host_snapshot("h")->dropped_lines, 1LL);
}

TEST(AgentWorstCaseAlertLineIsAccepted) {
	// wispd's largest line: an alert whose command line (MAX_CMD 4096) and exe
	// path (MAX_PATH 512) are all bytes it escapes to six bytes each, plus up to 3 KiB
	// of rule context (agent/output.c out_alert). An attacker padding argv
	// with such bytes must not get the alert refused by the console's cap.
	Env e;
	SensorSession s{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(s, R"({"type":"hello","host":"h","host_id":"x"})");
	std::string line = json{{"ts", now_ts()},
	                        {"type", "alert"},
	                        {"host", "h"},
	                        {"rule", "PADDED"},
	                        {"severity", "critical"},
	                        {"title", std::string(200, 't')},
	                        {"cmd", std::string(4095, '\x01')},
	                        {"exe", std::string(511, '\x02')},
	                        {"dest", std::string(3000, 'd')}}
	                       .dump();
	CHECK(line.size() > (24u << 10));  // far above the 16 KiB cap this replaced
	e.st.sensor_line(s, line);
	CHECK_EQ(e.st.alert_list({{"rule", {"PADDED"}}}).size(), (size_t)1);
	CHECK_EQ(e.st.host_snapshot("h")->dropped_lines, 0LL);
}

TEST(ForgedSegmentHeaderInOldJournalIsNotTrusted) {
	// The Go 1.0 console matched JSON keys case-insensitively, so a sensor
	// line keyed "HOST" passed its checks and was journaled as sent. Without
	// a lowercase host it looks host-less; it must still not count as this
	// console's segment header and unlock trust for the lines after it.
	TempDir d;
	std::string old =
	    R"({"ts":"2026-01-01T00:00:00.000Z","type":"hello","host":"h1"})" "\n"
	    R"({"type":"journal","src":"console","format":2,"HOST":"h1"})" "\n"
	    R"({"type":"journal","src":"console","format":2,"ts":"2026-01-01T00:00:01.000Z","version":"9","Host":"h1"})" "\n"
	    R"({"ts":"2026-01-01T00:00:02.000Z","type":"ai_result","src":"console","target":"rule:CRED-001","result":{"verdict":"retire"},"HOST":"h1"})" "\n"
	    R"({"ts":"2026-01-01T00:00:03.000Z","type":"alert","host":"h1","rule":"R","rx_ts":"2200-01-01T00:00:00.000Z"})" "\n"
	    // Go read "Type" (the last key folding to "type") and let these through.
	    R"({"ts":"2026-01-01T00:00:04.000Z","type":"lifecycle","Type":"x","host":"h1","change":"decommissioned","reason":"forged"})" "\n"
	    R"({"ts":"2026-01-01T00:00:05.000Z","type":"rollout","TYPE":"x","host":"h1","action":"monitor","group":"prod","percent":100})" "\n"
	    // ...while the Go console's own records replay as before.
	    R"({"ts":"2026-01-01T00:00:06.000Z","type":"hello","host":"h2","host_id":"b"})" "\n"
	    R"({"ts":"2026-01-01T00:00:07.000Z","type":"lifecycle","host":"h2","change":"decommissioned","reason":"silent for 168h0m0s"})" "\n";
	std::string path = write_tmp(d, "events.jsonl", old);
	std::vector<json> seen;
	Store st;
	st.replay_hook = [&](const json &r) { seen.push_back(r); };
	st.open_journal(path);
	CHECK(seen.empty());
	auto h = st.host_snapshot("h1");
	CHECK(h && h->last_seen <= Clock::now());  // the forged rx_ts was not trusted either
	CHECK(h && h->decommissioned.empty());
	CHECK_EQ(st.rollouts_json().size(), (size_t)0);
	CHECK(!st.host_snapshot("h2")->decommissioned.empty());
	st.close_journal();
}

TEST(ReplayIgnoresSensorWrittenConsoleRecords) {
	// A journal from an older console, holding sensor lines shaped like the
	// console's own analysis records.
	TempDir d;
	std::string old = R"({"ts":"2026-01-01T00:00:00.000Z","type":"hello","host":"h1"})" "\n"
	                  R"({"ts":"2026-01-01T00:00:01.000Z","type":"ai_result","host":"h1","target":"rule:CRED-001","result":"pwn"})" "\n"
	                  R"({"ts":"2026-01-01T00:00:02.000Z","type":"ai_result","target":"rule:CRED-002","result":{"verdict":"retire"},"src":"console"})" "\n";
	std::string path = write_tmp(d, "events.jsonl", old);
	std::vector<json> seen;
	{
		Store st;
		st.replay_hook = [&](const json &r) { seen.push_back(r); };
		st.open_journal(path);
		st.record_console({{"type", "ai_result"}, {"target", "rule:CRED-003"}, {"result", {{"verdict", "ok"}}}});
		st.close_journal();
	}
	CHECK(seen.empty());  // nothing from before this version's header is trusted
	Store st2;
	st2.replay_hook = [&](const json &r) { seen.push_back(r); };
	st2.open_journal(path);
	CHECK(seen.size() == 1 && seen[0]["target"] == "rule:CRED-003");
	// ...and AI job records are not searchable by viewers.
	CHECK_EQ(st2.search_events({{"type", {"ai_result"}}}).size(), (size_t)0);
	st2.close_journal();
}

TEST(InterruptedRolloutIsShown) {
	TempDir d;
	std::string path = d.path + "/events.jsonl";
	{
		Store st;
		st.open_journal(path);
		st.close_journal();
	}
	// The console died after journaling the intent, before the outcome.
	std::string body = read_file(path).value_or("") +
	                   json{{"ts", now_ts()}, {"type", "rollout_intent"}, {"id", "RO1-1"}, {"action", "enforce"},
	                        {"group", "prod"}, {"percent", 10}, {"cohort", {"web-1"}}, {"by", "dee"}, {"src", "console"}}
	                       .dump() +
	                   "\n";
	std::string err;
	write_file_atomic(path, body, 0600, &err);
	Store st2;
	st2.open_journal(path);
	auto r = st2.rollouts_json();
	CHECK(r.size() == 1 && r[0]["status"] == "interrupted" && r[0]["by"] == "dee");
	st2.close_journal();
	// A completed rollout replays as complete, once.
	Env e;
	e.send({{"type", "hello"}, {"host", "web-1"}, {"group", "prod"}});
	e.st.rollout("enforce", "prod", 100, "dee");
	Store st3;
	st3.open_journal(e.st.journal_path());
	auto r3 = st3.rollouts_json();
	CHECK(r3.size() == 1 && r3[0]["status"] == "complete");
	st3.close_journal();
}

TEST(RolloutPushesInParallel) {
	struct SlowLink : FakeLink {
		bool send(const std::string &line) override {
			std::this_thread::sleep_for(std::chrono::milliseconds(200));
			return FakeLink::send(line);
		}
	};
	Env e;
	std::vector<std::shared_ptr<SlowLink>> links;
	std::vector<SensorSession> sess;
	for (int i = 0; i < 20; i++) {
		links.push_back(std::make_shared<SlowLink>());
		sess.push_back({"", links.back()});
		e.st.sensor_line(sess.back(), json{{"type", "hello"}, {"host", "w" + std::to_string(i)}, {"group", "g"}}.dump());
	}
	auto t0 = std::chrono::steady_clock::now();
	Rollout r = e.st.rollout("reload", "g", 100, "t");
	CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2));  // serially: 4 s
	CHECK_EQ(r.delivered.size(), (size_t)20);
	links[0]->down = true;  // a write that fails is reported separately from "not connected"
	r = e.st.rollout("reload", "g", 100, "t");
	CHECK(r.send_failed.size() == 1 && r.send_failed[0] == "w0" && r.failed.size() == 1);
}

TEST(LegacyAlertIdsAreStableAcrossRotation) {
	TempDir d;
	auto line = [](int i) {
		return json{{"ts", "2025-01-01T00:00:0" + std::to_string(i) + ".000Z"}, {"type", "alert"}, {"host", "h"},
		            {"rule", "RULE-" + std::to_string(i)}, {"severity", "low"}}
		    .dump();
	};
	// Pre-1.0 journal: alerts without IDs, and a triage of the third ("R3").
	std::string seg1 = line(1) + "\n" + line(2) + "\n";
	std::string seg0 = line(3) + "\n" + line(4) + "\n" + line(5) + "\n" +
	                   R"({"ts":"2025-01-01T00:01:00.000Z","type":"triage","id":"R3","host":"h","rule":"RULE-3","status":"resolved","note":"false positive","by":"olive"})" "\n";
	write_tmp(d, "events.jsonl.1", seg1);
	write_tmp(d, "events.jsonl", seg0);
	auto status_of = [&](const std::string &rule) {
		Store st;
		st.open_journal(d.path + "/events.jsonl");
		auto a = st.alert_list({{"rule", {rule}}, {"status", {"all"}}});
		std::string s = a.size() == 1 ? a[0]["status"].get<std::string>() : "?";
		st.close_journal();
		return s;
	};
	CHECK_EQ(status_of("RULE-3"), std::string("resolved"));
	// Rotation drops the old segment: positions shift, the triage must not move.
	fs::remove(d.path + "/events.jsonl.1");
	CHECK_EQ(status_of("RULE-5"), std::string("open"));
}

TEST(InventoryIsCurrentStateAndRepeatsAreNotJournaled) {
	Env e;
	e.st.max_ring = 200;  // a small history window: the state must not depend on it
	auto inv = [&](const std::string &host, const std::string &name, const std::string &ver) {
		e.send({{"ts", now_ts()}, {"type", "inventory"}, {"host", host}, {"kind", "npm"}, {"name", name},
		        {"version", ver}, {"where", "/usr/lib/node_modules"}, {"change", "present"}});
	};
	e.send({{"type", "hello"}, {"host", "old"}, {"host_id", "o"}});
	inv("old", "lodash", "4.17.15");
	for (int h = 0; h < 10; h++)
		for (int p = 0; p < 50; p++)
			inv("busy-" + std::to_string(h), "pkg-" + std::to_string(p), "1.0.0");
	int found = 0;
	for (auto &f : e.st.vuln_findings())
		found += f.host == "old" && f.name == "lodash";
	CHECK_EQ(found, 1);
	CHECK_EQ(e.st.host_detail("old")->at("inventory").size(), (size_t)1);
	// A reconnect re-sends the same baseline: nothing new is journaled.
	size_t before = read_file(e.st.journal_path()).value_or("").size();
	inv("old", "lodash", "4.17.15");
	CHECK_EQ(read_file(e.st.journal_path()).value_or("").size(), before);
	inv("old", "lodash", "4.17.21");  // an upgrade is a change
	CHECK(read_file(e.st.journal_path()).value_or("").size() > before);
	CHECK_EQ(e.st.vuln_findings().size(), (size_t)0);
	// A package not re-reported after a reconnect was removed meanwhile.
	SensorSession s{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(s, R"({"type":"hello","host":"old","host_id":"o"})");
	e.st.inventory_grace = std::chrono::nanoseconds(0);
	e.st.reap();
	CHECK_EQ(e.st.host_detail("old")->at("inventory").size(), (size_t)0);
}

TEST(ExploitedTierNeedsTheWholePackageName) {
	Env e;
	e.send({{"type", "hello"}, {"host", "dev"}, {"host_id", "d"}});
	e.send({{"ts", now_ts()}, {"type", "inventory"}, {"host", "dev"}, {"kind", "npm"}, {"name", "ws"},
	        {"version", "7.0.0"}, {"change", "present"}});
	e.send({{"ts", now_ts()}, {"type", "alert"}, {"host", "dev"}, {"rule", "CRED-002"}, {"severity", "high"},
	        {"cmd", "cat /home/dev/.aws/credentials"}, {"title", "news views windows"}});
	auto f = e.st.vuln_findings();
	CHECK(f.size() == 1 && f[0].tier == "dormant");
	e.send({{"ts", now_ts()}, {"type", "alert"}, {"host", "dev"}, {"rule", "X"}, {"severity", "high"},
	        {"cmd", "node node_modules/ws/lib/websocket.js"}});
	f = e.st.vuln_findings();
	CHECK(f.size() == 1 && f[0].tier == "exploited");
}

TEST(VersionPrecedence) {
	CHECK(!ver_less("7.4.10+build.1", "7.4.6"));
	CHECK(!ver_less("v8.0.0", "7.4.6"));
	CHECK(ver_less("v7.4.5", "7.4.6"));
	CHECK(ver_less("7.4.6-rc.1", "7.4.6"));     // a pre-release is before its release
	CHECK(ver_less("1.2.6-beta.1", "1.2.6"));
	CHECK(!ver_less("1.2.6", "1.2.6-beta.1"));
	CHECK(ver_less("1.0.0-alpha", "1.0.0-alpha.1"));
	CHECK(ver_less("1.0.0-alpha.1", "1.0.0-alpha.beta"));
	CHECK(ver_less("1.0.0-beta.2", "1.0.0-beta.11"));
	CHECK(ver_less("2.31.0rc1", "2.31.0"));
	CHECK(!ver_less("1.0.post1", "1.0"));
	CHECK(ver_less("1.10a", "1.11"));  // digits of a suffixed component still count
	CHECK(!ver_less("5.4", "5.4"));
}

TEST(OneHostCannotEvictTheFleet) {
	Env e;
	e.st.max_ring = 100;
	for (int h = 0; h < 5; h++)
		e.send({{"ts", now_ts()}, {"type", "alert"}, {"host", "quiet-" + std::to_string(h)}, {"rule", "Q"},
		        {"severity", "high"}});
	for (int i = 0; i < 1000; i++)
		e.send({{"ts", now_ts()}, {"type", "alert"}, {"host", "noisy"}, {"rule", "N"}, {"severity", "low"}});
	CHECK_EQ(e.st.alert_list({{"rule", {"Q"}}, {"limit", {"5000"}}}).size(), (size_t)5);
	CHECK_EQ(e.st.alert_list({{"limit", {"5000"}}}).size(), (size_t)100);
	// Bulk telemetry does not evict security records from the search index.
	e.st.journal_keep = 50;
	for (int i = 0; i < 200; i++)
		e.send({{"ts", now_ts()}, {"type", "flow"}, {"host", "noisy"}, {"dest", "10.0.0.1"}});
	CHECK_EQ(e.st.search_events({{"type", {"alert"}}, {"rule", {"Q"}}}).size(), (size_t)5);
	// A connection that floods is throttled.
	e.st.sensor_line_burst = 10;
	e.st.sensor_lines_per_s = 0.001;
	SensorSession s{"", std::make_shared<FakeLink>()};
	e.st.sensor_line(s, R"({"type":"hello","host":"flood"})");
	for (int i = 0; i < 50; i++)
		e.st.sensor_line(s, R"({"type":"alert","host":"flood","rule":"F","severity":"low"})");
	CHECK_EQ(e.st.alert_list({{"rule", {"F"}}}).size(), (size_t)9);
	CHECK_EQ(e.st.host_snapshot("flood")->dropped_lines, 41LL);
}

TEST(ConsoleIsNotAFleetHost) {
	Env e;
	e.send({{"type", "hello"}, {"host", "web-1"}, {"group", "prod"}});
	CHECK_EQ(e.req("PUT", "/api/vault?key=api", TOK_ADMIN, "k").status, 200);
	CHECK_EQ(e.req("GET", "/api/vault?key=api", TOK_OPERATOR).status, 200);
	CHECK(!e.st.host_snapshot("console"));
	CHECK_EQ(e.st.host_list("all", "").size(), (size_t)1);
	CHECK_EQ(e.st.summary()["hosts"]["live"].get<int>(), 1);
	Rollout r = e.st.rollout("reload", "", 100, "t");
	CHECK(r.cohort.size() == 1 && r.cohort[0] == "web-1");
	CHECK_EQ(e.st.alert_list({{"rule", {"VAULT-ACCESS"}}}).size(), (size_t)1);  // the audit record stays
}

TEST(HostsAndRolloutsAreBounded) {
	Env e;
	e.st.max_rollouts = 3;
	for (int i = 0; i < 5; i++)
		e.st.rollout("reload", "", 100, "t");
	CHECK_EQ(e.st.rollout_count(), (size_t)3);
	for (int i = 0; i < 4; i++) {
		SensorSession s{"", std::make_shared<FakeLink>()};
		e.st.sensor_line(s, json{{"type", "hello"}, {"host", "ci-" + std::to_string(i)}, {"ephemeral", true}}.dump());
		e.st.sensor_closed(s);
	}
	CHECK_EQ(e.st.host_list("decommissioned", "").size(), (size_t)4);
	e.st.max_decommissioned = 2;
	e.st.reap();
	CHECK_EQ(e.st.host_list("decommissioned", "").size(), (size_t)2);
	e.st.ephemeral_retention = std::chrono::nanoseconds(0);
	e.st.reap();
	CHECK_EQ(e.st.host_list("all", "").size(), (size_t)0);
}

TEST(VaultRejectsBadInputAndWrongKeys) {
	TempDir d;
	std::string p = d.path + "/vault.json", err;
	auto v = Vault::open(p);
	CHECK(!v->set("a\xff", "x", &err));  // not UTF-8: refused, and nothing poisoned
	CHECK(!v->set("bin", std::string("\x30\x82\xff", 3), &err));
	CHECK(!v->set("", "x", &err));
	CHECK(!v->set("a\nb", "x", &err));
	CHECK(v->set("good", "fine", &err));
	CHECK_EQ(v->keys().size(), (size_t)1);
	Env e;
	CHECK_EQ(e.req("PUT", "/api/vault?key=a%FF", TOK_ADMIN, "x").status, 400);
	CHECK_EQ(e.req("PUT", "/api/vault?key=ok", TOK_ADMIN, "x").status, 200);
	CHECK_EQ(body_json(e.req("GET", "/api/vault", TOK_OPERATOR))["keys"].size(), (size_t)1);
	// The wrong key for an existing store is refused at open.
	std::string key = read_file(p + ".key").value_or("");
	write_file_atomic(p + ".key", "a-different-key-that-is-long-enough-0123", 0600, &err);
	bool threw = false;
	try {
		Vault::open(p);
	} catch (const std::exception &ex) {
		threw = std::string(ex.what()).find("does not decrypt") != std::string::npos;
	}
	CHECK(threw);
	write_file_atomic(p + ".key", key, 0600, &err);
	CHECK_EQ(Vault::open(p)->get("good").value_or("?"), std::string("fine"));
	// Empty or short key material for a new store is refused.
	TempDir d2;
	for (std::string k : {"\n", "short-key"}) {
		write_file_atomic(d2.path + "/k", k, 0600, &err);
		setenv("WISP_VAULT_KEY_FILE", (d2.path + "/k").c_str(), 1);
		threw = false;
		try {
			Vault::open(d2.path + "/vault.json");
		} catch (const std::exception &) {
			threw = true;
		}
		unsetenv("WISP_VAULT_KEY_FILE");
		CHECK(threw);
	}
	// A tampered entry is distinguishable from a missing one.
	auto items = json::parse(read_file(p).value_or("{}"));
	items["copy"] = items["good"];
	write_file_atomic(p, items.dump(), 0600, &err);
	bool undecryptable = false;
	CHECK(!Vault::open(p)->get("copy", &undecryptable) && undecryptable);
}

TEST(DurationsRejectOverflowAndJunk) {
	CHECK(!parse_duration("10000000h"));
	CHECK(!parse_duration("2562048h"));
	CHECK(!parse_duration("1.2.3s"));
	CHECK(!parse_duration(".s"));
	CHECK(!parse_duration("."));
	CHECK(!parse_duration("5"));
	CHECK(!parse_duration("-1h"));
	CHECK(parse_duration("1.5h") == std::chrono::nanoseconds(std::chrono::minutes(90)));
	CHECK(parse_duration(".5s") == std::chrono::nanoseconds(std::chrono::milliseconds(500)));
	CHECK(parse_duration("2562047h") == std::chrono::nanoseconds(std::chrono::hours(2562047)));
	CHECK(parse_duration("0") == std::chrono::nanoseconds(0));
	CHECK(parse_duration("3m0s") == std::chrono::nanoseconds(std::chrono::minutes(3)));
	CHECK_EQ(fmt_duration(std::chrono::nanoseconds(INT64_MIN)), std::string("-2562047h47m16.854775808s"));
}

TEST(LogLinesCannotBeForged) {
	char tmpl[] = "/tmp/wisp-log-XXXXXX";
	int fd = mkstemp(tmpl);
	fflush(stderr);
	int saved = dup(2);
	dup2(fd, 2);
	logf("sensor connected: version=%s", "1.0\n2026/10/23 12:00:00 api PUT /api/vault -> 200 user=ada\x1b[2J");
	fflush(stderr);
	dup2(saved, 2);
	close(saved);
	close(fd);
	std::string out = read_file(tmpl).value_or("");
	unlink(tmpl);
	CHECK_EQ(std::count(out.begin(), out.end(), '\n'), (long)1);
	CHECK(out.find("\\n2026/10/23") != std::string::npos && out.find("\\x1b[2J") != std::string::npos);
}

// ---- network layer and HTTP surface (release review) ----------------------------

static int dial(int port, int rcvbuf = 0) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (rcvbuf)
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
	struct sockaddr_in a {};
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
	if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void send_str(int fd, const std::string &s) {
	size_t off = 0;
	while (off < s.size()) {
		ssize_t w = ::send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
		if (w <= 0)
			return;
		off += (size_t)w;
	}
}

// Reads until EOF, an error, or `ms` without data; *eof says which.
static std::string recv_for(int fd, int ms, bool *eof = nullptr) {
	struct timeval tv = {ms / 1000, (ms % 1000) * 1000};
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	std::string out;
	char buf[65536];
	for (;;) {
		ssize_t n = recv(fd, buf, sizeof buf, 0);
		if (n > 0) {
			out.append(buf, (size_t)n);
			continue;
		}
		if (eof)
			*eof = n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK);
		return out;
	}
}

static size_t count_of(const std::string &hay, const std::string &needle) {
	size_t n = 0;
	for (size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
		n++;
	return n;
}

static json error_body(const std::string &resp) {
	auto he = resp.find("\r\n\r\n");
	return he == std::string::npos ? json() : json::parse(resp.substr(he + 4), nullptr, false);
}

TEST(HttpStrictParsingAndJsonErrors) {
	LiveServer s;
	auto status = [&](const std::string &raw) { return s.exchange(raw).substr(0, 12); };
	const std::string bad = "HTTP/1.1 400";
	CHECK_EQ(status("GET / HTTP/1.1\r\nHost : x\r\n\r\n"), bad);                    // whitespace before the colon
	CHECK_EQ(status("GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n folded\r\n\r\n"), bad);  // obs-fold
	CHECK_EQ(status("GET / HTTP/1.1\r\nHost: x\r\nno colon here\r\n\r\n"), bad);
	CHECK_EQ(status("POST /api/alerts/triage HTTP/1.1\r\nHost: x\r\nContent-Length: +2\r\n\r\n{}"), bad);
	CHECK_EQ(status("POST /api/alerts/triage HTTP/1.1\r\nHost: x\r\nContent-Length:\r\n\r\n"), bad);
	CHECK_EQ(status("POST /api/alerts/triage HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}"), bad);
	// an empty first Content-Length must not drop out of the joined value (it read as 2)
	CHECK_EQ(status("POST /api/alerts/triage HTTP/1.1\r\nHost: x\r\nContent-Length:\r\nContent-Length: 2\r\n\r\n{}"), bad);
	CHECK_EQ(status("GET / HTTP/1.1\r\n\r\n"), bad);                         // HTTP/1.1 needs Host
	CHECK_EQ(status("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"), bad);   // ... exactly one
	CHECK_EQ(status("GET / HTTP/1.0\r\n\r\n"), std::string("HTTP/1.1 200"));  // 1.0 may omit it
	CHECK_EQ(status("GET /api/x%0a2026 HTTP/1.1\r\nHost: x\r\n\r\n"), bad);  // decoded control bytes
	CHECK_EQ(status("GET /a%00b HTTP/1.1\r\nHost: x\r\n\r\n"), bad);
	CHECK_EQ(status("G(T / HTTP/1.1\r\nHost: x\r\n\r\n"), bad);  // method must be a token
	CHECK_EQ(status("GET  / HTTP/1.1\r\nHost: x\r\n\r\n"), bad);
	CHECK_EQ(status("GET / HTTP/1.1\r\nHost: x\r\nX-A: a\x01" "b\r\n\r\n"), bad);
	// bare LF: answered at once instead of waiting out the header timeout
	auto t0 = std::chrono::steady_clock::now();
	std::string lf = s.exchange("GET / HTTP/1.1\nHost: x\n\n");
	CHECK(lf.rfind(bad, 0) == 0);
	CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2));
	// errors the server writes itself are JSON, like the API's
	CHECK(error_body(lf).contains("error"));
	std::string te = s.exchange("POST /api/x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n");
	CHECK(te.rfind("HTTP/1.1 501", 0) == 0 && error_body(te).contains("error"));
	std::string big = s.exchange("GET / HTTP/1.1\r\nHost: x\r\nX-Pad: " + std::string(70000, 'a') + "\r\n\r\n");
	CHECK(big.rfind("HTTP/1.1 431", 0) == 0 && error_body(big).contains("error"));
	CHECK(s.exchange("GET http://console.example/healthz HTTP/1.1\r\nHost: x\r\n\r\n").find("ok\n") != std::string::npos);
}

TEST(HttpKeepAliveLeftoverBytesAndEmptyLines) {
	LiveServer s;
	// The second request arrives in two segments: it must still be answered.
	int fd = dial(s.ln.port());
	send_str(fd, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\nGET /readyz HTTP/1.1\r\nHo");
	std::this_thread::sleep_for(std::chrono::milliseconds(300));
	send_str(fd, "st: x\r\nConnection: close\r\n\r\n");
	std::string out = recv_for(fd, 3000);
	close(fd);
	CHECK_EQ(count_of(out, "HTTP/1.1 200"), (size_t)2);
	CHECK(out.find("ready\n") != std::string::npos);
	// RFC 9112 2.2: empty lines before a request line are ignored (a client
	// that sends CRLF after a POST body keeps its connection).
	CHECK(s.exchange("\r\n\r\nGET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").rfind("HTTP/1.1 200", 0) == 0);
	std::string two = s.exchange("POST /api/alerts/triage HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOK_OPERATOR +
	                                 "\r\nContent-Length: 2\r\n\r\n{}\r\nGET /healthz HTTP/1.1\r\nHost: x\r\nConnection: "
	                                 "close\r\n\r\n",
	                             2);
	CHECK(two.rfind("HTTP/1.1 400", 0) == 0);  // triage without an id
	CHECK(two.find("HTTP/1.1 200") != std::string::npos && two.find("ok\n") != std::string::npos);
}

TEST(HttpConformance) {
	CHECK_EQ(std::string(status_text(202)), std::string("Accepted"));
	CHECK_EQ(std::string(status_text(429)), std::string("Too Many Requests"));
	CHECK_EQ(std::string(status_text(299)), std::string("Success"));
	LiveServer s;
	// Connection is a token list
	CHECK(s.exchange("GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close, TE\r\n\r\n").find("Connection: close") !=
	      std::string::npos);
	// HTTP/1.0 keep-alive is acknowledged
	CHECK(s.exchange("GET /healthz HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").find("Connection: keep-alive") !=
	      std::string::npos);
	// static paths and probes are read-only
	CHECK(s.exchange("POST / HTTP/1.1\r\nHost: x\r\n\r\n").rfind("HTTP/1.1 405", 0) == 0);
	CHECK(s.exchange("GET / HTTP/1.1\r\nHost: x\r\nExpect: magic\r\n\r\n").rfind("HTTP/1.1 417", 0) == 0);
	// Expect: 100-continue gets the interim response before the body is sent
	int fd = dial(s.ln.port());
	send_str(fd, "PUT /api/vault?key=cont HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOK_ADMIN +
	                 "\r\nExpect: 100-continue\r\nContent-Length: 3\r\nConnection: close\r\n\r\n");
	std::string interim = recv_for(fd, 1000);
	CHECK(interim.rfind("HTTP/1.1 100 Continue\r\n\r\n", 0) == 0);
	send_str(fd, "abc");
	std::string fin = recv_for(fd, 3000);
	close(fd);
	CHECK(fin.find("HTTP/1.1 200") != std::string::npos);
	CHECK_EQ(s.env.st.vault->get("cont").value_or("?"), std::string("abc"));
}

TEST(HttpFirstRequestDeadlineAndUnauthenticatedBodies) {
	LiveServer s;
	s.srv.first_request = std::chrono::milliseconds(300);
	// A connection that never sends a request is closed after the first-
	// request deadline, not after the 120 s keep-alive idle time.
	int fd = dial(s.ln.port());
	auto t0 = std::chrono::steady_clock::now();
	bool eof = false;
	recv_for(fd, 5000, &eof);
	close(fd);
	CHECK(eof);
	CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(3));
	// An unauthenticated request is answered from its headers: the console
	// never waits for (or buffers) its body.
	fd = dial(s.ln.port());
	t0 = std::chrono::steady_clock::now();
	send_str(fd, "PUT /api/vault?key=a HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\n");
	std::string out = recv_for(fd, 3000, &eof);
	close(fd);
	CHECK(out.rfind("HTTP/1.1 401", 0) == 0);
	CHECK(eof && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2));
	CHECK(s.exchange("POST /assets/app.js HTTP/1.1\r\nHost: x\r\nContent-Length: 900000\r\n\r\n").rfind("HTTP/1.1 405", 0) ==
	      0);
	// authenticated: the body is read and routed as usual
	CHECK(s.exchange("PUT /api/vault?key=a HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOK_ADMIN +
	                 "\r\nContent-Length: 2\r\nConnection: close\r\n\r\nv1")
	          .rfind("HTTP/1.1 200", 0) == 0);
}

TEST(StreamWriteTimeoutEndsTheConnection) {
	// A write that times out leaves part of the message (with TLS, a pending
	// record OpenSSL would flush in place of the next write) on the wire: the
	// stream must refuse every later write instead of reporting it sent.
	Listener ln("127.0.0.1:0");
	int cfd = dial(ln.port(), 4096);
	int sfd = ln.accept_fd();
	CHECK(cfd >= 0 && sfd >= 0);
	Stream st(sfd, nullptr);
	std::string big(64u << 20, 'x');
	CHECK(!st.write_all(big, after(std::chrono::milliseconds(300))));
	CHECK(st.dead());
	CHECK(!st.write_all("{\"mode\":\"monitor\"}\n", after(std::chrono::seconds(1))));
	close(cfd);
	ln.close();
	CHECK(ln.closed());
	CHECK_EQ(ln.accept_fd(), -1);
}

TEST(ChunkedDecoderIsStrictAndBounded) {
	auto decode = [](const std::string &in, std::string *out = nullptr, size_t max = 1 << 20) {
		Dechunker d;
		auto st = d.feed(in, max);
		if (out)
			*out = d.out;
		return st;
	};
	std::string out;
	CHECK_EQ((int)decode("3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: y\r\n\r\n", &out), (int)Dechunker::DONE);
	CHECK_EQ(out, std::string("abcde"));
	CHECK_EQ((int)decode("FFFFFFFFFFFFFFEC\r\n0\r\n\r\n"), (int)Dechunker::BAD);  // wrapped the bound check before
	CHECK_EQ((int)decode("-1\r\nx\r\n0\r\n\r\n"), (int)Dechunker::BAD);
	CHECK_EQ((int)decode("1000000000000000\r\n"), (int)Dechunker::BAD);  // 16 hex digits
	CHECK_EQ((int)decode("5 junk\r\nabcde\r\n0\r\n\r\n"), (int)Dechunker::BAD);
	CHECK_EQ((int)decode("3\r\nabcX\r\n0\r\n\r\n"), (int)Dechunker::BAD);  // no CRLF after the data
	CHECK_EQ((int)decode("\r\n"), (int)Dechunker::BAD);
	CHECK_EQ((int)decode("11\r\n" + std::string(17, 'a') + "\r\n0\r\n\r\n", nullptr, 16), (int)Dechunker::BAD);  // max_out
	CHECK_EQ((int)decode("3\r\nab"), (int)Dechunker::DATA);  // incomplete, not an error
	CHECK_EQ((int)decode(std::string(5000, '1')), (int)Dechunker::BAD);  // a size line that never ends
	// incremental: fed byte by byte, the result is the same
	std::string in = "4\r\nwisp\r\n0\r\n\r\n", acc;
	Dechunker d;
	Dechunker::State st = Dechunker::SIZE;
	for (char c : in) {
		acc += c;
		st = d.feed(acc, 1 << 20);
	}
	CHECK_EQ((int)st, (int)Dechunker::DONE);
	CHECK_EQ(d.out, std::string("wisp"));
	int code = 0;
	CHECK(parse_status_line("HTTP/1.1 200 OK", &code) && code == 200);
	CHECK(parse_status_line("HTTP/1.0 103", &code) && code == 103);
	CHECK(!parse_status_line("HTTP/1.1 2000 OK", &code));
	CHECK(!parse_status_line("HTTP/1.1 20 OK", &code));
	CHECK(!parse_status_line("HTTP/2 200", &code));
}

// A plaintext (-dev style) ingest server on a loopback port.
struct LiveIngest {
	Env env;
	Listener ln{"127.0.0.1:0"};
	SSL_CTX *ctx;
	IngestServer ing;
	std::thread th;
	explicit LiveIngest(SSL_CTX *tls = nullptr, std::chrono::milliseconds hello = std::chrono::seconds(30), int unbound = 512)
	    : ctx(tls), ing(env.st, tls, 100) {
		ing.hello_wait = hello;
		ing.max_unbound = unbound;
		th = std::thread([this] { ing.serve(ln); });
	}
	~LiveIngest() {
		ln.close();
		th.join();
		ing.shutdown_all();
		for (int i = 0; i < 150 && ing.active() > 0; i++)
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
	template <class F> bool eventually(F f, int ms = 3000) {
		for (int i = 0; i < ms / 20; i++) {
			if (f())
				return true;
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		}
		return f();
	}
};

TEST(IngestSkipsOversizedLinesWithoutBufferingThem) {
	LiveIngest li;
	int fd = dial(li.ln.port());
	send_str(fd, R"({"type":"hello","host":"big-1"})" "\n");
	CHECK(li.eventually([&] { auto h = li.env.st.host_snapshot("big-1"); return h && h->connected; }));
	std::string huge = R"({"type":"alert","host":"big-1","rule":"HUGE","severity":"high","cmd":")" + std::string(200000, 'x');
	send_str(fd, huge);  // no newline yet: the console must not hold all of it
	send_str(fd, "\"}\n" R"({"type":"alert","host":"big-1","rule":"AFTER","severity":"low"})" "\n");
	CHECK(li.eventually([&] { return li.env.st.alert_list({}).size() == 1; }));
	auto a = li.env.st.alert_list({});
	CHECK(a.size() == 1 && a[0]["rule"] == "AFTER");  // the next line on the same connection still counts
	auto h = li.env.st.host_snapshot("big-1");
	CHECK(h && h->connected && h->dropped_lines >= 1);
	close(fd);
}

TEST(IngestHelloDeadlineAndUnboundCap) {
	LiveIngest li(nullptr, std::chrono::milliseconds(400), 2);
	int a = dial(li.ln.port()), b = dial(li.ln.port());
	CHECK(li.eventually([&] { return li.ing.active() == 2; }));
	// a third connection without a hello is refused at once
	int c = dial(li.ln.port());
	bool eof = false;
	recv_for(c, 1000, &eof);
	CHECK(eof);
	close(c);
	// the silent ones are closed once the hello deadline passes
	auto t0 = std::chrono::steady_clock::now();
	recv_for(a, 3000, &eof);
	CHECK(eof);
	recv_for(b, 3000, &eof);
	CHECK(eof);
	CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(3));
	close(a);
	close(b);
	CHECK(li.eventually([&] { return li.ing.active() == 0; }));
	// slots are free again, and a sensor that says hello stays connected
	int d = dial(li.ln.port());
	send_str(d, R"({"type":"hello","host":"ok-1"})" "\n");
	CHECK(li.eventually([&] { auto h = li.env.st.host_snapshot("ok-1"); return h && h->connected; }));
	std::this_thread::sleep_for(std::chrono::milliseconds(600));  // past the hello deadline
	CHECK(li.env.st.host_snapshot("ok-1")->connected);
	close(d);
}

TEST(IngestShutdownWakesEveryConnection) {
	LiveIngest li;
	int silent = dial(li.ln.port()), hello = dial(li.ln.port());
	send_str(hello, R"({"type":"hello","host":"w-1"})" "\n");
	CHECK(li.eventually([&] { auto h = li.env.st.host_snapshot("w-1"); return h && h->connected; }));
	CHECK(li.eventually([&] { return li.ing.active() == 2; }));
	auto t0 = std::chrono::steady_clock::now();
	li.env.st.shutdown_links();
	li.ing.shutdown_all();  // also the one that never said hello (the store does not know it)
	CHECK(li.eventually([&] { return li.ing.active() == 0; }, 2000));
	CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2));
	bool eof = false;
	recv_for(silent, 1000, &eof);
	CHECK(eof);
	close(silent);
	close(hello);
	// the host was recorded as disconnected by the shutdown, not decommissioned
	CHECK(li.env.st.host_snapshot("w-1") && li.env.st.host_snapshot("w-1")->decommissioned.empty());
}

// Captures what logf writes while f runs.
template <class F> static std::string capture_log(F f) {
	char tmpl[] = "/tmp/wisp-log-XXXXXX";
	int fd = mkstemp(tmpl);
	fflush(stderr);
	int saved = dup(2);
	dup2(fd, 2);
	f();
	fflush(stderr);
	dup2(saved, 2);
	close(saved);
	close(fd);
	std::string out = read_file(tmpl).value_or("");
	unlink(tmpl);
	return out;
}

// One TLS 1.2 client connection with a client certificate; resumes `resume`
// when given. Returns the session for a later resumption (caller frees).
static SSL_SESSION *tls_dial(int port, const std::string &cert, const std::string &key, SSL_SESSION *resume, bool *ok,
                             bool *reused) {
	*ok = *reused = false;
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);  // session-ID resumption, no tickets to wait for
	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
	SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM);
	int fd = dial(port);
	struct timeval tv = {3, 0};
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	if (resume)
		SSL_set_session(ssl, resume);
	SSL_SESSION *sess = nullptr;
	if (SSL_connect(ssl) == 1) {
		*ok = true;
		*reused = SSL_session_reused(ssl) == 1;
		sess = SSL_get1_session(ssl);
		SSL_write(ssl, "{\"type\":\"hello\",\"host\":\"tls-1\"}\n", 32);
	}
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(fd);
	SSL_CTX_free(ctx);
	return sess;
}

TEST(IngestTlsResumptionAndHandshakeFailuresAreLogged) {
	TempDir d;
	std::string cert = d.path + "/c.pem", key = d.path + "/k.pem";
	std::string cmd = "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=127.0.0.1 "
	                  "-keyout " + key + " -out " + cert + " >/dev/null 2>&1";
	CHECK(system(cmd.c_str()) == 0);
	auto ctx = make_server_ctx(cert, key, cert);  // mutual TLS: the same self-signed cert is the CA
	// resumption skips certificate re-verification: sessions are short-lived
	CHECK_EQ(SSL_CTX_get_timeout(ctx.get()), 300L);
	LiveIngest li(ctx.get());
	// A client that resumes its session must not be refused (no session ID
	// context used to turn this into a fatal internal_error).
	bool ok = false, reused = false;
	SSL_SESSION *sess = tls_dial(li.ln.port(), cert, key, nullptr, &ok, &reused);
	CHECK(ok && sess);
	if (sess) {
		if (SSL_SESSION *again = tls_dial(li.ln.port(), cert, key, sess, &ok, &reused))
			SSL_SESSION_free(again);
		CHECK(ok);
		SSL_SESSION_free(sess);
	}
	// A client without TLS (or without a certificate) is logged with its address and the reason.
	std::string log = capture_log([&] {
		int fd = dial(li.ln.port());
		send_str(fd, "{\"type\":\"hello\",\"host\":\"plain\"}\n");
		recv_for(fd, 2000);
		close(fd);
		li.eventually([&] { return li.ing.active() == 0; });
	});
	CHECK(log.find("ingest: TLS handshake with 127.0.0.1:") != std::string::npos);
	CHECK(log.find("failed:") != std::string::npos);
}

TEST(SlackTextEscapesSensorFields) {
	Event e;
	e.severity = "high";
	e.rule = "RSHELL-01";
	e.host = "web-1";
	e.title = "<!here> reverse shell";
	e.actor = "ai";
	e.cmd = "curl x ` <!channel> VPN expired, re-auth at <https://evil.example|https://vpn.corp> & \n> fake quote";
	std::string t = slack_alert_text(e);
	CHECK(t.find("<!channel>") == std::string::npos && t.find("<!here>") == std::string::npos);
	CHECK(t.find("&lt;!channel&gt;") != std::string::npos && t.find("&lt;https://evil.example|") != std::string::npos);
	CHECK(t.find(" &amp; ") != std::string::npos);
	CHECK_EQ(std::count(t.begin(), t.end(), '`'), (long)4);    // only the two code spans' own delimiters
	CHECK_EQ(std::count(t.begin(), t.end(), '\n'), (long)2);   // the layout's two line breaks, no injected ones
	e.cmd = std::string(999, 'a') + "\xe2\x80\x94" + std::string(3000, 'b');  // cut lands inside the em dash
	t = slack_alert_text(e);
	CHECK(t.size() < 1500);
	CHECK(valid_utf8(t));
}

TEST(OperatorActionsAreJournaledAndVaultAccessIsLogged) {
	Env e;
	auto link = std::make_shared<FakeLink>();
	SensorSession s{"", link};
	e.st.sensor_line(s, R"({"type":"hello","host":"web-1","host_id":"id1"})");
	CHECK_EQ(e.req("POST", "/api/policy/push?host=web-1&action=enforce", TOK_OPERATOR).status, 200);
	CHECK_EQ(e.req("POST", "/api/policy/push?host=gone&action=monitor", TOK_OPERATOR).status, 200);
	CHECK_EQ(e.req("PUT", "/api/vault?key=db/pw", TOK_ADMIN, "hunter2").status, 200);
	std::string log = capture_log([&] {
		CHECK_EQ(e.req("GET", "/api/vault", TOK_OPERATOR).status, 200);
		CHECK_EQ(e.req("GET", "/api/vault?key=db/pw", TOK_OPERATOR).status, 200);
	});
	// vault reads and listings are in the access log (name, never the value)
	CHECK(log.find("api GET /api/vault -> 200") != std::string::npos);
	CHECK(log.find("key=db/pw") != std::string::npos && log.find("key=(list)") != std::string::npos);
	CHECK(log.find("hunter2") == std::string::npos);
	std::string j = read_file(e.st.journal_path()).value_or("");
	CHECK_EQ(count_of(j, "\"type\":\"audit\""), (size_t)4);
	CHECK(j.find("\"op\":\"policy_push\"") != std::string::npos && j.find("\"target\":\"web-1\"") != std::string::npos);
	CHECK(j.find("\"by\":\"Olive Ortega\"") != std::string::npos);
	CHECK(j.find("\"op\":\"vault_write\"") != std::string::npos && j.find("\"key\":\"db/pw\"") != std::string::npos);
	CHECK(j.find("\"op\":\"vault_list\"") != std::string::npos);
	CHECK(j.find("hunter2") == std::string::npos);
	// audit records replay without creating hosts or alerts
	std::string path = e.st.journal_path();
	e.st.close_journal();
	Store st2;
	st2.vulndb = VulnDB::load("");
	st2.open_journal(path);
	CHECK_EQ(st2.host_list("all", "").size(), (size_t)1);
	CHECK(!st2.host_snapshot("console") && !st2.host_snapshot("gone"));
	CHECK_EQ(st2.search_events({{"type", {"audit"}}}).size(), (size_t)4);
	st2.close_journal();
}

TEST(QueryMustBeUtf8AndStaticPathsAreReadOnly) {
	Env e;
	CHECK_EQ(e.req("POST", "/api/policy/push?host=x%FF&action=reload", TOK_OPERATOR).status, 400);
	CHECK_EQ(e.req("GET", "/api/alerts?q=%C3", TOK_VIEWER).status, 400);
	CHECK_EQ(e.req("PUT", "/api/vault?key=caf%E9", TOK_ADMIN, "x").status, 400);
	// and the vault is still usable afterwards
	CHECK_EQ(e.req("PUT", "/api/vault?key=ok", TOK_ADMIN, "x").status, 200);
	CHECK_EQ(e.req("GET", "/api/vault", TOK_ADMIN).status, 200);
	CHECK_EQ(e.req("POST", "/").status, 405);
	CHECK_EQ(e.req("DELETE", "/healthz").status, 405);
	CHECK_EQ(e.req("HEAD", "/").status, 200);
	CHECK_EQ(e.req("GET", "/alerts").status, 200);
}

static int flags(std::vector<std::string> args, Config *out = nullptr) {
	std::vector<char *> argv;
	std::string prog = "wisp-console";
	argv.push_back(prog.data());
	for (auto &a : args)
		argv.push_back(a.data());
	argv.push_back(nullptr);
	Config c;
	std::ostringstream o, e;
	int code = parse_flags((int)args.size() + 1, argv.data(), c, o, e);
	if (out)
		*out = c;
	return code;
}

TEST(FlagValidation) {
	unsetenv("WISP_SLACK_WEBHOOK");
	Config c;
	CHECK_EQ(flags({}, &c), -1);
	CHECK(!c.listen_set && c.max_sensors == 16384 && c.journal_max_mb == 256);
	CHECK_EQ(flags({"-ai", "false", "-gen-token", "viewer:x"}), 2);  // a stray positional no longer drops flags silently
	CHECK_EQ(flags({"--", "-dev"}), 2);
	CHECK_EQ(flags({"-journal-max-mb", "10GB"}), 2);
	CHECK_EQ(flags({"-journal-max-mb", "-5"}), 2);
	CHECK_EQ(flags({"-journal-max-mb", "0"}, &c), -1);
	CHECK_EQ(c.journal_max_mb, 0);
	CHECK_EQ(flags({"-ai-max-per-hour", "+5"}), 2);
	CHECK_EQ(flags({"-max-sensors", "0"}), 2);
	CHECK_EQ(flags({"-http-key", "k.pem"}), 2);  // would have served plain HTTP
	CHECK_EQ(flags({"-cert", "c.pem"}), 2);
	CHECK_EQ(flags({"-slack", "http://hooks.example/x"}), 2);
	CHECK_EQ(flags({"-ai-url", "http://gateway.local"}), 2);
	CHECK_EQ(flags({"-decommission-after", "99999999999999h"}), 2);
	CHECK_EQ(flags({"-decommission-after", "1s"}), 2);
	CHECK_EQ(flags({"-decommission-after", "0"}), -1);
	CHECK_EQ(flags({"-stale-after", "0"}), 2);
	CHECK_EQ(flags({"-listen", "0.0.0.0:8750"}, &c), -1);
	CHECK(c.listen_set);
	CHECK_EQ(flags({"-h"}), 0);
	CHECK_EQ(flags({"-nope"}), 2);
}

int main() {
	signal(SIGPIPE, SIG_IGN);  // as run() does: a peer closing early must not kill the process
	for (auto &t : registry()) {
		current = t.name;
		int before = failures;
		try {
			t.fn();
		} catch (const std::exception &ex) {
			fprintf(stderr, "  FAIL %s: exception: %s\n", t.name, ex.what());
			failures++;
		}
		printf("%s %s\n", failures == before ? "--- PASS:" : "--- FAIL:", t.name);
	}
	printf("%s (%zu tests, %d failed checks)\n", failures ? "FAIL" : "ok", registry().size(), failures);
	return failures ? 1 : 0;
}
