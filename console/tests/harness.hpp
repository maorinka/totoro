// Shared test harness: a tiny registry-based runner, the Env fixture (a
// Store with roles, vault and journal in a temp dir) and a fake sensor link.
#pragma once

#include <arpa/inet.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iostream>
#include <mutex>
#include <set>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include "console.hpp"
#include "util.hpp"

using namespace wisp;
namespace fs = std::filesystem;

// ---- tiny harness ------------------------------------------------------------

struct TestCase {
	const char *name;
	std::function<void()> fn;
};
inline std::vector<TestCase> &registry() {
	static std::vector<TestCase> r;
	return r;
}
struct Reg {
	Reg(const char *n, std::function<void()> f) { registry().push_back({n, std::move(f)}); }
};
#define TEST(name)                              \
	static void test_##name();                  \
	static Reg reg_##name(#name, test_##name);  \
	static void test_##name()

inline int failures;
inline const char *current;
#define CHECK(cond)                                                                                     \
	do {                                                                                                \
		if (!(cond)) {                                                                                  \
			fprintf(stderr, "  FAIL %s (%s:%d): %s\n", current, __FILE__, __LINE__, #cond);             \
			failures++;                                                                                 \
		}                                                                                               \
	} while (0)
#define CHECK_EQ(a, b)                                                                                                \
	do {                                                                                                              \
		auto _va = (a);                                                                                               \
		auto _vb = (b);                                                                                               \
		if (!(_va == _vb)) {                                                                                          \
			std::cerr << "  FAIL " << current << " (" << __FILE__ << ":" << __LINE__ << "): " #a " == " #b "\n    got " \
			          << _va << " vs " << _vb << "\n";                                                            \
			failures++;                                                                                               \
		}                                                                                                             \
	} while (0)

// ---- fixtures ------------------------------------------------------------------

inline const std::string TOK_VIEWER = "viewer-token-0123456789";
inline const std::string TOK_DEPLOYER = "deployer-token-0123456789";
inline const std::string TOK_OPERATOR = "operator-token-0123456789";
inline const std::string TOK_ADMIN = "admin-token-0123456789";

struct TempDir {
	std::string path;
	TempDir() {
		char t[] = "/tmp/wisp-test-XXXXXX";
		path = mkdtemp(t);
	}
	~TempDir() { fs::remove_all(path); }
};

inline std::string hexsha(const std::string &s) {
	auto d = sha256(s);
	return hex_encode(d.data(), d.size());
}

struct Env {
	TempDir dir;
	Store st;
	Env() {
		st.vulndb = VulnDB::load("");
		std::string roles = dir.path + "/roles.conf";
		std::string body = "# test roles\nsha256:" + hexsha(TOK_VIEWER) + " viewer vic\n" + TOK_DEPLOYER +
		                   " deployer dee\n" + TOK_OPERATOR + " operator Olive Ortega\n" + TOK_ADMIN + " admin ada\n";
		std::string err;
		write_file_atomic(roles, body, 0600, &err);
		st.rbac = RBAC::load(roles);
		st.vault = Vault::open(dir.path + "/vault.json");
		st.open_journal(dir.path + "/events.jsonl");
		st.ready = true;
	}
	~Env() { st.close_journal(); }

	Response req(const std::string &method, const std::string &target, const std::string &tok = "",
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
		handle(st, r, resp);
		return resp;
	}
	void send(const json &e) { st.ingest(event_from_json(e), sanitize(e.dump())); }
};

// A fake sensor connection that records what was pushed to it.
struct FakeLink : SensorLink {
	std::mutex mu;
	std::vector<std::string> sent;
	std::atomic<bool> down{false};
	bool send(const std::string &line) override {
		std::lock_guard g(mu);
		if (down)
			return false;
		sent.push_back(line);
		return true;
	}
	void shutdown() override { down = true; }
};

inline json body_json(const Response &r) { return json::parse(r.body); }
