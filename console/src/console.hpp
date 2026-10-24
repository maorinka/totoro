// The console application: configuration, the HTTP surface and run().
#pragma once

#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <ostream>
#include <set>
#include <string>

#include "ai.hpp"
#include "analysis.hpp"
#include "http.hpp"
#include "store.hpp"

namespace wisp {

struct Config {
	std::string ingest_addr, http_addr, cert, key, client_ca, http_cert, http_key;
	std::string state_dir, vulndb, roles, vault, journal, slack, gen_token;
	bool listen_set = false;  // -listen given explicitly (else -dev plaintext ingest binds loopback)
	int journal_max_mb = 256;  // 0: never rotate
	int max_sensors = 16384;   // concurrent ingest connections (one thread each)
	int max_hosts = 100000;    // hosts not retired, in all
	int max_hosts_per_cert = 0;  // ...per sensor client certificate (0: no bound; shared fleet certificates)
	bool http_proxy_local = false;  // loopback HTTP clients share the per-client cap with no one (a local proxy)
	std::chrono::nanoseconds stale_after{}, decom_after{};
	bool dev = false, show_version = false;
	// analysis and the optional AI assistant
	std::chrono::nanoseconds analysis_interval{};
	bool ai = true, ai_fallback = true;
	std::string ai_key_file, ai_model, ai_effort, ai_url, ai_ca;
	int ai_max_per_hour = 60;
	std::string in_state(const std::string &p) const;  // relative paths resolve under state_dir
};

Config parse_flags(int argc, char **argv);  // exits on -h or bad flags, like Go's flag package
// The same without exiting: -1 when c is ready, else the exit status (0 after
// -h, 2 for a bad flag or value) with the message written to out or err.
int parse_flags(int argc, char **argv, Config &c, std::ostream &out, std::ostream &err);
int run(const Config &c);

// What the HTTP surface serves. The analyst and assistant are optional, so
// tests can exercise the core API on a bare Store.
struct App {
	Store &store;
	Analyst *analyst = nullptr;
	Assistant *ai = nullptr;
	std::string ai_off = "disabled with -ai=false";  // why ai is null (GET /api/ai/status)
};

// The whole HTTP surface (routing, auth, security headers, access log). Pure:
// no sockets, so tests can call it directly.
void handle(App &app, const Request &req, Response &resp);
void handle(Store &st, const Request &req, Response &resp);
// HttpServer::precheck: runs before a request body is read. Anything but an
// authenticated API request is answered from its headers alone (false), so
// unauthenticated clients can never make the console buffer a body.
bool precheck(App &app, const Request &req, Response &resp);
// -ai-key-file: the key, or false with why (the console then runs without
// the assistant, reporting why in GET /api/ai/status).
bool read_ai_key_file(const std::string &path, std::string *key, std::string *why);

// The sensor ingest server: one thread per connection, bounded twice: at most
// max_conns connections, and at most max_unbound of them not yet bound by a
// hello (still in the TLS handshake, or connected without speaking), since
// those need no certificate to open. A connection must send its hello within
// hello_wait. Thread-creation failures refuse the connection and keep
// serving. Failed TLS handshakes are logged with the peer and the reason
// (rate-limited per source).
class IngestServer {
public:
	IngestServer(Store &st, SSL_CTX *tls, int max_conns) : st_(st), tls_(tls), max_conns_(max_conns) {}
	// Accepts until the listener is closed (true) or fails (false, logged).
	bool serve(Listener &ln);
	// Wakes every connection (handshaking, pre-hello and superseded ones
	// included); connections accepted afterwards are shut down at once.
	void shutdown_all();
	int active() const { return total_; }
	int max_unbound = 512;
	std::chrono::milliseconds hello_wait{std::chrono::seconds(30)};

private:
	void connection(int fd);
	bool log_allow(const std::string &key);
	std::string suppressed_note();
	void refuse(const std::string &why);  // accept thread only
	Store &st_;
	SSL_CTX *tls_;
	int max_conns_;
	std::atomic<int> total_{0}, unbound_{0};
	std::mutex mu_;
	std::set<Stream *> live_;
	bool stopping_ = false;  // under mu_
	std::mutex log_mu_;
	std::map<std::string, std::chrono::steady_clock::time_point> log_last_;
	unsigned long long suppressed_ = 0;
	std::chrono::steady_clock::time_point shed_logged_{};
	unsigned long long shed_ = 0;
};

// Slack text for one alert: every sensor-supplied field is escaped for Slack
// mrkdwn (&, <, > as entities, so <!channel> or <url|label> stay literal;
// backticks and control characters neutralised) and length-capped.
std::string slack_alert_text(const Event &e);

}  // namespace wisp
