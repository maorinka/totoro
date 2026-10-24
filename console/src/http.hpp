// A small HTTP/1.1 server: one thread per connection, keep-alive, strict
// limits (64 KiB of headers, 1 MiB bodies) and timeouts modelled on Go
// net/http's: the first request's headers must arrive within 10 s of the
// connection (after the TLS handshake), later ones within 5 s of their first
// byte; 30 s to read a body, 60 s to write a response, 120 s idle between
// requests. Content-Length bodies only. Parsing is strict (RFC 9112): bare
// CR or LF, obs-fold, whitespace before a colon, a missing or repeated Host,
// and a Content-Length that is not plain digits are refused with 400, so a
// front proxy and this server can never disagree about where a request ends.
// Errors the server writes itself carry a JSON {"error": "..."} body (none
// for HEAD) and the same security headers as every other response. A path
// with an encoded '/' (%2F) is refused: routes match the decoded path, which
// must not join segments the client sent as one.
#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "net.hpp"
#include "store.hpp"

namespace wisp {

struct Request {
	std::string method, path, raw_query;
	Query query;
	std::map<std::string, std::string> headers;  // lowercase names
	std::string body;
	bool tls = false;
	std::string header(const std::string &lower_name) const {
		auto it = headers.find(lower_name);
		return it == headers.end() ? "" : it->second;
	}
};

struct Response {
	int status = 200;
	std::vector<std::pair<std::string, std::string>> headers;
	std::string body;
	void set(const std::string &name, const std::string &value);
	std::string get(const std::string &name) const;
};

using Handler = std::function<void(const Request &, Response &)>;
// Runs once the headers are parsed and before a request body is read (the
// request's body is still empty). Returning false sends the response it
// filled and closes the connection without reading the body, so an
// unauthenticated client cannot make the server buffer it.
using Precheck = std::function<bool(const Request &, Response &)>;

// Percent-decoding with '+' as space; parses a query string into a Query.
std::string url_decode(const std::string &s, bool plus_as_space);
// The headers every response carries, the server's own errors included:
// CSP, nosniff, framing, referrer and opener policies, and HSTS over TLS.
void security_headers(Response &r, bool tls);
Query parse_query(const std::string &q);
const char *status_text(int code);

class HttpServer {
public:
	HttpServer(Handler h, SSL_CTX *tls) : handler_(std::move(h)), tls_(tls) {}
	// Accepts until the listener is closed (or fails), then waits up to
	// `drain` for in-flight requests to finish. Connections still open after
	// that keep running until abort_connections().
	void serve(Listener &ln, std::chrono::milliseconds drain);
	// Shuts down every open connection's socket (wakes blocked reads and
	// writes), then waits up to `wait` for their threads to finish. Returns
	// the number still running.
	int abort_connections(std::chrono::milliseconds wait);
	int active() const { return active_; }
	std::atomic<bool> stopping{false};
	static constexpr int max_conns = 1024;
	// Per client address (IPv6: per /64), so one client -- or a handful --
	// cannot take every slot: it takes at least 16 sources to fill the server.
	int max_conns_per_source = max_conns / 16;
	// Loopback clients are limited like any other unless this is set (a
	// reverse proxy on this machine, whose connections carry every user).
	// X-Forwarded-For is never trusted.
	bool exempt_loopback = false;
	// From the end of the TLS handshake to the end of the first request's headers.
	std::atomic<std::chrono::milliseconds> first_request{std::chrono::seconds(10)};
	Precheck precheck;  // optional; set before serve()

private:
	void connection(int fd);
	Handler handler_;
	SSL_CTX *tls_;
	std::atomic<int> active_{0};
	std::mutex mu_;
	std::set<Stream *> live_;  // every connection's stream, for abort_connections()
	bool aborted_ = false;     // under mu_: connections opened from now on are shut down at once
	std::map<std::string, int> per_source_;  // under mu_
	std::chrono::steady_clock::time_point shed_logged_{};
	unsigned long long shed_ = 0;
};

}  // namespace wisp
