#include "http.hpp"

#include <arpa/inet.h>
#include <cctype>
#include <cstring>
#include <ctime>
#include <netinet/in.h>
#include <sys/socket.h>
#include <system_error>
#include <thread>
#include <unistd.h>

#include "util.hpp"

namespace wisp {

using namespace std::chrono;

void Response::set(const std::string &name, const std::string &value) {
	for (auto &[k, v] : headers)
		if (strcasecmp(k.c_str(), name.c_str()) == 0) {
			v = value;
			return;
		}
	headers.emplace_back(name, value);
}

std::string Response::get(const std::string &name) const {
	for (auto &[k, v] : headers)
		if (strcasecmp(k.c_str(), name.c_str()) == 0)
			return v;
	return "";
}

std::string url_decode(const std::string &s, bool plus_as_space) {
	std::string out;
	out.reserve(s.size());
	for (size_t i = 0; i < s.size(); i++) {
		char c = s[i];
		if (c == '+' && plus_as_space) {
			out += ' ';
		} else if (c == '%' && i + 2 < s.size() && isxdigit((unsigned char)s[i + 1]) &&
		           isxdigit((unsigned char)s[i + 2])) {
			auto hv = [](char x) { return isdigit((unsigned char)x) ? x - '0' : (tolower((unsigned char)x) - 'a' + 10); };
			out += (char)(hv(s[i + 1]) << 4 | hv(s[i + 2]));
			i += 2;
		} else {
			out += c;
		}
	}
	return out;
}

Query parse_query(const std::string &q) {
	Query out;
	size_t a = 0;
	while (a <= q.size()) {
		size_t b = q.find('&', a);
		if (b == std::string::npos)
			b = q.size();
		std::string kv = q.substr(a, b - a);
		if (!kv.empty()) {
			auto eq = kv.find('=');
			std::string k = url_decode(kv.substr(0, eq), true);
			std::string v = eq == std::string::npos ? "" : url_decode(kv.substr(eq + 1), true);
			out[k].push_back(v);
		}
		a = b + 1;
	}
	return out;
}

const char *status_text(int code) {
	switch (code) {
	case 100: return "Continue";
	case 200: return "OK";
	case 201: return "Created";
	case 202: return "Accepted";
	case 204: return "No Content";
	case 301: return "Moved Permanently";
	case 302: return "Found";
	case 304: return "Not Modified";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 408: return "Request Timeout";
	case 409: return "Conflict";
	case 411: return "Length Required";
	case 413: return "Request Entity Too Large";
	case 415: return "Unsupported Media Type";
	case 417: return "Expectation Failed";
	case 429: return "Too Many Requests";
	case 431: return "Request Header Fields Too Large";
	case 500: return "Internal Server Error";
	case 501: return "Not Implemented";
	case 502: return "Bad Gateway";
	case 503: return "Service Unavailable";
	case 504: return "Gateway Timeout";
	}
	if (code >= 200 && code < 300) return "Success";
	if (code >= 300 && code < 400) return "Redirection";
	if (code >= 400 && code < 500) return "Client Error";
	return "Server Error";
}

static std::string http_date() {
	time_t t = time(nullptr);
	struct tm tm;
	gmtime_r(&t, &tm);
	char b[64];
	strftime(b, sizeof b, "%a, %d %b %Y %H:%M:%S GMT", &tm);
	return b;
}

static constexpr size_t MAX_HEADER = 64 << 10, MAX_BODY = 1 << 20;
static constexpr auto HEADER_READ = seconds(5), BODY_READ = seconds(30), WRITE = seconds(60), IDLE = seconds(120);

// RFC 9110 5.6.2 tchar.
static bool tchar(unsigned char c) { return c && (isalnum(c) || strchr("!#$%&'*+-.^_`|~", c) != nullptr); }

static bool token(const std::string &s) {
	if (s.empty())
		return false;
	for (unsigned char c : s)
		if (!tchar(c))
			return false;
	return true;
}

// Optional whitespace is SP and HTAB only.
static std::string ows_trim(const std::string &s) {
	size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t");
	return a == std::string::npos ? std::string() : s.substr(a, b - a + 1);
}

// Connection: a comma-separated list of case-insensitive tokens.
static bool has_token(const std::string &list, const char *want) {
	size_t a = 0;
	while (a <= list.size()) {
		size_t b = list.find(',', a);
		if (b == std::string::npos)
			b = list.size();
		if (strcasecmp(ows_trim(list.substr(a, b - a)).c_str(), want) == 0)
			return true;
		a = b + 1;
	}
	return false;
}

void security_headers(Response &r, bool tls) {
	r.set("Content-Security-Policy",
	      "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
	      "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
	r.set("X-Content-Type-Options", "nosniff");
	r.set("X-Frame-Options", "DENY");
	r.set("Referrer-Policy", "no-referrer");
	r.set("Cross-Origin-Opener-Policy", "same-origin");
	if (tls)
		r.set("Strict-Transport-Security", "max-age=31536000");
}

// The status line, headers and (unless HEAD) body of a response.
static std::string serialize(Response &resp, bool head) {
	std::string out = "HTTP/1.1 " + std::to_string(resp.status) + " " + status_text(resp.status) + "\r\n";
	if (resp.get("Content-Type").empty() && !resp.body.empty())
		resp.set("Content-Type", "text/plain; charset=utf-8");
	resp.set("Date", http_date());
	resp.set("Content-Length", std::to_string(resp.body.size()));
	for (auto &[k, v] : resp.headers)
		out += k + ": " + v + "\r\n";
	out += "\r\n";
	if (!head)
		out += resp.body;
	return out;
}

// An error the server answers itself: JSON, like the API's own errors, with
// the security headers every response carries.
static Response error_body(int code, const std::string &msg, bool tls) {
	Response r;
	r.status = code;
	security_headers(r, tls);
	r.set("Content-Type", "application/json");
	r.set("Cache-Control", "no-store");
	r.body = json{{"error", msg}}.dump(-1, ' ', false, json::error_handler_t::replace) + "\n";
	return r;
}

static std::string error_response(int code, const std::string &msg, bool tls, bool head) {
	Response r = error_body(code, msg, tls);
	r.set("Connection", "close");
	return serialize(r, head);
}

// The client's address for per-source limits: IPv4 address, or the /64 of
// an IPv6 one; "lo" for loopback; "" when unknown.
static std::string source_key(int fd) {
	struct sockaddr_storage ss {};
	socklen_t len = sizeof ss;
	if (getpeername(fd, reinterpret_cast<struct sockaddr *>(&ss), &len) != 0)
		return "";
	const unsigned char *b = nullptr;
	if (ss.ss_family == AF_INET) {
		b = reinterpret_cast<const unsigned char *>(&reinterpret_cast<struct sockaddr_in *>(&ss)->sin_addr);
	} else if (ss.ss_family == AF_INET6) {
		auto *a6 = &reinterpret_cast<struct sockaddr_in6 *>(&ss)->sin6_addr;
		const unsigned char *x = a6->s6_addr;
		if (IN6_IS_ADDR_LOOPBACK(a6))
			return "lo";
		if (!IN6_IS_ADDR_V4MAPPED(a6))
			return hex_encode(x, 8);  // the /64
		b = x + 12;
	} else {
		return "";
	}
	if (b[0] == 127)
		return "lo";
	return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." + std::to_string(b[2]) + "." + std::to_string(b[3]);
}

void HttpServer::serve(Listener &ln, milliseconds drain) {
	auto shed = [this](const char *why) {  // rate-limited: at most one line per 10 s
		shed_++;
		auto now = steady_clock::now();
		if (shed_logged_ == steady_clock::time_point{} || now - shed_logged_ > seconds(10)) {
			logf("http: refusing connections: %s (%llu refused since the last report)", why, shed_);
			shed_ = 0;
			shed_logged_ = now;
		}
	};
	for (;;) {
		int fd = ln.accept_fd();
		if (fd < 0)
			break;
		if (active_ >= max_conns) {  // shed load rather than exhaust threads
			::close(fd);
			shed("connection limit reached");
			continue;
		}
		std::string src = source_key(fd);
		if (src == "lo" && exempt_loopback)
			src.clear();
		if (!src.empty()) {
			std::lock_guard g(mu_);
			int &n = per_source_[src];
			if (n >= max_conns_per_source) {
				::close(fd);
				shed(("per-client limit reached for " + src).c_str());
				continue;
			}
			n++;
		}
		auto release = [this](const std::string &key) {
			if (key.empty())
				return;
			std::lock_guard g(mu_);
			if (auto it = per_source_.find(key); it != per_source_.end() && --it->second <= 0)
				per_source_.erase(it);
		};
		active_++;
		try {
			std::thread([this, fd, src, release] {
				try {
					connection(fd);
				} catch (const std::exception &e) {
					logf("http: connection error: %s", e.what());
				}
				release(src);
				active_--;
			}).detach();
		} catch (const std::exception &e) {
			// No thread (task limit, memory): refuse this one, keep serving.
			release(src);
			active_--;
			::close(fd);
			shed((std::string("cannot start a connection thread: ") + e.what()).c_str());
			std::this_thread::sleep_for(milliseconds(50));
		}
	}
	stopping = true;
	auto end = steady_clock::now() + drain;
	while (active_ > 0 && steady_clock::now() < end)
		std::this_thread::sleep_for(milliseconds(20));
}

int HttpServer::abort_connections(milliseconds wait) {
	stopping = true;
	{
		std::lock_guard g(mu_);
		aborted_ = true;
		for (auto *s : live_)
			s->shutdown();
	}
	auto end = steady_clock::now() + wait;
	while (active_ > 0 && steady_clock::now() < end)
		std::this_thread::sleep_for(milliseconds(20));
	return active_;
}

void HttpServer::connection(int fd) {
	Stream s(fd, tls_);
	struct Track {  // registered for abort_connections() while the stream exists
		HttpServer &srv;
		Stream &s;
		Track(HttpServer &v, Stream &st) : srv(v), s(st) {
			std::lock_guard g(srv.mu_);
			srv.live_.insert(&s);
			if (srv.aborted_)
				s.shutdown();
		}
		~Track() {
			std::lock_guard g(srv.mu_);
			srv.live_.erase(&s);
		}
	} track{*this, s};
	struct Linger {  // on every exit path
		Stream &s;
		~Linger() { s.close_gracefully(after(milliseconds(500))); }
	} linger{s};
	if (!s.handshake(after(seconds(10))))
		return;
	bool head_req = false;  // the request being answered is a HEAD (known once its request line is parsed)
	auto fail = [&](int code, const std::string &msg) {
		s.write_all(error_response(code, msg, s.tls(), head_req), after(seconds(5)));
	};
	std::string buf;
	char chunk[16384];
	bool first = true;
	for (;;) {
		// The first request must arrive soon after the connection opens; later
		// ones may wait (idle) between requests, then their headers must follow
		// their first byte quickly. Bytes left over from a pipelined request
		// start that header clock now.
		Deadline idle_until = after(IDLE);
		Deadline hdr_until = first ? after(first_request.load()) : !buf.empty() ? after(HEADER_READ) : Deadline::max();
		size_t hdr_end, checked = 0;  // checked: bytes of buf already scanned
		for (;;) {
			// RFC 9112 2.2: ignore empty lines before a request line.
			size_t skip = 0;
			while (buf.compare(skip, 2, "\r\n") == 0)
				skip += 2;
			if (skip) {
				buf.erase(0, skip);
				checked = 0;
			}
			hdr_end = buf.find("\r\n\r\n", checked >= 3 ? checked - 3 : 0);
			// Bare CR or LF in the header section: reject rather than guess
			// where lines end (a proxy might guess differently). Incremental,
			// so a client trickling bytes costs linear time.
			size_t scan = hdr_end == std::string::npos ? buf.size() : hdr_end;
			for (size_t i = checked; i < scan; i++) {
				if ((buf[i] == '\n' && (i == 0 || buf[i - 1] != '\r')) ||
				    (buf[i] == '\r' && i + 1 < buf.size() && buf[i + 1] != '\n'))
					return fail(400, "malformed request: bare CR or LF");
			}
			checked = scan > 0 && buf[scan - 1] == '\r' ? scan - 1 : scan;  // a trailing CR needs its next byte
			if (hdr_end != std::string::npos)
				break;
			if (buf.size() > MAX_HEADER)
				return fail(431, "request headers too large");
			if (stopping && buf.empty())
				return;
			bool waiting = buf.empty() && !first;  // idle between requests
			Deadline limit = waiting ? idle_until : hdr_until;
			long n = s.read_some(chunk, sizeof chunk, std::min(limit, after(milliseconds(1000))));
			if (n > 0) {
				if (waiting)
					hdr_until = after(HEADER_READ);
				buf.append(chunk, (size_t)n);
				continue;
			}
			if (n == -2 && steady_clock::now() < limit && !(stopping && buf.empty()))
				continue;  // a 1 s slice elapsed: re-check for shutdown
			return;        // EOF, error, or a timeout
		}
		first = false;
		if (hdr_end > MAX_HEADER)  // the final read can complete an oversized header
			return fail(431, "request headers too large");
		std::string head = buf.substr(0, hdr_end);
		buf.erase(0, hdr_end + 4);
		auto req_deadline = after(BODY_READ);

		Request req;
		req.tls = s.tls();
		head_req = false;
		size_t le = head.find("\r\n");
		std::string line = head.substr(0, le);
		auto sp1 = line.find(' '), sp2 = line.rfind(' ');
		if (sp1 == std::string::npos || sp2 == sp1 || line.find(' ', sp1 + 1) != sp2)
			return fail(400, "malformed request line");
		req.method = line.substr(0, sp1);
		head_req = req.method == "HEAD";
		std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1), proto = line.substr(sp2 + 1);
		if (proto != "HTTP/1.1" && proto != "HTTP/1.0")
			return fail(400, "unsupported protocol version");
		if (!token(req.method))
			return fail(400, "malformed request method");
		for (unsigned char c : target)
			if (c <= 0x20 || c == 0x7f)
				return fail(400, "malformed request target");
		if (target.rfind("http://", 0) == 0 || target.rfind("https://", 0) == 0) {  // absolute-form
			size_t slash = target.find('/', target.find("//") + 2);
			target = slash == std::string::npos ? "/" : target.substr(slash);
		}
		if (target.empty() || (target[0] != '/' && !(target == "*" && req.method == "OPTIONS")))
			return fail(400, "malformed request target");
		auto qm = target.find('?');
		std::string raw_path = target.substr(0, qm);
		// Routes match the decoded path: an encoded '/' would let /api%2Fvault
		// reach /api/vault past anything in front that matches the raw path.
		for (size_t i = 0; i + 2 < raw_path.size(); i++)
			if (raw_path[i] == '%' && raw_path[i + 1] == '2' && (raw_path[i + 2] == 'f' || raw_path[i + 2] == 'F'))
				return fail(400, "malformed request path: encoded '/'");
		req.path = url_decode(raw_path, false);
		for (unsigned char c : req.path)  // %00, %0a ...: never a route, never into a log line
			if (c < 0x20 || c == 0x7f)
				return fail(400, "malformed request path");
		if (qm != std::string::npos) {
			req.raw_query = target.substr(qm + 1);
			req.query = parse_query(req.raw_query);
		}
		int hosts = 0;
		size_t pos = le == std::string::npos ? head.size() : le + 2;
		while (pos < head.size()) {
			size_t e = head.find("\r\n", pos);
			if (e == std::string::npos)
				e = head.size();
			std::string h = head.substr(pos, e - pos);
			pos = e + 2;
			if (h[0] == ' ' || h[0] == '\t')
				return fail(400, "obsolete header line folding is not supported");
			auto c = h.find(':');
			if (c == std::string::npos)
				return fail(400, "malformed header line");
			std::string name = h.substr(0, c);
			if (!token(name))  // also catches whitespace before the colon
				return fail(400, "malformed header name");
			std::string value = ows_trim(h.substr(c + 1));
			for (unsigned char ch : value)
				if ((ch < 0x20 && ch != '\t') || ch == 0x7f)
					return fail(400, "control character in a header value");
			name = to_lower(name);
			if (name == "host")
				hosts++;
			// One Content-Length line only. Joining a repeat with ", " would let
			// an empty first value drop out ("" then "5" reads as 5), so a proxy
			// that honours the first line and this server could disagree about
			// where the body ends.
			if (name == "content-length" && req.headers.count(name))
				return fail(400, "repeated Content-Length");
			auto &slot = req.headers[name];
			slot = slot.empty() ? value : slot + ", " + value;
		}
		if (proto == "HTTP/1.1" ? hosts != 1 : hosts > 1)
			return fail(400, hosts ? "more than one Host header" : "missing Host header");
		std::string conn = req.header("connection");
		bool keep_alive = proto == "HTTP/1.1" ? !has_token(conn, "close")
		                                      : has_token(conn, "keep-alive") && !has_token(conn, "close");
		if (req.headers.count("transfer-encoding"))
			return fail(501, "Transfer-Encoding is not supported; send a Content-Length");
		size_t clen = 0;
		if (req.headers.count("content-length")) {
			const std::string cl = req.header("content-length");
			if (cl.empty() || cl.find_first_not_of("0123456789") != std::string::npos)
				return fail(400, "malformed Content-Length");
			unsigned long long v = 0;
			for (char ch : cl) {
				v = v * 10 + (unsigned long long)(ch - '0');
				if (v > MAX_BODY)
					break;
			}
			if (v > MAX_BODY)
				return fail(413, "request body too large");
			clen = (size_t)v;
		}
		bool expect_continue = false;
		if (req.headers.count("expect")) {
			if (strcasecmp(req.header("expect").c_str(), "100-continue") != 0)
				return fail(417, "unsupported expectation");
			expect_continue = proto == "HTTP/1.1";
		}

		Response resp;
		bool body_pending = clen > buf.size();
		if (clen > 0 && precheck && !precheck(req, resp)) {
			keep_alive = false;  // the body was never read: the connection cannot be reused
		} else {
			if (expect_continue && body_pending &&
			    !s.write_all("HTTP/1.1 100 Continue\r\n\r\n", after(seconds(5))))
				return;
			while (buf.size() < clen) {
				long n = s.read_some(chunk, sizeof chunk, req_deadline);
				if (n <= 0)
					return;
				buf.append(chunk, (size_t)n);
			}
			req.body = buf.substr(0, clen);
			buf.erase(0, clen);
			try {
				handler_(req, resp);
			} catch (const std::exception &e) {
				logf("http: %s %s: handler error: %s", req.method.c_str(), req.path.c_str(), e.what());
				resp = error_body(500, "internal error", req.tls);
				keep_alive = false;
			}
		}

		if (stopping)
			keep_alive = false;
		if (!keep_alive)
			resp.set("Connection", "close");
		else if (proto == "HTTP/1.0")
			resp.set("Connection", "keep-alive");
		std::string out = serialize(resp, head_req);
		if (!s.write_all(out, after(WRITE)) || !keep_alive)
			return;
	}
}

}  // namespace wisp
