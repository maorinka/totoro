// Sockets and TLS (OpenSSL): listeners, deadline-bounded streams, and a small
// HTTPS client for webhooks and the AI
// assistant.
//
// OpenSSL does not allow one SSL object to be used from two threads at once,
// but the console reads a sensor connection on one thread while pushes write
// to it from others. Stream therefore keeps the socket non-blocking and holds
// a mutex only around each individual SSL call, waiting in poll() unlocked.
#pragma once

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <openssl/ssl.h>
#include <string>
#include <utility>
#include <vector>

namespace wisp {

using Deadline = std::chrono::steady_clock::time_point;
inline Deadline after(std::chrono::milliseconds d) { return std::chrono::steady_clock::now() + d; }

struct SSLCtxFree {
	void operator()(SSL_CTX *c) const { SSL_CTX_free(c); }
};
using SSLCtxPtr = std::unique_ptr<SSL_CTX, SSLCtxFree>;

// Server context: certificate + key; when client_ca is set, clients must
// present a certificate it signed (mutual TLS). Throws on error.
SSLCtxPtr make_server_ctx(const std::string &cert, const std::string &key, const std::string &client_ca);

// "ip:port" ("[v6]:port") of a connected socket's peer, or "unknown".
std::string peer_address(int fd);

class Stream {
public:
	// Takes ownership of fd (closed even when the constructor throws).
	Stream(int fd, SSL_CTX *ctx);  // ctx == nullptr: plaintext
	~Stream();
	Stream(const Stream &) = delete;
	Stream &operator=(const Stream &) = delete;

	// Server-side TLS accept (no-op if plaintext). On failure *why, when
	// given, says why: a timeout, the peer closing, or the TLS/verify error.
	bool handshake(Deadline dl, std::string *why = nullptr);
	// >0 bytes read, 0 = EOF, -1 = error or shutdown, -2 = deadline passed
	long read_some(char *buf, size_t n, Deadline dl);
	// All of data, or false. A failed or timed-out write leaves part of the
	// data (or, with TLS, a half-sent record that OpenSSL would flush in
	// place of the next write's bytes) on the connection, so the stream is
	// shut down: nothing written after a failure can be misattributed.
	bool write_all(const std::string &data, Deadline dl);
	void shutdown();  // thread-safe: wakes any blocked reader/writer; the stream is then dead
	bool dead() const { return dead_; }
	// Lingering close: stop sending, then discard what the peer is still sending
	// (until EOF or the deadline), so closing never turns unread input into a
	// TCP reset that destroys the response we just wrote.
	void close_gracefully(Deadline dl);
	bool tls() const { return ssl_ != nullptr; }
	int fd() const { return fd_; }
	// After a successful handshake: the client certificate's SHA-256 (hex) and
	// subject ("CN=...", then its DNS/IP SANs, comma-separated). False when
	// the peer presented none (or the stream is plaintext).
	bool peer_cert(std::string *fingerprint, std::string *subject);

private:
	int wait(short events, Deadline dl);  // 1 ready, 0 deadline passed, -1 error/shutdown
	int fd_;
	SSL *ssl_ = nullptr;
	std::mutex mu_;  // guards ssl_ calls
	std::atomic<bool> dead_{false};
};

class Listener {
public:
	// "host:port", ":port" (all interfaces, IPv4 and IPv6), "[v6]:port". Throws.
	explicit Listener(const std::string &addr);
	~Listener();
	// The next connection. Transient errors (out of descriptors or memory, a
	// connection reset while queued, LSM denials) are logged (rate-limited)
	// and retried after a short back-off. -1 once closed, or on an error the
	// listening socket cannot recover from (logged; closed() is then false).
	int accept_fd();
	void close();  // thread-safe; unblocks accept_fd()
	bool closed() const { return closed_; }
	const std::string &addr() const { return addr_; }
	int port() const;  // the bound port (useful with ":0")

private:
	bool backoff(int ms);  // false when closed meanwhile
	int fd_ = -1;
	int wake_[2] = {-1, -1};
	std::atomic<bool> closed_{false};
	std::string addr_;
	std::chrono::steady_clock::time_point err_logged_{};
	unsigned long long errs_ = 0;
};

using Headers = std::vector<std::pair<std::string, std::string>>;

struct HttpsResponse {
	int status = -1;  // -1: no HTTP response (see error)
	std::map<std::string, std::string> headers;  // lowercased names
	std::string body;
	std::string error;
};

// One HTTPS request with a verified certificate and hostname (the system trust
// store, or ca_file when given). Honours HTTPS_PROXY / NO_PROXY with an HTTP
// CONNECT tunnel. Content-Length, chunked and close-delimited bodies (at most
// 16 MiB); interim 1xx responses are skipped. Each resolved address gets its
// share of the timeout, so a black-holed first address (broken IPv6) still
// leaves time for the next. The method, URL and headers must not contain
// control characters (refused, so a value can never add a header).
// `cancel`, when given, aborts the request within ~0.5 s of being set (used
// on console shutdown; the result then carries status -1 and an error).
HttpsResponse https_request(const std::string &method, const std::string &url, const Headers &headers,
                            const std::string &body, std::chrono::milliseconds timeout, const std::string &ca_file,
                            const std::atomic<bool> *cancel = nullptr);

// Pieces of the client's response parsing, exposed for tests.
// "HTTP/1.x NNN[ reason]" -> status; false when malformed.
bool parse_status_line(const std::string &line, int *status);
// Incremental chunked-transfer decoder. feed() consumes in[pos..] as far as it
// can (call it again after appending more input); BAD for malformed framing
// or when the decoded body would exceed max_out.
struct Dechunker {
	enum State { SIZE, DATA, DATA_END, TRAILER, DONE, BAD } st = SIZE;
	size_t pos = 0;  // next unread byte of the input
	size_t left = 0, trailer_bytes = 0;
	std::string out;  // decoded body so far
	State feed(const std::string &in, size_t max_out);
};

// POST a body over HTTPS (certificate and hostname verified against the system
// trust store). Returns the HTTP status, or -1 with *err set.
int https_post(const std::string &url, const std::string &content_type, const std::string &body,
               std::chrono::milliseconds timeout, std::string *err);

}  // namespace wisp
