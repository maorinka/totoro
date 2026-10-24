#include "net.hpp"

#include "http.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

namespace wisp {

using namespace std::chrono;

static std::string ssl_err() {
	unsigned long e = ERR_get_error();
	char buf[256];
	ERR_error_string_n(e, buf, sizeof buf);
	return e ? buf : "unknown TLS error";
}

SSLCtxPtr make_server_ctx(const std::string &cert, const std::string &key, const std::string &client_ca) {
	SSLCtxPtr ctx(SSL_CTX_new(TLS_server_method()));
	if (!ctx)
		throw std::runtime_error("TLS: " + ssl_err());
	SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
	SSL_CTX_set_mode(ctx.get(), SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	if (SSL_CTX_use_certificate_chain_file(ctx.get(), cert.c_str()) != 1)
		throw std::runtime_error("TLS certificate " + cert + ": " + ssl_err());
	if (SSL_CTX_use_PrivateKey_file(ctx.get(), key.c_str(), SSL_FILETYPE_PEM) != 1)
		throw std::runtime_error("TLS key " + key + ": " + ssl_err());
	if (SSL_CTX_check_private_key(ctx.get()) != 1)
		throw std::runtime_error("TLS key " + key + " does not match certificate " + cert);
	if (!client_ca.empty()) {
		if (SSL_CTX_load_verify_locations(ctx.get(), client_ca.c_str(), nullptr) != 1)
			throw std::runtime_error("client-ca " + client_ca + ": " + ssl_err());
		STACK_OF(X509_NAME) *names = SSL_load_client_CA_file(client_ca.c_str());
		if (!names)
			throw std::runtime_error("client-ca " + client_ca + ": no certificates found");
		SSL_CTX_set_client_CA_list(ctx.get(), names);
		SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
	}
	// With peer verification on, OpenSSL refuses to resume a session (cache or
	// ticket) unless a session ID context is set: the client would get a fatal
	// internal_error instead of a full handshake. Sessions are bound to this
	// context's purpose, so one issued by the web listener never resumes on
	// the ingest listener.
	static const unsigned char ingest_sid[] = "wisp-ingest", web_sid[] = "wisp-web";
	if (!client_ca.empty()) {
		SSL_CTX_set_session_id_context(ctx.get(), ingest_sid, sizeof ingest_sid - 1);
		// A resumed session is not re-verified (an expired client certificate
		// included), so keep that window to minutes, not OpenSSL's 2 h default.
		SSL_CTX_set_timeout(ctx.get(), 300);
	} else {
		SSL_CTX_set_session_id_context(ctx.get(), web_sid, sizeof web_sid - 1);
	}
	return ctx;
}

std::string peer_address(int fd) {
	struct sockaddr_storage ss {};
	socklen_t len = sizeof ss;
	if (getpeername(fd, reinterpret_cast<struct sockaddr *>(&ss), &len) != 0)
		return "unknown";
	char host[INET6_ADDRSTRLEN] = "?";
	if (ss.ss_family == AF_INET) {
		auto *a = reinterpret_cast<struct sockaddr_in *>(&ss);
		inet_ntop(AF_INET, &a->sin_addr, host, sizeof host);
		return std::string(host) + ":" + std::to_string(ntohs(a->sin_port));
	}
	if (ss.ss_family == AF_INET6) {
		auto *a = reinterpret_cast<struct sockaddr_in6 *>(&ss);
		inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof host);
		return "[" + std::string(host) + "]:" + std::to_string(ntohs(a->sin6_port));
	}
	return "unknown";
}

// ---- Stream -------------------------------------------------------------------

Stream::Stream(int fd, SSL_CTX *ctx) : fd_(fd) {
	fcntl(fd_, F_SETFL, fcntl(fd_, F_GETFL) | O_NONBLOCK);
	int one = 1;
	setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
	if (ctx) {
		ssl_ = SSL_new(ctx);
		if (!ssl_ || SSL_set_fd(ssl_, fd_) != 1) {
			std::string e = ssl_err();
			if (ssl_)
				SSL_free(ssl_);
			::close(fd_);  // the destructor will not run
			throw std::runtime_error("TLS: " + e);
		}
	}
}

Stream::~Stream() {
	if (ssl_)
		SSL_free(ssl_);
	::close(fd_);
}

void Stream::shutdown() {
	dead_ = true;
	::shutdown(fd_, SHUT_RDWR);
}

void Stream::close_gracefully(Deadline dl) {
	if (dead_)
		return;
	if (ssl_) {
		std::lock_guard g(mu_);
		SSL_shutdown(ssl_);  // best effort close_notify
	}
	::shutdown(fd_, SHUT_WR);
	char buf[16384];
	size_t drained = 0;
	while (drained < (1u << 20)) {
		ssize_t r = ::read(fd_, buf, sizeof buf);
		if (r > 0) {
			drained += (size_t)r;
			continue;
		}
		if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
			return;
		if (wait(POLLIN, dl) != 1)
			return;
	}
}

bool Stream::peer_cert(std::string *fingerprint, std::string *subject) {
	if (!ssl_)
		return false;
	X509 *x = nullptr;
	{
		std::lock_guard g(mu_);
		x = SSL_get1_peer_certificate(ssl_);
	}
	if (!x)
		return false;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int n = 0;
	bool ok = X509_digest(x, EVP_sha256(), md, &n) == 1;
	if (ok) {
		static const char hexd[] = "0123456789abcdef";
		fingerprint->clear();
		for (unsigned int i = 0; i < n; i++) {
			*fingerprint += hexd[md[i] >> 4];
			*fingerprint += hexd[md[i] & 15];
		}
		std::string sub;
		char cn[256] = "";
		if (X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, cn, sizeof cn) > 0)
			sub = std::string("CN=") + cn;
		if (auto *sans = static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr))) {
			for (int i = 0; i < sk_GENERAL_NAME_num(sans); i++) {
				const GENERAL_NAME *g = sk_GENERAL_NAME_value(sans, i);
				std::string v;
				if (g->type == GEN_DNS) {
					v = "DNS:" + std::string(reinterpret_cast<const char *>(ASN1_STRING_get0_data(g->d.dNSName)),
					                         (size_t)ASN1_STRING_length(g->d.dNSName));
				} else if (g->type == GEN_IPADD) {
					char ip[INET6_ADDRSTRLEN] = "";
					int len = ASN1_STRING_length(g->d.iPAddress);
					const unsigned char *b = ASN1_STRING_get0_data(g->d.iPAddress);
					if (len == 4 || len == 16)
						inet_ntop(len == 4 ? AF_INET : AF_INET6, b, ip, sizeof ip);
					v = std::string("IP:") + ip;
				} else {
					continue;
				}
				sub += (sub.empty() ? "" : ",") + v;
			}
			GENERAL_NAMES_free(sans);
		}
		// Certificate text is the CA's, but keep it printable and bounded:
		// it reaches alerts and the journal.
		for (auto &c : sub)
			if ((unsigned char)c < 0x20 || c == 0x7f)
				c = '?';
		*subject = sub.substr(0, 512);
	}
	X509_free(x);
	return ok;
}

// Wait for the socket, in slices so a shutdown() from another thread is noticed.
int Stream::wait(short events, Deadline dl) {
	for (;;) {
		if (dead_)
			return -1;
		auto left = duration_cast<milliseconds>(dl - steady_clock::now()).count();
		if (left <= 0)
			return 0;
		struct pollfd p = {fd_, events, 0};
		int r = poll(&p, 1, (int)std::min<long long>(left, 500));
		if (r > 0)
			return 1;
		if (r < 0 && errno != EINTR)
			return -1;
	}
}

bool Stream::handshake(Deadline dl, std::string *why) {
	if (!ssl_)
		return true;
	auto fail = [&](std::string reason) {
		if (why)
			*why = std::move(reason);
		return false;
	};
	for (;;) {
		int r, e;
		std::string err;
		long verify = X509_V_OK;
		{
			std::lock_guard g(mu_);
			ERR_clear_error();
			r = SSL_accept(ssl_);
			e = r == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl_, r);
			if (e == SSL_ERROR_SSL || e == SSL_ERROR_SYSCALL) {
				verify = SSL_get_verify_result(ssl_);
				if (ERR_peek_error())
					err = ssl_err();
			}
		}
		if (r == 1)
			return true;
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
			int w = wait(e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, dl);
			if (w == 0)
				return fail("timed out");
			if (w != 1)
				return fail(dead_ ? "shut down" : "socket error");
			continue;
		}
		if (verify != X509_V_OK)
			return fail(std::string("client certificate rejected: ") + X509_verify_cert_error_string(verify));
		if (!err.empty())
			return fail(err);
		if (e == SSL_ERROR_SYSCALL || e == SSL_ERROR_ZERO_RETURN)
			return fail("connection closed by the peer");
		return fail("TLS error " + std::to_string(e));
	}
}

long Stream::read_some(char *buf, size_t n, Deadline dl) {
	for (;;) {
		if (dead_)
			return -1;
		if (!ssl_) {
			ssize_t r = ::read(fd_, buf, n);
			if (r >= 0)
				return r;
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				return -1;
			if (int w = wait(POLLIN, dl); w != 1)
				return w == 0 ? -2 : -1;
			continue;
		}
		int r, e;
		{
			std::lock_guard g(mu_);
			ERR_clear_error();
			r = SSL_read(ssl_, buf, (int)std::min<size_t>(n, 1 << 30));
			e = r > 0 ? SSL_ERROR_NONE : SSL_get_error(ssl_, r);
		}
		if (r > 0)
			return r;
		if (e == SSL_ERROR_ZERO_RETURN)
			return 0;
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
			if (int w = wait(e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, dl); w != 1)
				return w == 0 ? -2 : -1;
		} else if (e == SSL_ERROR_SYSCALL && r == 0) {
			return 0;  // peer closed without close_notify
		} else {
			return -1;
		}
	}
}

bool Stream::write_all(const std::string &data, Deadline dl) {
	// Any failure leaves the connection mid-message: never write on it again.
	auto failed = [this] {
		shutdown();
		return false;
	};
	size_t off = 0;
	while (off < data.size()) {
		if (dead_)
			return false;
		if (!ssl_) {
			ssize_t w = ::send(fd_, data.data() + off, data.size() - off, MSG_NOSIGNAL);
			if (w >= 0) {
				off += (size_t)w;
				continue;
			}
			if (errno == EINTR)
				continue;
			if ((errno != EAGAIN && errno != EWOULDBLOCK) || wait(POLLOUT, dl) != 1)
				return failed();
			continue;
		}
		int r, e;
		{
			std::lock_guard g(mu_);
			ERR_clear_error();
			r = SSL_write(ssl_, data.data() + off, (int)std::min<size_t>(data.size() - off, 1 << 30));
			e = r > 0 ? SSL_ERROR_NONE : SSL_get_error(ssl_, r);
		}
		if (r > 0) {
			off += (size_t)r;
		} else if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) {
			if (wait(e == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN, dl) != 1)
				return failed();
		} else {
			return failed();
		}
	}
	return true;
}

// ---- Listener -----------------------------------------------------------------

static void split_hostport(const std::string &addr, std::string &host, std::string &port) {
	if (!addr.empty() && addr[0] == '[') {
		auto e = addr.find(']');
		if (e == std::string::npos || e + 1 >= addr.size() || addr[e + 1] != ':')
			throw std::runtime_error("bad address " + addr);
		host = addr.substr(1, e - 1);
		port = addr.substr(e + 2);
		return;
	}
	auto c = addr.rfind(':');
	if (c == std::string::npos)
		throw std::runtime_error("bad address " + addr + " (want host:port)");
	host = addr.substr(0, c);
	port = addr.substr(c + 1);
}

Listener::Listener(const std::string &addr) : addr_(addr) {
	std::string host, port;
	split_hostport(addr, host, port);
	struct addrinfo hints {}, *res = nullptr;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	hints.ai_family = host.empty() ? AF_INET6 : AF_UNSPEC;
	int gr = getaddrinfo(host.empty() ? nullptr : host.c_str(), port.c_str(), &hints, &res);
	if (gr != 0 && host.empty()) {  // no IPv6 on this host: all IPv4 interfaces
		hints.ai_family = AF_INET;
		gr = getaddrinfo(nullptr, port.c_str(), &hints, &res);
	}
	if (gr != 0)
		throw std::runtime_error("listen " + addr + ": " + gai_strerror(gr));
	std::string last = "no usable address";
	for (auto *ai = res; ai; ai = ai->ai_next) {
		int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
		if (fd < 0)
			continue;
		int one = 1, zero = 0;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
		if (ai->ai_family == AF_INET6 && host.empty())
			setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);  // ":port" = IPv4 + IPv6
		if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, 512) == 0) {
			fd_ = fd;
			break;
		}
		last = strerror(errno);
		::close(fd);
	}
	freeaddrinfo(res);
	if (fd_ < 0)
		throw std::runtime_error("listen " + addr + ": " + last);
	if (pipe2(wake_, O_CLOEXEC | O_NONBLOCK) != 0) {
		::close(fd_);
		throw std::runtime_error("pipe: " + std::string(strerror(errno)));
	}
}

Listener::~Listener() {
	close();
	::close(fd_);
	::close(wake_[0]);
	::close(wake_[1]);
}

void Listener::close() {
	if (!closed_.exchange(true))
		(void)!write(wake_[1], "x", 1);
}

int Listener::port() const {
	struct sockaddr_storage ss {};
	socklen_t len = sizeof ss;
	if (getsockname(fd_, reinterpret_cast<struct sockaddr *>(&ss), &len) != 0)
		return -1;
	if (ss.ss_family == AF_INET)
		return ntohs(reinterpret_cast<struct sockaddr_in *>(&ss)->sin_port);
	return ntohs(reinterpret_cast<struct sockaddr_in6 *>(&ss)->sin6_port);
}

// Sleep up to ms, waking at once if the listener is closed.
bool Listener::backoff(int ms) {
	struct pollfd p = {wake_[0], POLLIN, 0};
	(void)poll(&p, 1, ms);
	return !closed_;
}

int Listener::accept_fd() {
	auto transient = [this](const char *what, int err) {
		errs_++;
		auto now = std::chrono::steady_clock::now();
		if (err_logged_ == std::chrono::steady_clock::time_point{} || now - err_logged_ > seconds(10)) {
			logf("listener %s: %s: %s (%llu error(s) since the last report); retrying", addr_.c_str(), what,
			     strerror(err), errs_);
			errs_ = 0;
			err_logged_ = now;
		}
	};
	for (;;) {
		if (closed_)
			return -1;
		struct pollfd p[2] = {{fd_, POLLIN, 0}, {wake_[0], POLLIN, 0}};
		int r = poll(p, 2, -1);
		if (r < 0) {
			int err = errno;
			if (err == EINTR)
				continue;
			if (err == ENOMEM || err == EAGAIN) {
				transient("poll", err);
				if (!backoff(100))
					return -1;
				continue;
			}
			logf("listener %s: poll: %s; no longer accepting connections", addr_.c_str(), strerror(err));
			return -1;
		}
		if (p[1].revents || closed_)
			return -1;
		if (p[0].revents & POLLNVAL) {
			logf("listener %s: listening socket is invalid; no longer accepting connections", addr_.c_str());
			return -1;
		}
		int c = accept4(fd_, nullptr, nullptr, SOCK_CLOEXEC);
		if (c >= 0)
			return c;
		int err = errno;
		if (err == EINTR || err == ECONNABORTED || err == EAGAIN || err == EWOULDBLOCK)
			continue;
		if (err == EBADF || err == EINVAL || err == ENOTSOCK || err == EOPNOTSUPP || err == EFAULT) {
			logf("listener %s: accept: %s; no longer accepting connections", addr_.c_str(), strerror(err));
			return -1;
		}
		// Out of descriptors or memory (EMFILE, ENFILE, ENOBUFS, ENOMEM), an
		// LSM denial (EPERM), or a network error passed up for a queued
		// connection (EPROTO, ENETDOWN, ...): accept(2) says to retry these.
		transient("accept", err);
		if (!backoff(err == EPROTO || err == ENETDOWN || err == ENETUNREACH || err == EHOSTUNREACH ||
		                     err == EHOSTDOWN || err == ENONET || err == ENOPROTOOPT
		                 ? 0
		                 : 100))
			return -1;
	}
}

// ---- HTTPS client -----------------------------------------------------------------

namespace {

struct Url {
	std::string host, port, path;
};

bool parse_url(const std::string &url, const std::string &scheme, const std::string &def_port, Url *u) {
	if (url.rfind(scheme, 0) != 0)
		return false;
	std::string rest = url.substr(scheme.size());
	std::string hostport = rest.substr(0, rest.find('/'));
	if (auto at = hostport.rfind('@'); at != std::string::npos)
		hostport = hostport.substr(at + 1);  // credentials are handled separately
	u->path = rest.find('/') == std::string::npos ? "/" : rest.substr(rest.find('/'));
	u->host = hostport;
	u->port = def_port;
	if (!hostport.empty() && hostport[0] == '[') {  // [v6]:port
		auto rb = hostport.find(']');
		if (rb == std::string::npos)
			return false;
		u->host = hostport.substr(1, rb - 1);
		if (rb + 1 < hostport.size() && hostport[rb + 1] == ':')
			u->port = hostport.substr(rb + 2);
	} else if (auto c = hostport.rfind(':'); c != std::string::npos) {
		u->host = hostport.substr(0, c);
		u->port = hostport.substr(c + 1);
	}
	return !u->host.empty() && !u->port.empty();
}

// NO_PROXY: comma-separated hosts or domain suffixes; "*" disables the proxy.
bool bypass_proxy(const std::string &host) {
	const char *np = getenv("NO_PROXY");
	if (!np)
		np = getenv("no_proxy");
	if (!np)
		return false;
	std::string h = to_lower(host);
	std::string list = np;
	size_t start = 0;
	while (start <= list.size()) {
		size_t end = list.find(',', start);
		std::string e = to_lower(trim(list.substr(start, end == std::string::npos ? std::string::npos : end - start)));
		start = end == std::string::npos ? list.size() + 1 : end + 1;
		if (e.empty())
			continue;
		if (e == "*")
			return true;
		if (auto slash = e.find('/'); slash != std::string::npos) {  // IPv4 CIDR
			struct in_addr net {}, ip {};
			int bits = atoi(e.c_str() + slash + 1);
			if (inet_pton(AF_INET, e.substr(0, slash).c_str(), &net) == 1 && inet_pton(AF_INET, h.c_str(), &ip) == 1 &&
			    bits >= 0 && bits <= 32) {
				uint32_t mask = bits == 0 ? 0 : htonl(~uint32_t(0) << (32 - bits));
				if ((ip.s_addr & mask) == (net.s_addr & mask))
					return true;
			}
			continue;
		}
		if (e.rfind("*.", 0) == 0)
			e = e.substr(2);
		else if (e[0] == '.')
			e = e.substr(1);
		if (h == e || (h.size() > e.size() && h.compare(h.size() - e.size(), e.size(), e) == 0 &&
		               h[h.size() - e.size() - 1] == '.'))
			return true;
	}
	return false;
}

int left_ms(steady_clock::time_point dl) { return (int)duration_cast<milliseconds>(dl - steady_clock::now()).count(); }

// Wait for fd readiness in <= 500 ms slices so a cancel flag is noticed
// promptly. 1 = ready, 0 = deadline passed or cancelled, -1 = poll error.
int wait_fd(int fd, short events, steady_clock::time_point dl, const std::atomic<bool> *cancel) {
	for (;;) {
		if (cancel && cancel->load())
			return 0;
		int left = left_ms(dl);
		if (left <= 0)
			return 0;
		struct pollfd p = {fd, events, 0};
		int r = poll(&p, 1, std::min(left, 500));
		if (r > 0)
			return 1;
		if (r < 0 && errno != EINTR)
			return -1;
	}
}

int tcp_connect(const std::string &host, const std::string &port, steady_clock::time_point dl, std::string *err,
                const std::atomic<bool> *cancel) {
	struct addrinfo hints {}, *res = nullptr;
	hints.ai_socktype = SOCK_STREAM;
	if (int g = getaddrinfo(host.c_str(), port.c_str(), &hints, &res); g != 0) {
		*err = host + ": " + gai_strerror(g);
		return -1;
	}
	size_t count = 0;
	for (auto *ai = res; ai; ai = ai->ai_next)
		count++;
	int fd = -1;
	std::string why = "no address";
	size_t idx = 0;
	for (auto *ai = res; ai && fd < 0; ai = ai->ai_next, idx++) {
		// Each address gets its share of what is left (at most 10 s while
		// others remain), so one that silently drops SYNs cannot use it all.
		auto now = steady_clock::now();
		if (now >= dl) {
			why = "timed out";
			break;
		}
		auto share = dl - now;
		if (size_t rest = count - idx; rest > 1)
			share = std::min<steady_clock::duration>(share / (long)rest, seconds(10));
		auto adl = now + share;
		fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, ai->ai_protocol);
		if (fd < 0) {
			why = strerror(errno);
			continue;
		}
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0 && errno != EINPROGRESS) {
			why = strerror(errno);
			::close(fd);
			fd = -1;
			continue;
		}
		int soerr = 0;
		socklen_t sl = sizeof soerr;
		int w = wait_fd(fd, POLLOUT, adl, cancel);
		if (w != 1 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr) {
			why = w == 0 ? "timed out" : w < 0 ? "poll failed" : strerror(soerr ? soerr : errno);
			::close(fd);
			fd = -1;
			if (cancel && cancel->load())
				break;
		}
	}
	freeaddrinfo(res);
	if (fd < 0)
		*err = cancel && cancel->load() ? "cancelled" : "connect to " + host + ":" + port + " failed: " + why;
	return fd;
}

// Plain-socket CONNECT through an HTTP proxy. Leaves fd positioned at the tunnel.
bool proxy_connect(int fd, const std::string &target, const std::string &auth, steady_clock::time_point dl,
                   std::string *err, const std::atomic<bool> *cancel) {
	std::string req = "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n";
	if (!auth.empty())
		req += "Proxy-Authorization: Basic " + base64_encode(auth) + "\r\n";
	req += "\r\n";
	size_t off = 0;
	while (off < req.size()) {
		ssize_t w = ::send(fd, req.data() + off, req.size() - off, MSG_NOSIGNAL);
		if (w > 0) {
			off += (size_t)w;
			continue;
		}
		if ((w < 0 && errno != EAGAIN && errno != EINTR) || wait_fd(fd, POLLOUT, dl, cancel) != 1) {
			*err = "proxy: write failed";
			return false;
		}
	}
	std::string resp;
	char c;
	while (resp.find("\r\n\r\n") == std::string::npos) {
		if (resp.size() >= 16384) {
			*err = "proxy: CONNECT reply has no end of headers within 16 KiB";
			return false;
		}
		ssize_t r = ::recv(fd, &c, 1, 0);  // byte at a time: never read past the proxy's reply
		if (r == 1) {
			resp += c;
			continue;
		}
		if (r == 0 || (r < 0 && errno != EAGAIN && errno != EINTR) || wait_fd(fd, POLLIN, dl, cancel) != 1) {
			*err = "proxy: no CONNECT reply";
			return false;
		}
	}
	int status = 0;
	if (!parse_status_line(resp.substr(0, resp.find("\r\n")), &status) || status < 200 || status > 299) {
		*err = "proxy refused CONNECT: " + log_escape(resp.substr(0, std::min<size_t>(resp.find("\r\n"), 200)));
		return false;
	}
	return true;
}

}  // namespace

bool parse_status_line(const std::string &line, int *status) {
	// HTTP/1.x SP 3DIGIT [SP reason]
	if (line.size() < 12 || line.compare(0, 7, "HTTP/1.") != 0 || !isdigit((unsigned char)line[7]) || line[8] != ' ')
		return false;
	for (int i = 9; i < 12; i++)
		if (!isdigit((unsigned char)line[i]))
			return false;
	if (line.size() > 12 && line[12] != ' ')
		return false;
	*status = (line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0');
	return *status >= 100;
}

// RFC 9112 section 7.1. Sizes are hex digits only (at most 15 of them, so no
// arithmetic can overflow) with an optional ;extension; every bound is
// checked by subtraction.
Dechunker::State Dechunker::feed(const std::string &in, size_t max_out) {
	constexpr size_t MAX_LINE = 4096;
	while (st != DONE && st != BAD) {
		if (pos > in.size())
			return st = BAD;
		size_t avail = in.size() - pos;
		if (st == SIZE || st == TRAILER) {
			size_t eol = in.find("\r\n", pos);
			if (eol == std::string::npos)
				return avail > MAX_LINE ? (st = BAD) : st;
			if (eol - pos > MAX_LINE)
				return st = BAD;
			if (st == TRAILER) {
				if (eol == pos)
					st = DONE;  // the empty line after the last chunk (and any trailers)
				trailer_bytes += eol - pos + 2;
				if (trailer_bytes > 16384)
					return st = BAD;
				pos = eol + 2;
				continue;
			}
			size_t i = pos, digits = 0;
			unsigned long long n = 0;
			for (; i < eol && isxdigit((unsigned char)in[i]); i++, digits++) {
				if (digits == 15)
					return st = BAD;
				char c = (char)tolower((unsigned char)in[i]);
				n = n * 16 + (unsigned long long)(isdigit((unsigned char)c) ? c - '0' : c - 'a' + 10);
			}
			if (digits == 0)
				return st = BAD;
			while (i < eol && (in[i] == ' ' || in[i] == '\t'))
				i++;
			if (i < eol && in[i] != ';')
				return st = BAD;
			for (; i < eol; i++)
				if ((unsigned char)in[i] < 0x20 && in[i] != '\t')
					return st = BAD;
			pos = eol + 2;
			if (n == 0) {
				st = TRAILER;
				continue;
			}
			if (n > max_out || out.size() > max_out - n)
				return st = BAD;
			left = (size_t)n;
			st = DATA;
		} else if (st == DATA) {
			size_t take = std::min(left, avail);
			out.append(in, pos, take);
			pos += take;
			left -= take;
			if (left)
				return st;
			st = DATA_END;
		} else {  // DATA_END
			if (avail < 2)
				return st;
			if (in.compare(pos, 2, "\r\n") != 0)
				return st = BAD;
			pos += 2;
			st = SIZE;
		}
	}
	return st;
}

namespace {

// Request text that could end a header line early (CR, LF, NUL and the
// other control characters) is refused rather than sent.
bool header_safe(const std::string &s) {
	for (unsigned char c : s)
		if ((c < 0x20 && c != '\t') || c == 0x7f)
			return false;
	return true;
}

bool token_char(unsigned char c) { return isalnum(c) || strchr("!#$%&'*+-.^_`|~", c) != nullptr; }

bool http_token(const std::string &s) {
	if (s.empty())
		return false;
	for (unsigned char c : s)
		if (!c || !token_char(c))
			return false;
	return true;
}

}  // namespace

HttpsResponse https_request(const std::string &method, const std::string &url, const Headers &headers,
                            const std::string &body, milliseconds timeout, const std::string &ca_file,
                            const std::atomic<bool> *cancel) {
	HttpsResponse out;
	Url u;
	for (unsigned char c : url)
		if (c <= 0x20 || c == 0x7f) {
			out.error = "invalid URL (spaces or control characters)";
			return out;
		}
	if (!http_token(method)) {
		out.error = "invalid HTTP method";
		return out;
	}
	for (auto &[k, v] : headers)
		if (!http_token(k) || !header_safe(v)) {
			out.error = "invalid request header " + log_escape(k) + " (control characters are not allowed)";
			return out;
		}
	if (!parse_url(url, "https://", "443", &u)) {
		out.error = "only https:// URLs are supported";
		return out;
	}
	auto dl = steady_clock::now() + timeout;

	// HTTPS_PROXY (CONNECT tunnel), honouring NO_PROXY.
	const char *pe = getenv("HTTPS_PROXY");
	if (!pe || !*pe)
		pe = getenv("https_proxy");
	Url pu;
	std::string pauth;
	bool via_proxy = false;
	if (pe && *pe && !bypass_proxy(u.host)) {
		std::string ps = pe;
		if (ps.find("://") == std::string::npos)
			ps = "http://" + ps;
		if (!parse_url(ps, "http://", "80", &pu) || !header_safe(ps)) {
			out.error = "HTTPS_PROXY: only http:// proxies are supported";
			return out;
		}
		auto sch = ps.find("://") + 3;
		// The authority ends at the first '/', and credentials at its last '@'
		// (the same split parse_url uses), so an unencoded '@' in the password works.
		size_t auth_end = std::min(ps.find('/', sch), ps.size());
		if (auto at = ps.rfind('@', auth_end); at != std::string::npos && at >= sch)
			pauth = url_decode(ps.substr(sch, at - sch), false);
		via_proxy = true;
	}
	int fd = via_proxy ? tcp_connect(pu.host, pu.port, dl, &out.error, cancel)
	                   : tcp_connect(u.host, u.port, dl, &out.error, cancel);
	if (fd < 0)
		return out;
	std::string host_hdr = u.host.find(':') != std::string::npos ? "[" + u.host + "]" : u.host;
	std::string target = host_hdr + ":" + u.port;
	if (via_proxy && !proxy_connect(fd, target, pauth, dl, &out.error, cancel)) {
		::close(fd);
		return out;
	}

	SSLCtxPtr ctx(SSL_CTX_new(TLS_client_method()));
	if (!ctx) {
		out.error = "TLS: " + ssl_err();
		::close(fd);
		return out;
	}
	SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
	SSL_CTX_set_default_verify_paths(ctx.get());
	if (!ca_file.empty() && SSL_CTX_load_verify_locations(ctx.get(), ca_file.c_str(), nullptr) != 1) {
		out.error = "CA file " + ca_file + ": " + ssl_err();
		::close(fd);
		return out;
	}
	SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
	SSL *ssl = SSL_new(ctx.get());
	if (!ssl || SSL_set_fd(ssl, fd) != 1) {
		out.error = "TLS: " + ssl_err();
		if (ssl)
			SSL_free(ssl);
		::close(fd);
		return out;
	}
	// An IP-literal URL is verified against the certificate's IP SANs and
	// sends no SNI (RFC 6066 forbids an address there); a name is verified
	// as a DNS name and sent as SNI.
	unsigned char ipbuf[sizeof(struct in6_addr)];
	bool ip_literal = inet_pton(AF_INET, u.host.c_str(), ipbuf) == 1 || inet_pton(AF_INET6, u.host.c_str(), ipbuf) == 1;
	bool named = ip_literal ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), u.host.c_str()) == 1
	                        : SSL_set_tlsext_host_name(ssl, u.host.c_str()) == 1 && SSL_set1_host(ssl, u.host.c_str()) == 1;
	if (!named) {
		out.error = "TLS: cannot verify host " + u.host + ": " + ssl_err();
		SSL_free(ssl);
		::close(fd);
		return out;
	}
	auto finish = [&](const std::string &e) {
		if (!e.empty()) {
			out.error = e;
			out.status = -1;
		}
		SSL_free(ssl);
		::close(fd);
		return out;
	};
	for (;;) {
		int r = SSL_connect(ssl);
		if (r == 1)
			break;
		int e = SSL_get_error(ssl, r);
		if ((e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) ||
		    wait_fd(fd, e == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN, dl, cancel) != 1)
			return finish(cancel && cancel->load() ? "cancelled" : "TLS handshake with " + u.host + ": " + ssl_err());
	}
	std::string req = method + " " + u.path + " HTTP/1.1\r\nHost: " + host_hdr + "\r\n";
	for (auto &[k, v] : headers)
		req += k + ": " + v + "\r\n";
	req += "Content-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;

	const size_t MAX_RESP = 16u << 20, MAX_HEAD = 64u << 10;
	size_t off = 0, hdr_end = std::string::npos;
	long long clen = -1;
	bool chunked = false;
	Dechunker dec;
	std::string resp;
	char buf[16384];
	// Parses the response head once it is complete, skipping interim 1xx
	// responses. 1: final head parsed, 0: need more, -1: malformed (error set).
	std::string head_error;
	auto parse_head = [&]() -> int {
		for (;;) {
			size_t he = resp.find("\r\n\r\n");
			if (he == std::string::npos) {
				if (resp.size() > MAX_HEAD) {
					head_error = "response headers from " + u.host + " are too large";
					return -1;
				}
				return 0;
			}
			std::string head = resp.substr(0, he);
			int status = 0;
			if (!parse_status_line(head.substr(0, head.find("\r\n")), &status)) {
				head_error = "malformed response from " + u.host;
				return -1;
			}
			if (status < 200) {
				if (status == 101) {
					head_error = "unexpected protocol switch from " + u.host;
					return -1;
				}
				resp.erase(0, he + 4);  // 100 Continue, 103 Early Hints, ...: the real answer follows
				continue;
			}
			out.status = status;
			size_t ls = head.find("\r\n");
			while (ls != std::string::npos) {
				size_t le = head.find("\r\n", ls + 2);
				std::string line = head.substr(ls + 2, le == std::string::npos ? std::string::npos : le - ls - 2);
				ls = le;
				auto colon = line.find(':');
				if (colon == std::string::npos)
					continue;
				std::string k = to_lower(trim(line.substr(0, colon))), v = trim(line.substr(colon + 1));
				out.headers[k] = v;
				if (k == "content-length") {
					if (v.empty() || v.size() > 18 || v.find_first_not_of("0123456789") != std::string::npos ||
					    (clen >= 0 && clen != atoll(v.c_str()))) {
						head_error = "malformed Content-Length from " + u.host;
						return -1;
					}
					clen = atoll(v.c_str());
				}
				if (k == "transfer-encoding" && contains(to_lower(v), "chunked"))
					chunked = true;
			}
			if (method == "HEAD" || out.status == 204 || out.status == 304) {
				clen = 0;
				chunked = false;
			}
			if (chunked)
				clen = -1;  // RFC 9112 6.3: Transfer-Encoding overrides Content-Length
			if (clen > (long long)MAX_RESP) {
				head_error = "response too large";
				return -1;
			}
			hdr_end = he + 4;
			dec.pos = hdr_end;
			return 1;
		}
	};
	bool eof = false;
	while (true) {
		if (hdr_end != std::string::npos) {
			if (chunked) {
				auto st = dec.feed(resp, MAX_RESP);
				if (st == Dechunker::DONE)
					break;
				if (st == Dechunker::BAD)
					return finish("malformed or oversized chunked response from " + u.host);
			} else if (clen >= 0 && (long long)(resp.size() - hdr_end) >= clen) {
				break;
			}
		}
		if (cancel && cancel->load())
			return finish("cancelled");
		if (left_ms(dl) <= 0)
			return finish("timed out waiting for " + u.host);
		int r = off < req.size() ? SSL_write(ssl, req.data() + off, (int)(req.size() - off))
		                         : SSL_read(ssl, buf, sizeof buf);
		if (r > 0) {
			if (off < req.size()) {
				off += (size_t)r;
				continue;
			}
			resp.append(buf, (size_t)r);
			if (resp.size() > (hdr_end == std::string::npos ? 0 : hdr_end) + MAX_RESP + 64 * 1024)
				return finish("response too large");
			if (hdr_end == std::string::npos && parse_head() < 0)
				return finish(head_error);
			continue;
		}
		int e = SSL_get_error(ssl, r);
		if (e == SSL_ERROR_ZERO_RETURN || (e == SSL_ERROR_SYSCALL && off >= req.size())) {
			eof = true;
			break;
		}
		if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
			return finish("connection to " + u.host + " failed: " + ssl_err());
		if (wait_fd(fd, e == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN, dl, cancel) < 0)
			return finish("connection to " + u.host + " failed: poll: " + strerror(errno));
	}
	if (hdr_end == std::string::npos)
		return finish("no response from " + u.host);
	if (chunked) {
		if (dec.st != Dechunker::DONE)
			return finish("truncated chunked response from " + u.host);
		out.body = std::move(dec.out);
	} else if (clen >= 0) {
		if ((long long)(resp.size() - hdr_end) < clen)
			return finish("truncated response from " + u.host);
		out.body = resp.substr(hdr_end, (size_t)clen);
	} else {
		(void)eof;
		out.body = resp.substr(hdr_end);  // delimited by connection close
		if (out.body.size() > MAX_RESP)
			return finish("response too large");
	}
	return finish("");
}

int https_post(const std::string &url, const std::string &content_type, const std::string &body, milliseconds timeout,
               std::string *err) {
	auto r = https_request("POST", url, {{"Content-Type", content_type}}, body, timeout, "");
	if (r.status < 0)
		*err = r.error;
	return r.status;
}

}  // namespace wisp
