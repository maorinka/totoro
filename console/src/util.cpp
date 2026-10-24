#include "util.hpp"

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace wisp {

static std::mutex log_mu;

// Control characters in a log message (a newline in a sensor-supplied
// version string, an AI-written title, an ESC sequence) would let the data
// forge extra, authentic-looking log lines or drive the operator's terminal.
// They are escaped, so one logf call is always exactly one line.
std::string log_escape(std::string_view s) {
	std::string out;
	out.reserve(s.size());
	for (unsigned char c : s) {
		if (c >= 0x20 && c != 0x7f && c != '\\') {
			out += (char)c;
			continue;
		}
		switch (c) {
		case '\n': out += "\\n"; break;
		case '\r': out += "\\r"; break;
		case '\t': out += "\\t"; break;
		case '\\': out += "\\\\"; break;
		default: {
			char b[8];
			snprintf(b, sizeof b, "\\x%02x", c);
			out += b;
		}
		}
	}
	return out;
}

void logf(const char *fmt, ...) {
	char msg[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);
	std::string safe = log_escape(msg);
	time_t t = time(nullptr);
	struct tm tm;
	localtime_r(&t, &tm);
	char ts[32];
	strftime(ts, sizeof ts, "%Y/%m/%d %H:%M:%S", &tm);
	std::lock_guard<std::mutex> g(log_mu);
	fprintf(stderr, "%s %s\n", ts, safe.c_str());
	fflush(stderr);
}

// ---- time -----------------------------------------------------------------

static void split(TimePoint t, time_t *sec, long *nsec) {
	auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t.time_since_epoch()).count();
	*sec = static_cast<time_t>(ns / 1000000000);
	*nsec = static_cast<long>(ns % 1000000000);
	if (*nsec < 0) {
		*nsec += 1000000000;
		(*sec)--;
	}
}

std::string fmt_ts_ms(TimePoint t) {
	time_t s;
	long ns;
	split(t, &s, &ns);
	struct tm tm;
	gmtime_r(&s, &tm);
	char b[64];
	size_t n = strftime(b, sizeof b, "%Y-%m-%dT%H:%M:%S", &tm);
	snprintf(b + n, sizeof b - n, ".%03ldZ", ns / 1000000);
	return b;
}

std::string fmt_rfc3339(TimePoint t) {
	if (is_zero(t))
		return "0001-01-01T00:00:00Z";
	time_t s;
	long ns;
	split(t, &s, &ns);
	struct tm tm;
	gmtime_r(&s, &tm);
	char b[64];
	size_t n = strftime(b, sizeof b, "%Y-%m-%dT%H:%M:%S", &tm);
	if (ns) {
		char frac[16];
		snprintf(frac, sizeof frac, "%09ld", ns);
		size_t l = strlen(frac);
		while (l > 0 && frac[l - 1] == '0')
			frac[--l] = 0;  // RFC 3339 "nano" form drops trailing zeros
		snprintf(b + n, sizeof b - n, ".%sZ", frac);
	} else {
		snprintf(b + n, sizeof b - n, "Z");
	}
	return b;
}

long long unix_now() { return std::chrono::duration_cast<std::chrono::seconds>(Clock::now().time_since_epoch()).count(); }

std::string now_ts() { return fmt_ts_ms(Clock::now()); }

static bool digits(std::string_view s, size_t pos, size_t n, int *out) {
	if (pos + n > s.size())
		return false;
	int v = 0;
	for (size_t i = 0; i < n; i++) {
		char c = s[pos + i];
		if (c < '0' || c > '9')
			return false;
		v = v * 10 + (c - '0');
	}
	*out = v;
	return true;
}

static bool leap(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

TimePoint parse_ts(std::string_view s) {
	// YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)
	int Y, M, D, h, m, sec;
	if (!digits(s, 0, 4, &Y) || s.size() < 19 || s[4] != '-' || !digits(s, 5, 2, &M) || s[7] != '-' ||
	    !digits(s, 8, 2, &D) || (s[10] != 'T' && s[10] != 't') || !digits(s, 11, 2, &h) || s[13] != ':' ||
	    !digits(s, 14, 2, &m) || s[16] != ':' || !digits(s, 17, 2, &sec))
		return TimePoint{};
	// Field ranges, and a year the nanosecond clock can represent (system_clock
	// counts int64 nanoseconds: 1678..2262). Out-of-range input is "no time",
	// never silently normalised or wrapped.
	static const int mdays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
	if (Y < 1970 || Y > 2261 || M < 1 || M > 12 || D < 1 || D > mdays[M - 1] + (M == 2 && leap(Y)) || h > 23 ||
	    m > 59 || sec > 60)
		return TimePoint{};
	size_t p = 19;
	long nanos = 0;
	if (p < s.size() && s[p] == '.') {
		p++;
		int nd = 0;
		while (p < s.size() && s[p] >= '0' && s[p] <= '9') {
			if (nd < 9) {
				nanos = nanos * 10 + (s[p] - '0');
				nd++;
			}
			p++;
		}
		for (; nd < 9; nd++)
			nanos *= 10;
	}
	long offset = 0;
	if (p < s.size() && (s[p] == 'Z' || s[p] == 'z')) {
		p++;
	} else if (p < s.size() && (s[p] == '+' || s[p] == '-')) {
		int oh, om;
		if (!digits(s, p + 1, 2, &oh) || p + 3 >= s.size() || s[p + 3] != ':' || !digits(s, p + 4, 2, &om) ||
		    oh > 23 || om > 59)
			return TimePoint{};
		offset = (s[p] == '-' ? -1 : 1) * (oh * 3600L + om * 60L);
		p += 6;
	} else {
		return TimePoint{};
	}
	if (p != s.size())
		return TimePoint{};
	struct tm tm {};
	tm.tm_year = Y - 1900;
	tm.tm_mon = M - 1;
	tm.tm_mday = D;
	tm.tm_hour = h;
	tm.tm_min = m;
	tm.tm_sec = sec;
	long long t = (long long)timegm(&tm) - offset;
	// 2261-12-31 plus the largest offset still fits: no overflow below.
	return TimePoint{} + std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(t) +
	                                                                   std::chrono::nanoseconds(nanos));
}

// ---- durations ------------------------------------------------------------

// Go's time.ParseDuration, without the sign (no setting here takes a negative
// duration): a sequence of decimal numbers, each with an optional fraction and
// a unit. Anything that does not parse completely, or that overflows int64
// nanoseconds (about 292 years), is rejected rather than wrapped.
std::optional<std::chrono::nanoseconds> parse_duration(std::string_view s) {
	if (s.empty())
		return std::nullopt;
	if (s == "0")
		return std::chrono::nanoseconds(0);
	constexpr uint64_t LIMIT = (uint64_t)INT64_MAX;
	auto isdig = [](char c) { return c >= '0' && c <= '9'; };
	uint64_t total = 0;
	size_t i = 0;
	while (i < s.size()) {
		if (!isdig(s[i]) && s[i] != '.')
			return std::nullopt;
		uint64_t v = 0;
		size_t start = i;
		for (; i < s.size() && isdig(s[i]); i++) {
			if (v > (LIMIT - 9) / 10)
				return std::nullopt;  // overflow
			v = v * 10 + (uint64_t)(s[i] - '0');
		}
		bool pre = i > start, post = false;
		uint64_t f = 0;
		double scale = 1;
		if (i < s.size() && s[i] == '.') {
			i++;
			size_t fs = i;
			for (; i < s.size() && isdig(s[i]); i++) {
				if (f > (LIMIT - 9) / 10)
					continue;  // more precision than int64 holds: drop the rest
				f = f * 10 + (uint64_t)(s[i] - '0');
				scale *= 10;
			}
			post = i > fs;
		}
		if (!pre && !post)
			return std::nullopt;  // "." or ".s"
		size_t us = i;
		while (i < s.size() && s[i] != '.' && !isdig(s[i]))
			i++;
		std::string_view unit = s.substr(us, i - us);
		uint64_t mult;
		if (unit == "ns") mult = 1;
		else if (unit == "us" || unit == "\xc2\xb5s" || unit == "\xce\xbcs") mult = 1000;  // us, µs, μs
		else if (unit == "ms") mult = 1000000;
		else if (unit == "s") mult = 1000000000ULL;
		else if (unit == "m") mult = 60000000000ULL;
		else if (unit == "h") mult = 3600000000000ULL;
		else return std::nullopt;  // missing or unknown unit
		if (v > LIMIT / mult)
			return std::nullopt;
		v *= mult;
		if (post) {
			double extra = (double)f * ((double)mult / scale);
			if (extra >= (double)LIMIT)
				return std::nullopt;
			v += (uint64_t)extra;
			if (v > LIMIT)
				return std::nullopt;
		}
		total += v;
		if (total > LIMIT)
			return std::nullopt;
	}
	return std::chrono::nanoseconds((long long)total);
}

std::string fmt_duration(std::chrono::nanoseconds d) {
	long long sns = d.count();
	if (sns == 0)
		return "0s";
	std::string sign = sns < 0 ? "-" : "";
	// magnitude as unsigned: -INT64_MIN does not fit in a long long
	unsigned long long ns = sns < 0 ? 0ULL - (unsigned long long)sns : (unsigned long long)sns;
	char b[64];
	if (ns < 1000000000ULL) {
		if (ns < 1000) snprintf(b, sizeof b, "%lluns", ns);
		else if (ns < 1000000) snprintf(b, sizeof b, "%g\xc2\xb5s", (double)ns / 1e3);
		else snprintf(b, sizeof b, "%gms", (double)ns / 1e6);
		return sign + b;
	}
	unsigned long long h = ns / 3600000000000ULL;
	unsigned long long m = (ns / 60000000000ULL) % 60;
	unsigned long long s = (ns / 1000000000ULL) % 60;
	unsigned long long frac = ns % 1000000000ULL;
	std::string secs = std::to_string(s);
	if (frac) {
		char f[16];
		snprintf(f, sizeof f, "%09llu", frac);
		std::string fs = f;
		while (!fs.empty() && fs.back() == '0')
			fs.pop_back();
		secs += "." + fs;
	}
	if (h)
		snprintf(b, sizeof b, "%lluh%llum%ss", h, m, secs.c_str());
	else if (m)
		snprintf(b, sizeof b, "%llum%ss", m, secs.c_str());
	else
		snprintf(b, sizeof b, "%ss", secs.c_str());
	return sign + b;
}

// ---- encodings ------------------------------------------------------------

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(std::string_view in) {
	std::string out;
	out.reserve((in.size() + 2) / 3 * 4);
	size_t i = 0;
	for (; i + 2 < in.size(); i += 3) {
		uint32_t v = (uint8_t)in[i] << 16 | (uint8_t)in[i + 1] << 8 | (uint8_t)in[i + 2];
		out += B64[v >> 18];
		out += B64[(v >> 12) & 63];
		out += B64[(v >> 6) & 63];
		out += B64[v & 63];
	}
	if (i < in.size()) {
		uint32_t v = (uint8_t)in[i] << 16;
		if (i + 1 < in.size())
			v |= (uint8_t)in[i + 1] << 8;
		out += B64[v >> 18];
		out += B64[(v >> 12) & 63];
		out += i + 1 < in.size() ? B64[(v >> 6) & 63] : '=';
		out += '=';
	}
	return out;
}

std::optional<std::string> base64_decode(std::string_view in) {
	if (in.size() % 4)
		return std::nullopt;
	auto val = [](char c) -> int {
		if (c >= 'A' && c <= 'Z') return c - 'A';
		if (c >= 'a' && c <= 'z') return c - 'a' + 26;
		if (c >= '0' && c <= '9') return c - '0' + 52;
		if (c == '+') return 62;
		if (c == '/') return 63;
		return -1;
	};
	std::string out;
	for (size_t i = 0; i < in.size(); i += 4) {
		int a = val(in[i]), b = val(in[i + 1]);
		if (a < 0 || b < 0)
			return std::nullopt;
		bool last = i + 4 == in.size();
		int c = in[i + 2] == '=' && last ? -2 : val(in[i + 2]);
		int d = in[i + 3] == '=' && last ? -2 : val(in[i + 3]);
		if (c == -1 || d == -1 || (c == -2 && d != -2))
			return std::nullopt;
		uint32_t v = a << 18 | b << 12 | (c >= 0 ? c << 6 : 0) | (d >= 0 ? d : 0);
		out += char(v >> 16);
		if (c >= 0) out += char((v >> 8) & 255);
		if (d >= 0) out += char(v & 255);
	}
	return out;
}

std::string hex_encode(const unsigned char *p, size_t n) {
	static const char H[] = "0123456789abcdef";
	std::string s(n * 2, '0');
	for (size_t i = 0; i < n; i++) {
		s[2 * i] = H[p[i] >> 4];
		s[2 * i + 1] = H[p[i] & 15];
	}
	return s;
}

std::optional<std::vector<unsigned char>> hex_decode(std::string_view s) {
	if (s.size() % 2)
		return std::nullopt;
	auto v = [](char c) -> int {
		if (c >= '0' && c <= '9') return c - '0';
		if (c >= 'a' && c <= 'f') return c - 'a' + 10;
		if (c >= 'A' && c <= 'F') return c - 'A' + 10;
		return -1;
	};
	std::vector<unsigned char> out(s.size() / 2);
	for (size_t i = 0; i < out.size(); i++) {
		int a = v(s[2 * i]), b = v(s[2 * i + 1]);
		if (a < 0 || b < 0)
			return std::nullopt;
		out[i] = (unsigned char)(a << 4 | b);
	}
	return out;
}

std::array<unsigned char, 32> sha256(std::string_view data) {
	std::array<unsigned char, 32> d{};
	unsigned int len = 0;
	if (!EVP_Digest(data.data(), data.size(), d.data(), &len, EVP_sha256(), nullptr) || len != 32)
		throw std::runtime_error("sha256 failed");
	return d;
}

uint32_t fnv1a32(std::string_view s) {
	uint32_t h = 0x811c9dc5u;
	for (unsigned char c : s) {
		h ^= c;
		h *= 0x01000193u;
	}
	return h;
}

std::string random_bytes(size_t n) {
	std::string b(n, '\0');
	if (RAND_bytes(reinterpret_cast<unsigned char *>(b.data()), (int)n) != 1)
		throw std::runtime_error("CSPRNG failure");
	return b;
}

// ---- strings --------------------------------------------------------------

std::string trim(std::string_view s) {
	size_t a = 0, b = s.size();
	while (a < b && isspace((unsigned char)s[a]))
		a++;
	while (b > a && isspace((unsigned char)s[b - 1]))
		b--;
	return std::string(s.substr(a, b - a));
}

std::vector<std::string> fields(std::string_view s) {
	std::vector<std::string> out;
	size_t i = 0;
	while (i < s.size()) {
		while (i < s.size() && isspace((unsigned char)s[i]))
			i++;
		size_t j = i;
		while (j < s.size() && !isspace((unsigned char)s[j]))
			j++;
		if (j > i)
			out.emplace_back(s.substr(i, j - i));
		i = j;
	}
	return out;
}

std::string to_lower(std::string_view s) {
	std::string o(s);
	for (auto &c : o)
		c = (char)tolower((unsigned char)c);
	return o;
}

bool contains(std::string_view hay, std::string_view needle) { return hay.find(needle) != std::string_view::npos; }

bool valid_utf8(std::string_view s) {
	size_t i = 0, n = s.size();
	while (i < n) {
		unsigned char c = (unsigned char)s[i];
		if (c < 0x80) {
			i++;
			continue;
		}
		size_t len;
		uint32_t cp;
		if (c >= 0xc2 && c <= 0xdf) {
			len = 2;
			cp = c & 0x1f;
		} else if (c >= 0xe0 && c <= 0xef) {
			len = 3;
			cp = c & 0x0f;
		} else if (c >= 0xf0 && c <= 0xf4) {
			len = 4;
			cp = c & 0x07;
		} else {
			return false;  // continuation byte, overlong lead (c0/c1) or > f4
		}
		if (i + len > n)
			return false;
		for (size_t k = 1; k < len; k++) {
			unsigned char cc = (unsigned char)s[i + k];
			if ((cc & 0xc0) != 0x80)
				return false;
			cp = cp << 6 | (cc & 0x3f);
		}
		if ((len == 3 && (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff))) || (len == 4 && (cp < 0x10000 || cp > 0x10ffff)))
			return false;
		i += len;
	}
	return true;
}

// ---- files ----------------------------------------------------------------

std::optional<std::string> read_file(const std::string &path, int *err) {
	FILE *f = fopen(path.c_str(), "rbe");
	if (!f) {
		if (err)
			*err = errno;
		return std::nullopt;
	}
	std::string out;
	char buf[65536];
	size_t n;
	while ((n = fread(buf, 1, sizeof buf, f)) > 0)
		out.append(buf, n);
	bool bad = ferror(f);
	int e = errno;
	fclose(f);
	if (bad) {
		if (err)
			*err = e;
		return std::nullopt;
	}
	if (err)
		*err = 0;
	return out;
}

bool write_file_atomic(const std::string &path, std::string_view data, unsigned mode, std::string *err) {
	std::string dir = ".", base = path;
	if (auto s = path.rfind('/'); s != std::string::npos) {
		dir = s == 0 ? "/" : path.substr(0, s);
		base = path.substr(s + 1);
	}
	std::string tmpl = dir + "/.tmp-" + base + "-XXXXXX";
	std::vector<char> name(tmpl.begin(), tmpl.end());
	name.push_back(0);
	int fd = mkostemp(name.data(), O_CLOEXEC);
	if (fd < 0) {
		*err = std::string("create temp: ") + strerror(errno);
		return false;
	}
	auto fail = [&](const char *what) {
		*err = std::string(what) + ": " + strerror(errno);
		close(fd);
		unlink(name.data());
		return false;
	};
	if (fchmod(fd, mode) != 0)
		return fail("chmod");
	size_t off = 0;
	while (off < data.size()) {
		ssize_t w = write(fd, data.data() + off, data.size() - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return fail("write");
		}
		off += (size_t)w;
	}
	if (fsync(fd) != 0)
		return fail("fsync");
	if (close(fd) != 0) {
		*err = std::string("close: ") + strerror(errno);
		unlink(name.data());
		return false;
	}
	if (rename(name.data(), path.c_str()) != 0) {
		*err = std::string("rename: ") + strerror(errno);
		unlink(name.data());
		return false;
	}
	return true;
}

}  // namespace wisp
