// Small shared helpers: logging, time, durations, encodings, hashing, files.
#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wisp {

using Clock = std::chrono::system_clock;
using TimePoint = Clock::time_point;

// "2006/01/02 15:04:05 message" on stderr, serialised across threads. The
// formatted message passes through log_escape(), so data that reaches a log
// line (sensor strings, AI output, API paths) can never start a new line.
void logf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
// Control characters (and backslash) as \n, \r, \t, \\, \xHH; everything else as is.
std::string log_escape(std::string_view s);

// Timestamps. Sensor and journal records use "YYYY-MM-DDTHH:MM:SS.mmmZ".
std::string fmt_ts_ms(TimePoint t);              // ...SS.mmmZ (UTC)
std::string fmt_rfc3339(TimePoint t);            // ...SS.nnnnnnnnnZ, or "0001-01-01T00:00:00Z" for zero
long long unix_now();  // seconds since the epoch
std::string now_ts();                            // fmt_ts_ms(now)
// RFC 3339 with optional fraction/offset. Zero on failure, including fields
// out of range (month 13, hour 25) and years outside 1970..2261.
TimePoint parse_ts(std::string_view s);
inline bool is_zero(TimePoint t) { return t.time_since_epoch().count() == 0; }

// Go-style durations ("3m", "168h", "1h30m", "250ms", "1.5h"). nullopt for
// anything that does not parse completely ("1.2.3s", ".s", "5 minutes"), has
// a sign, or overflows int64 nanoseconds.
std::optional<std::chrono::nanoseconds> parse_duration(std::string_view s);
std::string fmt_duration(std::chrono::nanoseconds d);   // "168h0m0s", "3m0s", "5s"

// Encodings and hashing.
std::string base64_encode(std::string_view in);
std::optional<std::string> base64_decode(std::string_view in);
std::string hex_encode(const unsigned char *p, size_t n);
std::optional<std::vector<unsigned char>> hex_decode(std::string_view s);
std::array<unsigned char, 32> sha256(std::string_view data);
uint32_t fnv1a32(std::string_view s);
std::string random_bytes(size_t n);              // CSPRNG; throws on failure

// Strings.
std::string trim(std::string_view s);
std::vector<std::string> fields(std::string_view s);   // split on runs of whitespace
std::string to_lower(std::string_view s);
bool contains(std::string_view hay, std::string_view needle);
// Well-formed UTF-8 (no overlongs, surrogates or code points past U+10FFFF):
// what nlohmann::json can serialise without throwing.
bool valid_utf8(std::string_view s);

// Files.
std::optional<std::string> read_file(const std::string &path, int *err = nullptr);
// temp file + fsync + rename, so a crash or full disk never leaves a half-written file.
bool write_file_atomic(const std::string &path, std::string_view data, unsigned mode, std::string *err);

}  // namespace wisp
