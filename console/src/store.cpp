#include "store.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#ifndef WISP_VERSION
#define WISP_VERSION "dev"
#endif

namespace wisp {

using namespace std::chrono;
using Mono = steady_clock;

// Segment header format. 2: sensor lines carry rx_ts, console records carry
// "src":"console", and CONSOLE_ONLY covers both (so neither can be forged).
static constexpr int JOURNAL_FORMAT = 2;
// Replay accepts any line this console can have written (a rollout record for
// a 30,000-host cohort is about 1.4 MiB); sensor lines are far smaller
// (Store::sensor_max_line).
static constexpr size_t MAX_REPLAY_LINE = 64u << 20;

const std::map<std::string, std::string> &control_commands() {
	static const std::map<std::string, std::string> m = {
	    {"reload", R"({"reload":true})"},
	    {"enforce", R"({"mode":"enforce"})"},
	    {"monitor", R"({"mode":"monitor"})"},
	};
	return m;
}

// Fields only the console may set. They are stripped from a sensor's raw line
// before it is journaled, so a sensor cannot forge triage state, rollout
// history, receipt times or console provenance that a later replay would trust.
static const char *const CONSOLE_ONLY[] = {"id",        "status", "note",   "triaged_by", "triaged_at", "percent",
                                           "cohort",    "delivered", "failed", "by",      "rx_ts",      "src",
                                           "id_kept",   "send_failed"};

std::string sanitize(const std::string &raw) {
	json m;
	try {
		m = json::parse(raw);
	} catch (...) {
		return raw;
	}
	if (!m.is_object())
		return raw;
	bool changed = false;
	for (auto k : CONSOLE_ONLY)
		changed |= m.erase(k) > 0;
	return changed ? m.dump() : raw;
}

std::string with_fields(const std::string &raw, const json &fields) {
	json m;
	try {
		m = json::parse(raw);
	} catch (...) {
		return raw;
	}
	if (!m.is_object())
		return raw;
	for (auto &[k, v] : fields.items())
		m[k] = v;
	return m.dump();
}

// A host's stable position in [0,100): a larger rollout percentage is always a
// superset of a smaller one. Must match the web UI's preview (FNV-1a 32).
int bucket(const std::string &host) { return (int)(fnv1a32(host) % 100); }

std::string grade(int score) {
	if (score >= 90) return "A";
	if (score >= 75) return "B";
	if (score >= 60) return "C";
	if (score >= 40) return "D";
	return "F";
}

// Record types only the console writes; a sensor line of one of these types
// is dropped at ingest.
static bool console_only_type(const std::string &t) {
	return t == "triage" || t == "rollout" || t == "rollout_intent" || t == "lifecycle" || t == "journal" ||
	       Store::console_record_type(t);
}

// How strongly a host identity is anchored (agent/identity.c tiers).
static int trust_rank(const std::string &t) {
	if (t == "tpm") return 4;
	if (t == "dmi") return 3;
	if (t == "machine-id") return 2;
	if (t == "generated") return 1;
	return 0;
}

static std::string clip(const std::string &s, size_t n = 96) { return s.size() <= n ? s : s.substr(0, n) + "..."; }

static TimePoint file_mtime(const std::string &p) {
	struct stat st;
	if (stat(p.c_str(), &st) != 0)
		return Clock::now();
	return TimePoint{} + duration_cast<Clock::duration>(seconds(st.st_mtim.tv_sec) + nanoseconds(st.st_mtim.tv_nsec));
}

// A format-2 segment header exactly as open_segment() writes it, and nothing
// else. The key set is checked, not just "no host": the Go 1.0 console
// decoded sensor lines case-insensitively (so {"HOST":"x",...} passed its
// hello and host checks) and journaled them with their original keys, so a
// line with no lowercase "host" key can sit in a pre-upgrade journal. Every
// sensor line carries some spelling of host, which disqualifies it here.
static bool segment_header(const json &j) {
	static const std::set<std::string> keys = {"ts", "type", "src", "format", "version"};
	for (auto it = j.begin(); it != j.end(); ++it)
		if (!keys.count(it.key()))
			return false;
	auto t = j.find("type"), s = j.find("src"), f = j.find("format");
	return t != j.end() && *t == "journal" && s != j.end() && *s == "console" && f != j.end() &&
	       f->is_number_integer() && f->get<long long>() >= 2;
}

// Go's encoding/json matches object keys to struct fields case-insensitively
// (also folding U+017F to s and U+212A to k) and takes the last match. A
// line with two keys that fold alike ({"type":"lifecycle","Type":"x"}) was
// therefore read differently by the Go 1.0 console's filter (type "x",
// accepted) than by this one (type "lifecycle"). No console ever writes such
// a line, so in segments from older consoles it is a sensor's forgery.
static std::string go_fold(const std::string &k) {
	std::string out;
	for (size_t i = 0; i < k.size(); i++) {
		if (k.compare(i, 2, "\xc5\xbf") == 0) {  // long s
			out += 's';
			i += 1;
		} else if (k.compare(i, 3, "\xe2\x84\xaa") == 0) {  // Kelvin sign
			out += 'k';
			i += 2;
		} else {
			out += (char)std::tolower((unsigned char)k[i]);
		}
	}
	return out;
}

static bool ambiguous_keys(const json &j) {
	std::set<std::string> seen;
	for (auto it = j.begin(); it != j.end(); ++it)
		if (!seen.insert(go_fold(it.key())).second)
			return true;
	return false;
}

Store::Store(std::string slack_webhook) : slack_(std::move(slack_webhook)) {}

// ---- journal ----------------------------------------------------------------

void Store::open_journal(const std::string &path) {
	std::unique_lock lk(mu_);
	journal_path_ = path;
	journal_closed_ = false;
	const TimePoint replay_start = Clock::now();
	size_t n = 0, untrusted_console = 0, ambiguous = 0;
	for (const auto &p : {path + ".1", path}) {
		std::ifstream in(p, std::ios::binary);
		if (!in)
			continue;
		// Nothing in a segment was received after the file was last written.
		const TimePoint mtime = std::min(file_mtime(p), replay_start);
		// Until a format-2 header, lines come from an older console: its
		// sensor lines may carry fields this version reserves (it did not
		// strip rx_ts/src), so those fields are ignored there.
		bool trusted = false;
		std::string line;
		while (std::getline(in, line)) {
			if (line.size() > MAX_REPLAY_LINE)
				continue;
			json j;
			try {
				j = json::parse(line);
			} catch (...) {
				continue;  // a torn line (crash, full disk) or junk
			}
			if (!j.is_object())
				continue;
			Event e = event_from_json(j);
			if (e.type == "journal") {
				if (segment_header(j))
					trusted = true;
				continue;
			}
			if (!trusted) {
				if (ambiguous_keys(j)) {
					ambiguous++;  // slipped past the Go 1.0 console's filter as another type or host
					continue;
				}
				e.rx_ts.clear();
				e.src.clear();
				e.id_kept = false;
				if (e.type == "rollout_intent")
					continue;  // a type older consoles never wrote (and did not block from sensors)
			}
			if (console_record_type(e.type)) {
				// Only this version writes these, always with the marker, and
				// only after a header: anything else came from a sensor through
				// an older console's sanitiser. Never replay it.
				if (!trusted || e.src != "console") {
					untrusted_console++;
					continue;
				}
				index_event(line);
				if (replay_hook)
					replay_hook(j);
				n++;
				continue;
			}
			// When did the console see it? Its own records carry its clock;
			// sensor records carry the receipt time it stamped. A sensor's own
			// ts is only a fallback (older journals), never later than mtime.
			TimePoint at;
			bool console_written = e.type == "triage" || e.type == "rollout" || e.type == "rollout_intent" ||
			                       e.type == "lifecycle" || e.src == "console";
			if (console_written)
				at = parse_ts(e.ts);
			else if (!e.rx_ts.empty())
				at = parse_ts(e.rx_ts);
			else if (at = parse_ts(e.ts); !is_zero(at) && at > mtime)
				at = mtime;
			index_event(line);
			apply(e, at, true);
			n++;
		}
	}
	// A rollout_intent without its rollout record: the console stopped
	// mid-push. Some hosts may have been switched; show it rather than forget it.
	for (auto &[_, r] : intents_)
		rollouts_.push_back(r);
	if (!intents_.empty())
		std::stable_sort(rollouts_.begin(), rollouts_.end(),
		                 [](const Rollout &a, const Rollout &b) { return a.ts < b.ts; });
	while (rollouts_.size() > max_rollouts)
		rollouts_.erase(rollouts_.begin());
	if (!intents_.empty())
		logf("journal: %zu rollout(s) were interrupted before their outcome was recorded", intents_.size());
	intents_.clear();
	legacy_alias_.clear();
	if (untrusted_console)
		logf("journal: ignored %zu console-type record(s) not written by this console (sensor-supplied lines "
		     "journaled by an older version)",
		     untrusted_console);
	if (ambiguous)
		logf("journal: ignored %zu record(s) from an older console with keys differing only in case (a sensor "
		     "line the Go 1.0 console read as a different type or host)",
		     ambiguous);
	if (n)
		logf("journal: replayed %zu events (%zu hosts, %zu alerts, %zu rollouts) from %s", n, hosts_.size(),
		     alerts_.size(), rollouts_.size(), path.c_str());
	std::string err;
	long long size = 0;
	int fd = open_segment(&err, &size);
	if (fd < 0)
		throw std::runtime_error("journal " + path + ": " + err);
	journal_fd_ = fd;
	journal_size_ = size;
	health_ = JournalHealth{};
	write_error_.clear();
	rotate_error_.clear();
	journal_ok_ = true;
}

static bool write_all(int fd, const std::string &s, size_t *written, int *err) {
	size_t off = 0;
	while (off < s.size()) {
		ssize_t w = ::write(fd, s.data() + off, s.size() - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			*err = errno;
			break;
		}
		if (w == 0) {
			*err = EIO;
			break;
		}
		off += (size_t)w;
	}
	*written = off;
	return off == s.size();
}

// Opens (creating) the journal for appending: repairs a torn last line, so
// the first record after a crash or full disk is not glued onto the fragment
// and lost with it, and writes the segment header.
int Store::open_segment(std::string *err, long long *size) {
	int fd = ::open(journal_path_.c_str(), O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd < 0) {
		*err = strerror(errno);
		return -1;
	}
	struct stat st;
	if (fstat(fd, &st) != 0) {
		*err = std::string("stat: ") + strerror(errno);
		::close(fd);
		return -1;
	}
	std::string head;
	if (st.st_size > 0) {
		char c = '\n';
		if (pread(fd, &c, 1, st.st_size - 1) == 1 && c != '\n') {
			head = "\n";
			logf("journal: %s ended in a partial line (crash or full disk); it is skipped on replay",
			     journal_path_.c_str());
		}
	}
	head += json{{"ts", now_ts()},
	             {"type", "journal"},
	             {"src", "console"},
	             {"format", JOURNAL_FORMAT},
	             {"version", WISP_VERSION}}
	            .dump() +
	        "\n";
	size_t w = 0;
	int e = 0;
	if (!write_all(fd, head, &w, &e)) {
		*err = std::string("write: ") + strerror(e);
		if (w && ftruncate(fd, st.st_size) != 0) {
			// leave it: the next open repairs the torn header
		}
		::close(fd);
		return -1;
	}
	*size = (long long)st.st_size + (long long)head.size();
	return fd;
}

void Store::journal_failure(const std::string &what, int err) {
	write_error_ = what + ": " + strerror(err);
	health_.write_errors++;
	if (health_.ok) {
		health_.ok = false;
		health_.failing_since = Clock::now();
	}
	journal_ok_ = false;
	auto mono = Mono::now();
	if (error_logged_ == Mono::time_point{} || mono - error_logged_ > minutes(1)) {
		error_logged_ = mono;
		logf("journal: %s: %s (%llu failed writes; events are kept in memory but will not survive a restart "
		     "until writes succeed)",
		     journal_path_.c_str(), write_error_.c_str(), health_.write_errors);
	}
}

void Store::rotate() {
	auto mono = Mono::now();
	if (mono < rotate_retry_at_)
		return;
	if (!rotate_pending_) {
		(void)fdatasync(journal_fd_);
		if (::rename(journal_path_.c_str(), (journal_path_ + ".1").c_str()) != 0) {
			rotate_error_ = std::string("rotate: rename: ") + strerror(errno);
			rotate_retry_at_ = mono + minutes(1);
			logf("journal: %s; still appending to %s, retrying in 1m", rotate_error_.c_str(), journal_path_.c_str());
			return;
		}
		rotate_pending_ = true;  // journal_fd_ now appends to the .1 segment
	}
	std::string err;
	long long size = 0;
	int fd = open_segment(&err, &size);
	if (fd < 0) {
		// Nothing is lost: records keep going to the .1 segment (replayed at
		// start) until a new segment can be opened.
		rotate_error_ = "rotate: open new segment: " + err;
		rotate_retry_at_ = mono + rotate_retry;
		if (rotate_logged_ == Mono::time_point{} || mono - rotate_logged_ > minutes(1)) {
			rotate_logged_ = mono;
			logf("journal: %s; still appending to %s.1, retrying", rotate_error_.c_str(), journal_path_.c_str());
		}
		return;
	}
	::close(journal_fd_);
	journal_fd_ = fd;
	journal_size_ = size;
	rotate_pending_ = false;
	rotate_error_.clear();
	need_newline_ = false;
	logf("journal: rotated at %lld MiB", journal_max >> 20);
}

// Search-index classes: security records keep their own window so bulk
// telemetry (reconnect hellos, inventory baselines, flows) cannot evict them.
static bool security_record(const std::string &type, const json &m) {
	if (type == "lifecycle") {
		auto c = m.find("change");
		return c != m.end() && c->is_string() && c->get<std::string>() == "decommissioned";
	}
	return type == "alert" || type == "triage" || type == "rollout" || type == "rollout_intent" ||
	       type == "suggestion" || type == "suggestion_decision";
}

void Store::index_event(const std::string &raw) {
	json m;
	try {
		m = json::parse(raw);
	} catch (...) {
		return;
	}
	if (!m.is_object())
		return;
	auto t = m.find("type");
	std::string type = t != m.end() && t->is_string() ? t->get<std::string>() : "";
	// AI job records hold operators' questions and answers: operator-only
	// (/api/ai/jobs), so not searchable by viewers through /api/events.
	if (type == "ai_result" || type == "journal")
		return;
	Window &w = security_record(type, m) ? security_ : telemetry_;
	std::string ts = m.contains("ts") && m["ts"].is_string() ? m["ts"].get<std::string>() : "";
	size_t cost = raw.size() * 3 + 256;  // the raw line plus its parsed DOM, roughly
	w.entries.push_back({++event_seq_, cost, std::move(ts), raw, std::move(m)});
	w.bytes += cost;
	while (!w.entries.empty() && (w.entries.size() > journal_keep || w.bytes > journal_keep_bytes)) {
		w.bytes -= w.entries.front().cost;
		w.entries.pop_front();
	}
}

void Store::record(const std::string &raw, bool sync) {
	if (journal_fd_ >= 0) {
		std::string line;
		line.reserve(raw.size() + 2);
		if (need_newline_)
			line += '\n';
		line += raw;
		line += '\n';
		size_t off = 0;
		int err = 0;
		if (!write_all(journal_fd_, line, &off, &err)) {
			// Take the partial line back so the next record starts on a line of
			// its own; if that fails too, the next record starts with '\n'.
			struct stat st;
			bool undone = off == 0 || (fstat(journal_fd_, &st) == 0 && st.st_size >= (off_t)off &&
			                           ftruncate(journal_fd_, st.st_size - (off_t)off) == 0);
			if (!undone)
				need_newline_ = true;
			journal_failure("write", err);
		} else {
			need_newline_ = false;
			journal_size_ += (long long)off;
			if (!health_.ok) {
				logf("journal: writes to %s succeed again (%llu failed while it was failing)", journal_path_.c_str(),
				     health_.write_errors);
				health_.ok = true;
				health_.failing_since = TimePoint{};
				write_error_.clear();
				journal_ok_ = true;
			}
			if (sync)
				(void)fdatasync(journal_fd_);
		}
		if (journal_max > 0 && (journal_size_ > journal_max || rotate_pending_))
			rotate();
	}
	index_event(raw);
}

void Store::close_journal() {
	std::unique_lock lk(mu_);
	if (journal_fd_ >= 0) {
		fsync(journal_fd_);
		::close(journal_fd_);
		journal_fd_ = -1;
	}
	journal_closed_ = true;
}

JournalHealth Store::journal_health() {
	std::shared_lock lk(mu_);
	JournalHealth h = health_;
	h.path = journal_path_;
	h.rotate_pending = rotate_pending_;
	h.error = !write_error_.empty() ? write_error_ : rotate_error_;
	if (journal_fd_ < 0 && !journal_path_.empty() && !journal_closed_) {
		h.ok = false;
		h.error = "journal is not open";
	}
	return h;
}

// ---- state ------------------------------------------------------------------

Host &Store::host_ref(const std::string &name, const std::string &group, TimePoint at, bool replay) {
	auto [it, created] = hosts_.try_emplace(name);
	Host &h = it->second;
	if (created) {
		h.name = name;
		h.group = group;
	}
	if (!group.empty())
		h.group = group;
	if (!is_zero(at)) {
		if (is_zero(h.first_seen) || at < h.first_seen)
			h.first_seen = at;
		// Live records carry the console's clock now, which wins even after a
		// backward step; replayed ones only ever move it forward.
		if (!replay || at > h.last_seen)
			h.last_seen = at;
		if (replay && at > h.journaled_seen)
			h.journaled_seen = at;
	}
	return h;
}

std::string Store::host_state(const Host &h, TimePoint now) const {
	if (!h.decommissioned.empty())
		return "decommissioned";
	// Heard from since this process started: judge silence on the monotonic
	// clock. Otherwise (replayed only) the wall clock is all there is.
	auto silent = h.last_contact != Mono::time_point{} ? duration_cast<nanoseconds>(Mono::now() - h.last_contact)
	                                                    : duration_cast<nanoseconds>(now - h.last_seen);
	return silent > stale_after ? "stale" : "active";
}

// A known host presenting a different (or no, or a weaker) identity is a
// spoofing or re-imaging signal: alert, and never let it erase the record.
// While a connection presenting the recorded identity is live, the recorded
// identity is kept (e.id_kept) and that connection keeps receiving control
// lines; otherwise (the original is gone, e.g. re-imaged) the new one is
// recorded.
void Store::identity_check(Event &e) {
	auto it = hosts_.find(e.host);
	if (it == hosts_.end() || it->second.host_id.empty())
		return;
	const Host &h = it->second;
	auto original_live = [&] {
		auto l = links_.find(e.host);
		if (l == links_.end())
			return false;
		for (auto &x : l->second)
			if (x.host_id == h.host_id && trust_rank(x.trust) >= trust_rank(h.trust))
				return true;
		return false;
	};
	std::string why;
	bool kept = false;
	if (e.host_id.empty()) {
		why = "Host identity missing (was " + clip(h.host_id) + "; the hello presented none)";
		kept = true;
	} else if (e.host_id != h.host_id) {
		why = "Host identity changed (was " + clip(h.host_id) + ", now " + clip(e.host_id) + ")";
		kept = original_live();
	} else if (trust_rank(e.trust) < trust_rank(h.trust)) {
		why = "Host identity trust downgraded (was " + clip(h.trust, 16) + ", now " +
		      clip(e.trust.empty() ? "none" : e.trust, 16) + ")";
		kept = original_live();
	} else {
		return;
	}
	if (kept)
		why += e.host_id.empty() ? "; the recorded identity was kept"
		                         : "; the recorded identity was kept: a sensor presenting it is still connected";
	e.id_kept = kept;
	console_alert("HOST-ID-MISMATCH", "high", e.host, why,
	              "a sensor presented a different host identity for an existing hostname");
}

void Store::ingest(Event e, std::string raw) {
	std::vector<Event> notify_now;
	{
		std::unique_lock lk(mu_);
		ingest_locked(e, std::move(raw), notify_now);
	}
	if (notify)
		for (auto &a : notify_now)
			notify(a);
}

void Store::ingest_locked(Event &e, std::string raw, std::vector<Event> &notify_now) {
	auto now = Clock::now();
	std::string rx = fmt_ts_ms(now);
	json add = json::object();
	if (e.type == "alert") {
		alert_seq_++;
		e.id = "A" + std::to_string(unix_now()) + "-" + std::to_string(alert_seq_);
		e.status = "open";
		add["id"] = e.id;
		add["status"] = e.status;
	}
	if (e.type == "hello") {
		identity_check(e);
		if (e.id_kept)
			add["id_kept"] = true;
	}
	// Some sensor records (hello, bye) carry no timestamp; stamp receipt time.
	if (e.ts.empty()) {
		e.ts = rx;
		add["ts"] = e.ts;
	}
	// The receipt time is what replay trusts for host first/last seen; the
	// sensor's own ts is only its claim.
	e.rx_ts = rx;
	add["rx_ts"] = rx;
	// Heartbeats are not journaled, nor are inventory records that only
	// repeat what the console already knows (every reconnect re-sends the
	// baseline): they would flood the journal and the search index.
	bool journal = e.type != "heartbeat" && !inventory_unchanged(e);
	if (journal)
		record(with_fields(raw, add));
	apply(e, now, false);
	if (journal && !e.host.empty())
		if (auto it = hosts_.find(e.host); it != hosts_.end())
			it->second.journaled_seen = now;
	for (auto &a : pending_notify_)
		notify_now.push_back(std::move(a));
	pending_notify_.clear();
}

void Store::add_alert(const Event &e, bool replay) {
	auto a = std::make_shared<Event>(e);
	if (a->status.empty())
		a->status = "open";
	if (a->id.empty()) {
		// A journal written by a console older than 1.0: derive the ID from
		// the alert's content, so it does not shift when rotation drops older
		// alerts. The old positional ID ("R<n>") is kept as an alias for
		// triage records that used it, during this replay only.
		alert_seq_++;
		auto d = sha256(a->ts + "\x1f" + a->host + "\x1f" + a->rule + "\x1f" + std::to_string(a->pid) + "\x1f" +
		                a->cmd + "\x1f" + a->title);
		std::string base = "R" + hex_encode(d.data(), 8), id = base;
		for (int k = 2; alert_by_id_.count(id); k++)
			id = base + "-" + std::to_string(k);
		a->id = id;
		if (replay)
			legacy_alias_["R" + std::to_string(++legacy_seq_)] = id;
	}
	alert_by_id_[a->id] = a;
	alerts_.push(a->host, a, max_ring, [&](const std::shared_ptr<Event> &old) {
		auto f = alert_by_id_.find(old->id);
		if (f != alert_by_id_.end() && f->second == old)
			alert_by_id_.erase(f);
	});
	if (!replay && !slack_.empty() && (e.severity == "high" || e.severity == "critical"))
		pending_notify_.push_back(*a);
}

static std::string inv_key(const Event &e) { return e.kind + "|" + to_lower(e.name) + "|" + e.where; }

// Rough memory held by one Event (its strings plus the struct itself).
static size_t event_bytes(const Event &e) {
	size_t n = sizeof(Event);
	for (const std::string *f : {&e.id,      &e.ts,     &e.type,   &e.host,   &e.group,  &e.rule,     &e.mitre,
	                             &e.title,   &e.severity, &e.action, &e.actor, &e.actor_src, &e.comm, &e.exe,
	                             &e.cmd,     &e.dest,   &e.kind,   &e.name,   &e.version, &e.host_id, &e.trust,
	                             &e.where,   &e.change, &e.path,   &e.mode,   &e.reason, &e.status,   &e.note,
	                             &e.triaged_by, &e.triaged_at, &e.by, &e.rx_ts, &e.src})
		n += f->size();
	for (const auto *v : {&e.runtimes, &e.cohort, &e.delivered, &e.failed, &e.send_failed})
		for (auto &x : *v)
			n += x.size() + sizeof(std::string);
	return n;
}

bool Store::inventory_unchanged(const Event &e) const {
	if (e.type != "inventory" || e.change != "present")
		return false;
	auto h = inv_.find(e.host);
	if (h == inv_.end())
		return false;
	auto it = h->second.items.find(inv_key(e));
	return it != h->second.items.end() && it->second.e.version == e.version;
}

// Keeps the host's current package state; true when this record changed it
// (and so belongs in the change history).
bool Store::inventory_update(const Event &e, bool replay) {
	auto &st = inv_[e.host];
	std::string key = inv_key(e);
	auto stamp = replay ? Mono::time_point{} : Mono::now();
	auto it = st.items.find(key);
	if (e.change == "removed") {
		if (it != st.items.end()) {
			st.bytes -= std::min(st.bytes, event_bytes(it->second.e) + key.size());
			st.items.erase(it);
		}
		return true;
	}
	size_t cost = event_bytes(e) + key.size();
	if (it != st.items.end()) {
		bool same = it->second.e.version == e.version && e.change == "present";
		st.bytes -= std::min(st.bytes, event_bytes(it->second.e) + key.size());
		st.bytes += cost;
		it->second.e = e;
		if (!replay)
			it->second.confirmed = stamp;
		return !same;
	}
	if (st.items.size() >= max_inventory_per_host || st.bytes + cost > max_inventory_bytes_per_host) {
		// Recorded in history, but this host's state is full: its packages
		// past the cap are not checked for vulnerabilities. Say so once.
		if (!st.full_logged && !replay) {
			st.full_logged = true;
			logf("inventory: host %s reports more than %zu packages (%zu KiB); the rest are kept only in history "
			     "and are not checked for vulnerabilities",
			     e.host.c_str(), st.items.size(), st.bytes >> 10);
		}
		return true;
	}
	st.items[key] = {e, stamp};
	st.bytes += cost;
	return true;
}

void Store::apply(const Event &e, TimePoint at, bool replay) {
	bump();
	if (e.type == "triage") {
		auto it = alert_by_id_.find(e.id);
		if (it == alert_by_id_.end() && replay)
			if (auto al = legacy_alias_.find(e.id); al != legacy_alias_.end())
				it = alert_by_id_.find(al->second);
		if (it != alert_by_id_.end()) {
			auto &a = *it->second;
			// The record names the alert it was written for; never apply it to
			// a different one (old positional IDs shift after a rotation).
			if ((!e.host.empty() && e.host != a.host) || (!e.rule.empty() && e.rule != a.rule))
				return;
			a.status = e.status;
			a.note = e.note;
			a.triaged_by = e.by;
			a.triaged_at = e.ts;
		}
		return;
	}
	if (e.type == "rollout" || e.type == "rollout_intent") {
		Rollout r{parse_ts(e.ts), e.by, e.action, e.group, (int)e.percent, e.cohort, e.delivered, e.failed,
		          e.id,           "",   e.send_failed};
		if (e.type == "rollout_intent") {
			if (replay && !e.id.empty()) {
				r.status = "interrupted";
				intents_[e.id] = r;
			}
			return;
		}
		if (!e.id.empty())
			intents_.erase(e.id);
		rollouts_.push_back(std::move(r));
		while (rollouts_.size() > max_rollouts)
			rollouts_.erase(rollouts_.begin());
		return;
	}
	if (e.host.empty() || e.type == "journal")
		return;
	if (e.host == "console") {
		// The console's own audit alerts (VAULT-ACCESS): kept as alerts, but
		// "console" is not a fleet host (no host entry, rollout target, ...).
		if (e.type == "alert")
			add_alert(e, replay);
		return;
	}
	Host &h = host_ref(e.host, e.group, at, replay);
	if (!replay)
		h.last_contact = Mono::now();
	if (e.type == "hello") {
		if (!e.id_kept) {
			h.version = e.version;
			// An id-less hello never erases a recorded identity.
			if (!e.host_id.empty() || h.host_id.empty()) {
				h.host_id = e.host_id;
				h.trust = e.trust;
			}
			h.ephemeral = e.ephemeral;
		}
		h.decommissioned.clear();  // a returning host is provisioned again
		h.decommissioned_at = TimePoint{};
		if (!replay) {  // the sensor now re-sends its whole inventory
			auto &iv = inv_[h.name];
			iv.baseline = Mono::now();
			iv.swept = false;
		}
	} else if (e.type == "lifecycle") {
		if (e.change == "decommissioned") {
			h.decommissioned = e.reason;
			h.decommissioned_at = at;
			inv_.erase(h.name);
		}
		// "disconnected" and "seen" only carry liveness (host_ref above).
	} else if (e.type == "bye") {
		// Only an ephemeral runner/container is retired on exit. A persistent
		// host that stops (restart, upgrade, maintenance) just goes stale and
		// is reaped later if it never comes back.
		if (replay)
			return;
		if (h.ephemeral)
			decommission(h, e.reason.empty() ? "agent exit" : e.reason);
		else
			logf("lifecycle: host %s stopped (%s); will go stale", h.name.c_str(), e.reason.c_str());
	} else if (e.type == "heartbeat") {
		h.execs = e.execs;
		h.cpu_pct = e.cpu_pct;
		h.peak_cpu = std::max(h.peak_cpu, e.cpu_pct);
		h.rss_kb = e.rss_kb;
		if (!e.mode.empty())
			h.mode = e.mode;
		if (e.has_runtimes)
			h.runtimes = e.runtimes;
	} else if (e.type == "alert") {
		h.alerts++;
		add_alert(e, replay);
	} else if (e.type == "inventory") {
		if (inventory_update(e, replay))
			inventory_.push(e.host, e, max_ring, [](const Event &) {});
	}
}

void Store::console_alert(const std::string &rule, const std::string &sev, const std::string &host,
                          const std::string &title, const std::string &cmd) {
	alert_seq_++;
	Event e;
	e.id = "A" + std::to_string(unix_now()) + "-" + std::to_string(alert_seq_);
	e.ts = now_ts();
	e.type = "alert";
	e.host = host;
	e.rule = rule;
	e.severity = sev;
	e.title = title;
	e.action = "alert";
	e.cmd = cmd;
	e.actor = "console";
	e.status = "open";
	e.src = "console";
	record(event_to_json(e).dump());
	apply(e, Clock::now(), false);
}

void Store::lifecycle_record(Host &h, const std::string &change, const std::string &reason) {
	Event e;
	e.ts = now_ts();
	e.type = "lifecycle";
	e.host = h.name;
	e.group = h.group;
	e.change = change;
	e.reason = reason;
	e.src = "console";
	record(event_to_json(e).dump());
	h.journaled_seen = Clock::now();
}

void Store::decommission(Host &h, const std::string &reason) {
	if (!h.decommissioned.empty())
		return;
	h.decommissioned = reason;
	h.decommissioned_at = Clock::now();
	if (auto it = links_.find(h.name); it != links_.end()) {
		for (auto &l : it->second)
			l.link->shutdown();  // non-blocking: wakes the reader, which tears down
		links_.erase(it);
	}
	conns_.erase(h.name);
	h.connected = false;
	inv_.erase(h.name);
	lifecycle_record(h, "decommissioned", reason);
	logf("lifecycle: host %s decommissioned (%s)", h.name.c_str(), reason.c_str());
	bump();
}

void Store::reap() {
	std::unique_lock lk(mu_);
	auto now = Clock::now();
	auto mono = Mono::now();
	bool changed = false;
	// 1. Retire persistent hosts that have been silent too long. Never one
	// with a live connection (a wall-clock step must not disconnect the
	// fleet), and not one unheard-of since start until it had time to
	// reconnect (heartbeats are not journaled, so replay understates liveness).
	if (decom_after > nanoseconds(0)) {
		bool in_grace = mono - started_ < reap_grace;
		for (auto &[name, h] : hosts_) {
			if (!h.decommissioned.empty() || links_.count(name))
				continue;
			bool live = h.last_contact != Mono::time_point{};
			if (!live && in_grace)
				continue;
			auto silent = live ? duration_cast<nanoseconds>(mono - h.last_contact)
			                   : duration_cast<nanoseconds>(now - h.last_seen);
			if (silent > decom_after)
				decommission(h, "silent for " + fmt_duration(decom_after));
		}
	}
	// 2. Liveness markers: a quiet connected host may journal nothing for
	// days; after a crash its replayed last_seen would be that old.
	nanoseconds every = hours(24);
	if (decom_after > nanoseconds(0))
		every = std::clamp<nanoseconds>(decom_after / 4, minutes(1), hours(24));
	for (auto &[name, _] : links_)
		if (auto h = hosts_.find(name); h != hosts_.end() && h->second.decommissioned.empty() &&
		                                now - h->second.journaled_seen > every)
			lifecycle_record(h->second, "seen", "");
	// 3. A reconnected sensor has re-sent its inventory: whatever it did not
	// report again was removed while the console was not listening.
	for (auto &[name, iv] : inv_) {
		if (iv.swept || mono - iv.baseline < inventory_grace)
			continue;
		iv.swept = true;
		if (!links_.count(name))
			continue;  // the connection dropped mid-baseline: keep what we know
		for (auto it = iv.items.begin(); it != iv.items.end();) {
			if (it->second.confirmed >= iv.baseline) {
				++it;
				continue;
			}
			Event r = it->second.e;
			r.ts = now_ts();
			r.rx_ts.clear();
			r.change = "removed";
			r.reason = "not in the sensor's inventory after it reconnected";
			r.src = "console";
			record(event_to_json(r).dump());
			inventory_.push(r.host, r, max_ring, [](const Event &) {});
			iv.bytes -= std::min(iv.bytes, event_bytes(it->second.e) + it->first.size());
			it = iv.items.erase(it);
			changed = true;
		}
	}
	// 4. Forget long-decommissioned hosts (their history stays in the
	// journal): ephemeral runners with unique names would otherwise grow
	// hosts_ for as long as the console runs.
	std::vector<std::pair<TimePoint, std::string>> retired;
	for (auto &[name, h] : hosts_)
		if (!h.decommissioned.empty() && !links_.count(name))
			retired.emplace_back(h.decommissioned_at, name);
	std::sort(retired.begin(), retired.end());
	size_t excess = retired.size() > max_decommissioned ? retired.size() - max_decommissioned : 0;
	for (size_t i = 0; i < retired.size(); i++) {
		auto it = hosts_.find(retired[i].second);
		auto keep = it->second.ephemeral ? ephemeral_retention : decom_retention;
		if (i < excess || (!is_zero(it->second.decommissioned_at) && now - it->second.decommissioned_at > keep)) {
			inv_.erase(it->first);
			hosts_.erase(it);
			changed = true;
		}
	}
	if (changed)
		bump();
}

// ---- sensor ingest ------------------------------------------------------------

// Per-connection admission: one sensor (or a stolen sensor certificate) must
// not be able to exhaust the console's memory or flood the shared journal.
bool Store::admit(SensorSession &s, size_t len) {
	auto now = Mono::now();
	if (s.line_tokens < 0) {
		s.line_tokens = sensor_line_burst;
		s.byte_tokens = sensor_byte_burst;
	} else {
		double dt = duration<double>(now - s.refilled).count();
		s.line_tokens = std::min(sensor_line_burst, s.line_tokens + dt * sensor_lines_per_s);
		s.byte_tokens = std::min(sensor_byte_burst, s.byte_tokens + dt * sensor_bytes_per_s);
	}
	s.refilled = now;
	const char *why = nullptr;
	if (len > sensor_max_line)
		why = "line too long";
	else if (s.line_tokens < 1 || s.byte_tokens < (double)len)
		why = "rate limit";
	if (!why) {
		s.line_tokens -= 1;
		s.byte_tokens -= (double)len;
		return true;
	}
	s.dropped++;
	if (!s.host.empty()) {
		std::unique_lock lk(mu_);
		if (auto h = hosts_.find(s.host); h != hosts_.end())
			h->second.dropped_lines++;
	}
	if (s.drop_logged == Mono::time_point{} || now - s.drop_logged > minutes(1)) {
		logf("sensor %s: refused %llu line(s) (%s; limits: %zu-byte lines, %.0f lines/s, %.0f bytes/s)",
		     s.host.empty() ? "(before hello)" : s.host.c_str(), s.dropped, why, sensor_max_line, sensor_lines_per_s,
		     sensor_bytes_per_s);
		s.dropped = 0;
		s.drop_logged = now;
	}
	return false;
}

// The live connection that receives control lines for a host: the newest one
// presenting the recorded identity, else the newest one.
void Store::choose_link(const std::string &host) {
	auto it = links_.find(host);
	if (it == links_.end() || it->second.empty()) {
		conns_.erase(host);
		return;
	}
	auto h = hosts_.find(host);
	const LiveLink *best = nullptr;
	bool best_match = false;
	for (auto &l : it->second) {
		bool match = h == hosts_.end() || h->second.host_id.empty() ||
		             (l.host_id == h->second.host_id && trust_rank(l.trust) >= trust_rank(h->second.trust));
		if (!best || (match && !best_match) || (match == best_match && l.seq > best->seq)) {
			best = &l;
			best_match = match;
		}
	}
	conns_[host] = best->link;
}

void Store::sensor_line(SensorSession &s, const std::string &line) {
	if (!admit(s, line.size()))
		return;
	json j;
	try {
		j = json::parse(line);
	} catch (...) {
		return;
	}
	if (!j.is_object())
		return;
	Event e = event_from_json(j);
	if (e.host.empty() || e.type.empty())
		return;
	// Console-only fields are never accepted from a sensor.
	e.id.clear();
	e.status.clear();
	e.note.clear();
	e.triaged_by.clear();
	e.triaged_at.clear();
	e.percent = 0;
	e.cohort.clear();
	e.delivered.clear();
	e.failed.clear();
	e.by.clear();
	e.rx_ts.clear();
	e.src.clear();
	e.id_kept = false;
	e.send_failed.clear();
	if (console_only_type(e.type) || e.host == "console")
		return;  // console-only record types, and the console's reserved name
	if (e.type == "hello") {
		if (!s.host.empty() && e.host != s.host)
			return;  // a connection speaks for one host for its whole life
	} else if (s.host.empty() || e.host != s.host) {
		return;  // ...named by its hello
	}
	std::vector<Event> notify_now;
	size_t live = 0;
	{
		std::unique_lock lk(mu_);
		if (e.type == "bye") {
			// Only the connection that receives the host's control lines may
			// retire it: a second connection for the name (an impostor whose
			// identity was refused, or a stray debug copy) must not decommission
			// the host and cut off the real sensor.
			auto c = conns_.find(e.host);
			if (c == conns_.end() || c->second != s.link)
				return;
		}
		ingest_locked(e, sanitize(line), notify_now);
		if (e.type == "hello") {
			auto &v = links_[e.host];
			auto it = std::find_if(v.begin(), v.end(), [&](const LiveLink &l) { return l.link == s.link; });
			if (it == v.end())
				v.push_back({s.link, e.host_id, e.trust, ++link_seq_});
			else {
				it->host_id = e.host_id;
				it->trust = e.trust;
			}
			live = v.size();
			choose_link(e.host);
			if (auto h = hosts_.find(e.host); h != hosts_.end())
				h->second.connected = true;
			bump();
		}
	}
	if (e.type == "hello") {
		s.host = e.host;
		logf("sensor connected: host=%s group=%s version=%s trust=%s%s", e.host.c_str(), e.group.c_str(),
		     e.version.c_str(), e.trust.c_str(),
		     live > 1 ? (" (" + std::to_string(live) + " live connections for this host)").c_str() : "");
	}
	if (notify)
		for (auto &a : notify_now)
			notify(a);
}

void Store::sensor_closed(SensorSession &s) {
	std::unique_lock lk(mu_);
	if (s.host.empty())
		return;  // never identified
	auto it = links_.find(s.host);
	if (it == links_.end())
		return;  // decommissioned meanwhile
	auto &v = it->second;
	auto li = std::find_if(v.begin(), v.end(), [&](const LiveLink &l) { return l.link == s.link; });
	if (li == v.end())
		return;
	v.erase(li);
	if (!v.empty()) {
		// Another live connection speaks for this host: it stays connected
		// and that connection takes over control lines.
		choose_link(s.host);
		bump();
		return;
	}
	links_.erase(it);
	conns_.erase(s.host);
	auto h = hosts_.find(s.host);
	if (h == hosts_.end())
		return;
	h->second.connected = false;
	bump();
	if (stopping_)
		return;  // the console is shutting down: shutdown_links() journaled it
	// An ephemeral runner/container that drops its connection is gone:
	// decommission it now rather than waiting for it to go stale.
	if (h->second.ephemeral)
		decommission(h->second, "ephemeral connection closed");
	else
		lifecycle_record(h->second, "disconnected", "connection closed");
}

int Store::push_one(const std::string &host, const std::string &cmd) {
	std::shared_ptr<SensorLink> link;
	{
		std::shared_lock lk(mu_);
		auto it = conns_.find(host);
		if (it == conns_.end())
			return 1;
		link = it->second;
	}
	return link->send(cmd) ? 0 : 2;
}

bool Store::push_control(const std::string &host, const std::string &cmd) { return push_one(host, cmd) == 0; }

void Store::shutdown_links() {
	std::unique_lock lk(mu_);
	stopping_ = true;
	for (auto &[name, v] : links_) {
		// The console is going away, not the hosts: record that they were
		// connected until now, and do not retire ephemeral ones.
		if (auto h = hosts_.find(name); h != hosts_.end() && h->second.decommissioned.empty())
			lifecycle_record(h->second, "disconnected", "console shutdown");
		for (auto &l : v)
			l.link->shutdown();
	}
}

// ---- read models ----------------------------------------------------------------

static std::string first(const Query &q, const std::string &k) {
	auto it = q.find(k);
	return it == q.end() || it->second.empty() ? std::string() : it->second.front();
}

json Store::host_list(const std::string &state, const std::string &group) {
	std::shared_lock lk(mu_);
	auto now = Clock::now();
	json out = json::array();
	for (auto &[_, h] : hosts_) {  // std::map: sorted by name
		Host c = h;
		c.state = host_state(h, now);
		if (!group.empty() && c.group != group)
			continue;
		if (state == "all" || c.state == state || (state.empty() && c.state != "decommissioned"))
			out.push_back(host_to_json(c));
	}
	return out;
}

std::optional<Host> Store::host_snapshot(const std::string &name) {
	std::shared_lock lk(mu_);
	auto it = hosts_.find(name);
	if (it == hosts_.end())
		return std::nullopt;
	Host h = it->second;
	h.state = host_state(h, Clock::now());
	return h;
}

static json posture_to_json(const Posture &p) {
	json v = json::object(), a = json::object();
	for (auto &[k, n] : p.vulns)
		v[k] = n;
	for (auto &[k, n] : p.alerts_by_severity)
		a[k] = n;
	return {{"host", p.host},
	        {"score", p.score},
	        {"grade", p.grade},
	        {"trust", p.trust},
	        {"mode", p.mode},
	        {"vulns", v},
	        {"unsanctioned_tooling", p.unsanctioned},
	        {"anomalies", p.anomalies},
	        {"alerts_by_severity", a},
	        {"findings", p.findings}};
}

std::optional<json> Store::host_detail(const std::string &name) {
	auto postures = posture().second;
	std::shared_lock lk(mu_);
	auto it = hosts_.find(name);
	if (it == hosts_.end())
		return std::nullopt;
	Host h = it->second;
	h.state = host_state(h, Clock::now());
	json d = {{"host", host_to_json(h)}, {"alerts", json::array()}, {"inventory", json::array()}};
	for (auto &p : postures)
		if (p.host == name)
			d["posture"] = posture_to_json(p);
	for (auto a = alerts_.items.rbegin(); a != alerts_.items.rend() && d["alerts"].size() < 100; ++a)
		if ((*a)->host == name)
			d["alerts"].push_back(event_to_json(**a));
	if (auto iv = inv_.find(name); iv != inv_.end())
		for (auto &[_, item] : iv->second.items)  // key order: kind, lowercase name, location
			d["inventory"].push_back(event_to_json(item.e));
	return d;
}

static int sev_rank(const std::string &s) {
	if (s == "critical") return 5;
	if (s == "high") return 4;
	if (s == "medium") return 3;
	if (s == "low") return 2;
	if (s == "info") return 1;
	return 0;
}

json Store::alert_list(const Query &q) {
	long limit = 500;
	try {
		long l = std::stol(first(q, "limit"));
		if (l > 0 && l <= 5000)
			limit = l;
	} catch (...) {
	}
	int min_sev = sev_rank(first(q, "severity"));
	std::string status = first(q, "status");
	if (status == "all")
		status.clear();
	const std::string host = first(q, "host"), rule = first(q, "rule"), actor = first(q, "actor");
	std::string text = to_lower(first(q, "q"));
	std::shared_lock lk(mu_);
	json out = json::array();
	for (auto it = alerts_.items.rbegin(); it != alerts_.items.rend() && (long)out.size() < limit; ++it) {
		const Event &a = **it;
		if ((min_sev > 0 && sev_rank(a.severity) < min_sev) || (!status.empty() && a.status != status) ||
		    (!host.empty() && a.host != host) || (!rule.empty() && a.rule != rule) ||
		    (!actor.empty() && a.actor != actor))
			continue;
		if (!text.empty() &&
		    !contains(to_lower(a.rule + " " + a.title + " " + a.cmd + " " + a.host + " " + a.comm + " " + a.exe), text))
			continue;
		out.push_back(event_to_json(a));
	}
	return out;
}

// The value of a field as text, for exact-match filtering. Numbers print
// without exponent or trailing zeros (4242, 0.25), as the Go console did.
static std::string field_string(const json &v) {
	if (v.is_null())
		return "";
	if (v.is_string())
		return v.get<std::string>();
	if (v.is_boolean())
		return v.get<bool>() ? "true" : "false";
	if (v.is_number_integer())
		return v.dump();
	if (v.is_number_float()) {
		char b[64];
		snprintf(b, sizeof b, "%.17g", v.get<double>());
		double d = v.get<double>();
		for (int prec = 1; prec <= 17; prec++) {  // shortest round-tripping form, fixed notation
			snprintf(b, sizeof b, "%.*f", prec, d);
			if (strtod(b, nullptr) == d)
				break;
		}
		std::string s = b;
		if (s.find('.') != std::string::npos) {
			while (s.back() == '0')
				s.pop_back();
			if (s.back() == '.')
				s.pop_back();
		}
		return s;
	}
	return v.dump();
}

json Store::search_events(const Query &q) {
	long limit = 500;
	try {
		long l = std::stol(first(q, "limit"));
		if (l > 0)
			limit = l;
	} catch (...) {
	}
	const std::string since = first(q, "since"), until = first(q, "until"), text = first(q, "q");
	std::shared_lock lk(mu_);
	json out = json::array();
	// Newest first across both windows (security records and telemetry).
	auto a = security_.entries.rbegin(), ae = security_.entries.rend();
	auto b = telemetry_.entries.rbegin(), be = telemetry_.entries.rend();
	while ((a != ae || b != be) && (long)out.size() < limit) {
		const JournalEntry &e = (b == be || (a != ae && a->seq > b->seq)) ? *a++ : *b++;
		if ((!since.empty() && e.ts < since) || (!until.empty() && e.ts >= until))
			continue;
		if (!text.empty() && !contains(e.raw, text))
			continue;
		bool ok = true;
		for (auto &[k, vs] : q) {
			if (k == "limit" || k == "since" || k == "until" || k == "q")
				continue;
			auto f = e.m.find(k);
			if (field_string(f == e.m.end() ? json() : *f) != (vs.empty() ? "" : vs.front())) {
				ok = false;
				break;
			}
		}
		if (ok)
			out.push_back(e.m);
	}
	return out;  // newest first
}

json Store::inventory_json(const std::string &host) {
	std::shared_lock lk(mu_);
	json out = json::array();
	for (auto it = inventory_.items.rbegin(); it != inventory_.items.rend() && out.size() < 1000; ++it)
		if (host.empty() || it->host == host)
			out.push_back(event_to_json(*it));
	return out;
}

static int tier_rank(const std::string &t) {
	if (t == "exploited") return 5;
	if (t == "vulnerable") return 4;
	if (t == "reachable") return 3;
	if (t == "dormant") return 2;
	if (t == "theoretical") return 1;
	return 0;
}

std::vector<Finding> Store::vuln_findings() {
	std::shared_lock lk(mu_);
	return vuln_findings_locked();
}

static bool name_char(unsigned char c) { return std::isalnum(c) || c == '_' || c == '-'; }

// `name` occurs in `text` as a whole package name, not inside a longer word:
// "ws" matches "npm i ws@7" and "node_modules/ws/", never ".aws/credentials"
// or "news".
static bool mentions(std::string_view text, std::string_view name) {
	if (name.empty())
		return false;
	for (size_t p = text.find(name); p != std::string_view::npos; p = text.find(name, p + 1)) {
		size_t end = p + name.size();
		if ((p == 0 || !name_char((unsigned char)text[p - 1])) &&
		    (end == text.size() || !name_char((unsigned char)text[end])))
			return true;
	}
	return false;
}

std::vector<Finding> Store::vuln_findings_locked() {
	// Exploitation signals: package names that appear in any alert, per host.
	std::set<std::string> names;
	for (auto &v : vulndb.list)
		names.insert(to_lower(v.name));
	std::set<std::string> exploited;  // host|lowercase name
	for (auto &ap : alerts_.items) {
		std::string text = to_lower(ap->cmd + " " + ap->name + " " + ap->title);
		for (auto &n : names)
			if (mentions(text, n))
				exploited.insert(ap->host + "|" + n);
	}
	// Current packages per host (the inventory state, not a window of events).
	struct Inv {
		std::string host, eco, name, ver;
	};
	std::vector<Inv> present;
	std::set<std::string> seen;  // one finding per host|eco|name|version, whatever the install location
	for (auto &[host, iv] : inv_)
		for (auto &[_, it] : iv.items) {
			const Event &e = it.e;
			if (seen.insert(host + "|" + e.kind + "|" + to_lower(e.name) + "|" + e.version).second)
				present.push_back({host, e.kind, e.name, e.version});
		}
	std::vector<Finding> out;
	for (auto &it : present) {
		auto vs = vulndb.by_key.find(it.eco + "|" + to_lower(it.name));
		if (vs == vulndb.by_key.end())
			continue;
		for (auto &v : vs->second) {
			// Tiers are only what the sensor can actually observe:
			//   exploited   - an alert on this host involves the package
			//   reachable   - an affected version is installed and its runtime
			//                 (node, python, ...) is executing on the host
			//   dormant     - an affected version is installed, runtime not seen
			//   theoretical - installed, but its version is unknown
			// io.security's "vulnerable" tier (the vulnerable code is loaded)
			// needs module-load visibility the sensor does not have.
			std::string tier;
			if (it.ver.empty())
				tier = "theoretical";
			else if (!v.affects(it.ver))
				continue;  // a fixed / unaffected version
			else if (exploited.count(it.host + "|" + to_lower(it.name)))
				tier = "exploited";
			else {
				auto h = hosts_.find(it.host);
				tier = h != hosts_.end() && h->second.runtime_active(it.eco) ? "reachable" : "dormant";
			}
			out.push_back({it.host, it.eco, it.name, it.ver, v.cve, v.severity, tier, v.note, v.cvss});
		}
	}
	std::stable_sort(out.begin(), out.end(), [](const Finding &a, const Finding &b) {
		if (tier_rank(a.tier) != tier_rank(b.tier))
			return tier_rank(a.tier) > tier_rank(b.tier);
		return a.cvss > b.cvss;
	});
	return out;
}

json Store::vulns_json() {
	json out = json::array();
	for (auto &f : vuln_findings())
		out.push_back({{"host", f.host},
		               {"ecosystem", f.ecosystem},
		               {"name", f.name},
		               {"version", f.version},
		               {"cve", f.cve},
		               {"severity", f.severity},
		               {"cvss", f.cvss},
		               {"tier", f.tier},
		               {"note", f.note}});
	return out;
}

static std::string word(int n, const char *one, const char *many) { return n == 1 ? one : many; }

std::pair<int, std::vector<Posture>> Store::posture() {
	auto vf = vuln_findings();
	std::shared_lock lk(mu_);
	std::map<std::string, Posture> ps;
	for (auto &[name, h] : hosts_) {
		if (!h.decommissioned.empty() || h.host_id.empty())  // skip retired and non-sensor entries
			continue;
		Posture p;
		p.host = name;
		p.trust = h.trust;
		p.mode = h.mode;
		ps[name] = p;
	}
	for (auto &f : vf)
		if (auto it = ps.find(f.host); it != ps.end())
			it->second.vulns[f.tier]++;
	for (auto &ap : alerts_.items) {
		auto it = ps.find(ap->host);
		if (it == ps.end())
			continue;
		auto &p = it->second;
		p.alerts_by_severity[ap->severity]++;
		if (ap->rule.rfind("CAT-", 0) == 0)
			p.unsanctioned++;
		if (ap->rule == "ANOM-001")
			p.anomalies++;
	}
	static const std::pair<const char *, int> weights[] = {
	    {"exploited", 30}, {"reachable", 12}, {"dormant", 3}, {"theoretical", 1}};
	std::vector<Posture> fleet;
	int total = 0;
	for (auto &[_, p] : ps) {
		int score = 100;
		for (auto &[tier, w] : weights) {  // fixed order: findings read the same every time
			int n = p.vulns.count(tier) ? p.vulns[tier] : 0;
			if (n > 0) {
				score -= w * n;
				p.findings.push_back(std::to_string(n) + " " + tier + " vulnerabilit" + (n == 1 ? "y" : "ies"));
			}
		}
		if (p.unsanctioned > 0) {
			score -= 4 * std::min(p.unsanctioned, 5);
			p.findings.push_back(std::to_string(p.unsanctioned) + " unsanctioned tool or package " +
			                     word(p.unsanctioned, "install", "installs"));
		}
		if (p.anomalies > 0) {
			score -= 2 * std::min(p.anomalies, 5);
			p.findings.push_back(std::to_string(p.anomalies) + " never-before-seen " +
			                     word(p.anomalies, "program", "programs"));
		}
		int c = p.alerts_by_severity.count("critical") ? p.alerts_by_severity["critical"] : 0;
		int hi = p.alerts_by_severity.count("high") ? p.alerts_by_severity["high"] : 0;
		if (c + hi > 0) {
			score -= 8 * std::min(c, 3) + 4 * std::min(hi, 5);
			std::string parts;
			if (c > 0)
				parts = std::to_string(c) + " critical";
			if (hi > 0)
				parts += (parts.empty() ? "" : " and ") + std::to_string(hi) + " high";
			p.findings.push_back(parts + " severity " + word(c + hi, "alert", "alerts"));
		}
		if (p.trust == "generated" || p.trust.empty()) {
			score -= 10;
			p.findings.push_back("host identity not hardware/platform-anchored");
		}
		if (p.mode == "monitor") {  // unknown (no heartbeat yet) is not scored
			score -= 5;
			p.findings.push_back("policy in monitor mode (not enforcing)");
		}
		p.score = std::max(score, 0);
		p.grade = grade(p.score);
		total += p.score;
		fleet.push_back(p);
	}
	std::stable_sort(fleet.begin(), fleet.end(), [](const Posture &a, const Posture &b) { return a.score < b.score; });
	int avg = fleet.empty() ? 100 : total / (int)fleet.size();
	return {avg, fleet};
}

json Store::posture_json() {
	auto [avg, fleet] = posture();
	json hosts = json::array();
	for (auto &p : fleet)
		hosts.push_back(posture_to_json(p));
	return {{"fleet_score", avg}, {"fleet_grade", grade(avg)}, {"hosts", hosts}};
}

json Store::rollouts_json() {
	std::shared_lock lk(mu_);
	std::vector<Rollout> out = rollouts_;
	std::stable_sort(out.begin(), out.end(), [](const Rollout &a, const Rollout &b) { return a.ts > b.ts; });
	json j = json::array();
	for (auto &r : out)
		j.push_back(rollout_to_json(r));
	return j;
}

size_t Store::rollout_count() {
	std::shared_lock lk(mu_);
	return rollouts_.size();
}

json Store::summary() {
	int fleet_score = posture().first;
	auto vf = vuln_findings();
	JournalHealth jh = journal_health();
	std::shared_lock lk(mu_);
	auto now = Clock::now();
	json hosts = {{"live", 0},      {"active", 0},    {"stale", 0},           {"decommissioned", 0},
	              {"connected", 0}, {"ephemeral", 0}, {"groups", json::object()}};
	double cpu_sum = 0, cpu_max = 0;
	int cpu_n = 0, over = 0;
	for (auto &[_, h] : hosts_) {
		std::string st = host_state(h, now);
		if (st == "decommissioned") {
			hosts["decommissioned"] = hosts["decommissioned"].get<int>() + 1;
			continue;
		}
		hosts[st] = hosts[st].get<int>() + 1;
		hosts["live"] = hosts["live"].get<int>() + 1;
		auto &g = hosts["groups"][h.group];
		g = g.is_null() ? 1 : g.get<int>() + 1;
		if (h.ephemeral)
			hosts["ephemeral"] = hosts["ephemeral"].get<int>() + 1;
		if (h.connected) {
			hosts["connected"] = hosts["connected"].get<int>() + 1;
			cpu_sum += h.cpu_pct;
			cpu_n++;
			cpu_max = std::max(cpu_max, h.cpu_pct);
			if (h.cpu_pct > 0.05)
				over++;
		}
	}
	json open = json::object();
	int open_total = 0, last24 = 0, ai = 0;
	std::vector<int> hourly(24, 0);
	std::map<std::string, std::pair<std::string, int>> rules;  // rule -> (title, count)
	auto day_ago = now - hours(24);
	for (auto &ap : alerts_.items) {
		const Event &a = *ap;
		if (a.status == "open" && a.severity != "info") {
			open[a.severity] = open.value(a.severity, 0) + 1;
			open_total++;
		}
		TimePoint t = parse_ts(a.ts);
		if (t < day_ago)
			continue;
		last24++;
		long b = 23 - (long)duration_cast<hours>(now - t).count();
		if (b >= 0 && b < 24)
			hourly[b]++;
		if (a.actor == "ai")
			ai++;
		auto &rc = rules[a.rule];
		if (rc.second == 0)
			rc.first = a.title;
		rc.second++;
	}
	std::vector<std::tuple<std::string, std::string, int>> top;
	for (auto &[rule, tc] : rules)
		top.emplace_back(rule, tc.first, tc.second);
	std::stable_sort(top.begin(), top.end(), [](auto &x, auto &y) { return std::get<2>(x) > std::get<2>(y); });
	if (top.size() > 6)
		top.resize(6);
	json top_j = json::array();
	for (auto &[r, t, n] : top)
		top_j.push_back({{"rule", r}, {"title", t}, {"count", n}});
	json vulns = json::object();
	for (auto &f : vf)
		vulns[f.tier] = vulns.value(f.tier, 0) + 1;
	json recent = json::array();
	for (auto it = rollouts_.rbegin(); it != rollouts_.rend() && recent.size() < 5; ++it)
		recent.push_back(rollout_to_json(*it));
	return {{"hosts", hosts},
	        {"alerts",
	         {{"open_by_severity", open},
	          {"open_total", open_total},
	          {"last_24h", last24},
	          {"hourly_24h", hourly},
	          {"top_rules_24h", top_j},
	          {"ai_actor_alerts_24h", ai}}},
	        {"vulns_by_tier", vulns},
	        {"posture", {{"score", fleet_score}, {"grade", grade(fleet_score)}}},
	        {"sensor_cpu",
	         {{"budget_pct", 0.05},
	          {"max_pct", cpu_max},
	          {"avg_pct", cpu_n ? cpu_sum / cpu_n : 0.0},
	          {"hosts_over_budget", over}}},
	        {"recent_rollouts", recent},
	        {"journal",
	         {{"ok", jh.ok},
	          {"error", jh.error},
	          {"rotate_pending", jh.rotate_pending},
	          {"write_errors", jh.write_errors},
	          {"failing_since", is_zero(jh.failing_since) ? "" : fmt_rfc3339(jh.failing_since)}}},
	        {"generated", fmt_rfc3339(now)}};
}

// ---- writes ---------------------------------------------------------------------

json Store::triage(const std::string &id, const std::string &status, const std::string &note, const std::string &by) {
	if (status != "open" && status != "acknowledged" && status != "resolved")
		throw std::invalid_argument("status must be open, acknowledged or resolved");
	if (note.size() > 2000)
		throw std::invalid_argument("note too long (max 2000 chars)");
	std::unique_lock lk(mu_);
	auto it = alert_by_id_.find(id);
	if (it == alert_by_id_.end())
		throw std::invalid_argument("no such alert (it may have aged out of the console's window)");
	Event ev;
	ev.ts = now_ts();
	ev.type = "triage";
	ev.id = id;
	ev.host = it->second->host;
	ev.rule = it->second->rule;
	ev.status = status;
	ev.note = note;
	ev.by = by;
	ev.src = "console";
	auto alert = it->second;
	record(event_to_json(ev).dump(), true);
	apply(ev, Clock::now(), false);
	return event_to_json(*alert);
}

Rollout Store::rollout(const std::string &action, const std::string &group, int percent, const std::string &by) {
	auto cmd = control_commands().find(action);
	if (cmd == control_commands().end())
		throw std::invalid_argument("bad action");
	if (percent < 1 || percent > 100)
		throw std::invalid_argument("percent must be 1..100");
	Rollout r;
	{
		std::shared_lock lk(mu_);
		for (auto &[name, h] : hosts_) {  // sorted by name
			if (!h.decommissioned.empty() || (!group.empty() && h.group != group))
				continue;
			if (bucket(name) < percent)
				r.cohort.push_back(name);
		}
	}
	r.ts = Clock::now();
	r.by = by;
	r.action = action;
	r.group = group;
	r.percent = percent;
	Event ev;
	ev.ts = fmt_ts_ms(r.ts);
	ev.action = action;
	ev.group = group;
	ev.percent = percent;
	ev.cohort = r.cohort;
	ev.by = by;
	ev.src = "console";
	{
		// Intent first, on disk: if the console dies mid-push, the hosts that
		// were already switched are not lost from the audit trail.
		std::unique_lock lk(mu_);
		r.id = ev.id = "RO" + std::to_string(unix_now()) + "-" + std::to_string(++rollout_seq_);
		ev.type = "rollout_intent";
		record(event_to_json(ev).dump(), true);
	}
	// Push in parallel: each write may wait up to the link's deadline, and a
	// few wedged sensors must not stretch a fleet rollout to minutes. Once the
	// console is stopping, the rest are not attempted (reported as failed).
	const size_t n = r.cohort.size();
	std::vector<int> res(n, 1);
	std::atomic<size_t> next{0};
	auto worker = [&] {
		for (size_t i; (i = next.fetch_add(1)) < n;)
			res[i] = stopping_ ? 1 : push_one(r.cohort[i], cmd->second);
	};
	std::vector<std::thread> pool;
	for (size_t k = 1; k < std::min<size_t>(n, 32); k++) {
		try {
			pool.emplace_back(worker);
		} catch (const std::system_error &) {
			break;  // fewer threads: this one and the others take the rest
		}
	}
	worker();
	for (auto &t : pool)
		t.join();
	for (size_t i = 0; i < n; i++) {
		(res[i] == 0 ? r.delivered : r.failed).push_back(r.cohort[i]);
		if (res[i] == 2)
			r.send_failed.push_back(r.cohort[i]);
	}
	r.status = "complete";
	{
		std::unique_lock lk(mu_);
		ev.type = "rollout";
		ev.delivered = r.delivered;
		ev.failed = r.failed;
		ev.send_failed = r.send_failed;
		record(event_to_json(ev).dump(), true);
		apply(ev, r.ts, false);
	}
	logf("rollout %s action=%s group=\"%s\" percent=%d cohort=%zu delivered=%zu send_failed=%zu by=%s", r.id.c_str(),
	     action.c_str(), group.c_str(), percent, r.cohort.size(), r.delivered.size(), r.send_failed.size(), by.c_str());
	return r;
}

bool Store::console_record_type(const std::string &type) {
	return type == "suggestion" || type == "suggestion_decision" || type == "ai_result";
}

void Store::record_console(json j) {
	if (!j.contains("ts"))
		j["ts"] = now_ts();
	j["src"] = "console";
	std::unique_lock lk(mu_);
	record(j.dump());
}

std::vector<Event> Store::alerts_copy() {
	std::shared_lock lk(mu_);
	std::vector<Event> out;
	out.reserve(alerts_.size());
	for (auto &a : alerts_.items)
		out.push_back(*a);
	return out;
}

std::vector<Host> Store::hosts_copy() {
	std::shared_lock lk(mu_);
	auto now = Clock::now();
	std::vector<Host> out;
	for (auto &[_, h] : hosts_) {
		out.push_back(h);
		out.back().state = host_state(h, now);
	}
	return out;
}

std::vector<Rollout> Store::rollouts_copy() {
	std::shared_lock lk(mu_);
	return rollouts_;
}

void Store::audit_secret_access(const std::string &key, const std::string &who) {
	std::unique_lock lk(mu_);
	console_alert("VAULT-ACCESS", "info", "console", "Secret '" + key + "' accessed by " + who, "vault get " + key);
}

}  // namespace wisp
