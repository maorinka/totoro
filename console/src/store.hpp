// The console's state: hosts, alerts (with triage), inventory, the event
// journal, host lifecycle, rollouts, and the read models served by the API.
//
// Every security-relevant event is appended to an on-disk JSONL journal and
// replayed at startup through the same apply() path as live ingest, so a
// restart loses nothing but live connections and heartbeat gauges.
#pragma once

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>
#include <tuple>
#include <vector>

#include "model.hpp"
#include "rbac.hpp"
#include "vault.hpp"
#include "vulndb.hpp"

namespace wisp {

using Query = std::map<std::string, std::vector<std::string>>;

// A live connection to one sensor, as seen by the store. The ingest server
// implements it over TLS; tests use a fake.
class SensorLink {
public:
	virtual ~SensorLink() = default;
	virtual bool send(const std::string &line) = 0;  // one control line; false if not delivered
	virtual void shutdown() = 0;                     // wake the reader so the connection ends
};

// Per-connection ingest state.
struct SensorSession {
	std::string host;  // bound by the first hello; a connection speaks for one host
	std::shared_ptr<SensorLink> link;
	// Per-connection admission control, kept by Store::sensor_line: token
	// buckets for lines and bytes (negative: not started yet) and the count of
	// refused lines since the last log line about them.
	double line_tokens = -1, byte_tokens = -1;
	std::chrono::steady_clock::time_point refilled{}, drop_logged{};
	unsigned long long dropped = 0;
};

// An arrival-ordered window shared by many hosts. When it is full, the host
// holding the most entries gives up its oldest one (ties: the host whose
// oldest entry is oldest), so one noisy or hostile host can only push out its
// own history, never every other host's.
template <class T> class FairRing {
public:
	std::list<T> items;  // oldest first

	// Appends v for host, evicting down to `max`; `evicted` sees each entry removed.
	template <class F> void push(const std::string &host, T v, size_t max, F &&evicted) {
		auto &q = by_host_[host];
		if (!q.empty())
			heavy_.erase({-(long long)q.size(), q.front().first, host});
		items.push_back(std::move(v));
		q.push_back({++seq_, std::prev(items.end())});
		heavy_.insert({-(long long)q.size(), q.front().first, host});
		while (items.size() > max && !heavy_.empty()) {
			auto top = *heavy_.begin();
			heavy_.erase(heavy_.begin());
			const std::string &h = std::get<2>(top);
			auto qi = by_host_.find(h);
			auto it = qi->second.front().second;
			qi->second.pop_front();
			evicted(*it);
			items.erase(it);
			if (qi->second.empty())
				by_host_.erase(qi);
			else
				heavy_.insert({-(long long)qi->second.size(), qi->second.front().first, h});
		}
	}
	size_t size() const { return items.size(); }

private:
	using Pos = typename std::list<T>::iterator;
	std::map<std::string, std::deque<std::pair<unsigned long long, Pos>>> by_host_;
	std::set<std::tuple<long long, unsigned long long, std::string>> heavy_;  // (-count, oldest seq, host)
	unsigned long long seq_ = 0;
};

struct Finding {
	std::string host, ecosystem, name, version, cve, severity, tier, note;
	double cvss = 0;
};

struct Posture {
	std::string host, grade, trust, mode;
	int score = 100;
	std::map<std::string, int> vulns, alerts_by_severity;
	int unsanctioned = 0, anomalies = 0;
	std::vector<std::string> findings;
};

// Whether events are reaching disk (see Store::journal_health).
struct JournalHealth {
	bool ok = true;              // journal open and the last write succeeded (or no journal configured)
	bool rotate_pending = false; // rotated, but the new segment could not be opened yet: still appending to .1
	std::string path, error;     // error: last write/rotation problem, "" when healthy
	unsigned long long write_errors = 0;
	TimePoint failing_since{};
};

// Journal records (one JSON object per line, append-only):
//   sensor lines    as received, minus CONSOLE_ONLY fields, plus "rx_ts" (receipt time)
//   console records "src":"console": triage, rollout_intent, rollout, lifecycle
//                   (decommissioned / disconnected / seen), console alerts, and
//                   record_console() records (suggestion, suggestion_decision, ai_result)
//   segment header  {"type":"journal","src":"console","format":2,...} at the top
//                   of each segment this version opens; only records after it are
//                   trusted to carry console-set fields (rx_ts, src, id_kept)
// Older consoles ignore the new types and fields; this console replays journals
// written by older ones (their sensor timestamps are clamped to the segment's
// mtime, and console-only record types found there are dropped).
class Store {
public:
	explicit Store(std::string slack_webhook = "");

	// configuration (set before serving)
	std::chrono::nanoseconds stale_after = std::chrono::minutes(3);
	std::chrono::nanoseconds decom_after = std::chrono::hours(24 * 7);  // 0: never reap silent hosts
	// No host that has not been heard from since this process started is
	// reaped until it has had this long to reconnect (heartbeats are not
	// journaled, so a replayed last_seen understates a quiet host's liveness).
	std::chrono::nanoseconds reap_grace = std::chrono::minutes(5);
	// Decommissioned hosts are purged from memory after this (the journal
	// keeps their history); ephemeral ones sooner. At most max_decommissioned
	// are kept in any case (oldest purged first).
	std::chrono::nanoseconds decom_retention = std::chrono::hours(24 * 30);
	std::chrono::nanoseconds ephemeral_retention = std::chrono::hours(24);
	size_t max_decommissioned = 10000;
	long long journal_max = 256LL << 20;
	// The /api/events search index: two windows (security records, and bulk
	// telemetry such as hello/inventory/flow), each bounded by entries and by
	// estimated memory, so a flood of telemetry never evicts alerts.
	size_t journal_keep = 50000;
	size_t journal_keep_bytes = 128u << 20;
	size_t max_ring = 5000;         // alerts and inventory history kept in memory (fair across hosts)
	size_t max_rollouts = 1000;     // rollout history kept in memory
	size_t max_inventory_per_host = 5000;
	size_t max_inventory_bytes_per_host = 4u << 20;  // estimated memory of one host's package state
	// After a live hello the sensor re-sends its whole inventory; packages it
	// did not re-report within this long are dropped from the current state.
	std::chrono::nanoseconds inventory_grace = std::chrono::minutes(5);
	// Per-connection sensor admission: lines larger than sensor_max_line are
	// refused, and two token buckets bound the rate. The limit must stay above
	// wispd's largest line, an alert whose command line and exe path are fully
	// escaped at six bytes per input byte (agent/output.c out_alert: JESC_MAX(MAX_CMD) +
	// JESC_MAX(MAX_PATH) + 3072, about 30 KiB): an attacker who pads argv with
	// non-UTF-8 bytes must not get the alert refused at the console.
	size_t sensor_max_line = 64u << 10;
	double sensor_lines_per_s = 200, sensor_line_burst = 20000;
	double sensor_bytes_per_s = 256u << 10, sensor_byte_burst = 8u << 20;
	std::chrono::nanoseconds rotate_retry = std::chrono::seconds(5);  // reopen a new segment after a failure
	VulnDB vulndb;
	RBAC rbac;  // thread-safe; rbac.reload() re-reads roles.conf atomically
	std::unique_ptr<Vault> vault;
	std::atomic<bool> ready{false};
	// Called (outside the store lock) for each new high/critical alert.
	std::function<void(const Event &)> notify;

	// journal
	void open_journal(const std::string &path);  // throws
	void close_journal();
	bool journal_ok() const { return journal_ok_.load(std::memory_order_acquire); }
	JournalHealth journal_health();

	// sensor ingest
	void sensor_line(SensorSession &s, const std::string &line);
	void sensor_closed(SensorSession &s);
	bool push_control(const std::string &host, const std::string &cmd);
	// Wakes every sensor connection and marks the store as stopping: hosts are
	// journaled as disconnected (not decommissioned) and rollouts stop pushing.
	void shutdown_links();

	// live event (sensor or console-originated); exposed for tests
	void ingest(Event e, std::string raw);

	// read models
	json host_list(const std::string &state, const std::string &group);
	std::optional<json> host_detail(const std::string &name);
	json alert_list(const Query &q);
	json search_events(const Query &q);  // never includes ai_result records (operator-only, see /api/ai/jobs)
	std::vector<Finding> vuln_findings();
	json vulns_json();
	std::pair<int, std::vector<Posture>> posture();  // fleet score, hosts weakest first
	json posture_json();
	json summary();
	json rollouts_json();
	json inventory_json(const std::string &host);  // recent inventory changes, newest first

	// writes
	json triage(const std::string &id, const std::string &status, const std::string &note, const std::string &by);
	// Journals a rollout_intent (fsynced) before pushing, pushes in parallel,
	// then journals the rollout record. A rollout whose intent has no record
	// (the console died mid-push) replays as status "interrupted".
	Rollout rollout(const std::string &action, const std::string &group, int percent, const std::string &by);
	void audit_secret_access(const std::string &key, const std::string &who);
	// Housekeeping, run every few seconds: retire persistent hosts silent past
	// decom_after (never a connected one), purge long-decommissioned hosts,
	// journal liveness markers for connected hosts, and drop inventory a
	// reconnected sensor no longer reports.
	void reap();

	// Console-originated records (analysis suggestions and decisions, AI
	// results): journaled with "src":"console" and handed to replay_hook at
	// startup. Sensors can never send these types, and replay only trusts
	// them from segments this version wrote.
	void record_console(json j);
	std::function<void(const json &)> replay_hook;
	static bool console_record_type(const std::string &type);

	// consistent copies for the analysis engine
	std::vector<Event> alerts_copy();
	std::vector<Host> hosts_copy();  // with state filled in
	std::vector<Rollout> rollouts_copy();

	// Changes whenever anything a read model depends on changes.
	unsigned long long generation() const { return generation_.load(std::memory_order_acquire); }

	// introspection for tests
	size_t rollout_count();
	std::optional<Host> host_snapshot(const std::string &name);
	std::string journal_path() const { return journal_path_; }

private:
	struct JournalEntry {
		unsigned long long seq;
		size_t cost;  // estimated bytes held (raw + parsed DOM)
		std::string ts, raw;
		json m;
	};
	struct Window {
		std::deque<JournalEntry> entries;
		size_t bytes = 0;
	};
	struct LiveLink {
		std::shared_ptr<SensorLink> link;
		std::string host_id, trust;  // the identity its hello presented
		unsigned long long seq;      // bind order: newest wins among equals
	};
	struct InvEntry {
		Event e;
		std::chrono::steady_clock::time_point confirmed{};  // last live report (zero: replayed only)
	};
	struct InvState {
		std::map<std::string, InvEntry> items;  // "kind|lowercase name|where"
		std::chrono::steady_clock::time_point baseline{};  // last live hello
		bool swept = true;
		bool full_logged = false;  // the per-host cap was hit and logged
		size_t bytes = 0;          // estimated memory held by items
	};

	// All of these require mu_ held exclusively.
	Host &host_ref(const std::string &name, const std::string &group, TimePoint at, bool replay);
	void ingest_locked(Event &e, std::string raw, std::vector<Event> &notify_now);
	void apply(const Event &e, TimePoint at, bool replay);
	void identity_check(Event &e);
	void record(const std::string &raw, bool sync = false);
	void index_event(const std::string &raw);
	void rotate();
	int open_segment(std::string *err, long long *size);
	void decommission(Host &h, const std::string &reason);
	void lifecycle_record(Host &h, const std::string &change, const std::string &reason);
	void console_alert(const std::string &rule, const std::string &sev, const std::string &host,
	                   const std::string &title, const std::string &cmd);
	void choose_link(const std::string &host);
	void add_alert(const Event &e, bool replay);
	int push_one(const std::string &host, const std::string &cmd);  // 0 delivered, 1 not connected, 2 send failed
	bool inventory_update(const Event &e, bool replay);
	bool inventory_unchanged(const Event &e) const;
	void journal_failure(const std::string &what, int err);
	std::string host_state(const Host &h, TimePoint now) const;
	std::vector<Finding> vuln_findings_locked();
	bool admit(SensorSession &s, size_t len);

	std::shared_mutex mu_;
	std::map<std::string, Host> hosts_;
	FairRing<std::shared_ptr<Event>> alerts_;
	std::map<std::string, std::shared_ptr<Event>> alert_by_id_;
	std::map<std::string, std::string> legacy_alias_;  // replay only: positional "R<n>" -> stable id
	FairRing<Event> inventory_;            // change history
	std::map<std::string, InvState> inv_;  // current packages per host
	unsigned long long alert_seq_ = 0, legacy_seq_ = 0, rollout_seq_ = 0, link_seq_ = 0, event_seq_ = 0;
	std::string slack_;
	std::map<std::string, std::vector<LiveLink>> links_;  // every identified live connection per host
	std::map<std::string, std::shared_ptr<SensorLink>> conns_;  // the one that receives control lines
	Window security_, telemetry_;
	int journal_fd_ = -1;
	std::string journal_path_;
	long long journal_size_ = 0;
	bool journal_closed_ = false, rotate_pending_ = false, need_newline_ = false;
	std::chrono::steady_clock::time_point rotate_retry_at_{}, error_logged_{}, rotate_logged_{};
	JournalHealth health_;
	std::string write_error_, rotate_error_;
	std::atomic<bool> journal_ok_{true};
	std::atomic<bool> stopping_{false};
	std::vector<Rollout> rollouts_;
	std::map<std::string, Rollout> intents_;  // replay only: rollout_intent without its record yet
	std::vector<Event> pending_notify_;  // collected under the lock, sent after
	std::chrono::steady_clock::time_point started_ = std::chrono::steady_clock::now();
	std::atomic<unsigned long long> generation_{0};
	void bump() { generation_.fetch_add(1, std::memory_order_release); }
};

// Control lines for the agent, keyed by action.
const std::map<std::string, std::string> &control_commands();
std::string sanitize(const std::string &raw);
std::string with_fields(const std::string &raw, const json &fields);
int bucket(const std::string &host);
std::string grade(int score);

}  // namespace wisp
