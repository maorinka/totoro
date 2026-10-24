// Data model shared by ingest, the journal and the API. The JSON shapes match
// the original Go console exactly (field names and omit-when-empty rules), so
// journals written by either implementation replay in the other.
#pragma once

#include <chrono>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "util.hpp"

namespace wisp {

using json = nlohmann::json;

struct Event {
	std::string id, ts, type, host, group, rule, mitre, title, severity, action, actor, actor_src;
	long long pid = 0, ppid = 0, uid = 0;
	std::string comm, exe, cmd, dest;
	long long dport = 0;
	std::string kind, name, version, host_id, trust, where, change, path;
	long long execs = 0, alerts_total = 0;
	double cpu_pct = 0;
	long long rss_kb = 0;
	std::vector<std::string> runtimes;
	bool has_runtimes = false;  // distinguishes "no runtimes" from "field absent"
	bool ephemeral = false;
	std::string mode, reason;
	// alert triage (console-set)
	std::string status, note, triaged_by, triaged_at;
	// lifecycle / rollout journal records
	long long percent = 0;
	std::vector<std::string> cohort, delivered, failed;
	std::string by;
	// Journal provenance (console-set; stripped from sensor lines):
	//   rx_ts   - console receipt time of a sensor record ("...SS.mmmZ"); replay
	//             uses it, never the sensor's own ts, for host first/last seen
	//   src     - "console" on every record the console itself writes
	//   id_kept - on a hello: the console refused the identity it presented
	//   send_failed - on a rollout: cohort hosts that were connected but whose
	//             control write failed or timed out (a subset of failed)
	std::string rx_ts, src;
	bool id_kept = false;
	std::vector<std::string> send_failed;
};

// Decode from a sensor or journal line. Unknown fields are ignored; a field of
// the wrong JSON type is ignored rather than trusted.
Event event_from_json(const json &j);
json event_to_json(const Event &e);

struct Host {
	std::string name, group, version, host_id, trust;
	TimePoint first_seen{}, last_seen{};
	bool connected = false;
	long long alerts = 0, execs = 0;
	double cpu_pct = 0, peak_cpu = 0;
	long long rss_kb = 0;
	std::vector<std::string> runtimes;
	bool ephemeral = false;
	std::string mode, state, decommissioned;
	TimePoint decommissioned_at{};
	long long dropped_lines = 0;  // sensor lines refused (rate limit, oversize)

	// In-memory only (not serialised): liveness on the monotonic clock, so a
	// wall-clock step never makes a live host look silent (or a dead one
	// fresh), and when a record last put this host's liveness on disk.
	std::chrono::steady_clock::time_point last_contact{};
	TimePoint journaled_seen{};

	bool runtime_active(const std::string &eco) const {
		for (auto &r : runtimes)
			if (r == eco)
				return true;
		return false;
	}
};
json host_to_json(const Host &h);

struct Rollout {
	TimePoint ts{};
	std::string by, action, group;
	int percent = 0;
	std::vector<std::string> cohort, delivered, failed;
	std::string id;      // "RO<unix>-<seq>"; empty for records from older consoles
	std::string status;  // "complete", or "interrupted": started but the console stopped mid-push
	std::vector<std::string> send_failed;  // connected, but the write failed or timed out (subset of failed)
};
json rollout_to_json(const Rollout &r);

}  // namespace wisp
