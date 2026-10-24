// Fleet analysis: "we observe, research and analyze; we curate; we prioritize;
// we suggest, you approve, we solve".
//
// Everything here is deterministic and explainable, and runs inside the
// console with no external service:
//
//   incidents    related alerts on a host correlated into one incident, scored
//                0-100 and ranked P1-P4, with the reason for every point
//   fleet health sensors over budget, silent hosts, version drift, weak
//                identities, alert spikes, unprotected hosts under attack
//   rule review  per-rule volume, spread and triage outcomes; noisy rules and
//                rules ready to enforce
//   suggestions  concrete remediations built from the above. An operator (or
//                deployer, for rollouts) approves one and the console carries
//                it out: push a mode to a host, stage a rollout, close alerts.
//                Changes the console cannot make itself (editing rules.conf,
//                upgrading a package) are "manual": approval records the
//                decision and shows the exact change.
//
// Suggestions and their decisions are journaled, so the inbox and its history
// survive a restart. The optional AI assistant (ai.hpp) adds suggestions
// through the same validated path; it can never act on its own.
#pragma once

#include <deque>
#include <map>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "model.hpp"
#include "store.hpp"

namespace wisp {

struct Incident {
	std::string id, host, group, first_ts, last_ts, severity, status, priority, summary;
	TimePoint last_rx{};  // console receipt time of the newest alert (sensor ts when unknown)
	int score = 0;
	bool contained = false;
	std::vector<std::string> reasons;  // "+45 high-severity detection", ...
	std::vector<std::string> alert_ids, rules, techniques, actors, titles, campaign_hosts;
	std::vector<Event> alerts;  // oldest first
};

struct Suggestion {
	std::string id, ts, kind, title, rationale, severity, source, key;
	// proposed | applying | applied | accepted | failed | rejected | expired |
	// interrupted (the console stopped between journaling "applying" and the outcome)
	std::string status = "proposed";
	json action;                      // see validate_action()
	std::vector<std::string> evidence;
	std::string decided_by, decided_at, result;
};

struct RuleStat {
	std::string rule, title, severity, technique, action;
	int alerts = 0, open = 0, acknowledged = 0, resolved = 0, benign = 0;
	std::vector<std::string> hosts;
	std::vector<std::pair<std::string, int>> programs;  // most frequent first
	std::string assessment;                              // noisy | ready_to_enforce | ok
	std::string advice;
};

// The role an action needs, mirroring the endpoint it stands in for.
std::string required_role(const json &action);
// The role needed to approve or reject a suggestion: required_role(action),
// and at least "operator" for one the AI proposed (source "ai").
std::string approval_role(const Suggestion &s);
json suggestion_to_json(const Suggestion &s);

// UTF-8 helpers for text that ends up in JSON: the longest prefix of at most
// `max` bytes that does not split a character, and a copy with every invalid
// byte replaced by U+FFFD.
std::string utf8_prefix(const std::string &s, size_t max);
std::string utf8_clean(std::string_view s);

// A triage note that marks an alert as a false positive (whole words, not
// negated: "benign", "false positive", "fp", "expected", "known good", "legit").
bool benign_note(const std::string &note);
// Whether an alert's triage counts as a person's benign verdict. Triage that
// came from an approved suggestion (engine or AI; its note is machine-written)
// never counts.
bool human_benign(const Event &a);
// The `by` recorded on alerts that an approved suggestion triaged.
std::string suggestion_actor(const std::string &by, const std::string &suggestion_id);

class Analyst {
public:
	explicit Analyst(Store &store);

	// tuning
	std::chrono::minutes incident_gap{30};   // alerts closer than this join one incident
	std::chrono::minutes campaign_window{60};
	int campaign_hosts = 3;                  // same rule on this many hosts = campaign
	std::chrono::hours suppress_rejected{24 * 7};
	size_t max_close_stale = 50;             // close_stale suggestions proposed per pass
	// Decided and expired suggestions are kept (in memory and re-journaled)
	// this long, and at most max_history of them.
	std::chrono::hours keep_decided{24 * 30};
	size_t max_history = 5000;
	// Wall clock used for every age the engine judges (tests simulate clock steps).
	std::function<TimePoint()> wall_clock = [] { return Clock::now(); };

	// read models
	std::vector<Incident> incidents();  // open first, then by score
	std::optional<Incident> incident(const std::string &id);
	json incidents_json(const Query &q);
	json incident_json(const Incident &inc, bool detail);
	json health_json();
	std::vector<RuleStat> rule_stats();
	json rules_json();
	// Newest first, at most `limit`: status "" = open (proposed or applying), "all" = everything.
	json suggestions_json(const std::string &status, size_t limit = 1000);
	std::optional<Suggestion> suggestion(const std::string &id);

	// One analysis pass: proposes new suggestions and expires ones whose
	// condition no longer holds. Returns the number proposed.
	int run();

	// Adds a suggestion after validating its action (throws std::invalid_argument).
	// Duplicate keys that are open, recently rejected or recently applied are
	// ignored; an expired one with the same key is reopened under its old id.
	// The suggestion is journaled before anyone can see or decide it. Returns
	// the stored suggestion either way.
	Suggestion propose(Suggestion s);

	// Approve (carry it out) or reject. `role` is the caller's role; throws
	// std::invalid_argument (bad id/state) or std::domain_error (role too low).
	// An approval is journaled as "applying" before the action runs, and runs
	// without blocking analysis passes.
	Suggestion decide(const std::string &id, bool approve, const std::string &by, const std::string &role,
	                  const std::string &note);

	// Triage the alerts of an incident. When `shown` is given (the alert ids the
	// operator was looking at), only those are triaged: alerts that joined the
	// incident since are left alone and counted in "skipped".
	json triage_incident(const std::string &id, const std::string &status, const std::string &note,
	                     const std::string &by, const std::vector<std::string> *shown = nullptr);

	// AI results attached to incidents / rules, restored from the journal.
	// Results that are not a JSON object with an object "result" are ignored.
	void attach_ai(const std::string &target, const json &result);
	std::optional<json> ai_for(const std::string &target);
	// ai_result records replayed from the journal (every purpose, ask included),
	// oldest first, at most 200: the assistant rebuilds its job history from them.
	std::vector<json> replayed_ai_jobs();

	// Journal replay of suggestion records (Store::replay_hook).
	void replay(const json &rec);
	// Records that must outlive journal rotation: every suggestion that still
	// suppresses a proposal (rejected, applied or accepted within its hold) and
	// its decision. Re-journaling them keeps the hold across a restart once the
	// segment that held them has rotated away (see run(), and Store's rotation).
	std::vector<json> carry_forward();

	// Throws std::invalid_argument when an action is malformed or targets
	// something that does not exist. Used for engine and AI suggestions alike.
	void validate_action(const json &action);

private:
	// What validation looks at, taken once per analysis pass.
	struct Snapshot {
		std::vector<Host> hosts;
		std::unordered_set<std::string> alert_ids;
	};
	Snapshot snapshot();
	void validate_action(const json &action, const Snapshot &snap);
	Suggestion propose(Suggestion s, const Snapshot *snap, bool *fresh);
	std::vector<Suggestion> build_suggestions(const std::vector<Incident> &incs, const std::vector<RuleStat> &rules);
	std::string apply(const Suggestion &s, const std::string &by, bool *ok);
	void journal(const Suggestion &s);
	void journal_decision(const Suggestion &s);
	// Seconds since wall time t, never more than the console has actually been
	// up since then: a forward step of the clock is not elapsed time.
	std::chrono::seconds elapsed_since(TimePoint t) const;
	void reindex();  // rebuilds by_id_ / by_key_ (callers hold mu_)
	void prune();    // drops old decided suggestions and orphaned AI results (callers hold mu_)

	Store &store_;
	std::mutex mu_;
	std::vector<Suggestion> suggestions_;              // creation order
	std::unordered_map<std::string, size_t> by_id_;   // id -> index in suggestions_
	std::unordered_map<std::string, size_t> by_key_;  // key -> index of the newest with that key
	std::map<std::string, json> ai_;                   // target -> latest AI result
	std::deque<json> ai_jobs_;                         // replayed ai_result records (bounded)
	unsigned long long seq_ = 0;
	std::mutex propose_mu_;  // propose(): journal, then publish, one at a time
	std::mutex run_mu_;      // one analysis pass at a time (decisions do not take it)
	std::chrono::steady_clock::time_point started_ = std::chrono::steady_clock::now();
	TimePoint started_wall_ = Clock::now();
	std::chrono::steady_clock::time_point carried_{};  // last carry_forward() re-journal by run()
	// incidents() is recomputed only when the store changed, by one caller at a
	// time (the others wait for its result).
	std::mutex compute_mu_;
	std::mutex cache_mu_;
	unsigned long long cache_gen_ = ~0ULL;
	std::vector<Incident> cache_;
	// Stable incident ids: alert id -> the incident id it was last part of, and
	// ids that were merged into another incident (old id -> current id).
	std::unordered_map<std::string, std::string> alert_inc_;
	std::map<std::string, std::string> inc_alias_;
	std::vector<Incident> correlate();
	std::string resolve_incident(const std::string &id);
};

}  // namespace wisp
