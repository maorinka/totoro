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

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "model.hpp"
#include "store.hpp"

namespace wisp {

struct Incident {
	std::string id, host, group, first_ts, last_ts, severity, status, priority, summary;
	int score = 0;
	bool contained = false;
	std::vector<std::string> reasons;  // "+45 high-severity detection", ...
	std::vector<std::string> alert_ids, rules, techniques, actors, titles, campaign_hosts;
	std::vector<Event> alerts;  // oldest first
};

struct Suggestion {
	std::string id, ts, kind, title, rationale, severity, source, key;
	std::string status = "proposed";  // proposed | applied | accepted | failed | rejected | expired
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
json suggestion_to_json(const Suggestion &s);

class Analyst {
public:
	explicit Analyst(Store &store);

	// tuning
	std::chrono::minutes incident_gap{30};   // alerts closer than this join one incident
	std::chrono::minutes campaign_window{60};
	int campaign_hosts = 3;                  // same rule on this many hosts = campaign
	std::chrono::hours suppress_rejected{24 * 7};

	// read models
	std::vector<Incident> incidents();  // open first, then by score
	std::optional<Incident> incident(const std::string &id);
	json incidents_json(const Query &q);
	json incident_json(const Incident &inc, bool detail);
	json health_json();
	std::vector<RuleStat> rule_stats();
	json rules_json();
	json suggestions_json(const std::string &status);
	std::optional<Suggestion> suggestion(const std::string &id);

	// One analysis pass: proposes new suggestions and expires ones whose
	// condition no longer holds. Returns the number proposed.
	int run();

	// Adds a suggestion after validating its action (throws std::invalid_argument).
	// Duplicate keys that are open, recently rejected or recently applied are
	// ignored; returns the stored suggestion either way.
	Suggestion propose(Suggestion s);

	// Approve (carry it out) or reject. `role` is the caller's role; throws
	// std::invalid_argument (bad id/state) or std::domain_error (role too low).
	Suggestion decide(const std::string &id, bool approve, const std::string &by, const std::string &role,
	                  const std::string &note);

	// Triage every alert in an incident.
	json triage_incident(const std::string &id, const std::string &status, const std::string &note,
	                     const std::string &by);

	// AI results attached to incidents / rules, restored from the journal.
	void attach_ai(const std::string &target, const json &result);
	std::optional<json> ai_for(const std::string &target);

	// Journal replay of suggestion records (Store::replay_hook).
	void replay(const json &rec);

	// Throws std::invalid_argument when an action is malformed or targets
	// something that does not exist. Used for engine and AI suggestions alike.
	void validate_action(const json &action);

private:
	std::vector<Suggestion> build_suggestions(const std::vector<Incident> &incs, const std::vector<RuleStat> &rules);
	std::string apply(const Suggestion &s, const std::string &by, bool *ok);
	void journal(const Suggestion &s);
	void journal_decision(const Suggestion &s);

	Store &store_;
	std::mutex mu_;
	std::vector<Suggestion> suggestions_;  // creation order
	std::map<std::string, json> ai_;       // target -> latest AI result
	unsigned long long seq_ = 0;
	std::mutex run_mu_;  // one analysis pass / decision at a time
	// incidents() is recomputed only when the store changed
	std::mutex cache_mu_;
	unsigned long long cache_gen_ = ~0ULL;
	std::vector<Incident> cache_;
	std::vector<Incident> correlate();
};

}  // namespace wisp
