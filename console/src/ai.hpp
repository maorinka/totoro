// Optional AI assistance for triage and rule curation, on the Claude API.
//
//   triage  an incident: verdict, confidence, reasoning and recommended actions
//   curate  a rule: assessment and concrete rules.conf changes
//   ask     a question about the fleet, answered with read-only tools over the
//           console's own data (incidents, alerts, events, hosts, posture...)
//
// Safety model:
//   - Off unless an API key is configured (-ai-key-file, the vault secret
//     "anthropic/api-key", or ANTHROPIC_API_KEY).
//   - Telemetry is redacted (credentials, tokens, keys, high-entropy strings;
//     JSON keys as well as values; every string capped at 4 KB) before it
//     leaves the console, and is presented to the model as untrusted data
//     inside <fleet_data>, with '<', '>' and '&' escaped so the data cannot
//     close that block: command lines are attacker-controlled. Operator
//     questions are redacted too.
//   - The model only proposes. Its recommendations go through the analysis
//     engine's validation (allow-listed action types, real targets, scoped to
//     the incident) and wait in the suggestion inbox for a human to approve.
//     It cannot recommend monitor mode, a rollout beyond the incident host's
//     own (named) group, or anything outside the incident. Rule-curation
//     proposals that would weaken detection (allow-list entries, lower
//     severity, no longer blocking, exclusions) are marked as such. Notes the
//     model wrote never count as a person's "benign" verdict.
//   - Every job is journaled (who, what, model, token usage, outcome), also
//     jobs cancelled by a shutdown; job history survives a restart.
//   - Jobs run on one background thread with a bounded queue and an hourly cap
//     that counts API requests (every attempt and tool round), not jobs.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include "analysis.hpp"
#include "model.hpp"
#include "store.hpp"

namespace wisp {

struct AiConfig {
	// Key precedence: api_key (-ai-key-file), else the vault secret
	// anthropic/api-key (read per request), else env_key ($ANTHROPIC_API_KEY).
	std::string api_key;
	std::string env_key;
	std::string base_url = "https://api.anthropic.com";
	std::string model = "claude-opus-5-5";
	std::string effort = "high";
	std::string ca_file;  // extra trust anchor (TLS-inspecting proxy, private gateway, tests)
	bool fallback = true;  // server-side refusal fallback ("fallbacks": "default")
	int max_per_hour = 60;  // API requests per hour; 0 turns the assistant off
	size_t max_queue = 8;
	int max_tool_turns = 10;
	std::chrono::seconds timeout{600};
	long max_tokens = 0;  // 0: 16000, or 32000 at effort xhigh/max
	bool disabled = false;
};

// Replace credentials and other secrets in free text with [REDACTED]. Input
// is cut to 4 KB (on a character boundary) first, so the cost is bounded.
// Base64 that decodes to readable text with spaces (an encoded command) is
// shown decoded, and redacted like any other text.
std::string redact(const std::string &s);
json redact_json(const json &j);  // keys too

// JSON for the model's untrusted-data block: '<', '>' and '&' escaped as
// JSON unicode escapes (u003c, u003e, u0026), so nothing in it can close <fleet_data>.
std::string fence_json(const json &j, int indent = -1);

// Syntax check for a rules.conf line (the sensor's grammar); empty when valid.
std::string check_rule_line(const std::string &line);

class Assistant {
public:
	Assistant(Store &store, Analyst &analyst, AiConfig cfg);
	~Assistant();
	Assistant(const Assistant &) = delete;
	Assistant &operator=(const Assistant &) = delete;

	bool configured();  // a key is available and the configuration can work
	json status_json();

	// Queue a job. kind: triage (target = incident id), curate (target = rule
	// id) or ask (target = question). Throws std::invalid_argument for bad
	// input, std::runtime_error when AI is off, busy or over its hourly cap.
	json submit(const std::string &kind, const std::string &target, const std::string &by);
	std::optional<json> job(const std::string &id);
	json jobs_json();
	void stop();

	// One Messages API call with retries; throws std::runtime_error. Public for tests.
	json call(json body, json *usage);

private:
	struct Job {
		// status: queued | running | done | failed | cancelled
		std::string id, kind, target, by, status = "queued", created, started, finished, error, model;
		json result;
		json usage = json::object();  // accumulated by call(), billed attempts included
		long long input_tokens = 0, output_tokens = 0;
	};
	void worker();
	void finish(Job &j);  // journal, attach, log, publish; never throws
	std::string unusable();  // why the configuration cannot work, "" when it can
	json run_triage(Job &j);
	json run_curate(Job &j);
	json run_ask(Job &j);
	json tool(const std::string &name, const json &input);
	std::string key();
	json job_json(const Job &j);

	Store &store_;
	Analyst &analyst_;
	AiConfig cfg_;
	std::mutex mu_;
	std::condition_variable cv_;
	std::deque<Job> jobs_;  // newest last; bounded history
	std::deque<std::string> queue_;
	std::deque<std::chrono::steady_clock::time_point> recent_;
	unsigned long long seq_ = 0;
	bool reserved_ = false;  // the running job's first request was counted at submit
	bool stop_ = false, stopped_ = false;
	std::atomic<bool> stopping_{false};  // read by the HTTPS client between polls
	std::thread thread_;
};

}  // namespace wisp
