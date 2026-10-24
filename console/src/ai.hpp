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
//   - Telemetry is redacted (credentials, tokens, keys, high-entropy strings)
//     before it leaves the console, and is presented to the model as untrusted
//     data: command lines are attacker-controlled.
//   - The model only proposes. Its recommendations go through the analysis
//     engine's validation (allow-listed action types, real targets, scoped to
//     the incident) and wait in the suggestion inbox for a human to approve.
//     It cannot recommend weakening protection (monitor mode).
//   - Every call is journaled (who, what, model, token usage, outcome).
//   - Jobs run on one background thread with a bounded queue and an hourly cap.
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
	int max_per_hour = 60;
	size_t max_queue = 8;
	int max_tool_turns = 10;
	std::chrono::seconds timeout{600};
	bool disabled = false;
};

// Replace credentials and other secrets in free text with [REDACTED].
std::string redact(const std::string &s);
json redact_json(const json &j);

// Syntax check for a rules.conf line (the sensor's grammar); empty when valid.
std::string check_rule_line(const std::string &line);

class Assistant {
public:
	Assistant(Store &store, Analyst &analyst, AiConfig cfg);
	~Assistant();
	Assistant(const Assistant &) = delete;
	Assistant &operator=(const Assistant &) = delete;

	bool configured();  // a key is available
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
		std::string id, kind, target, by, status = "queued", created, started, finished, error, model;
		json result;
		long long input_tokens = 0, output_tokens = 0;
	};
	void worker();
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
	bool stop_ = false;
	std::atomic<bool> stopping_{false};  // read by the HTTPS client between polls
	std::thread thread_;
};

}  // namespace wisp
