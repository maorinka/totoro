#include "analysis.hpp"

#include <algorithm>
#include <regex>
#include <set>
#include <stdexcept>
#include <unordered_set>

#include "rbac.hpp"

namespace wisp {

using namespace std::chrono;

namespace {

int sev_rank(const std::string &s) {
	if (s == "critical") return 4;
	if (s == "high") return 3;
	if (s == "medium") return 2;
	if (s == "low") return 1;
	return 0;
}

// A rule that blocks in enforce mode (and reports "would-block" in monitor mode).
bool blocking_action(const std::string &a) {
	return a == "kill" || a == "quarantine" || a == "kill-failed" || a == "would-block";
}

bool contained_action(const std::string &a) {
	return a == "kill" || a == "quarantine" || a == "deny" || a == "blocked";
}

bool weak_identity(const Host &h) { return h.trust.empty() || h.trust == "generated"; }

std::string program_of(const Event &a) {
	if (!a.comm.empty())
		return a.comm;
	auto s = a.exe.rfind('/');
	return s == std::string::npos ? a.exe : a.exe.substr(s + 1);
}

std::string plural(int n, const std::string &one, const std::string &many) {
	return std::to_string(n) + " " + (n == 1 ? one : many);
}

std::string join(const std::vector<std::string> &v, const std::string &sep, size_t max = 0) {
	std::string out;
	for (size_t i = 0; i < v.size(); i++) {
		if (max && i == max) {
			out += sep + "+" + std::to_string(v.size() - max) + " more";
			break;
		}
		out += (i ? sep : "") + v[i];
	}
	return out;
}

std::string fmt_span(seconds s) {
	if (s < minutes(1))
		return std::to_string(s.count()) + "s";
	if (s < hours(1))
		return std::to_string(duration_cast<minutes>(s).count()) + " min";
	if (s < hours(48))
		return std::to_string(duration_cast<hours>(s).count()) + " h";
	return std::to_string(duration_cast<hours>(s).count() / 24) + " days";
}

std::string str(const json &j, const char *k) {
	auto it = j.find(k);
	return it != j.end() && it->is_string() ? it->get<std::string>() : std::string();
}

std::string priority_of(int score) {
	if (score >= 75) return "P1";
	if (score >= 55) return "P2";
	if (score >= 30) return "P3";
	return "P4";
}

int status_rank(const std::string &s) { return s == "open" ? 0 : s == "acknowledged" ? 1 : 2; }

// When the console received an alert; the sensor's own ts for records from
// consoles that did not stamp receipt time. Ages and windows the engine acts
// on use this, so a sensor clock that is off cannot make an alert look stale
// (or fresh).
TimePoint received(const Event &a) { return parse_ts(a.rx_ts.empty() ? a.ts : a.rx_ts); }

// Actor attributions the sensor falls back to when nothing specific is known
// (agent/actor.c): sharing one of these says nothing about two alerts.
bool generic_actor(const Event &a) {
	return a.actor.empty() || a.actor == "unknown" || a.actor_src == "unknown" ||
	       (a.actor == "service" && (a.actor_src.empty() || a.actor_src == "system")) ||
	       (a.actor == "human" && (a.actor_src.empty() || a.actor_src == "tty"));
}

// A value that can go into a rules.conf condition as is: the sensor splits
// values on commas and the tokenizer on quotes.
bool rule_safe(const std::string &v) {
	if (v.empty() || v.size() > 200)
		return false;
	for (unsigned char c : v)
		if (c < 0x20 || c == ',' || c == '"' || c == '\\' || c == 0x7f)
			return false;
	return true;
}

std::string quote_cond(const std::string &cond) {
	return cond.find(' ') == std::string::npos ? cond : "\"" + cond + "\"";
}

const std::set<std::string> &decision_statuses() {
	static const std::set<std::string> s = {"applying", "applied", "accepted", "failed", "rejected", "expired",
	                                        "interrupted"};
	return s;
}

json suggestion_record(const Suggestion &s) {
	return {{"ts", s.ts},           {"type", "suggestion"},     {"id", s.id},         {"kind", s.kind},
	        {"title", s.title},     {"rationale", s.rationale}, {"severity", s.severity}, {"source", s.source},
	        {"key", s.key},         {"action", s.action},       {"evidence", s.evidence}};
}

json decision_record(const Suggestion &s) {
	return {{"ts", s.decided_at}, {"type", "suggestion_decision"}, {"id", s.id},
	        {"status", s.status}, {"by", s.decided_by},             {"result", s.result}};
}

}  // namespace

std::string utf8_prefix(const std::string &s, size_t max) {
	if (s.size() <= max)
		return s;
	size_t cut = max;
	while (cut > 0 && ((unsigned char)s[cut] & 0xc0) == 0x80)
		cut--;
	return s.substr(0, cut);
}

std::string utf8_clean(std::string_view s) {
	if (valid_utf8(s))
		return std::string(s);
	std::string out;
	out.reserve(s.size());
	for (size_t i = 0; i < s.size();) {
		unsigned char c = (unsigned char)s[i];
		size_t len = c < 0x80 ? 1 : c >= 0xc2 && c <= 0xdf ? 2 : c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
		if (len && i + len <= s.size() && valid_utf8(s.substr(i, len))) {
			out.append(s.substr(i, len));
			i += len;
		} else {
			out += "\xEF\xBF\xBD";  // U+FFFD
			i++;
		}
	}
	return out;
}

bool benign_note(const std::string &note) {
	// Whole words only: "php-fpm", "unexpected" and "benignity" are not verdicts.
	static const std::regex re(R"(\b(benign|false[ -]?positives?|fp|expected|known[ -]good|legit(imate)?)\b)",
	                           std::regex::icase);
	// "not benign", "NOT a false positive", "non-benign", "wasn't expected"
	static const std::regex negated(R"(\b(not|no|never|non|isn'?t|wasn'?t|aren'?t|weren'?t)\W+(\w+\W+){0,2}$)",
	                                std::regex::icase);
	std::string n = utf8_prefix(note, 2000);
	for (auto it = std::sregex_iterator(n.begin(), n.end(), re); it != std::sregex_iterator(); ++it) {
		size_t at = (size_t)it->position();
		size_t from = at > 40 ? at - 40 : 0;
		if (!std::regex_search(n.substr(from, at - from), negated))
			return true;
	}
	return false;
}

std::string suggestion_actor(const std::string &by, const std::string &suggestion_id) {
	return by + " via " + suggestion_id;
}

bool human_benign(const Event &a) {
	if (a.status != "resolved" || !benign_note(a.note))
		return false;
	// Set by an approved suggestion: the note was written by the engine or the
	// model (from telemetry an attacker controls), not by the person approving.
	if (a.triaged_by.find(" via S") != std::string::npos)
		return false;
	// The same, from journals written before triage named the suggestion.
	return a.note.rfind("AI triage", 0) != 0 && a.note.rfind("Closed by analysis", 0) != 0;
}

json suggestion_to_json(const Suggestion &s) {
	return {{"id", s.id},
	        {"ts", s.ts},
	        {"kind", s.kind},
	        {"title", s.title},
	        {"rationale", s.rationale},
	        {"severity", s.severity},
	        {"source", s.source},
	        {"status", s.status},
	        {"action", s.action},
	        {"required_role", approval_role(s)},
	        {"evidence", s.evidence},
	        {"decided_by", s.decided_by},
	        {"decided_at", s.decided_at},
	        {"result", s.result}};
}

std::string required_role(const json &action) {
	return action.is_object() && str(action, "type") == "rollout" ? "deployer" : "operator";
}

std::string approval_role(const Suggestion &s) {
	std::string r = required_role(s.action);
	return s.source == "ai" && role_rank(r) < role_rank("operator") ? "operator" : r;
}

Analyst::Analyst(Store &store) : store_(store) {}

// ---- incidents -------------------------------------------------------------------

std::vector<Incident> Analyst::incidents() {
	// The store's generation is read before the snapshot: if it moves while we
	// correlate, the cache holds a slightly older but consistent result and the
	// next call recomputes. One caller computes at a time; the others wait and
	// take its result instead of correlating the same data again.
	unsigned long long gen = store_.generation();
	{
		std::lock_guard lk(cache_mu_);
		if (gen == cache_gen_)
			return cache_;
	}
	std::lock_guard one(compute_mu_);
	gen = store_.generation();
	{
		std::lock_guard lk(cache_mu_);
		if (gen == cache_gen_)
			return cache_;
	}
	auto out = correlate();
	std::lock_guard lk(cache_mu_);
	cache_gen_ = gen;
	cache_ = out;
	return out;
}

std::string Analyst::resolve_incident(const std::string &id) {
	std::lock_guard lk(cache_mu_);
	auto it = inc_alias_.find(id);
	return it == inc_alias_.end() ? id : it->second;
}

std::vector<Incident> Analyst::correlate() {  // callers hold compute_mu_
	auto alerts = store_.alerts_copy();
	std::map<std::string, Host> hosts;
	for (auto &h : store_.hosts_copy())
		hosts[h.name] = h;
	std::map<std::string, int> exploited, reachable;
	for (auto &f : store_.vuln_findings()) {
		if (f.tier == "exploited")
			exploited[f.host]++;
		else if (f.tier == "reachable")
			reachable[f.host]++;
	}

	std::vector<std::pair<TimePoint, Event>> evs;
	for (auto &a : alerts)
		if (!a.host.empty() && a.host != "console" && sev_rank(a.severity) > 0)
			evs.emplace_back(parse_ts(a.ts), std::move(a));
	std::stable_sort(evs.begin(), evs.end(), [](auto &x, auto &y) {
		return x.second.host != y.second.host ? x.second.host < y.second.host : x.first < y.first;
	});

	// rule -> (time, host) for campaign detection, time-ordered
	std::map<std::string, std::vector<std::pair<TimePoint, std::string>>> by_rule;
	for (auto &[t, a] : evs)
		by_rule[a.rule].emplace_back(t, a.host);
	for (auto &[r, v] : by_rule)
		std::sort(v.begin(), v.end());

	// Correlate within each host: two alerts belong together when they are
	// close in time and share a specific actor (the same agent, tool or user;
	// not the sensor's catch-all service/system, human/tty or unknown) or a
	// process lineage (same pid, one is the other's parent, or siblings under
	// one parent that is not init). Union-find, so a chain links through
	// intermediate alerts.
	std::vector<Incident> out;
	std::vector<std::pair<TimePoint, TimePoint>> spans;
	std::vector<size_t> parent(evs.size());
	for (size_t i = 0; i < parent.size(); i++)
		parent[i] = i;
	auto find = [&](size_t x) {
		while (parent[x] != x)
			x = parent[x] = parent[parent[x]];
		return x;
	};
	auto related = [](const Event &a, const Event &b) {
		if (a.actor == b.actor && a.actor_src == b.actor_src && !generic_actor(a))
			return true;
		return (a.pid && (a.pid == b.pid || a.pid == b.ppid)) || (a.ppid && a.ppid == b.pid) ||
		       (a.ppid > 1 && a.ppid == b.ppid);
	};
	for (size_t i = 0; i < evs.size(); i++)
		for (size_t j = i; j-- > 0;) {
			if (evs[j].second.host != evs[i].second.host || evs[i].first - evs[j].first > incident_gap)
				break;
			if (related(evs[i].second, evs[j].second))
				parent[find(i)] = find(j);
		}
	std::map<size_t, size_t> comp;  // root -> index in out
	for (size_t i = 0; i < evs.size(); i++) {
		size_t r = find(i);
		auto [it, fresh] = comp.try_emplace(r, out.size());
		if (fresh) {
			out.emplace_back();
			spans.emplace_back(evs[i].first, evs[i].first);
		}
		out[it->second].alerts.push_back(evs[i].second);  // evs is time-ordered within a host
		spans[it->second].second = evs[i].first;
	}

	// Stable ids: an incident keeps the id it had (through any of its alerts)
	// when its oldest alert ages out, an earlier alert joins, or it absorbs
	// another incident; the absorbed id becomes an alias of the survivor.
	std::unordered_map<std::string, std::string> next_alert_inc;
	std::map<std::string, std::string> aliases;
	{
		std::lock_guard lk(cache_mu_);
		aliases = inc_alias_;
	}
	std::unordered_set<std::string> used;
	for (auto &inc : out) {
		std::string id;
		for (auto &a : inc.alerts)
			if (auto it = alert_inc_.find(a.id); it != alert_inc_.end() && !used.count(it->second)) {
				id = it->second;
				break;
			}
		for (size_t k = 0; id.empty() && k < inc.alerts.size(); k++)
			if (!used.count("INC-" + inc.alerts[k].id))
				id = "INC-" + inc.alerts[k].id;
		used.insert(id);
		inc.id = id;
		for (auto &a : inc.alerts) {
			if (auto it = alert_inc_.find(a.id); it != alert_inc_.end() && it->second != id)
				aliases[it->second] = id;
			next_alert_inc[a.id] = id;
		}
	}
	alert_inc_ = std::move(next_alert_inc);
	for (auto it = aliases.begin(); it != aliases.end();) {
		std::string to = it->second;
		for (int hop = 0; hop < 8 && !used.count(to); hop++) {
			auto n = aliases.find(to);
			if (n == aliases.end())
				break;
			to = n->second;
		}
		if (used.count(it->first) || !used.count(to)) {
			it = aliases.erase(it);
		} else {
			it->second = to;
			++it;
		}
	}
	{
		std::lock_guard lk(cache_mu_);
		inc_alias_ = std::move(aliases);
	}

	for (size_t n = 0; n < out.size(); n++) {
		Incident &inc = out[n];
		auto [t0, t1] = spans[n];
		const Event &first = inc.alerts.front();
		inc.host = first.host;
		auto hit = hosts.find(inc.host);
		const Host *h = hit == hosts.end() ? nullptr : &hit->second;
		inc.group = h ? h->group : first.group;
		inc.first_ts = first.ts;
		inc.last_ts = inc.alerts.back().ts;
		std::set<std::string> rules, techs, actors, titles_seen;
		int maxsev = 0, n_open = 0, n_ack = 0, n_contained = 0, n_wouldblock = 0;
		const Event *top = &first;
		for (auto &a : inc.alerts) {
			inc.alert_ids.push_back(a.id);
			inc.last_rx = std::max(inc.last_rx, received(a));
			if (rules.insert(a.rule).second)
				inc.rules.push_back(a.rule);
			if (!a.mitre.empty() && a.mitre != "-" && techs.insert(a.mitre).second)
				inc.techniques.push_back(a.mitre);
			std::string actor = a.actor.empty() ? "unknown" : a.actor;
			if (!a.actor_src.empty())
				actor += "/" + a.actor_src;
			if (actors.insert(actor).second)
				inc.actors.push_back(actor);
			if (titles_seen.insert(a.title).second)
				inc.titles.push_back(a.title);
			if (sev_rank(a.severity) > maxsev) {
				maxsev = sev_rank(a.severity);
				top = &a;
			}
			n_open += a.status == "open" || a.status.empty();
			n_ack += a.status == "acknowledged";
			n_contained += contained_action(a.action);
			n_wouldblock += a.action == "would-block";
		}
		inc.severity = top->severity;
		inc.status = n_open ? "open" : n_ack ? "acknowledged" : "resolved";
		inc.contained = n_contained == (int)inc.alerts.size();

		// campaign: the same medium-or-higher detection on other hosts around
		// the same time. Report the rule that spread furthest.
		std::string campaign_rule;
		std::set<std::string> others;
		for (auto &r : inc.rules) {
			bool strong = false;
			for (auto &a : inc.alerts)
				strong |= a.rule == r && sev_rank(a.severity) >= 2;
			if (!strong)
				continue;
			// a window query on the time-ordered list; the count stops at 200
			std::set<std::string> hs;
			auto &v = by_rule[r];
			auto lo = std::lower_bound(v.begin(), v.end(), std::make_pair(t0 - campaign_window, std::string()));
			for (auto it = lo; it != v.end() && it->first <= t1 + campaign_window && hs.size() < 200; ++it)
				if (it->second != inc.host)
					hs.insert(it->second);
			if (hs.size() > others.size()) {
				others = hs;
				campaign_rule = r;
			}
		}
		if ((int)others.size() + 1 >= campaign_hosts)
			for (auto &o : others)
				if (inc.campaign_hosts.size() < 25)
					inc.campaign_hosts.push_back(o);

		// score, with the reason for every point
		int score = 0;
		auto add = [&](int pts, const std::string &why) {
			score += pts;
			inc.reasons.push_back((pts >= 0 ? "+" : "") + std::to_string(pts) + " " + why);
		};
		static const int base[] = {0, 10, 25, 45, 60};
		add(base[maxsev], inc.severity + "-severity detection: " + top->title);
		int strong = 0;
		for (auto &r : inc.rules)
			for (auto &a : inc.alerts)
				if (a.rule == r) {
					strong += sev_rank(a.severity) >= 2;
					break;
				}
		if (strong > 1)
			add(std::min(5 * (strong - 1), 15), std::to_string(strong) + " different medium-or-higher detections");
		if (inc.techniques.size() > 1)
			add(std::min(4 * ((int)inc.techniques.size() - 1), 12),
			    std::to_string(inc.techniques.size()) + " ATT&CK techniques (" + join(inc.techniques, ", ", 4) +
			        "): looks like a chain, not a one-off");
		if (rules.count("ANOM-001") && rules.size() > 1)
			add(5, "a never-before-seen program is involved");
		bool ai_actor = false;
		for (auto &a : inc.alerts)
			ai_actor |= a.actor == "ai";
		if (ai_actor)
			add(5, "an AI agent was the actor");
		if (!inc.campaign_hosts.empty())
			add(10, campaign_rule + " also fired on " + plural((int)others.size(), "other host", "other hosts") +
			            " within " + fmt_span(duration_cast<seconds>(campaign_window)) + ": a campaign");
		if (exploited.count(inc.host))
			add(10, "the host has an exploited vulnerability");
		else if (reachable.count(inc.host))
			add(5, "the host runs a reachable vulnerable package");
		if (h && !h->host_id.empty() && weak_identity(*h))
			add(3, "the host's identity is not hardware-anchored");
		if (inc.contained)
			add(-20, "contained: the sensor stopped every offending process");
		else if (n_wouldblock)
			add(5, "a blocking rule matched but the host is in monitor mode, so nothing was stopped");
		inc.score = std::clamp(score, 0, 100);
		inc.priority = priority_of(inc.score);

		auto span = duration_cast<seconds>(t1 - t0);
		inc.summary = plural((int)inc.alerts.size(), "alert", "alerts") + " on " + inc.host +
		              (span > seconds(0) ? " over " + fmt_span(span) : "") + ": " + join(inc.titles, "; ", 3) +
		              ". Actor" + (inc.actors.size() > 1 ? "s " : " ") + join(inc.actors, ", ", 4) + "." +
		              (inc.contained ? " Contained by the sensor." : "") +
		              (inc.campaign_hosts.empty() ? ""
		                                          : " Also seen on " + join(inc.campaign_hosts, ", ", 5) + ".");
	}
	std::stable_sort(out.begin(), out.end(), [](const Incident &a, const Incident &b) {
		if (status_rank(a.status) != status_rank(b.status))
			return status_rank(a.status) < status_rank(b.status);
		if (a.score != b.score)
			return a.score > b.score;
		return a.last_ts > b.last_ts;
	});
	return out;
}

std::optional<Incident> Analyst::incident(const std::string &id) {
	for (auto &i : incidents())
		if (i.id == id)
			return i;
	return std::nullopt;
}

json Analyst::incident_json(const Incident &inc, bool detail) {
	json j = {{"id", inc.id},
	          {"host", inc.host},
	          {"group", inc.group},
	          {"priority", inc.priority},
	          {"score", inc.score},
	          {"severity", inc.severity},
	          {"status", inc.status},
	          {"first_ts", inc.first_ts},
	          {"last_ts", inc.last_ts},
	          {"alert_count", inc.alerts.size()},
	          {"rules", inc.rules},
	          {"techniques", inc.techniques},
	          {"actors", inc.actors},
	          {"campaign_hosts", inc.campaign_hosts},
	          {"contained", inc.contained},
	          {"summary", inc.summary},
	          {"reasons", inc.reasons}};
	// The incident under its current id and every id it was known by before.
	std::vector<std::string> names = {inc.id};
	{
		std::lock_guard lk(cache_mu_);
		for (auto &[from, to] : inc_alias_)
			if (to == inc.id)
				names.push_back(from);
	}
	std::optional<json> ai;
	for (auto &n : names)
		if ((ai = ai_for(n)))
			break;
	if (ai) {
		json r = ai->contains("result") && (*ai)["result"].is_object() ? (*ai)["result"] : json::object();
		j["ai"] = detail ? *ai
		                 : json{{"verdict", str(r, "verdict")},
		                        {"confidence", str(r, "confidence")},
		                        {"summary", str(r, "summary")},
		                        {"ts", str(*ai, "ts")}};
	} else {
		j["ai"] = nullptr;
	}
	if (detail) {
		json al = json::array();
		for (auto &a : inc.alerts)
			al.push_back(event_to_json(a));
		j["alerts"] = al;
		json sug = json::array();
		std::lock_guard lk(mu_);
		for (auto it = suggestions_.rbegin(); it != suggestions_.rend(); ++it)
			for (auto &n : names)
				if (std::find(it->evidence.begin(), it->evidence.end(), n) != it->evidence.end()) {
					sug.push_back(suggestion_to_json(*it));
					break;
				}
		j["suggestions"] = sug;
	}
	return j;
}

json Analyst::incidents_json(const Query &q) {
	auto get = [&](const char *k) {
		auto it = q.find(k);
		return it == q.end() || it->second.empty() ? std::string() : it->second.front();
	};
	std::string status = get("status"), prio = get("priority"), host = get("host");
	long limit = 200;
	try {
		if (!get("limit").empty())
			limit = std::max(1L, std::stol(get("limit")));
	} catch (...) {
	}
	json out = json::array();
	for (auto &inc : incidents()) {
		if ((long)out.size() >= limit)
			break;
		if (status.empty() ? inc.status == "resolved" : (status != "all" && inc.status != status))
			continue;
		if (!prio.empty() && inc.priority != prio)
			continue;
		if (!host.empty() && inc.host != host)
			continue;
		out.push_back(incident_json(inc, false));
	}
	return out;
}

json Analyst::triage_incident(const std::string &id, const std::string &status, const std::string &note,
                              const std::string &by, const std::vector<std::string> *shown) {
	if (status != "open" && status != "acknowledged" && status != "resolved")
		throw std::invalid_argument("status must be open, acknowledged or resolved");
	auto inc = incident(id);
	if (!inc)
		throw std::invalid_argument("no such incident");
	// Only what the operator saw: an alert that joined the incident after the
	// page was loaded (a new detection from the same actor) keeps its status.
	std::set<std::string> allowed;
	if (shown)
		allowed.insert(shown->begin(), shown->end());
	int n = 0, skipped = 0;
	for (auto &a : inc->alert_ids) {
		if (shown && !allowed.count(a)) {
			skipped++;
			continue;
		}
		try {
			store_.triage(a, status, note, by);
			n++;
		} catch (const std::invalid_argument &) {  // aged out of the window meanwhile
		}
	}
	return {{"incident", inc->id}, {"status", status}, {"updated", n}, {"skipped", skipped}};
}

// ---- fleet health ------------------------------------------------------------------

json Analyst::health_json() {
	auto hosts = store_.hosts_copy();
	auto incs = incidents();
	auto rules = rule_stats();
	json findings = json::array();
	auto finding = [&](const std::string &id, const std::string &sev, const std::string &cat,
	                   const std::string &title, const std::string &detail, std::vector<std::string> hs) {
		std::sort(hs.begin(), hs.end());
		findings.push_back(
		    {{"id", id}, {"severity", sev}, {"category", cat}, {"title", title}, {"detail", detail}, {"hosts", hs}});
	};
	std::vector<std::string> over, stale, weak, drift;
	std::map<std::string, int> versions;
	double peak = 0;
	int live = 0, sensors = 0;
	for (auto &h : hosts) {
		if (h.state == "decommissioned" || h.host_id.empty())
			continue;
		live++;
		sensors += h.connected;
		if (h.connected && h.cpu_pct > 0.05) {
			over.push_back(h.name);
			peak = std::max(peak, h.cpu_pct);
		}
		if (h.state == "stale")
			stale.push_back(h.name);
		if (weak_identity(h))
			weak.push_back(h.name);
		if (!h.version.empty())
			versions[h.version]++;
	}
	if (!over.empty()) {
		char buf[64];
		snprintf(buf, sizeof buf, "%.3f%%", peak);
		finding("sensor-cpu", "medium", "sensor", plural((int)over.size(), "sensor is", "sensors are") +
		                                              " over the 0.05% CPU budget",
		        std::string("Peak ") + buf +
		            " of one core. The governor sheds work above budget, so detections can be delayed. Check the "
		            "exec rate on these hosts and the size of the rule set.",
		        over);
	}
	if (!stale.empty())
		finding("stale", "low", "coverage", plural((int)stale.size(), "host has", "hosts have") + " stopped reporting",
		        "No heartbeat for longer than the stale threshold. Persistent hosts are decommissioned "
		        "automatically if they stay silent; check the sensor service and network path to the console.",
		        stale);
	if (versions.size() > 1) {
		auto major = std::max_element(versions.begin(), versions.end(),
		                              [](auto &a, auto &b) { return a.second < b.second; })->first;
		for (auto &h : hosts)
			if (h.state != "decommissioned" && !h.host_id.empty() && !h.version.empty() && h.version != major)
				drift.push_back(h.name);
		finding("version-drift", "low", "sensor", "Mixed sensor versions",
		        "Most hosts run " + major + "; " + plural((int)drift.size(), "host runs", "hosts run") +
		            " a different version. Upgrade them so every host enforces the same policy.",
		        drift);
	}
	if (!weak.empty())
		finding("identity", "medium", "trust",
		        plural((int)weak.size(), "host uses", "hosts use") + " a software-generated identity",
		        "Their mutual-TLS key is a file on disk, so a copied key could impersonate the host. Enroll a "
		        "TPM or Secure Enclave key (docs/installation.md).",
		        weak);
	std::set<std::string> exposed;
	for (auto &inc : incs) {
		if (inc.status == "resolved" || (inc.priority != "P1" && inc.priority != "P2"))
			continue;
		for (auto &h : hosts)
			if (h.name == inc.host && h.mode == "monitor" && h.state != "decommissioned")
				exposed.insert(h.name);
	}
	if (!exposed.empty())
		finding("unprotected", "high", "enforcement",
		        plural((int)exposed.size(), "host with an open P1/P2 incident is", "hosts with open P1/P2 incidents are") +
		            " not enforcing",
		        "These hosts run in monitor mode, so the sensor reports attacks but does not stop them. See the "
		        "suggestions to switch them to enforce mode.",
		        {exposed.begin(), exposed.end()});
	// Alert volume: the last hour against the hourly mean of the 23 before it,
	// by console receipt time (a sensor clock that is off neither fakes nor
	// hides a spike). The alert window holds at most max_ring alerts; when it
	// is full and covers less than a day, the mean is taken over the hours it
	// does cover, and said so.
	auto now = Clock::now();
	int last_hour = 0, before = 0;
	auto ring = store_.alerts_copy();
	TimePoint oldest = now;
	for (auto &a : ring) {
		if (a.host == "console")
			continue;
		auto t = received(a);
		oldest = std::min(oldest, t);
		if (t > now - hours(1))
			last_hour++;
		else if (t > now - hours(24))
			before++;
	}
	double span = 23;
	if (ring.size() >= store_.max_ring)
		span = std::min(23.0, duration<double>(now - hours(1) - oldest).count() / 3600);
	double mean = span >= 1 ? before / span : 0;
	if (span >= 1 && last_hour >= 10 && last_hour >= 3 * mean + 1) {
		char buf[160];
		if (span < 23)
			snprintf(buf, sizeof buf,
			         "%d alerts in the last hour against an average of %.1f per hour over the %.0f h before it that the "
			         "console's alert window still holds",
			         last_hour, mean, span);
		else
			snprintf(buf, sizeof buf, "%d alerts in the last hour against an average of %.1f per hour", last_hour, mean);
		finding("alert-spike", "medium", "activity", "Alert volume spike",
		        std::string(buf) + ". Check the Incidents page for a campaign.", {});
	}
	std::vector<std::string> noisy;
	for (auto &r : rules)
		if (r.assessment == "noisy")
			noisy.push_back(r.rule);
	if (!noisy.empty())
		finding("noisy-rules", "low", "rules", plural((int)noisy.size(), "rule is", "rules are") + " mostly noise",
		        "Most of their triaged alerts were closed as benign: " + join(noisy, ", ", 6) +
		            ". See Rule review for the suggested change.",
		        {});
	int worst = 0;
	for (auto &f : findings)
		worst = std::max(worst, sev_rank(f["severity"].get<std::string>()));
	return {{"status", worst >= 3 ? "critical" : findings.empty() ? "ok" : "attention"},
	        {"hosts_live", live},
	        {"sensors_connected", sensors},
	        {"findings", findings},
	        {"generated", fmt_rfc3339(now)}};
}

// ---- rule review ---------------------------------------------------------------------

std::vector<RuleStat> Analyst::rule_stats() {
	std::map<std::string, RuleStat> m;
	std::map<std::string, std::set<std::string>> hosts;
	std::map<std::string, std::map<std::string, int>> progs;
	std::map<std::string, std::map<std::string, std::map<std::string, int>>> exes;  // rule -> program -> exe -> n
	for (auto &a : store_.alerts_copy()) {
		if (a.rule.empty() || a.host == "console")
			continue;
		RuleStat &r = m[a.rule];
		r.rule = a.rule;
		r.title = a.title;  // latest wins
		r.severity = a.severity;
		r.technique = a.mitre;
		r.action = a.action;
		r.alerts++;
		if (a.status == "acknowledged")
			r.acknowledged++;
		else if (a.status == "resolved") {
			r.resolved++;
			r.benign += human_benign(a);
		} else
			r.open++;
		hosts[a.rule].insert(a.host);
		std::string p = program_of(a);
		if (!p.empty()) {
			progs[a.rule][p]++;
			if (!a.exe.empty())
				exes[a.rule][p][a.exe]++;
		}
	}
	std::vector<RuleStat> out;
	for (auto &[id, r] : m) {
		r.hosts.assign(hosts[id].begin(), hosts[id].end());
		for (auto &[p, n] : progs[id])
			r.programs.emplace_back(p, n);
		std::stable_sort(r.programs.begin(), r.programs.end(), [](auto &a, auto &b) { return a.second > b.second; });
		if (r.programs.size() > 5)
			r.programs.resize(5);
		int triaged = r.acknowledged + r.resolved;
		r.assessment = "ok";
		if (r.alerts >= 10 && r.benign >= 5 && r.benign * 10 >= 6 * triaged) {
			r.assessment = "noisy";
			std::string why = std::to_string(r.benign) + " of " + std::to_string(triaged) +
			                  " triaged alerts were closed as benign";
			// An exclusion by full path where the sensor saw one (comm is
			// whatever a process calls itself), quoted when it has spaces,
			// and none at all for a name the rule grammar cannot carry.
			std::string cond;
			if (!r.programs.empty() && r.programs[0].second * 10 >= 6 * r.alerts) {
				const std::string &prog = r.programs[0].first;
				std::string exe;
				int best = 0;
				for (auto &[x, n] : exes[id][prog])
					if (n > best) {
						best = n;
						exe = x;
					}
				if (!exe.empty() && exe[0] == '/' && rule_safe(exe) && best * 10 >= 9 * r.programs[0].second)
					cond = quote_cond("!exe=" + exe);
				else if (rule_safe(prog))
					cond = quote_cond("!comm=" + prog);
			}
			if (!cond.empty())
				r.advice = "Exclude " + r.programs[0].first + ": add `" + cond + "` to rule " + r.rule +
				           " in rules.conf. It accounts for " + std::to_string(r.programs[0].second * 100 / r.alerts) +
				           "% of the rule's alerts, and " + why + "." +
				           (cond.find("comm=") != std::string::npos
				                ? " A comm exclusion also lets anything that renames itself to that name evade the rule;"
				                  " prefer exe= with the full path where you can."
				                : "");
			else
				r.advice = "Narrow the conditions of rule " + r.rule + " in rules.conf or lower its severity: " + why +
				           ".";
		} else if (r.action == "alert" && sev_rank(r.severity) >= 3 && r.alerts >= 3 && r.benign == 0 &&
		           triaged >= 2) {
			r.assessment = "ready_to_enforce";
			r.advice = "Every triaged alert of rule " + r.rule + " was a real finding (none closed as benign). "
			           "Change its action from alert to kill in rules.conf so hosts in enforce mode stop it.";
		}
		out.push_back(r);
	}
	std::stable_sort(out.begin(), out.end(), [](auto &a, auto &b) { return a.alerts > b.alerts; });
	return out;
}

json Analyst::rules_json() {
	json out = json::array();
	for (auto &r : rule_stats()) {
		json progs = json::array();
		for (auto &[p, n] : r.programs)
			progs.push_back({{"program", p}, {"alerts", n}});
		json j = {{"rule", r.rule},
		          {"title", r.title},
		          {"severity", r.severity},
		          {"technique", r.technique},
		          {"action", r.action},
		          {"alerts", r.alerts},
		          {"open", r.open},
		          {"acknowledged", r.acknowledged},
		          {"resolved", r.resolved},
		          {"benign", r.benign},
		          {"hosts", r.hosts},
		          {"programs", progs},
		          {"assessment", r.assessment},
		          {"advice", r.advice}};
		auto ai = ai_for("rule:" + r.rule);
		j["ai"] = ai ? *ai : json(nullptr);
		out.push_back(j);
	}
	return out;
}

// ---- suggestions ------------------------------------------------------------------------

Analyst::Snapshot Analyst::snapshot() {
	Snapshot snap;
	snap.hosts = store_.hosts_copy();
	for (auto &e : store_.alerts_copy())
		snap.alert_ids.insert(e.id);
	return snap;
}

void Analyst::validate_action(const json &a) {
	if (!a.is_object())
		throw std::invalid_argument("action must be an object");
	validate_action(a, snapshot());
}

void Analyst::validate_action(const json &a, const Snapshot &snap) {
	if (!a.is_object())
		throw std::invalid_argument("action must be an object");
	std::string type = str(a, "type");
	auto live_host = [&](const std::string &name) {
		for (auto &h : snap.hosts)
			if (h.name == name && h.state != "decommissioned")
				return true;
		return false;
	};
	if (type == "push" || type == "rollout") {
		if (!control_commands().count(str(a, "control")))
			throw std::invalid_argument("action.control must be enforce, monitor or reload");
	}
	if (type == "push") {
		if (!live_host(str(a, "host")))
			throw std::invalid_argument("action.host is not a live host");
	} else if (type == "rollout") {
		if (!a.contains("group") || !a["group"].is_string())
			throw std::invalid_argument("action.group is required");
		// A suggestion never stages a fleet-wide rollout: to Store::rollout an
		// empty group means every group, not the ungrouped hosts.
		std::string g = a["group"].get<std::string>();
		if (g.empty())
			throw std::invalid_argument("action.group must name a group (an empty group would reach every group)");
		bool found = false;
		for (auto &h : snap.hosts)  // sensors only: not the console's own pseudo-host
			found |= h.group == g && h.state != "decommissioned" && !h.host_id.empty();
		if (!found)
			throw std::invalid_argument("action.group has no live hosts");
		auto p = a.find("percent");
		if (p == a.end() || !p->is_number_integer() || p->get<int>() < 1 || p->get<int>() > 100)
			throw std::invalid_argument("action.percent must be an integer 1..100");
	} else if (type == "triage") {
		std::string st = str(a, "status");
		if (st != "open" && st != "acknowledged" && st != "resolved")
			throw std::invalid_argument("action.status must be open, acknowledged or resolved");
		if (str(a, "note").size() > 2000)
			throw std::invalid_argument("action.note too long");
		auto ids = a.find("alerts");
		if (ids == a.end() || !ids->is_array() || ids->empty() || ids->size() > 500)
			throw std::invalid_argument("action.alerts must list 1..500 alert ids");
		for (auto &id : *ids)
			if (!id.is_string() || !snap.alert_ids.count(id.get<std::string>()))
				throw std::invalid_argument("action.alerts names an unknown alert");
	} else if (type == "manual") {
		auto in = str(a, "instructions");
		if (in.empty() || in.size() > 4000)
			throw std::invalid_argument("action.instructions must be 1..4000 characters");
	} else {
		throw std::invalid_argument("action.type must be push, rollout, triage or manual");
	}
}

Suggestion Analyst::propose(Suggestion s) { return propose(std::move(s), nullptr, nullptr); }

Suggestion Analyst::propose(Suggestion s, const Snapshot *snap, bool *fresh) {
	if (fresh)
		*fresh = false;
	if (s.title.empty() || s.title.size() > 300 || s.rationale.size() > 6000)
		throw std::invalid_argument("suggestion needs a title (max 300) and a rationale (max 6000)");
	if (!valid_utf8(s.title) || !valid_utf8(s.rationale) || !valid_utf8(s.key) || !valid_utf8(s.kind))
		throw std::invalid_argument("suggestion text must be valid UTF-8");
	if (!s.action.is_object())
		throw std::invalid_argument("action must be an object");
	if (s.key.empty())
		s.key = s.kind + ":" + s.action.dump(-1, ' ', false, json::error_handler_t::replace);
	// One at a time: dedup, journal, publish. Nothing is visible (or can be
	// decided) before its record is on disk, so the journal never holds a
	// decision ahead of its suggestion.
	std::lock_guard one(propose_mu_);
	std::string reopen;
	{
		std::lock_guard lk(mu_);
		if (auto k = by_key_.find(s.key); k != by_key_.end()) {
			const Suggestion &it = suggestions_[k->second];
			if (it.status == "proposed" || it.status == "applying")
				return it;
			auto age = elapsed_since(parse_ts(it.decided_at));
			if (it.status == "rejected" && age < suppress_rejected)
				return it;
			if ((it.status == "applied" || it.status == "accepted") && age < hours(24))
				return it;
			if (it.status == "expired")
				reopen = it.id;  // the same condition again: same suggestion, not a new one
		}
	}
	if (snap)
		validate_action(s.action, *snap);
	else
		validate_action(s.action);
	s.ts = now_ts();
	s.status = "proposed";
	s.decided_by.clear();
	s.decided_at.clear();
	s.result.clear();
	if (s.source.empty())
		s.source = "analysis";
	{
		std::lock_guard lk(mu_);
		s.id = !reopen.empty() ? reopen : "S" + std::to_string(unix_now()) + "-" + std::to_string(++seq_);
	}
	journal(s);  // throws (bad text): nothing was published
	{
		std::lock_guard lk(mu_);
		auto i = by_id_.find(s.id);
		if (i != by_id_.end()) {
			suggestions_[i->second] = s;
		} else {
			suggestions_.push_back(s);
			by_id_[s.id] = suggestions_.size() - 1;
		}
		by_key_[s.key] = by_id_[s.id];
	}
	if (fresh)
		*fresh = true;
	logf("analysis: %s %s %s: %s", reopen.empty() ? "suggested" : "reopened", s.id.c_str(), s.kind.c_str(),
	     s.title.c_str());
	return s;
}

void Analyst::journal(const Suggestion &s) { store_.record_console(suggestion_record(s)); }

void Analyst::journal_decision(const Suggestion &s) { store_.record_console(decision_record(s)); }

std::string Analyst::apply(const Suggestion &s, const std::string &by, bool *ok) {
	const json &a = s.action;
	std::string type = str(a, "type");
	if (type == "push") {
		std::string host = str(a, "host"), ctl = str(a, "control");
		*ok = store_.push_control(host, control_commands().at(ctl));
		return *ok ? "sent " + ctl + " to " + host : host + " is not connected; nothing was sent";
	}
	if (type == "rollout") {
		std::string g = str(a, "group"), ctl = str(a, "control");
		int pct = a["percent"].get<int>();
		// The cohort Store::rollout will pick; an empty one is nothing done,
		// not a completed stage the next suggestion could build on.
		int cohort = 0;
		for (auto &h : store_.hosts_copy())
			cohort += h.group == g && h.state != "decommissioned" && bucket(h.name) < pct;
		if (!cohort) {
			*ok = false;
			return "nothing to do: no host of " + g + " falls in the " + std::to_string(pct) + "% cohort";
		}
		Rollout r = store_.rollout(ctl, g, pct, suggestion_actor(by, s.id));
		std::set<std::string> write_failed(r.send_failed.begin(), r.send_failed.end());
		std::vector<std::string> offline, failed_writes;
		for (auto &h : r.failed)
			(write_failed.count(h) ? failed_writes : offline).push_back(h);
		*ok = !r.delivered.empty();
		return ctl + " to " + std::to_string(r.percent) + "% of " + (r.group.empty() ? "all groups" : r.group) + ": " +
		       plural((int)r.cohort.size(), "host", "hosts") + ", " + std::to_string(r.delivered.size()) + " delivered" +
		       (offline.empty() ? "" : ", not connected: " + join(offline, ", ", 8)) +
		       (failed_writes.empty() ? "" : ", write failed: " + join(failed_writes, ", ", 8));
	}
	if (type == "triage") {
		int n = 0;
		for (auto &id : a["alerts"]) {
			try {
				// Recorded as set through this suggestion, so its machine-written
				// note never counts as a person's verdict (see human_benign).
				store_.triage(id.get<std::string>(), str(a, "status"), str(a, "note"), suggestion_actor(by, s.id));
				n++;
			} catch (const std::invalid_argument &) {
			}
		}
		*ok = n > 0;
		return "marked " + plural(n, "alert", "alerts") + " " + str(a, "status");
	}
	*ok = true;  // manual
	return "accepted; apply by hand: " + str(a, "instructions");
}

Suggestion Analyst::decide(const std::string &id, bool approve, const std::string &by, const std::string &role,
                           const std::string &note) {
	if (note.size() > 2000)
		throw std::invalid_argument("note too long (max 2000 chars)");
	Suggestion s;
	{
		// Check and claim in one step: a second approval sees "applying", and
		// an analysis pass never expires a suggestion that is being carried out.
		std::lock_guard lk(mu_);
		auto i = by_id_.find(id);
		if (i == by_id_.end())
			throw std::invalid_argument("no such suggestion");
		Suggestion &x = suggestions_[i->second];
		if (x.status != "proposed")
			throw std::invalid_argument("suggestion is already " + x.status);
		if (role_rank(role) < role_rank(approval_role(x)))
			throw std::domain_error("this suggestion needs the " + approval_role(x) + " role");
		x.status = "applying";
		x.decided_by = by;
		x.decided_at = now_ts();
		x.result = approve ? "being carried out" : "being rejected";
		s = x;
	}
	auto publish = [&](const Suggestion &v) {
		std::lock_guard lk(mu_);
		if (auto i = by_id_.find(id); i != by_id_.end())
			suggestions_[i->second] = v;
	};
	if (!approve) {
		s.status = "rejected";
		s.result = note.empty() ? "rejected" : note;
	} else {
		// On disk before anything happens: a console that dies mid-apply
		// replays this as "interrupted", never as still proposed.
		try {
			journal_decision(s);
		} catch (...) {
			s.status = "proposed";
			s.decided_by.clear();
			s.decided_at.clear();
			s.result.clear();
			publish(s);
			throw;
		}
		try {
			validate_action(s.action);  // the fleet may have changed since it was proposed
			bool ok = false;
			s.result = apply(s, by, &ok);
			s.status = !ok ? "failed" : str(s.action, "type") == "manual" ? "accepted" : "applied";
		} catch (const std::exception &e) {
			s.status = "failed";
			s.result = std::string("no longer valid: ") + e.what();
		}
		if (!note.empty())
			s.result += " (note: " + note + ")";
	}
	s.decided_by = by;
	s.decided_at = now_ts();
	s.result = utf8_clean(s.result);
	publish(s);
	journal_decision(s);
	logf("analysis: %s %s by %s: %s", s.id.c_str(), s.status.c_str(), by.c_str(), s.result.c_str());
	return s;
}

json Analyst::suggestions_json(const std::string &status, size_t limit, size_t offset, size_t *total) {
	std::lock_guard lk(mu_);
	// Newest first by proposal time (a reopened suggestion keeps its place in
	// the history but is new again).
	std::vector<const Suggestion *> v;
	for (auto it = suggestions_.rbegin(); it != suggestions_.rend(); ++it) {
		bool open = it->status == "proposed" || it->status == "applying";
		if (status.empty() ? !open : (status != "all" && it->status != status))
			continue;
		v.push_back(&*it);
	}
	std::stable_sort(v.begin(), v.end(), [](auto *a, auto *b) { return a->ts > b->ts; });
	if (total)
		*total = v.size();
	json out = json::array();
	for (size_t i = offset; i < v.size() && out.size() < limit; i++)
		out.push_back(suggestion_to_json(*v[i]));
	return out;
}

std::optional<Suggestion> Analyst::suggestion(const std::string &id) {
	std::lock_guard lk(mu_);
	if (auto i = by_id_.find(id); i != by_id_.end())
		return suggestions_[i->second];
	return std::nullopt;
}

seconds Analyst::elapsed_since(TimePoint t) const {
	auto wall = duration_cast<seconds>(wall_clock() - t);
	auto bound = duration_cast<seconds>(started_wall_ - t) + duration_cast<seconds>(steady_clock::now() - started_);
	return std::min(wall, bound);
}

std::vector<Suggestion> Analyst::build_suggestions(const std::vector<Incident> &incs,
                                                   const std::vector<RuleStat> &rules) {
	std::vector<Suggestion> out;
	auto hosts = store_.hosts_copy();
	auto now = wall_clock();
	std::map<std::string, const Host *> by_name;
	for (auto &h : hosts)
		by_name[h.name] = &h;

	// 1. contain: hosts under a P1/P2 attack that are not enforcing
	std::set<std::string> contained_hosts;
	for (auto &inc : incs) {
		if (inc.status == "resolved" || (inc.priority != "P1" && inc.priority != "P2"))
			continue;
		auto it = by_name.find(inc.host);
		if (it == by_name.end() || it->second->mode != "monitor" || !it->second->connected ||
		    it->second->state == "decommissioned" ||
		    !contained_hosts.insert(inc.host).second)
			continue;
		Suggestion s;
		s.kind = "contain";
		s.severity = inc.priority == "P1" ? "critical" : "high";
		s.title = "Switch " + inc.host + " to enforce mode";
		s.rationale = inc.priority + " incident " + inc.id + ": " + inc.summary +
		              " The host is in monitor mode, so the sensor only reports these. In enforce mode it stops "
		              "processes that match blocking rules.";
		s.action = {{"type", "push"}, {"host", inc.host}, {"control", "enforce"}};
		s.evidence = {inc.id};
		s.key = "enforce-host:" + inc.host;
		out.push_back(s);
	}

	// 2. gradual enforcement per group: 10% -> 50% -> 100%. Never for the
	// ungrouped hosts: a rollout to the empty group reaches every group.
	std::map<std::string, std::vector<const Host *>> groups;
	for (auto &h : hosts)
		if (h.state != "decommissioned" && !h.host_id.empty() && !h.group.empty())
			groups[h.group].push_back(&h);
	auto alerts = store_.alerts_copy();
	auto rollouts = store_.rollouts_copy();  // journal order
	// How far back the alert window reaches (it holds at most max_ring alerts).
	TimePoint window = now - hours(24 * 7);
	if (alerts.size() >= store_.max_ring && !alerts.empty()) {
		TimePoint first = now;
		for (auto &a : alerts)
			first = std::min(first, received(a));
		window = std::max(window, first);
	}
	for (auto &[g, members] : groups) {
		int monitoring = 0, min_bucket = 100;
		TimePoint oldest = now;
		for (auto *h : members) {
			monitoring += h->mode == "monitor";
			min_bucket = std::min(min_bucket, bucket(h->name));
			if (!is_zero(h->first_seen))
				oldest = std::min(oldest, h->first_seen);
		}
		auto watched = elapsed_since(oldest);
		if (!monitoring || watched < hours(24))
			continue;  // nothing to enforce, or not watched long enough to judge noise
		// The newest rollout that touched this group, in the order they were
		// made (not by timestamp: the clock may have been stepped since), a
		// fleet-wide one included. An enforce stage that reached no host is
		// not a stage.
		const Rollout *last = nullptr;
		for (auto it = rollouts.rbegin(); it != rollouts.rend() && !last; ++it)
			if ((it->group == g || it->group.empty()) &&
			    ((it->action == "enforce" && !it->delivered.empty()) || it->action == "monitor"))
				last = &*it;
		int next = 10;
		if (last && last->action == "enforce") {
			if (last->percent >= 100 || elapsed_since(last->ts) < hours(24))
				continue;
			next = last->percent < 50 ? 50 : 100;
		} else if (last && last->action == "monitor" && elapsed_since(last->ts) < hours(24 * 7)) {
			continue;  // someone deliberately rolled back; leave it a week
		}
		// Small groups: the stage must reach at least one host (bucket < percent).
		next = std::max(next, min_bucket + 1);
		bool first_stage = !last || last->action != "enforce";
		// Noise gate: a blocking rule that a person closed as benign in this
		// group would have stopped legitimate work under enforcement. Judged by
		// when it was closed (console time), not by the sensor's timestamp.
		std::set<std::string> names;
		for (auto *h : members)
			names.insert(h->name);
		std::string blocker;
		for (auto &a : alerts)
			if (names.count(a.host) && blocking_action(a.action) && human_benign(a) &&
			    elapsed_since(parse_ts(a.triaged_at.empty() ? a.ts : a.triaged_at)) < hours(24 * 7)) {
				blocker = a.rule;
				break;
			}
		if (!blocker.empty())
			continue;
		std::string covered = window > now - hours(24 * 7)
		                          ? "in the " + fmt_span(duration_cast<seconds>(now - window)) +
		                                " of alerts the console still holds"
		                          : "in the last 7 days";
		Suggestion s;
		s.kind = "rollout";
		s.severity = "medium";
		s.title = first_stage ? "Start enforcing in " + g + " with a " + std::to_string(next) + "% canary"
		                      : "Expand enforcement in " + g + " to " + std::to_string(next) + "%";
		s.rationale =
		    plural(monitoring, "host", "hosts") + " in " + g + " " + (monitoring == 1 ? "is" : "are") +
		    " in monitor mode and the group has been watched for " + fmt_span(watched) +
		    ". No alert from a blocking rule in this group was closed as benign " + covered +
		    ", so enforcing is unlikely to stop legitimate work. " +
		    (first_stage ? "The cohort is the deterministic " + std::to_string(next) +
		                       "% the Rollouts page previews (the smallest stage that reaches a host); later stages "
		                       "keep it."
		                 : "The previous " + std::to_string(last->percent) + "% stage reached " +
		                       plural((int)last->delivered.size(), "host", "hosts") + " and has run for " +
		                       fmt_span(elapsed_since(last->ts)) + " without a benign blocking alert.");
		s.action = {{"type", "rollout"}, {"group", g}, {"control", "enforce"}, {"percent", next}};
		s.key = "rollout:" + g + ":" + std::to_string(next);
		out.push_back(s);
	}

	// 3. rule curation (manual: the console does not own rules.conf)
	for (auto &r : rules) {
		if (r.assessment == "ok")
			continue;
		Suggestion s;
		bool noisy = r.assessment == "noisy";
		s.kind = noisy ? "tune_rule" : "enforce_rule";
		s.severity = noisy ? "low" : "medium";
		s.title = noisy ? "Tune noisy rule " + r.rule : "Make rule " + r.rule + " blocking";
		s.rationale = r.rule + " (" + r.title + ") fired " + plural(r.alerts, "time", "times") + " on " +
		              plural((int)r.hosts.size(), "host", "hosts") + ". " + r.advice;
		s.action = {{"type", "manual"},
		            {"instructions", utf8_prefix(r.advice + " Then check rules.conf with `wispd --check-config` and push a "
		                                                    "policy reload.",
		                                         4000)}};
		s.evidence = {"rule:" + r.rule};
		s.key = s.kind + ":" + r.rule;
		out.push_back(s);
	}

	// 4. close stale, low-priority incidents: quiet for a week by when the
	// console received their alerts (a sensor clock running behind must not
	// make a fresh alert look stale)
	for (auto &inc : incs) {
		if (inc.status != "open" || inc.priority != "P4" || elapsed_since(inc.last_rx) < hours(24 * 7))
			continue;
		json ids = json::array();
		for (auto &a : inc.alerts)
			if (a.status == "open" || a.status.empty())
				ids.push_back(a.id);
		if (ids.empty() || ids.size() > 500)
			continue;
		Suggestion s;
		s.kind = "close_stale";
		s.severity = "info";
		s.title = "Close a stale low-priority incident on " + inc.host;
		s.rationale = inc.summary + " Priority P4 and no new activity for " + fmt_span(elapsed_since(inc.last_rx)) + ".";
		s.action = {{"type", "triage"},
		            {"alerts", ids},
		            {"status", "resolved"},
		            {"note", "Closed by analysis: low priority, no activity for 7 days"}};
		s.evidence = {inc.id};
		s.key = "close:" + inc.id;
		out.push_back(s);
	}

	// 5. patch exploited (and critical reachable) vulnerabilities
	std::map<std::string, std::pair<Finding, std::vector<std::string>>> vulns;
	for (auto &f : store_.vuln_findings())
		if (f.tier == "exploited" || (f.tier == "reachable" && f.cvss >= 9.0)) {
			auto &e = vulns[f.ecosystem + "|" + f.name + "|" + f.version + "|" + f.cve];
			e.first = f;
			e.second.push_back(f.host);
		}
	for (auto &[key, v] : vulns) {
		auto &[f, hs] = v;
		std::string fixed;
		auto db = store_.vulndb.by_key.find(f.ecosystem + "|" + to_lower(f.name));
		if (db != store_.vulndb.by_key.end())
			for (auto &x : db->second)
				if (x.cve == f.cve)
					fixed = !x.fixed.empty() ? x.fixed : x.affected_below;
		Suggestion s;
		s.kind = "patch";
		s.severity = f.tier == "exploited" ? "critical" : "high";
		s.title = "Upgrade " + f.name + " " + f.version + " (" + f.cve + ")";
		char cvss[16];
		snprintf(cvss, sizeof cvss, "%.1f", f.cvss);
		s.rationale = f.cve + " (CVSS " + cvss + ") is " + f.tier + " on " + join(hs, ", ", 8) + ". " + f.note;
		// The host list is bounded: a widespread package must not make the
		// instructions too long to propose.
		s.action = {{"type", "manual"},
		            {"instructions", utf8_prefix("Upgrade " + f.ecosystem + " package " + f.name + " from " + f.version +
		                                             (fixed.empty() ? " to a fixed release" : " to " + fixed + " or later") +
		                                             " on: " + join(hs, ", ", 50) +
		                                             (hs.size() > 50 ? " (the Vulnerabilities page lists every host)" : "") +
		                                             ".",
		                                         4000)}};
		s.evidence = {f.cve};
		s.key = "patch:" + key;
		out.push_back(s);
	}
	return out;
}

int Analyst::run() {
	std::lock_guard run(run_mu_);
	auto incs = incidents();
	auto rules = rule_stats();
	auto built = build_suggestions(incs, rules);
	auto snap = snapshot();  // one copy of hosts and alert ids for every validation this pass
	std::set<std::string> keys;
	int created = 0;
	size_t new_close = 0;
	for (auto &s : built) {
		if (s.kind == "close_stale" && new_close >= max_close_stale) {
			keys.insert(s.key);  // still true: an open copy stays open; the rest come in later passes
			continue;
		}
		bool fresh = false;
		try {
			propose(s, &snap, &fresh);
		} catch (const std::exception &e) {
			// Not a live suggestion any more: leave its key out so a stale
			// proposed copy below expires this pass.
			logf("analysis: dropped suggestion %s: %s", s.title.c_str(), e.what());
			continue;
		}
		keys.insert(s.key);
		created += fresh;
		new_close += fresh && s.kind == "close_stale";
	}
	// Expire engine suggestions whose condition no longer holds, but not on
	// inputs that are unknown rather than false: a host whose mode has not
	// arrived yet (heartbeats are not journaled, so every host is in this
	// state for a minute or more after a restart) or that is not connected.
	std::map<std::string, const Host *> by_name;
	for (auto &h : snap.hosts)
		by_name[h.name] = &h;
	auto unknown = [&](const Suggestion &s) {
		if (s.kind == "contain") {
			auto it = by_name.find(str(s.action, "host"));
			return it != by_name.end() && it->second->state != "decommissioned" &&
			       (it->second->mode.empty() || !it->second->connected);
		}
		if (s.kind == "rollout") {
			bool any = false, known = false;
			for (auto &h : snap.hosts)
				if (h.group == str(s.action, "group") && h.state != "decommissioned" && !h.host_id.empty()) {
					any = true;
					known |= !h.mode.empty() && h.connected;
				}
			return any && !known;
		}
		return false;
	};
	std::vector<Suggestion> expired;
	std::set<std::string> live_targets;
	for (auto &i : incs)
		live_targets.insert(i.id);
	for (auto &r : rules)
		live_targets.insert("rule:" + r.rule);
	{
		std::lock_guard lk(mu_);
		for (auto &s : suggestions_)
			if (s.status == "proposed" && s.source == "analysis" && !keys.count(s.key) && !unknown(s)) {
				s.status = "expired";
				s.decided_by = "analysis";
				s.decided_at = now_ts();
				s.result = "the condition no longer holds";
				expired.push_back(s);
			}
		prune();
		// AI results for incidents and rules that are gone (incident ids that
		// merged into another stay reachable through their alias).
		std::lock_guard ck(cache_mu_);
		for (auto it = ai_.begin(); it != ai_.end();)
			if (!live_targets.count(it->first) && !inc_alias_.count(it->first))
				it = ai_.erase(it);
			else
				++it;
	}
	for (auto &s : expired)
		journal_decision(s);
	// Holds (rejections, recent approvals) must survive journal rotation.
	if (steady_clock::now() - std::max(carried_, started_) >= hours(6)) {
		carried_ = steady_clock::now();
		for (auto &rec : carry_forward())
			store_.record_console(rec);
	}
	return created;
}

void Analyst::reindex() {
	by_id_.clear();
	by_key_.clear();
	for (size_t i = 0; i < suggestions_.size(); i++) {
		by_id_[suggestions_[i].id] = i;
		by_key_[suggestions_[i].key] = i;
	}
}

void Analyst::prune() {
	size_t before = suggestions_.size();
	auto gone = [&](const Suggestion &s) {
		return s.status != "proposed" && s.status != "applying" && elapsed_since(parse_ts(s.decided_at)) > keep_decided;
	};
	suggestions_.erase(std::remove_if(suggestions_.begin(), suggestions_.end(), gone), suggestions_.end());
	// Over the cap: the oldest decided ones go first; open ones always stay.
	size_t excess = suggestions_.size() > max_history ? suggestions_.size() - max_history : 0;
	for (auto it = suggestions_.begin(); excess && it != suggestions_.end();) {
		if (it->status != "proposed" && it->status != "applying") {
			it = suggestions_.erase(it);
			excess--;
		} else {
			++it;
		}
	}
	if (suggestions_.size() != before)
		reindex();
}

// ---- AI results and replay ----------------------------------------------------------------

namespace {
// What an incident or rule view may read from a stored AI result.
bool ai_result_ok(const json &rec) {
	return rec.is_object() && rec.contains("result") && rec["result"].is_object();
}
}  // namespace

void Analyst::attach_ai(const std::string &target, const json &result) {
	if (!ai_result_ok(result) || target.empty() || target.rfind("ask:", 0) == 0)
		return;
	std::lock_guard lk(mu_);
	ai_[target] = result;
}

std::optional<json> Analyst::ai_for(const std::string &target) {
	std::lock_guard lk(mu_);
	auto it = ai_.find(target);
	return it == ai_.end() ? std::nullopt : std::optional<json>(it->second);
}

std::vector<json> Analyst::replayed_ai_jobs() {
	std::lock_guard lk(mu_);
	return {ai_jobs_.begin(), ai_jobs_.end()};
}

std::vector<json> Analyst::carry_forward() {
	std::lock_guard lk(mu_);
	std::vector<json> out;
	for (auto &s : suggestions_) {
		auto hold = s.status == "rejected"                            ? duration_cast<seconds>(suppress_rejected)
		            : s.status == "applied" || s.status == "accepted" ? duration_cast<seconds>(hours(24))
		                                                              : seconds(0);
		if (hold > seconds(0) && elapsed_since(parse_ts(s.decided_at)) < hold) {
			out.push_back(suggestion_record(s));
			out.push_back(decision_record(s));
		}
	}
	return out;
}

void Analyst::replay(const json &rec) {
	std::string type = str(rec, "type");
	std::lock_guard lk(mu_);
	if (type == "suggestion") {
		Suggestion s;
		s.id = str(rec, "id");
		s.ts = str(rec, "ts");
		s.kind = str(rec, "kind");
		s.title = str(rec, "title");
		s.rationale = str(rec, "rationale");
		s.severity = str(rec, "severity");
		s.source = str(rec, "source");
		s.key = str(rec, "key");
		if (auto ac = rec.find("action"); ac != rec.end() && ac->is_object())
			s.action = *ac;
		else
			s.action = json::object();
		if (auto ev = rec.find("evidence"); ev != rec.end() && ev->is_array())
			for (auto &e : *ev)
				if (e.is_string())
					s.evidence.push_back(e.get<std::string>());
		if (s.id.empty())
			return;
		if (auto i = by_id_.find(s.id); i != by_id_.end()) {
			// Reopened, or carried forward across a rotation: the same
			// suggestion again (a decision record follows when it has one).
			suggestions_[i->second] = s;
			by_key_[s.key] = std::max(by_key_[s.key], i->second);
		} else {
			suggestions_.push_back(s);
			by_id_[s.id] = suggestions_.size() - 1;
			by_key_[s.key] = suggestions_.size() - 1;
			seq_++;
		}
	} else if (type == "suggestion_decision") {
		auto i = by_id_.find(str(rec, "id"));
		std::string status = str(rec, "status");
		if (i == by_id_.end() || !decision_statuses().count(status))
			return;
		Suggestion &s = suggestions_[i->second];
		s.status = status;
		s.decided_by = str(rec, "by");
		s.decided_at = str(rec, "ts");
		s.result = str(rec, "result");
		if (status == "applying") {  // no outcome followed: the console stopped mid-apply
			s.status = "interrupted";
			s.result = "the console stopped while this was being carried out; check its target before acting again";
		}
	} else if (type == "ai_result") {
		ai_jobs_.push_back(rec);
		while (ai_jobs_.size() > 200)
			ai_jobs_.pop_front();
		// Incident and rule results only (asks are never attached), and only
		// in the shape the views read.
		std::string target = str(rec, "target"), purpose = str(rec, "purpose");
		if (target.empty() || purpose == "ask" || target.rfind("ask:", 0) == 0 || !ai_result_ok(rec))
			return;
		ai_[target] = rec;
	}
}

}  // namespace wisp
