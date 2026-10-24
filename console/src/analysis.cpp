#include "analysis.hpp"

#include <algorithm>
#include <regex>
#include <set>
#include <stdexcept>

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

// Triage notes that mark an alert as a false positive.
bool benign_note(const std::string &note) {
	static const std::regex re(R"(\b(benign|false[ -]?positive|fp|expected|known[ -]good|legit))",
	                           std::regex::icase);
	return std::regex_search(note, re);
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

}  // namespace

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
	        {"required_role", required_role(s.action)},
	        {"evidence", s.evidence},
	        {"decided_by", s.decided_by},
	        {"decided_at", s.decided_at},
	        {"result", s.result}};
}

std::string required_role(const json &action) {
	return action.is_object() && str(action, "type") == "rollout" ? "deployer" : "operator";
}

Analyst::Analyst(Store &store) : store_(store) {}

// ---- incidents -------------------------------------------------------------------

std::vector<Incident> Analyst::incidents() {
	// The store's generation is read before the snapshot: if it moves while we
	// correlate, the cache holds a slightly older but consistent result and the
	// next call recomputes.
	unsigned long long gen = store_.generation();
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

std::vector<Incident> Analyst::correlate() {
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

	// rule -> (time, host) for campaign detection
	std::map<std::string, std::vector<std::pair<TimePoint, std::string>>> by_rule;
	for (auto &[t, a] : evs)
		by_rule[a.rule].emplace_back(t, a.host);

	// Correlate within each host: two alerts belong together when they are
	// close in time and share an actor (the same agent, tool or user) or a
	// process lineage (same pid, or one is the other's parent). Union-find, so
	// a chain links through intermediate alerts.
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
		if (a.actor == b.actor && a.actor_src == b.actor_src && !a.actor.empty())
			return true;
		return (a.pid && (a.pid == b.pid || a.pid == b.ppid)) || (a.ppid && a.ppid == b.pid);
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

	for (size_t n = 0; n < out.size(); n++) {
		Incident &inc = out[n];
		auto [t0, t1] = spans[n];
		const Event &first = inc.alerts.front();
		inc.id = "INC-" + first.id;
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
			std::set<std::string> hs;
			for (auto &[t, host] : by_rule[r])
				if (host != inc.host && t >= t0 - campaign_window && t <= t1 + campaign_window)
					hs.insert(host);
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
	auto ai = ai_for(inc.id);
	if (ai) {
		json r = ai->value("result", json::object());
		j["ai"] = detail ? *ai
		                 : json{{"verdict", r.value("verdict", "")},
		                        {"confidence", r.value("confidence", "")},
		                        {"summary", r.value("summary", "")},
		                        {"ts", ai->value("ts", "")}};
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
			if (std::find(it->evidence.begin(), it->evidence.end(), inc.id) != it->evidence.end())
				sug.push_back(suggestion_to_json(*it));
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
                              const std::string &by) {
	if (status != "open" && status != "acknowledged" && status != "resolved")
		throw std::invalid_argument("status must be open, acknowledged or resolved");
	auto inc = incident(id);
	if (!inc)
		throw std::invalid_argument("no such incident");
	int n = 0;
	for (auto &a : inc->alert_ids) {
		try {
			store_.triage(a, status, note, by);
			n++;
		} catch (const std::invalid_argument &) {  // aged out of the window meanwhile
		}
	}
	return {{"incident", id}, {"status", status}, {"updated", n}};
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
	// alert volume: the last hour against the hourly mean of the 23 before it
	auto now = Clock::now();
	int last_hour = 0, before = 0;
	for (auto &a : store_.alerts_copy()) {
		if (a.host == "console")
			continue;
		auto t = parse_ts(a.ts);
		if (t > now - hours(1))
			last_hour++;
		else if (t > now - hours(24))
			before++;
	}
	double mean = before / 23.0;
	if (last_hour >= 10 && last_hour >= 3 * mean + 1) {
		char buf[96];
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
			r.benign += benign_note(a.note);
		} else
			r.open++;
		hosts[a.rule].insert(a.host);
		std::string p = program_of(a);
		if (!p.empty())
			progs[a.rule][p]++;
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
			if (!r.programs.empty() && r.programs[0].second * 10 >= 6 * r.alerts)
				r.advice = "Exclude " + r.programs[0].first + ": add `!comm=" + r.programs[0].first + "` to rule " +
				           r.rule + " in rules.conf. It accounts for " +
				           std::to_string(r.programs[0].second * 100 / r.alerts) + "% of the rule's alerts, and " +
				           why + ".";
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

void Analyst::validate_action(const json &a) {
	if (!a.is_object())
		throw std::invalid_argument("action must be an object");
	std::string type = str(a, "type");
	auto live_host = [&](const std::string &name) {
		for (auto &h : store_.hosts_copy())
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
		bool found = false;
		for (auto &h : store_.hosts_copy())
			found |= h.group == a["group"].get<std::string>() && h.state != "decommissioned";
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
		std::set<std::string> known;
		for (auto &e : store_.alerts_copy())
			known.insert(e.id);
		for (auto &id : *ids)
			if (!id.is_string() || !known.count(id.get<std::string>()))
				throw std::invalid_argument("action.alerts names an unknown alert");
	} else if (type == "manual") {
		auto in = str(a, "instructions");
		if (in.empty() || in.size() > 4000)
			throw std::invalid_argument("action.instructions must be 1..4000 characters");
	} else {
		throw std::invalid_argument("action.type must be push, rollout, triage or manual");
	}
}

Suggestion Analyst::propose(Suggestion s) {
	validate_action(s.action);
	if (s.title.empty() || s.title.size() > 300 || s.rationale.size() > 6000)
		throw std::invalid_argument("suggestion needs a title (max 300) and a rationale (max 6000)");
	if (s.key.empty())
		s.key = s.kind + ":" + s.action.dump();
	auto now = Clock::now();
	{
		std::lock_guard lk(mu_);
		for (auto it = suggestions_.rbegin(); it != suggestions_.rend(); ++it) {
			if (it->key != s.key)
				continue;
			if (it->status == "proposed")
				return *it;
			auto decided = parse_ts(it->decided_at);
			if (it->status == "rejected" && now - decided < suppress_rejected)
				return *it;
			if ((it->status == "applied" || it->status == "accepted") && now - decided < hours(24))
				return *it;
			break;
		}
		seq_++;
		s.id = "S" + std::to_string(unix_now()) + "-" + std::to_string(seq_);
		s.ts = now_ts();
		s.status = "proposed";
		if (s.source.empty())
			s.source = "analysis";
		suggestions_.push_back(s);
	}
	journal(s);
	logf("analysis: suggested %s %s: %s", s.id.c_str(), s.kind.c_str(), s.title.c_str());
	return s;
}

void Analyst::journal(const Suggestion &s) {
	store_.record_console({{"ts", s.ts},
	                       {"type", "suggestion"},
	                       {"id", s.id},
	                       {"kind", s.kind},
	                       {"title", s.title},
	                       {"rationale", s.rationale},
	                       {"severity", s.severity},
	                       {"source", s.source},
	                       {"key", s.key},
	                       {"action", s.action},
	                       {"evidence", s.evidence}});
}

void Analyst::journal_decision(const Suggestion &s) {
	store_.record_console({{"ts", s.decided_at},
	                       {"type", "suggestion_decision"},
	                       {"id", s.id},
	                       {"status", s.status},
	                       {"by", s.decided_by},
	                       {"result", s.result}});
}

std::string Analyst::apply(const Suggestion &s, const std::string &by, bool *ok) {
	const json &a = s.action;
	std::string type = str(a, "type");
	if (type == "push") {
		std::string host = str(a, "host"), ctl = str(a, "control");
		*ok = store_.push_control(host, control_commands().at(ctl));
		return *ok ? "sent " + ctl + " to " + host : host + " is not connected; nothing was sent";
	}
	if (type == "rollout") {
		Rollout r = store_.rollout(str(a, "control"), str(a, "group"), a["percent"].get<int>(), by + " via " + s.id);
		*ok = r.cohort.empty() || r.delivered.size() > 0;
		return str(a, "control") + " to " + std::to_string(r.percent) + "% of " +
		       (r.group.empty() ? "all groups" : r.group) + ": " + plural((int)r.cohort.size(), "host", "hosts") +
		       ", " + std::to_string(r.delivered.size()) + " delivered" +
		       (r.failed.empty() ? "" : ", not connected: " + join(r.failed, ", ", 8));
	}
	if (type == "triage") {
		int n = 0;
		for (auto &id : a["alerts"]) {
			try {
				store_.triage(id.get<std::string>(), str(a, "status"), str(a, "note"), by);
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
	std::lock_guard run(run_mu_);
	Suggestion s;
	{
		std::lock_guard lk(mu_);
		auto it = std::find_if(suggestions_.begin(), suggestions_.end(), [&](auto &x) { return x.id == id; });
		if (it == suggestions_.end())
			throw std::invalid_argument("no such suggestion");
		if (it->status != "proposed")
			throw std::invalid_argument("suggestion is already " + it->status);
		s = *it;
	}
	if (role_rank(role) < role_rank(required_role(s.action)))
		throw std::domain_error("this suggestion needs the " + required_role(s.action) + " role");
	if (note.size() > 2000)
		throw std::invalid_argument("note too long (max 2000 chars)");
	if (!approve) {
		s.status = "rejected";
		s.result = note.empty() ? "rejected" : note;
	} else {
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
	{
		std::lock_guard lk(mu_);
		for (auto &x : suggestions_)
			if (x.id == id)
				x = s;
	}
	journal_decision(s);
	logf("analysis: %s %s by %s: %s", s.id.c_str(), s.status.c_str(), by.c_str(), s.result.c_str());
	return s;
}

json Analyst::suggestions_json(const std::string &status) {
	std::lock_guard lk(mu_);
	json out = json::array();
	for (auto it = suggestions_.rbegin(); it != suggestions_.rend(); ++it) {
		bool open = it->status == "proposed";
		if (status.empty() ? !open : (status != "all" && it->status != status))
			continue;
		out.push_back(suggestion_to_json(*it));
	}
	return out;
}

std::optional<Suggestion> Analyst::suggestion(const std::string &id) {
	std::lock_guard lk(mu_);
	for (auto &s : suggestions_)
		if (s.id == id)
			return s;
	return std::nullopt;
}

std::vector<Suggestion> Analyst::build_suggestions(const std::vector<Incident> &incs,
                                                   const std::vector<RuleStat> &rules) {
	std::vector<Suggestion> out;
	auto hosts = store_.hosts_copy();
	auto now = Clock::now();
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

	// 2. gradual enforcement per group: 10% -> 50% -> 100%
	std::map<std::string, std::vector<const Host *>> groups;
	for (auto &h : hosts)
		if (h.state != "decommissioned" && !h.host_id.empty())
			groups[h.group].push_back(&h);
	auto alerts = store_.alerts_copy();
	auto rollouts = store_.rollouts_copy();
	for (auto &[g, members] : groups) {
		int monitoring = 0;
		TimePoint oldest = now;
		for (auto *h : members) {
			monitoring += h->mode == "monitor";
			if (!is_zero(h->first_seen))
				oldest = std::min(oldest, h->first_seen);
		}
		if (!monitoring || now - oldest < hours(24))
			continue;  // nothing to enforce, or not watched long enough to judge noise
		const Rollout *last = nullptr;
		for (auto &r : rollouts)
			if (r.group == g && (r.action == "enforce" || r.action == "monitor") && (!last || r.ts >= last->ts))
				last = &r;
		int next = 10;
		if (last && last->action == "enforce") {
			if (last->percent >= 100 || now - last->ts < hours(24))
				continue;
			next = last->percent < 50 ? 50 : 100;
		} else if (last && last->action == "monitor" && now - last->ts < hours(24 * 7)) {
			continue;  // someone deliberately rolled back; leave it a week
		}
		// Noise gate: a blocking rule closed as benign in this group would have
		// stopped legitimate work under enforcement.
		std::set<std::string> names;
		for (auto *h : members)
			names.insert(h->name);
		std::string blocker;
		for (auto &a : alerts)
			if (names.count(a.host) && blocking_action(a.action) && a.status == "resolved" && benign_note(a.note) &&
			    parse_ts(a.ts) > now - hours(24 * 7)) {
				blocker = a.rule;
				break;
			}
		if (!blocker.empty())
			continue;
		std::string gname = g.empty() ? "(no group)" : g;
		Suggestion s;
		s.kind = "rollout";
		s.severity = "medium";
		s.title = next == 10 ? "Start enforcing in " + gname + " with a 10% canary"
		                     : "Expand enforcement in " + gname + " to " + std::to_string(next) + "%";
		s.rationale =
		    plural(monitoring, "host", "hosts") + " in " + gname + " " + (monitoring == 1 ? "is" : "are") +
		    " in monitor mode and the group has been watched for " +
		    fmt_span(duration_cast<seconds>(now - oldest)) +
		    ". No alert from a blocking rule in this group was closed as benign in the last 7 days, so enforcing "
		    "is unlikely to stop legitimate work. " +
		    (next == 10 ? "The cohort is the deterministic 10% the Rollouts page previews; later stages keep it."
		                : "The previous " + std::to_string(last->percent) + "% stage has run for " +
		                      fmt_span(duration_cast<seconds>(now - last->ts)) + " without a benign blocking alert.");
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
		s.action = {{"type", "manual"}, {"instructions", r.advice + " Then push a policy reload."}};
		s.evidence = {"rule:" + r.rule};
		s.key = s.kind + ":" + r.rule;
		out.push_back(s);
	}

	// 4. close stale, low-priority incidents
	for (auto &inc : incs) {
		if (inc.status != "open" || inc.priority != "P4" || parse_ts(inc.last_ts) > now - hours(24 * 7))
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
		s.rationale = inc.summary + " Priority P4 and no new activity for " +
		              fmt_span(duration_cast<seconds>(now - parse_ts(inc.last_ts))) + ".";
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
		s.action = {{"type", "manual"},
		            {"instructions", "Upgrade " + f.ecosystem + " package " + f.name + " from " + f.version +
		                                 (fixed.empty() ? " to a fixed release" : " to " + fixed + " or later") +
		                                 " on: " + join(hs, ", ") + "."}};
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
	std::set<std::string> keys;
	int created = 0;
	for (auto &s : built) {
		size_t before;
		{
			std::lock_guard lk(mu_);
			before = suggestions_.size();
		}
		try {
			propose(s);
		} catch (const std::exception &e) {
			// Not a live suggestion any more: leave its key out so a stale
			// proposed copy below expires this pass.
			logf("analysis: dropped suggestion %s: %s", s.title.c_str(), e.what());
			continue;
		}
		keys.insert(s.key);
		std::lock_guard lk(mu_);
		created += suggestions_.size() > before;
	}
	// Expire engine suggestions whose condition no longer holds.
	std::vector<Suggestion> expired;
	{
		std::lock_guard lk(mu_);
		for (auto &s : suggestions_)
			if (s.status == "proposed" && s.source == "analysis" && !keys.count(s.key)) {
				s.status = "expired";
				s.decided_by = "analysis";
				s.decided_at = now_ts();
				s.result = "the condition no longer holds";
				expired.push_back(s);
			}
	}
	for (auto &s : expired)
		journal_decision(s);
	return created;
}

// ---- AI results and replay ----------------------------------------------------------------

void Analyst::attach_ai(const std::string &target, const json &result) {
	std::lock_guard lk(mu_);
	ai_[target] = result;
}

std::optional<json> Analyst::ai_for(const std::string &target) {
	std::lock_guard lk(mu_);
	auto it = ai_.find(target);
	return it == ai_.end() ? std::nullopt : std::optional<json>(it->second);
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
		s.action = rec.value("action", json::object());
		if (auto ev = rec.find("evidence"); ev != rec.end() && ev->is_array())
			for (auto &e : *ev)
				if (e.is_string())
					s.evidence.push_back(e.get<std::string>());
		if (!s.id.empty()) {
			suggestions_.push_back(s);
			seq_++;
		}
	} else if (type == "suggestion_decision") {
		for (auto &s : suggestions_)
			if (s.id == str(rec, "id")) {
				s.status = str(rec, "status");
				s.decided_by = str(rec, "by");
				s.decided_at = str(rec, "ts");
				s.result = str(rec, "result");
			}
	} else if (type == "ai_result" && !str(rec, "target").empty() && rec.contains("result")) {
		ai_[str(rec, "target")] = rec;
	}
}

}  // namespace wisp
