#include "model.hpp"

#include <cmath>

namespace wisp {

static void get_str(const json &j, const char *k, std::string &out) {
	auto it = j.find(k);
	if (it != j.end() && it->is_string())
		out = it->get<std::string>();
}

static void get_int(const json &j, const char *k, long long &out) {
	auto it = j.find(k);
	if (it == j.end() || !it->is_number())
		return;
	if (it->is_number_integer())
		out = it->get<long long>();
	else {
		double d = it->get<double>();
		if (std::isfinite(d) && d == std::floor(d) && std::fabs(d) < 9.2e18)
			out = static_cast<long long>(d);  // integral value sent as a float
	}
}

static void get_double(const json &j, const char *k, double &out) {
	auto it = j.find(k);
	if (it != j.end() && it->is_number())
		out = it->get<double>();
}

static void get_bool(const json &j, const char *k, bool &out) {
	auto it = j.find(k);
	if (it != j.end() && it->is_boolean())
		out = it->get<bool>();
}

static bool get_strs(const json &j, const char *k, std::vector<std::string> &out) {
	auto it = j.find(k);
	if (it == j.end() || !it->is_array())
		return false;
	out.clear();
	for (auto &v : *it)
		if (v.is_string())
			out.push_back(v.get<std::string>());
	return true;
}

Event event_from_json(const json &j) {
	Event e;
	if (!j.is_object())
		return e;
	get_str(j, "id", e.id);
	get_str(j, "ts", e.ts);
	get_str(j, "type", e.type);
	get_str(j, "host", e.host);
	get_str(j, "group", e.group);
	get_str(j, "rule", e.rule);
	get_str(j, "mitre", e.mitre);
	get_str(j, "title", e.title);
	get_str(j, "severity", e.severity);
	get_str(j, "action", e.action);
	get_str(j, "actor", e.actor);
	get_str(j, "actor_src", e.actor_src);
	get_int(j, "pid", e.pid);
	get_int(j, "ppid", e.ppid);
	get_int(j, "uid", e.uid);
	get_str(j, "comm", e.comm);
	get_str(j, "exe", e.exe);
	get_str(j, "cmd", e.cmd);
	get_str(j, "dest", e.dest);
	get_int(j, "dport", e.dport);
	get_str(j, "kind", e.kind);
	get_str(j, "name", e.name);
	get_str(j, "version", e.version);
	get_str(j, "host_id", e.host_id);
	get_str(j, "trust", e.trust);
	get_str(j, "where", e.where);
	get_str(j, "change", e.change);
	get_str(j, "path", e.path);
	get_int(j, "execs", e.execs);
	get_int(j, "alerts_total", e.alerts_total);
	get_double(j, "cpu_pct", e.cpu_pct);
	get_int(j, "rss_kb", e.rss_kb);
	e.has_runtimes = get_strs(j, "runtimes", e.runtimes);
	get_bool(j, "ephemeral", e.ephemeral);
	get_str(j, "mode", e.mode);
	get_str(j, "reason", e.reason);
	get_str(j, "status", e.status);
	get_str(j, "note", e.note);
	get_str(j, "triaged_by", e.triaged_by);
	get_str(j, "triaged_at", e.triaged_at);
	get_int(j, "percent", e.percent);
	get_strs(j, "cohort", e.cohort);
	get_strs(j, "delivered", e.delivered);
	get_strs(j, "failed", e.failed);
	get_str(j, "by", e.by);
	get_str(j, "rx_ts", e.rx_ts);
	get_str(j, "src", e.src);
	get_bool(j, "id_kept", e.id_kept);
	get_strs(j, "send_failed", e.send_failed);
	return e;
}

json event_to_json(const Event &e) {
	json j = json::object();
	auto s = [&](const char *k, const std::string &v) { if (!v.empty()) j[k] = v; };
	auto i = [&](const char *k, long long v) { if (v) j[k] = v; };
	auto a = [&](const char *k, const std::vector<std::string> &v) { if (!v.empty()) j[k] = v; };
	s("id", e.id);
	j["ts"] = e.ts;  // always present, as in the Go console
	j["type"] = e.type;
	j["host"] = e.host;
	j["group"] = e.group;
	s("rule", e.rule);
	s("mitre", e.mitre);
	s("title", e.title);
	s("severity", e.severity);
	s("action", e.action);
	s("actor", e.actor);
	s("actor_src", e.actor_src);
	i("pid", e.pid);
	i("ppid", e.ppid);
	i("uid", e.uid);
	s("comm", e.comm);
	s("exe", e.exe);
	s("cmd", e.cmd);
	s("dest", e.dest);
	i("dport", e.dport);
	s("kind", e.kind);
	s("name", e.name);
	s("version", e.version);
	s("host_id", e.host_id);
	s("trust", e.trust);
	s("where", e.where);
	s("change", e.change);
	s("path", e.path);
	i("execs", e.execs);
	i("alerts_total", e.alerts_total);
	if (e.cpu_pct != 0)
		j["cpu_pct"] = e.cpu_pct;
	i("rss_kb", e.rss_kb);
	a("runtimes", e.runtimes);
	if (e.ephemeral)
		j["ephemeral"] = true;
	s("mode", e.mode);
	s("reason", e.reason);
	s("status", e.status);
	s("note", e.note);
	s("triaged_by", e.triaged_by);
	s("triaged_at", e.triaged_at);
	i("percent", e.percent);
	a("cohort", e.cohort);
	a("delivered", e.delivered);
	a("failed", e.failed);
	s("by", e.by);
	s("rx_ts", e.rx_ts);
	s("src", e.src);
	if (e.id_kept)
		j["id_kept"] = true;
	a("send_failed", e.send_failed);
	return j;
}

json host_to_json(const Host &h) {
	json j = {
	    {"name", h.name},
	    {"group", h.group},
	    {"version", h.version},
	    {"host_id", h.host_id},
	    {"trust", h.trust},
	    {"first_seen", fmt_rfc3339(h.first_seen)},
	    {"last_seen", fmt_rfc3339(h.last_seen)},
	    {"connected", h.connected},
	    {"alerts", h.alerts},
	    {"execs", h.execs},
	    {"cpu_pct", h.cpu_pct},
	    {"peak_cpu", h.peak_cpu},
	    {"rss_kb", h.rss_kb},
	    {"runtimes", h.runtimes},
	    {"ephemeral", h.ephemeral},
	    {"mode", h.mode},
	    {"state", h.state},
	    {"decommissioned_at", fmt_rfc3339(h.decommissioned_at)},
	};
	if (!h.decommissioned.empty())
		j["decommissioned"] = h.decommissioned;
	if (h.dropped_lines)
		j["dropped_lines"] = h.dropped_lines;
	return j;
}

json rollout_to_json(const Rollout &r) {
	json j = {{"ts", fmt_rfc3339(r.ts)}, {"by", r.by},         {"action", r.action},       {"group", r.group},
	          {"percent", r.percent},    {"cohort", r.cohort}, {"delivered", r.delivered}, {"failed", r.failed},
	          {"status", r.status.empty() ? "complete" : r.status}};
	if (!r.id.empty())
		j["id"] = r.id;
	if (!r.send_failed.empty())
		j["send_failed"] = r.send_failed;
	return j;
}

}  // namespace wisp
