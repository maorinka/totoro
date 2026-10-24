#include "vulndb.hpp"

#include <algorithm>
#include <cstring>
#include <nlohmann/json.hpp>
#include <stdexcept>

#include "assets.hpp"
#include "util.hpp"

namespace wisp {

static std::vector<std::string> split(const std::string &s, char sep) {
	std::vector<std::string> out;
	size_t a = 0;
	for (;;) {
		size_t b = s.find(sep, a);
		out.push_back(s.substr(a, b == std::string::npos ? std::string::npos : b - a));
		if (b == std::string::npos)
			return out;
		a = b + 1;
	}
}

// A version as the comparison sees it: numeric release components, and the
// pre-release identifiers (semver "-rc.1", or a PEP 440 style "rc1"/"b2"/
// ".dev3" suffix). A leading "v" and "+build" metadata are ignored.
struct Ver {
	std::vector<long> nums;
	std::vector<std::string> pre;
};

static bool all_digits(const std::string &s) {
	return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

static long num(const std::string &digits) {
	long v = 0;
	for (char c : digits) {
		if (v > 100000000L)
			return v;  // absurdly long component: saturate instead of overflowing
		v = v * 10 + (c - '0');
	}
	return v;
}

static Ver parse_ver(std::string s) {
	Ver v;
	if (s.size() > 1 && (s[0] == 'v' || s[0] == 'V') && s[1] >= '0' && s[1] <= '9')
		s.erase(0, 1);
	if (auto plus = s.find('+'); plus != std::string::npos)
		s.erase(plus);  // build metadata never affects precedence
	std::string pre;
	if (auto dash = s.find('-'); dash != std::string::npos) {
		pre = s.substr(dash + 1);
		s.erase(dash);
	}
	for (auto &c : split(s, '.')) {
		size_t k = 0;
		while (k < c.size() && c[k] >= '0' && c[k] <= '9')
			k++;
		if (k == 0) {
			if (!c.empty() && pre.empty())
				pre = c;  // "1.0.dev3", "1.0.rc1": a pre-release tag after the release numbers
			break;
		}
		v.nums.push_back(num(c.substr(0, k)));
		if (k < c.size()) {
			if (pre.empty())
				pre = c.substr(k);  // "1.0rc1", "2.0b2"
			break;
		}
	}
	if (!pre.empty() && to_lower(pre).rfind("post", 0) != 0)  // ".post1" is after the release
		v.pre = split(pre, '.');
	return v;
}

// Semver precedence for pre-release identifiers: numeric ones compare
// numerically and sort before alphanumeric ones; a shorter list sorts first.
static int cmp_pre(const std::vector<std::string> &a, const std::vector<std::string> &b) {
	for (size_t i = 0; i < a.size() && i < b.size(); i++) {
		bool an = all_digits(a[i]), bn = all_digits(b[i]);
		if (an && bn) {
			long x = num(a[i]), y = num(b[i]);
			if (x != y)
				return x < y ? -1 : 1;
		} else if (an != bn) {
			return an ? -1 : 1;
		} else if (int c = a[i].compare(b[i]); c != 0) {
			return c < 0 ? -1 : 1;
		}
	}
	return a.size() == b.size() ? 0 : a.size() < b.size() ? -1 : 1;
}

bool ver_less(const std::string &a, const std::string &b) {
	Ver x = parse_ver(a), y = parse_ver(b);
	for (size_t i = 0; i < x.nums.size() || i < y.nums.size(); i++) {
		long p = i < x.nums.size() ? x.nums[i] : 0;
		long q = i < y.nums.size() ? y.nums[i] : 0;
		if (p != q)
			return p < q;
	}
	// Same release numbers: a pre-release comes before the release itself.
	if (x.pre.empty() || y.pre.empty())
		return !x.pre.empty() && y.pre.empty();
	return cmp_pre(x.pre, y.pre) < 0;
}

bool Vuln::affects(const std::string &version) const {
	for (auto &a : affected)
		if (a == version)
			return true;
	if (!affected_below.empty() && !version.empty())
		return ver_less(version, affected_below);
	return false;
}

VulnDB VulnDB::load(const std::string &path) {
	std::string body;
	if (path.empty()) {
		auto a = find_asset("vulndb.json");
		if (!a)
			throw std::runtime_error("vulndb: bundled database missing from build");
		body.assign(a->data, a->size);
	} else {
		int err = 0;
		auto b = read_file(path, &err);
		if (!b)
			throw std::runtime_error("vulndb: open " + path + ": " + strerror(err));
		body = *b;
	}
	VulnDB db;
	try {
		auto j = nlohmann::json::parse(body);
		if (!j.is_array())
			throw std::runtime_error("expected a JSON array");
		for (auto &e : j) {
			Vuln v;
			auto str = [&](const char *k) { return e.contains(k) && e[k].is_string() ? e[k].get<std::string>() : ""; };
			v.ecosystem = str("ecosystem");
			v.name = str("name");
			v.affected_below = str("affectedBelow");
			v.fixed = str("fixed");
			v.cve = str("cve");
			v.severity = str("severity");
			v.note = str("note");
			if (e.contains("cvss") && e["cvss"].is_number())
				v.cvss = e["cvss"].get<double>();
			if (e.contains("affected") && e["affected"].is_array())
				for (auto &x : e["affected"])
					if (x.is_string())
						v.affected.push_back(x.get<std::string>());
			db.list.push_back(v);
		}
	} catch (const std::exception &ex) {
		throw std::runtime_error("vulndb \"" + path + "\": " + ex.what());
	}
	for (auto &v : db.list)
		db.by_key[v.ecosystem + "|" + to_lower(v.name)].push_back(v);
	return db;
}

}  // namespace wisp
