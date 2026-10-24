// Vulnerability database (ecosystem + package name -> known vulnerabilities).
#pragma once

#include <map>
#include <string>
#include <vector>

namespace wisp {

struct Vuln {
	std::string ecosystem, name;
	std::vector<std::string> affected;  // exact vulnerable versions
	std::string affected_below;          // vulnerable if version < this
	std::string fixed, cve, severity, note;
	double cvss = 0;
	bool affects(const std::string &version) const;
};

struct VulnDB {
	std::vector<Vuln> list;
	std::map<std::string, std::vector<Vuln>> by_key;  // "ecosystem|lowercase name"
	// Loads `path`, or the copy bundled into the binary when empty. A missing
	// or malformed file throws: an empty DB would silently report "no vulns".
	static VulnDB load(const std::string &path);
};

// Version precedence for affectedBelow: numeric components (leading digits
// of each), a leading "v" and "+build" ignored, and a pre-release ("-rc.1",
// "rc1", ".dev2") before its release, per semver for the identifiers.
bool ver_less(const std::string &a, const std::string &b);

}  // namespace wisp
