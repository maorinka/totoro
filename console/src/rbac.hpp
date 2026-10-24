// Role-based access control for the console.
//
//   viewer   - read fleet state (hosts, alerts, events, inventory, vulns, posture)
//   deployer - viewer + staged rollouts (gradual deployment controls)
//   operator - deployer + alert triage, single-host policy push, vault read
//   admin    - everything, including vault write
//
// roles.conf maps API tokens to roles, one per line:
//
//   sha256:<hex digest> <role> [name]      recommended: only the hash on disk
//   <token> <role> [name]                  plaintext token (>= 16 chars; warned)
//
// Placeholder tokens (anything containing CHANGE-ME, CHANGEME or similar) and
// a token that appears on two lines are refused, so a template copied into
// place unedited cannot grant access and a leftover line cannot silently
// decide a role.
//
// Generate a token and its hash with `wisp-console -gen-token`. Every API
// request carries "Authorization: Bearer <token>". Tokens are compared in
// constant time. Without a roles file the console refuses to start unless
// -dev is given, in which case every request is admin (local demos only).
#pragma once

#include <array>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace wisp {

int role_rank(const std::string &role);  // 0 for unknown

// Thread-safe: identify() may run on every HTTP thread while reload() swaps
// in a new table (for example on SIGHUP). A request sees either the old or
// the new table, never a mix.
class RBAC {
public:
	RBAC() = default;
	RBAC(const RBAC &o);
	RBAC &operator=(const RBAC &o);

	// Throws std::runtime_error with a "file:line: ..." message on bad input:
	// unknown roles, short or placeholder plaintext tokens (the CHANGE-ME
	// examples), bad digests, the same token on two lines, or no tokens.
	static RBAC load(const std::string &path);
	// Re-read the file this table was loaded from and swap it in atomically.
	// On any error the current table stays in force and the error is thrown.
	// A no-op for a table that was not loaded from a file (-dev).
	void reload();
	bool enabled() const;
	std::string path() const;
	size_t size() const;  // number of tokens
	// Non-fatal findings from the last load/reload ("file:line: plaintext
	// token ..."). They never contain token material.
	std::vector<std::string> warnings() const;
	// role and display name for an Authorization header value ("" if unauthenticated).
	std::pair<std::string, std::string> identify(const std::string &authorization) const;

private:
	struct Principal {
		std::array<unsigned char, 32> digest;
		std::string role, name;
	};
	struct Table {
		std::string path;
		std::vector<Principal> principals;
		std::vector<std::string> warnings;
		bool enabled = false;
	};
	static std::shared_ptr<const Table> parse(const std::string &path);
	std::shared_ptr<const Table> table() const;

	mutable std::mutex mu_;
	std::shared_ptr<const Table> t_ = std::make_shared<const Table>();
};

std::string random_token();
// A fresh token and the roles.conf line holding only its hash.
std::pair<std::string, std::string> gen_token(const std::string &role, const std::string &name);

}  // namespace wisp
