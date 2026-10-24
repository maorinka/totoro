#include "rbac.hpp"

#include <cstring>
#include <openssl/crypto.h>
#include <sstream>
#include <stdexcept>

#include "util.hpp"

namespace wisp {

int role_rank(const std::string &role) {
	if (role == "viewer") return 1;
	if (role == "deployer") return 2;
	if (role == "operator") return 3;
	if (role == "admin") return 4;
	return 0;
}

RBAC::RBAC(const RBAC &o) : t_(o.table()) {}

RBAC &RBAC::operator=(const RBAC &o) {
	if (this != &o) {
		auto t = o.table();
		std::lock_guard g(mu_);
		t_ = std::move(t);
	}
	return *this;
}

std::shared_ptr<const RBAC::Table> RBAC::table() const {
	std::lock_guard g(mu_);
	return t_;
}

// Plaintext tokens that are obviously not secret: the shipped examples
// ("CHANGE-ME-admin-token") and the usual template spellings.
static bool placeholder(const std::string &token) {
	std::string t = to_lower(token);
	for (const char *p : {"change-me", "changeme", "change_me", "replace-me", "replaceme", "replace_me", "placeholder",
	                      "example", "your-token", "your_token", "<", ">"})
		if (contains(t, p))
			return true;
	return false;
}

std::shared_ptr<const RBAC::Table> RBAC::parse(const std::string &path) {
	auto t = std::make_shared<Table>();
	t->path = path;
	if (path.empty())
		return t;
	int err = 0;
	auto body = read_file(path, &err);
	if (!body)
		throw std::runtime_error("roles file: open " + path + ": " + strerror(err));
	std::istringstream in(*body);
	std::string raw;
	std::vector<int> line_of;  // source line of each principal, for duplicate reports
	int plaintext = 0, first_plain = 0;
	for (int ln = 1; std::getline(in, raw); ln++) {
		std::string line = trim(raw);
		if (line.empty() || line[0] == '#')
			continue;
		auto parts = fields(line);
		auto where = path + ":" + std::to_string(ln) + ": ";
		if (parts.size() < 2 || role_rank(parts[1]) == 0)
			throw std::runtime_error(where + "want \"<sha256:hex|token> <viewer|deployer|operator|admin> [name]\"");
		Principal p;
		p.role = parts[1];
		p.name = parts[1];
		if (parts.size() >= 3) {  // display names may contain spaces
			p.name = parts[2];
			for (size_t i = 3; i < parts.size(); i++)
				p.name += " " + parts[i];
		}
		if (parts[0].rfind("sha256:", 0) == 0) {
			auto b = hex_decode(std::string_view(parts[0]).substr(7));
			if (!b || b->size() != 32)
				throw std::runtime_error(where + "bad sha256 digest");
			std::copy(b->begin(), b->end(), p.digest.begin());
		} else {
			if (parts[0].size() < 16)
				throw std::runtime_error(where + "token too short (min 16 chars)");
			if (placeholder(parts[0]))
				throw std::runtime_error(where +
				                         "placeholder token (e.g. CHANGE-ME-...) is not a credential; generate a "
				                         "real one with `wisp-console -gen-token <role>:<name>`");
			p.digest = sha256(parts[0]);
			if (plaintext++ == 0)
				first_plain = ln;
		}
		for (size_t i = 0; i < t->principals.size(); i++)
			if (CRYPTO_memcmp(t->principals[i].digest.data(), p.digest.data(), 32) == 0)
				throw std::runtime_error(where + "the same token is already defined on line " +
				                         std::to_string(line_of[i]) + "; remove one of the two lines");
		t->principals.push_back(std::move(p));
		line_of.push_back(ln);
	}
	if (t->principals.empty())
		throw std::runtime_error("roles file " + path + " defines no tokens");
	if (plaintext)
		t->warnings.push_back(path + ":" + std::to_string(first_plain) + ": " + std::to_string(plaintext) +
		                      " plaintext token" + (plaintext == 1 ? "" : "s") +
		                      " on disk; store only hashes (sha256:... lines from -gen-token)");
	t->enabled = true;
	return t;
}

RBAC RBAC::load(const std::string &path) {
	RBAC r;
	r.t_ = parse(path);
	return r;
}

void RBAC::reload() {
	auto cur = table();
	if (cur->path.empty())
		return;
	auto next = parse(cur->path);  // throws: the current table stays
	std::lock_guard g(mu_);
	t_ = std::move(next);
}

bool RBAC::enabled() const { return table()->enabled; }
std::string RBAC::path() const { return table()->path; }
size_t RBAC::size() const { return table()->principals.size(); }
std::vector<std::string> RBAC::warnings() const { return table()->warnings; }

std::pair<std::string, std::string> RBAC::identify(const std::string &authorization) const {
	auto t = table();
	if (!t->enabled)
		return {"admin", "dev"};
	static const std::string prefix = "Bearer ";
	if (authorization.rfind(prefix, 0) != 0 || authorization.size() == prefix.size())
		return {"", ""};
	auto d = sha256(std::string_view(authorization).substr(prefix.size()));
	std::string role, name;
	// Check every principal so timing does not reveal which (if any) matched.
	// Digests are unique (load refuses duplicates), so at most one matches.
	for (auto &p : t->principals)
		if (CRYPTO_memcmp(d.data(), p.digest.data(), 32) == 0) {
			role = p.role;
			name = p.name;
		}
	return {role, name};
}

std::string random_token() {
	std::string b64 = base64_encode(random_bytes(24));  // 24 bytes -> 32 chars, no padding
	for (auto &c : b64) {  // URL-safe alphabet, matching the Go console's tokens
		if (c == '+') c = '-';
		else if (c == '/') c = '_';
	}
	return "wisp_" + b64;
}

std::pair<std::string, std::string> gen_token(const std::string &role, const std::string &name) {
	std::string tok = random_token();
	auto d = sha256(tok);
	return {tok, "sha256:" + hex_encode(d.data(), d.size()) + " " + role + " " + name};
}

}  // namespace wisp
