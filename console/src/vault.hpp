// Policy-controlled secrets vault ("fleet-wide secrets management with
// policy-controlled access").
//
// Secrets are encrypted at rest with AES-256-GCM (the secret's name is bound
// as associated data, so ciphertexts cannot be swapped between names). The
// master key comes from, in order: WISP_VAULT_KEY, the file named by
// WISP_VAULT_KEY_FILE, or a random key generated once into <store>.key with
// mode 0600. Access is gated by RBAC (operator+ to read, admin to write) and
// every read is audited as a console alert.
//
// On-disk format (compatible with the Go console): a JSON object mapping each
// name to base64(nonce[12] || ciphertext || tag[16]), keyed by SHA-256 of the
// key material.
//
// Key material must be at least 32 characters (the generated key is base64
// of 32 random bytes); empty or short material is refused for a new store,
// because SHA-256 of a guessable string is an offline-crackable key. Opening
// an existing store test-decrypts its entries: a key that opens none of them
// is refused ("wrong key") instead of reading every secret as "not found"
// and mixing two keys in one file.
#pragma once

#include <array>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace wisp {

class Vault {
public:
	// Throws std::runtime_error (corrupt store, missing key for an existing store, ...).
	static std::unique_ptr<Vault> open(const std::string &path);
	// "" when name and secret are acceptable, else why not (for a 400): names
	// are 1..256 bytes of UTF-8 without control characters; secrets are UTF-8
	// text (base64-encode binary material) of at most 1 MiB.
	static std::string check(const std::string &name, const std::string &secret);
	// False with *err set on invalid input (see check) or a failed write; the
	// in-memory store is unchanged then.
	bool set(const std::string &name, const std::string &secret, std::string *err);
	// nullopt when the name is unknown, or when its entry cannot be decrypted
	// with the current key (tampered, or written under another key); the
	// latter sets *undecryptable and is logged.
	std::optional<std::string> get(const std::string &name, bool *undecryptable = nullptr) const;
	std::vector<std::string> keys() const;

private:
	std::string path_;
	std::array<unsigned char, 32> key_{};
	std::map<std::string, std::string> items_;
	mutable std::shared_mutex mu_;
};

}  // namespace wisp
