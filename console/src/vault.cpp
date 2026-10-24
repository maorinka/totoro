#include "vault.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <stdexcept>
#include <sys/stat.h>

#include "util.hpp"

namespace wisp {

static constexpr int NONCE = 12, TAG = 16;

static constexpr size_t MIN_KEY = 32;     // characters of key material
static constexpr size_t MAX_NAME = 256;
static constexpr size_t MAX_SECRET = 1 << 20;

struct KeyMaterial {
	std::string value, source;
	bool generated = false;
};

static KeyMaterial vault_key(const std::string &path) {
	if (const char *k = getenv("WISP_VAULT_KEY"); k && *k)
		return {k, "WISP_VAULT_KEY"};
	if (const char *kf = getenv("WISP_VAULT_KEY_FILE"); kf && *kf) {
		int err = 0;
		auto b = read_file(kf, &err);
		if (!b)
			throw std::runtime_error(std::string("WISP_VAULT_KEY_FILE: ") + strerror(err));
		return {trim(*b), std::string("WISP_VAULT_KEY_FILE ") + kf};
	}
	std::string kp = path + ".key";
	int err = 0;
	if (auto b = read_file(kp, &err))
		return {trim(*b), "vault key file " + kp};
	if (err != ENOENT)
		throw std::runtime_error("vault key " + kp + ": " + strerror(err));
	struct stat st;
	if (stat(path.c_str(), &st) == 0)
		// A store exists but its key does not: generating a new key would
		// make every stored secret unreadable. Refuse instead.
		throw std::runtime_error("vault store " + path + " exists but its key " + kp +
		                         " is missing; restore the key or set WISP_VAULT_KEY");
	std::string k = base64_encode(random_bytes(32));
	std::string werr;
	if (!write_file_atomic(kp, k, 0600, &werr))
		throw std::runtime_error("vault key: " + werr);
	return {k, "vault key file " + kp, true};
}

static std::optional<std::string> open_sealed(const std::array<unsigned char, 32> &key, const std::string &aad,
                                              const std::string &raw);

std::unique_ptr<Vault> Vault::open(const std::string &path) {
	auto v = std::make_unique<Vault>();
	v->path_ = path;
	KeyMaterial km = vault_key(path);
	if (km.value.empty())
		// sha256("") is a key anyone can compute: an empty key file (a failed
		// template or secret-manager mount) must not silently encrypt with it.
		throw std::runtime_error(km.source + " is empty; refusing to encrypt secrets with an empty key");
	v->key_ = sha256(km.value);
	int err = 0;
	auto b = read_file(path, &err);
	if (!b && err != ENOENT)
		throw std::runtime_error("vault store: " + std::string(strerror(err)));
	if (b) {
		try {
			auto j = nlohmann::json::parse(*b);
			if (!j.is_object())
				throw std::runtime_error("not a JSON object");
			for (auto &[k, val] : j.items()) {
				if (!val.is_string())
					throw std::runtime_error("entry " + k + " is not a string");
				v->items_[k] = val.get<std::string>();
			}
		} catch (const std::exception &e) {
			throw std::runtime_error("vault store " + path + " is corrupt: " + e.what());
		}
	}
	// Does this key open the store? A wrong key would otherwise read every
	// secret as "not found" and new writes would mix two keys in one file.
	size_t opened = 0, failed = 0;
	for (auto &[name, enc] : v->items_) {
		auto raw = base64_decode(enc);
		if (raw && open_sealed(v->key_, name, *raw))
			opened++;
		else
			failed++;
	}
	if (failed && !opened)
		throw std::runtime_error("vault key from " + km.source + " does not decrypt any of the " +
		                         std::to_string(failed) + " secrets in " + path +
		                         " (wrong key?); start with the key the store was written with");
	if (failed)
		logf("vault: WARNING: %zu of %zu entries in %s cannot be decrypted with the current key (tampered, or "
		     "written under another key)",
		     failed, failed + opened, path.c_str());
	if (km.value.size() < MIN_KEY) {
		if (!opened)
			throw std::runtime_error(km.source + " is too short (" + std::to_string(km.value.size()) + " chars, need >= " +
			                         std::to_string(MIN_KEY) +
			                         "); use e.g. `openssl rand -base64 32`, a short key can be brute-forced offline "
			                         "from a copy of the store");
		logf("vault: WARNING: key material from %s is only %zu chars; anyone with a copy of %s can brute-force it "
		     "offline. Move the secrets to a store with a random >= %zu-char key",
		     km.source.c_str(), km.value.size(), path.c_str(), MIN_KEY);
	}
	return v;
}

struct CtxFree {
	void operator()(EVP_CIPHER_CTX *c) const { EVP_CIPHER_CTX_free(c); }
};

static bool seal(const std::array<unsigned char, 32> &key, const std::string &aad, const std::string &plain,
                 std::string &out) {
	std::string nonce = random_bytes(NONCE);
	std::unique_ptr<EVP_CIPHER_CTX, CtxFree> c(EVP_CIPHER_CTX_new());
	int len = 0;
	std::string ct(plain.size(), '\0');
	unsigned char tag[TAG];
	if (!c || EVP_EncryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, key.data(),
	                             reinterpret_cast<const unsigned char *>(nonce.data())) != 1 ||
	    EVP_EncryptUpdate(c.get(), nullptr, &len, reinterpret_cast<const unsigned char *>(aad.data()), (int)aad.size()) != 1 ||
	    EVP_EncryptUpdate(c.get(), reinterpret_cast<unsigned char *>(ct.data()), &len,
	                      reinterpret_cast<const unsigned char *>(plain.data()), (int)plain.size()) != 1 ||
	    EVP_EncryptFinal_ex(c.get(), nullptr, &len) != 1 ||
	    EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_GET_TAG, TAG, tag) != 1)
		return false;
	out = nonce + ct + std::string(reinterpret_cast<char *>(tag), TAG);
	return true;
}

static std::optional<std::string> open_sealed(const std::array<unsigned char, 32> &key, const std::string &aad,
                                              const std::string &raw) {
	if (raw.size() < (size_t)(NONCE + TAG))
		return std::nullopt;
	size_t ctlen = raw.size() - NONCE - TAG;
	std::string pt(ctlen, '\0');
	std::unique_ptr<EVP_CIPHER_CTX, CtxFree> c(EVP_CIPHER_CTX_new());
	int len = 0;
	std::string tag = raw.substr(NONCE + ctlen);
	if (!c || EVP_DecryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, key.data(),
	                             reinterpret_cast<const unsigned char *>(raw.data())) != 1 ||
	    EVP_DecryptUpdate(c.get(), nullptr, &len, reinterpret_cast<const unsigned char *>(aad.data()), (int)aad.size()) != 1 ||
	    EVP_DecryptUpdate(c.get(), reinterpret_cast<unsigned char *>(pt.data()), &len,
	                      reinterpret_cast<const unsigned char *>(raw.data()) + NONCE, (int)ctlen) != 1 ||
	    EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_TAG, TAG, tag.data()) != 1 ||
	    EVP_DecryptFinal_ex(c.get(), nullptr, &len) != 1)
		return std::nullopt;
	return pt;
}

std::string Vault::check(const std::string &name, const std::string &secret) {
	if (name.empty())
		return "key required";
	if (name.size() > MAX_NAME)
		return "key too long (max " + std::to_string(MAX_NAME) + " bytes)";
	if (!valid_utf8(name))
		return "key must be UTF-8 text";
	for (unsigned char c : name)
		if (c < 0x20 || c == 0x7f)
			return "key must not contain control characters";
	if (secret.size() > MAX_SECRET)
		return "secret too large (max 1 MiB)";
	if (!valid_utf8(secret))
		return "secret must be UTF-8 text; base64-encode binary material";
	return "";
}

bool Vault::set(const std::string &name, const std::string &secret, std::string *err) {
	if (std::string why = check(name, secret); !why.empty()) {
		*err = why;
		return false;
	}
	std::string sealed;
	if (!seal(key_, name, secret, sealed)) {
		*err = "encryption failed";
		return false;
	}
	std::unique_lock lk(mu_);
	// Serialise a copy first: the live map changes only once the new store is
	// safely on disk, so no failure (or exception) can leave it half-updated.
	auto next = items_;
	next[name] = base64_encode(sealed);
	std::string body;
	try {
		body = nlohmann::json(next).dump();
	} catch (const std::exception &e) {
		*err = std::string("serialise: ") + e.what();
		return false;
	}
	if (!write_file_atomic(path_, body, 0600, err))
		return false;
	items_.swap(next);
	return true;
}

std::optional<std::string> Vault::get(const std::string &name, bool *undecryptable) const {
	if (undecryptable)
		*undecryptable = false;
	std::string enc;
	{
		std::shared_lock lk(mu_);
		auto it = items_.find(name);
		if (it == items_.end())
			return std::nullopt;
		enc = it->second;
	}
	auto raw = base64_decode(enc);
	auto pt = raw ? open_sealed(key_, name, *raw) : std::nullopt;
	if (!pt) {
		if (undecryptable)
			*undecryptable = true;
		logf("vault: entry '%s' cannot be decrypted with the current key (tampered, or written under another key)",
		     name.c_str());
	}
	return pt;
}

std::vector<std::string> Vault::keys() const {
	std::shared_lock lk(mu_);
	std::vector<std::string> ks;
	for (auto &[k, _] : items_)
		ks.push_back(k);  // std::map: already sorted
	return ks;
}

}  // namespace wisp
