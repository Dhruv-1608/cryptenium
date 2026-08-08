#ifndef CRYPTENIUM_VAULT_HPP
#define CRYPTENIUM_VAULT_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "crypto/Crypto.h"

namespace cryptenium {

struct Entry {
    std::string service;
    std::string username;
    std::string password;
};

// Encrypted vault backed by a single binary file using envelope encryption:
//
//   Master password ──Argon2id──► KEK ──encrypts──► DEK ──encrypts──► entries
//
// The DEK is a random 32-byte key generated at vault creation. The KEK is
// derived from the master password (Argon2id). The DEK is wrapped (encrypted)
// under the KEK and stored in the vault header. Re-keying the master password
// would only re-wrap the 32-byte DEK — the entries never change.
//
// On-disk format (multi-byte integers little-endian):
//   [0..12)      magic            "CRYPTENIUM" (12 bytes, last two zero)
//   [12)         version          0x01
//   [13..17)     mem_limit        uint32 Argon2id memory (bytes)
//   [17..21)     ops_limit        uint32 Argon2id ops cost
//   [21..37)     salt             SALT_LEN (16) bytes
//   [37..45)     verifier         VERIFIER_LEN (8) bytes (BLAKE2b KEK fingerprint)
//   [45..117)    wrapped_dek      aead_encrypt(KEK, DEK): nonce(24)+ct(32)+tag(16)
//   [117..121)   entry_count      uint32
//   then entry_count blobs, each:
//   [u32 len][aead_encrypt(entry_key(DEK, index), plaintext)]
//
// Entry plaintext serialization:
//   u32 service_len + service
//   u32 username_len + username
//   u32 password_len + password
class Vault {
public:
    // Constructs an empty, locked vault.
    Vault() = default;
    Vault(Vault&&) = default;
    Vault& operator=(Vault&&) = default;
    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;

    static std::string default_vault_path();

    // Returns true if a vault file exists at path.
    static bool exists(const std::string& path);

    // Creates a brand-new encrypted vault at path with the given master
    // password. Returns false if the file already exists. Throws on I/O error.
    static bool create(const std::string& path, const std::string& master_password);

    // Opens and unlocks an existing vault. Throws std::runtime_error if the
    // master password is wrong or the file is corrupt/unreadable. The KEK and
    // DEK are retained in secure (locked) memory for the session.
    void open(const std::string& path, const std::string& master_password);

    // --- Unlocked operations (require a successful open()) ---

    // Adds a new entry. Returns false if an entry with the same service +
    // username already exists.
    bool add(const Entry& entry);

    // Finds an entry. When username is empty, matches the first entry with the
    // given service.
    std::optional<Entry> find(const std::string& service,
                              const std::string& username = "") const;

    // Updates the password of a matching entry. Returns false if not found.
    bool update(const std::string& service,
                const std::string& username,
                const std::string& new_password);

    // Removes a matching entry. Returns false if not found.
    bool remove(const std::string& service, const std::string& username = "");

    const std::vector<Entry>& entries() const { return entries_; }
    std::size_t entry_count() const { return entries_.size(); }

    // Persists the in-memory entries back to the vault file (encrypted).
    // Re-wraps the DEK under the cached KEK; does not require the password.
    void save();

private:
    static std::vector<unsigned char> serialize_entry(const Entry& e);
    static Entry deserialize_entry(const std::vector<unsigned char>& data);
    std::vector<unsigned char> build_file() const;

    std::string path_;
    crypto::SecureBuffer kek_;  // cached Key Encryption Key (session only)
    crypto::SecureBuffer dek_;  // Data Encryption Key (32 bytes)
    std::vector<unsigned char> salt_;
    std::uint32_t mem_limit_ = 0;
    std::uint32_t ops_limit_ = 0;
    std::vector<Entry> entries_;
};

} // namespace cryptenium

#endif // CRYPTENIUM_VAULT_HPP
