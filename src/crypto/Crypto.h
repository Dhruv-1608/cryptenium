#ifndef CRYPTENIUM_CRYPTO_H
#define CRYPTENIUM_CRYPTO_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Cryptographic module for Cryptenium, built on libsodium.
//
// Implements:
//   - Argon2id key derivation (crypto_pwhash)
//   - XChaCha20-Poly1305 authenticated encryption (AEAD)
//   - BLAKE2b keyed hashing for master-password verification + per-entry keys
//   - OS CSPRNG random bytes
//   - Locked/guarded secure memory (sodium_malloc / sodium_memzero)
//
// All functions throw std::runtime_error on hard failures. Call crypto::init()
// exactly once at process start.

namespace cryptenium::crypto {

// Initialize libsodium. Returns true on success; must be called once at startup.
bool init();

// ---------------------------------------------------------------------------
// Secure memory
// ---------------------------------------------------------------------------

// A fixed-size RAII buffer allocated with sodium_malloc (locked into RAM,
// guarded pages, zeroed on free). Non-copyable; movable only. Intended for
// keys, master passwords, and decrypted plaintext.
class SecureBuffer {
public:
    SecureBuffer() : data_(nullptr), size_(0) {}
    explicit SecureBuffer(std::size_t n);
    ~SecureBuffer();

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    unsigned char* data() { return data_; }
    const unsigned char* data() const { return data_; }
    std::size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }

    void resize(std::size_t n);  // re-allocates; old region is zeroed

private:
    void release() noexcept;
    unsigned char* data_;
    std::size_t size_;
};

// ---------------------------------------------------------------------------
// Random numbers (OS CSPRNG via libsodium)
// ---------------------------------------------------------------------------

// Returns n cryptographically-secure random bytes.
std::vector<unsigned char> random_bytes(std::size_t n);

// Fills buf with n cryptographically-secure random bytes.
void fill_random(unsigned char* buf, std::size_t n);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr std::size_t KEY_LEN      = 32;  // 256-bit keys (KEK / DEK / entry keys)
constexpr std::size_t SALT_LEN     = 16;  // Argon2id salt (crypto_pwhash_SALTBYTES)
constexpr std::size_t VERIFIER_LEN = 8;   // stored master-password key fingerprint
constexpr std::size_t NONCE_LEN    = 24;  // XChaCha20-Poly1305 IETF public nonce
constexpr std::size_t MAC_LEN      = 16;  // Poly1305 authentication tag
constexpr std::size_t DEK_LEN      = 32;  // data encryption key length

// ---------------------------------------------------------------------------
// Key derivation (Argon2id)
// ---------------------------------------------------------------------------

// Derives a 32-byte KEK from the master password using Argon2id.
// salt must be SALT_LEN bytes. mem_limit is in bytes; ops_limit is an integer
// cost parameter. Both are persisted in the vault header so they can be raised
// in future versions while old vaults remain openable.
SecureBuffer derive_kek(const std::string& password,
                        const unsigned char* salt,
                        std::uint32_t mem_limit,
                        std::uint32_t ops_limit);

// Key fingerprint for fast, constant-time master-password verification.
// verifier = first 8 bytes of BLAKE2b(key = KEK, data = "cryptenium-vault-verify-v1")
std::vector<unsigned char> compute_verifier(const unsigned char* kek);

// Derive a per-entry encryption key: BLAKE2b(key = DEK, data =
// "cryptenium-entry-v1" || little-endian entry index). Each entry therefore
// has a unique key even if nonces were reused.
SecureBuffer derive_entry_key(const unsigned char* dek, std::uint64_t index);

// ---------------------------------------------------------------------------
// Authenticated encryption (XChaCha20-Poly1305)
// ---------------------------------------------------------------------------

// Encrypt plaintext with key; returns nonce || ciphertext || tag.
std::vector<unsigned char> aead_encrypt(const unsigned char* key,
                                        const std::vector<unsigned char>& plaintext);

// Decrypts a blob produced by aead_encrypt. Throws if the key is wrong or the
// data has been tampered with.
std::vector<unsigned char> aead_decrypt(const unsigned char* key,
                                        const std::vector<unsigned char>& blob);

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// Constant-time comparison (used for verifier / master password checks).
bool constant_time_equal(const unsigned char* a, const unsigned char* b, std::size_t n);

} // namespace cryptenium::crypto

#endif // CRYPTENIUM_CRYPTO_H
