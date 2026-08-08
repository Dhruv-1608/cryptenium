#include "crypto/Crypto.h"

#include <sodium.h>

#include <cstring>
#include <stdexcept>

namespace cryptenium::crypto {

bool init() {
    return sodium_init() >= 0;
}

// ---------------------------------------------------------------------------
// Secure memory
// ---------------------------------------------------------------------------

SecureBuffer::SecureBuffer(std::size_t n) : data_(nullptr), size_(n) {
    if (size_ == 0) return;
    data_ = static_cast<unsigned char*>(sodium_malloc(size_));
    if (data_ == nullptr) {
        throw std::runtime_error("crypto: sodium_malloc failed (out of secure memory?)");
    }
    sodium_memzero(data_, size_);
}

SecureBuffer::~SecureBuffer() {
    release();
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        release();
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

void SecureBuffer::resize(std::size_t n) {
    if (n == size_) return;
    // Allocate fresh, copy, then release old (which zeroes it).
    unsigned char* new_data = static_cast<unsigned char*>(sodium_malloc(n));
    if (new_data == nullptr) {
        throw std::runtime_error("crypto: sodium_malloc failed");
    }
    sodium_memzero(new_data, n);
    if (data_ != nullptr) {
        std::memcpy(new_data, data_, n < size_ ? n : size_);
    }
    release();
    data_ = new_data;
    size_ = n;
}

void SecureBuffer::release() noexcept {
    if (data_ != nullptr) {
        sodium_free(data_);
        data_ = nullptr;
    }
    size_ = 0;
}

// ---------------------------------------------------------------------------
// Random numbers
// ---------------------------------------------------------------------------

std::vector<unsigned char> random_bytes(std::size_t n) {
    std::vector<unsigned char> out(n);
    if (n > 0) randombytes_buf(out.data(), n);
    return out;
}

void fill_random(unsigned char* buf, std::size_t n) {
    if (n > 0) randombytes_buf(buf, n);
}

// ---------------------------------------------------------------------------
// Key derivation (Argon2id)
// ---------------------------------------------------------------------------

SecureBuffer derive_kek(const std::string& password,
                        const unsigned char* salt,
                        std::uint32_t mem_limit,
                        std::uint32_t ops_limit) {
    SecureBuffer kek(KEY_LEN);
    int rc = crypto_pwhash(kek.data(), KEY_LEN,
                           password.c_str(), password.size(),
                           salt,
                           ops_limit, mem_limit,
                           crypto_pwhash_ALG_ARGON2ID13);
    if (rc != 0) {
        throw std::runtime_error("crypto: Argon2id key derivation failed");
    }
    return kek;
}

std::vector<unsigned char> compute_verifier(const unsigned char* kek) {
    // BLAKE2b keyed hash: verifier = BLAKE2b(key=KEK, "cryptenium-vault-verify-v1")
    const char* msg = "cryptenium-vault-verify-v1";
    const std::size_t msg_len = std::strlen(msg);
    std::vector<unsigned char> full(crypto_generichash_BYTES_MAX);
    int rc = crypto_generichash(full.data(), crypto_generichash_BYTES_MAX,
                                reinterpret_cast<const unsigned char*>(msg), msg_len,
                                kek, KEY_LEN);
    if (rc != 0) {
        throw std::runtime_error("crypto: BLAKE2b verification hash failed");
    }
    full.resize(VERIFIER_LEN);
    return full;
}

SecureBuffer derive_entry_key(const unsigned char* dek, std::uint64_t index) {
    // BLAKE2b(key = DEK, data = "cryptenium-entry-v1" || LE(index))
    const unsigned char prefix[] = "cryptenium-entry-v1";
    std::uint8_t idx_bytes[8];
    for (int i = 0; i < 8; ++i) {
        idx_bytes[i] = static_cast<std::uint8_t>((index >> (8 * i)) & 0xFF);
    }

    SecureBuffer key(KEY_LEN);
    crypto_generichash_state state;
    crypto_generichash_init(&state, dek, KEY_LEN, KEY_LEN);
    crypto_generichash_update(&state, prefix, sizeof(prefix) - 1);
    crypto_generichash_update(&state, idx_bytes, sizeof(idx_bytes));
    crypto_generichash_final(&state, key.data(), KEY_LEN);
    return key;
}

// ---------------------------------------------------------------------------
// Authenticated encryption (XChaCha20-Poly1305)
// ---------------------------------------------------------------------------

std::vector<unsigned char> aead_encrypt(const unsigned char* key,
                                        const std::vector<unsigned char>& plaintext) {
    std::vector<unsigned char> nonce = random_bytes(NONCE_LEN);

    std::vector<unsigned char> out(NONCE_LEN + plaintext.size() + MAC_LEN);
    std::copy(nonce.begin(), nonce.end(), out.begin());

    unsigned long long ciphertext_len = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.data() + NONCE_LEN, &ciphertext_len,
        plaintext.data(), plaintext.size(),
        nullptr, 0,          // no associated data
        nullptr,             // nsec (unused in IETF)
        nonce.data(),        // npub
        key);
    if (rc != 0) {
        throw std::runtime_error("crypto: XChaCha20-Poly1305 encryption failed");
    }
    out.resize(NONCE_LEN + static_cast<std::size_t>(ciphertext_len));
    return out;
}

std::vector<unsigned char> aead_decrypt(const unsigned char* key,
                                        const std::vector<unsigned char>& blob) {
    if (blob.size() < NONCE_LEN + MAC_LEN) {
        throw std::runtime_error("crypto: ciphertext too short (corrupt vault?)");
    }

    std::vector<unsigned char> plaintext(blob.size() - NONCE_LEN);
    unsigned long long plaintext_len = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(), &plaintext_len,
        nullptr,             // nsec (unused in IETF)
        blob.data() + NONCE_LEN, blob.size() - NONCE_LEN,
        nullptr, 0,          // no associated data
        blob.data(),         // npub (stored before ciphertext)
        key);
    if (rc != 0) {
        throw std::runtime_error("crypto: authentication failed (wrong master password or tampered vault)");
    }
    plaintext.resize(static_cast<std::size_t>(plaintext_len));
    return plaintext;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

bool constant_time_equal(const unsigned char* a, const unsigned char* b, std::size_t n) {
    if (n == 0) return true;
    return sodium_memcmp(a, b, n) == 0;
}

} // namespace cryptenium::crypto
