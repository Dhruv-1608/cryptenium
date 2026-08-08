#include "vault.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <stdexcept>

#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace cryptenium {

namespace {

// Vault file magic and version.
const char MAGIC[12] = {'C', 'R', 'Y', 'P', 'T', 'E', 'N', 'I', 'U', 'M', '\0', '\0'};
constexpr std::uint8_t VERSION = 0x01;

// Argon2id defaults (see PROJECT_PLAN §4.9). Stored in the header per-vault so
// they can be raised later while old vaults stay openable.
constexpr std::uint32_t DEFAULT_MEM_LIMIT = 64U * 1024U * 1024U;  // 64 MiB
constexpr std::uint32_t DEFAULT_OPS_LIMIT = 3U;

// Header layout offsets.
constexpr std::size_t OFF_MAGIC      = 0;   // 12 bytes
constexpr std::size_t OFF_VERSION    = 12;  // 1 byte
constexpr std::size_t OFF_MEM_LIMIT  = 13;  // 4 bytes
constexpr std::size_t OFF_OPS_LIMIT  = 17;  // 4 bytes
constexpr std::size_t OFF_SALT       = 21;  // 16 bytes
constexpr std::size_t OFF_VERIFIER   = 37;  // 8 bytes
constexpr std::size_t OFF_WRAPPED_DEK = 45; // 72 bytes
constexpr std::size_t OFF_ENTRY_CNT  = 117; // 4 bytes
constexpr std::size_t HEADER_LEN     = 121; // total header size

// little-endian helpers
void put_u32(std::vector<unsigned char>& out, std::uint32_t v) {
    out.push_back(static_cast<unsigned char>(v & 0xFF));
    out.push_back(static_cast<unsigned char>((v >> 8) & 0xFF));
    out.push_back(static_cast<unsigned char>((v >> 16) & 0xFF));
    out.push_back(static_cast<unsigned char>((v >> 24) & 0xFF));
}

std::uint32_t get_u32(const std::vector<unsigned char>& buf, std::size_t off) {
    if (off + 4 > buf.size()) {
        throw std::runtime_error("vault: truncated integer (corrupt file)");
    }
    return static_cast<std::uint32_t>(buf[off]) |
           (static_cast<std::uint32_t>(buf[off + 1]) << 8) |
           (static_cast<std::uint32_t>(buf[off + 2]) << 16) |
           (static_cast<std::uint32_t>(buf[off + 3]) << 24);
}

// Append a length-prefixed field: u32 len + bytes.
void put_field(std::vector<unsigned char>& out, const std::string& s) {
    put_u32(out, static_cast<std::uint32_t>(s.size()));
    for (char c : s) out.push_back(static_cast<unsigned char>(c));
}

// Reads a length-prefixed field.
std::string get_field(const std::vector<unsigned char>& buf, std::size_t& off) {
    std::uint32_t len = get_u32(buf, off);
    off += 4;
    if (off + len > buf.size()) {
        throw std::runtime_error("vault: truncated field (corrupt file)");
    }
    std::string s;
    s.reserve(len);
    for (std::uint32_t i = 0; i < len; ++i) {
        s.push_back(static_cast<char>(buf[off + i]));
    }
    off += len;
    return s;
}

// Restrict file permissions to the owning user only.
void restrict_permissions(const std::string& path) {
#ifdef _WIN32
    (void)path;  // best-effort on Windows; DACL handling is a Phase 3 item
#else
    chmod(path.c_str(), 0600);
#endif
}

std::vector<unsigned char> read_file_binary(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        throw std::runtime_error("vault: cannot open file: " + path);
    }
    std::streamsize n = f.tellg();
    if (n < 0) {
        throw std::runtime_error("vault: cannot read file: " + path);
    }
    f.seekg(0, std::ios::beg);
    std::vector<unsigned char> data(static_cast<std::size_t>(n));
    if (n > 0) {
        f.read(reinterpret_cast<char*>(data.data()), n);
    }
    return data;
}

void write_file_binary_atomic(const std::string& path,
                              const std::vector<unsigned char>& data) {
    // Write to a temp file, then atomically rename over the target.
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) {
            throw std::runtime_error("vault: cannot write file: " + tmp);
        }
        f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
        f.flush();
        if (!f.good()) {
            throw std::runtime_error("vault: write failed for: " + tmp);
        }
    }
    restrict_permissions(tmp);
#ifdef _WIN32
    if (!MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        throw std::runtime_error("vault: atomic rename failed (Windows)");
    }
#else
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        throw std::runtime_error("vault: atomic rename failed");
    }
#endif
}

} // anonymous namespace

std::string Vault::default_vault_path() {
#ifdef _WIN32
    const char* home = std::getenv("USERPROFILE");
#else
    const char* home = std::getenv("HOME");
#endif
    if (home == nullptr) home = ".";
    return std::string(home) + "/.cryptenium/vault.dat";
}

bool Vault::exists(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return f.good();
}

bool Vault::create(const std::string& path, const std::string& master_password) {
    if (exists(path)) return false;

    // Create the parent directory if needed.
    std::string dir;
    auto slash = path.find_last_of("/\\");
    if (slash != std::string::npos) dir = path.substr(0, slash);
    if (!dir.empty()) {
#ifdef _WIN32
        CreateDirectoryA(dir.c_str(), nullptr);
#else
        std::string cur;
        std::size_t pos = 0;
        while ((pos = dir.find('/', pos)) != std::string::npos) {
            cur = dir.substr(0, pos);
            if (!cur.empty()) ::mkdir(cur.c_str(), 0700);
            ++pos;
        }
        ::mkdir(dir.c_str(), 0700);
#endif
    }

    // Random salt + Data Encryption Key.
    auto salt = crypto::random_bytes(crypto::SALT_LEN);
    crypto::SecureBuffer dek(crypto::DEK_LEN);
    crypto::fill_random(dek.data(), dek.size());

    // Derive KEK from the master password.
    auto kek = crypto::derive_kek(master_password, salt.data(),
                                  DEFAULT_MEM_LIMIT, DEFAULT_OPS_LIMIT);

    // Wrap the DEK under the KEK.
    std::vector<unsigned char> dek_vec(dek.data(), dek.data() + dek.size());
    auto wrapped_dek = crypto::aead_encrypt(kek.data(), dek_vec);

    // Compute the verification fingerprint.
    auto verifier = crypto::compute_verifier(kek.data());

    // Build the file.
    std::vector<unsigned char> out;
    out.reserve(HEADER_LEN);
    out.insert(out.end(), MAGIC, MAGIC + 12);
    out.push_back(VERSION);
    put_u32(out, DEFAULT_MEM_LIMIT);
    put_u32(out, DEFAULT_OPS_LIMIT);
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), verifier.begin(), verifier.end());
    out.insert(out.end(), wrapped_dek.begin(), wrapped_dek.end());
    put_u32(out, 0);  // entry_count = 0

    write_file_binary_atomic(path, out);
    restrict_permissions(path);
    return true;
}

void Vault::open(const std::string& path, const std::string& master_password) {
    auto data = read_file_binary(path);

    if (data.size() < HEADER_LEN) {
        throw std::runtime_error("vault: file too small to be a Cryptenium vault");
    }
    if (std::memcmp(data.data(), MAGIC, 12) != 0) {
        throw std::runtime_error("vault: not a Cryptenium vault file");
    }
    if (data[OFF_VERSION] != VERSION) {
        throw std::runtime_error("vault: unsupported vault version");
    }

    mem_limit_ = get_u32(data, OFF_MEM_LIMIT);
    ops_limit_ = get_u32(data, OFF_OPS_LIMIT);
    salt_.assign(data.begin() + OFF_SALT,
                 data.begin() + OFF_SALT + crypto::SALT_LEN);
    std::vector<unsigned char> verifier(data.begin() + OFF_VERIFIER,
                                        data.begin() + OFF_VERIFIER + crypto::VERIFIER_LEN);
    std::vector<unsigned char> wrapped_dek(data.begin() + OFF_WRAPPED_DEK,
                                           data.begin() + OFF_WRAPPED_DEK + 72);
    std::uint32_t entry_count = get_u32(data, OFF_ENTRY_CNT);

    // --- Derive KEK and verify master password ---
    auto kek = crypto::derive_kek(master_password, salt_.data(), mem_limit_, ops_limit_);
    auto expected = crypto::compute_verifier(kek.data());
    if (!crypto::constant_time_equal(verifier.data(), expected.data(), crypto::VERIFIER_LEN)) {
        throw std::runtime_error("vault: incorrect master password");
    }

    // --- Unwrap the DEK ---
    std::vector<unsigned char> dek_plain = crypto::aead_decrypt(kek.data(), wrapped_dek);
    if (dek_plain.size() != crypto::DEK_LEN) {
        throw std::runtime_error("vault: invalid wrapped DEK length");
    }
    dek_.resize(crypto::DEK_LEN);
    std::copy(dek_plain.begin(), dek_plain.end(), dek_.data());
    crypto::fill_random(dek_plain.data(), dek_plain.size());

    // Cache the KEK in secure memory for re-saving (envelope re-wrap).
    kek_.resize(crypto::KEY_LEN);
    std::copy_n(kek.data(), crypto::KEY_LEN, kek_.data());

    // --- Decrypt entries ---
    entries_.clear();
    std::size_t pos = HEADER_LEN;
    for (std::uint32_t i = 0; i < entry_count; ++i) {
        if (pos + 4 > data.size()) {
            throw std::runtime_error("vault: truncated entry list (corrupt file)");
        }
        std::uint32_t blob_len = get_u32(data, pos);
        pos += 4;
        if (pos + blob_len > data.size()) {
            throw std::runtime_error("vault: truncated entry (corrupt file)");
        }
        std::vector<unsigned char> blob(data.begin() + pos, data.begin() + pos + blob_len);
        pos += blob_len;

        auto entry_key = crypto::derive_entry_key(dek_.data(), i);
        auto plain = crypto::aead_decrypt(entry_key.data(), blob);
        entries_.push_back(deserialize_entry(plain));
    }

    path_ = path;
}

bool Vault::add(const Entry& entry) {
    for (const auto& e : entries_) {
        if (e.service == entry.service && e.username == entry.username) {
            return false;
        }
    }
    entries_.push_back(entry);
    return true;
}

std::optional<Entry> Vault::find(const std::string& service,
                                 const std::string& username) const {
    for (const auto& e : entries_) {
        if (e.service == service && (username.empty() || e.username == username)) {
            return e;
        }
    }
    return std::nullopt;
}

bool Vault::update(const std::string& service,
                   const std::string& username,
                   const std::string& new_password) {
    for (auto& e : entries_) {
        if (e.service == service && (username.empty() || e.username == username)) {
            e.password = new_password;
            return true;
        }
    }
    return false;
}

bool Vault::remove(const std::string& service, const std::string& username) {
    auto it = std::remove_if(entries_.begin(), entries_.end(),
                             [&](const Entry& e) {
                                 return e.service == service &&
                                        (username.empty() || e.username == username);
                             });
    if (it == entries_.end()) return false;
    entries_.erase(it, entries_.end());
    return true;
}

void Vault::save() {
    if (path_.empty()) {
        throw std::runtime_error("vault: not open");
    }
    write_file_binary_atomic(path_, build_file());
}

std::vector<unsigned char> Vault::serialize_entry(const Entry& e) {
    std::vector<unsigned char> out;
    put_field(out, e.service);
    put_field(out, e.username);
    put_field(out, e.password);
    return out;
}

Entry Vault::deserialize_entry(const std::vector<unsigned char>& data) {
    std::size_t off = 0;
    Entry e;
    e.service  = get_field(data, off);
    e.username = get_field(data, off);
    e.password = get_field(data, off);
    return e;
}

std::vector<unsigned char> Vault::build_file() const {
    std::vector<unsigned char> out;
    out.reserve(HEADER_LEN + entries_.size() * 128);
    out.insert(out.end(), MAGIC, MAGIC + 12);
    out.push_back(VERSION);
    put_u32(out, mem_limit_);
    put_u32(out, ops_limit_);
    out.insert(out.end(), salt_.begin(), salt_.end());

    // Re-wrap the DEK under the cached KEK.
    std::vector<unsigned char> dek_vec(dek_.data(), dek_.data() + dek_.size());
    auto wrapped_dek = crypto::aead_encrypt(kek_.data(), dek_vec);
    auto verifier = crypto::compute_verifier(kek_.data());
    out.insert(out.end(), verifier.begin(), verifier.end());
    out.insert(out.end(), wrapped_dek.begin(), wrapped_dek.end());

    put_u32(out, static_cast<std::uint32_t>(entries_.size()));
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        auto plain = serialize_entry(entries_[i]);
        auto entry_key = crypto::derive_entry_key(dek_.data(), static_cast<std::uint64_t>(i));
        auto blob = crypto::aead_encrypt(entry_key.data(), plain);
        put_u32(out, static_cast<std::uint32_t>(blob.size()));
        out.insert(out.end(), blob.begin(), blob.end());
    }
    return out;
}

} // namespace cryptenium
