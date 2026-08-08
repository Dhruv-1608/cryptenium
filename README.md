<div align="center">

# 🔐 Cryptenium

**A zero-knowledge, encrypted CLI password manager written in C++17.**

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![libsodium](https://img.shields.io/badge/libsodium-1.0.19-4b8bbe)](https://doc.libsodium.org/)
[![CMake](https://img.shields.io/badge/CMake-%E2%89%A53.10-green.svg)](https://cmake.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#build)

**Your credentials, encrypted at rest. Nothing is ever written in plaintext.**

</div>

---

## Table of Contents

- [Highlights](#highlights)
- [Security Model](#security-model)
- [How It Works](#how-it-works)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Build from Source](#build-from-source)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

---

## Highlights

- 🛡️ **Zero-knowledge by design** — the vault file is a binary blob; no master password or credential plaintext ever touches disk.
- 🔑 **Envelope encryption** — your master password derives a Key Encryption Key (KEK) that wraps a random Data Encryption Key (DEK); the DEK encrypts every entry.
- ⚡ **Argon2id KDF** — memory-hard password hashing (64 MiB / 3 iterations) via libsodium, GPU/ASIC-resistant.
- 🔒 **XChaCha20-Poly1305 AEAD** — authenticated encryption per entry with 192-bit nonces; tamper-evident.
- 🧠 **Secure memory** — secrets live in `sodium_malloc` guarded pages, locked, and zeroed on release (RAII).
- 🎲 **CSPRNG generation** — unbiased secure random passwords with rejection sampling.
- 📋 **Clipboard hygiene** — retrieved passwords auto-clear from the clipboard after 15 seconds.
- 🖥️ **Cross-platform** — Windows, Linux, and macOS.

---

## Security Model

Cryptenium uses a **defense-in-depth** approach centered on client-side encryption:

```
        Master Password
              │
              ▼
    Argon2id (crypto_pwhash)          ← memory-hard, slow to brute-force
              │
              ▼
    Key Encryption Key (KEK) ──────┐   ← held only in secure memory
                                   │   wraps
                                   ▼
    Data Encryption Key (DEK)      │   ← random 256-bit, generated at init
              │                    │
              ▼                    │
    Per-Entry Keys (BLAKE2b)       │   ← unique key per entry from the DEK
              │                    │
              ▼                    ▼
    XChaCha20-Poly1305 per entry   │   ← AEAD: ciphertext + MAC + nonce
                                   │
   ┌───────────────────────────────┴──────────────────────────┐
   │  vault.dat: header (KDF params · salt · 8-byte verifier  │
   │             · wrapped DEK · entry count) + AEAD blobs    │
   └──────────────────────────────────────────────────────────┘
```

- **Nothing recoverable from disk** — without the master password, the vault yields only KDF parameters, a random salt, a wrapped DEK, and ciphertext.
- **Master password verification** — an 8-byte BLAKE2b fingerprint of the KEK is stored and compared in constant time (`sodium_memcmp`); it leaks nothing about the password (preimage-resistant).
- **Per-entry keys** — a single compromised entry key does not compromise the rest of the vault.

---

## How It Works

1. `init` derives a **KEK** from your master password with Argon2id and generates a random **DEK**.
2. The DEK is **wrapped** (encrypted) under the KEK; only the wrapped DEK is stored.
3. Each entry is encrypted under its own key derived from the DEK via BLAKE2b.
4. On unlock, the client re-derives the KEK, verifies the fingerprint, unwraps the DEK, and decrypts entries — all in memory.

Because the KEK exists only for the duration of a session, **changing the master password later only requires re-wrapping the DEK** — the entire vault never needs re-encryption.

---

## Features

| Command | Description |
|---------|-------------|
| `init` | Create a new encrypted vault and set your master password |
| `add` | Store a credential (provided or auto-generated) |
| `get` | Retrieve a credential; password is copied to the clipboard and cleared after 15 s |
| `list` | List all stored entries (service / username only — never passwords) |
| `delete` | Remove a credential (with confirmation prompt) |
| `generate` | Generate a secure random password with configurable character sets |
| `version` / `help` | Print version or usage information |

---

## Installation

### Prerequisites

- A C++17 compiler (GCC 8+, Clang, MSVC)
- CMake ≥ 3.10
- [libsodium](https://doc.libsodium.org/) ≥ 1.0.18

| OS | Install libsodium |
|----|-------------------|
| MSYS2 (UCRT64) | `pacman -S mingw-w64-ucrt-x86_64-libsodium` |
| Debian / Ubuntu | `sudo apt install libsodium-dev` |
| macOS | `brew install libsodium` |
| Windows (vcpkg) | `vcpkg install libsodium` |

### Build

```bash
git clone https://github.com/<you>/cryptenium.git
cd cryptenium
mkdir build && cd build
cmake .. -G "MinGW Makefiles"     # or your platform's generator (e.g. "Unix Makefiles")
cmake --build .
```

The binary is produced at `build/cryptenium` (or `build\cryptenium.exe` on Windows).

---

## Usage

All commands that access the vault prompt for your master password.

```bash
# Initialize your vault (sets your master password)
cryptenium init

# Store a credential
cryptenium add --service github --username alice --password secret123

# ...or generate one and store it
cryptenium add --service gmail --username bob --generate --length 20 --symbols

# List all entries
cryptenium list

# Retrieve a credential (password copied to clipboard, cleared after 15 s)
cryptenium get --service github

# Generate a standalone password
cryptenium generate --length 24 --symbols
```

### Command Reference

```
cryptenium init
cryptenium add --service <s> --username <u> [--password <p> | --generate [--length <n>] [--symbols]]
cryptenium get --service <s> [--username <u>]
cryptenium list
cryptenium delete --service <s> [--username <u>]
cryptenium generate [--length <n>] [--no-digits] [--no-lower] [--no-upper] [--symbols]
cryptenium version
cryptenium help
```

> **Note:** For interactive use the master password is read with echo disabled. When piping stdin (e.g. in scripts), trailing whitespace is trimmed so piped input behaves consistently.

### Vault Location

- **Windows:** `%USERPROFILE%\.cryptenium\vault.dat`
- **Linux / macOS:** `~/.cryptenium/vault.dat`

---

## Testing

An automated end-to-end suite runs 10 scenarios against an isolated test home (`USERPROFILE`/`HOME`), so your real vault is never touched:

```bash
cd tests
run_tests.cmd        # Windows / cmd
```

The suite verifies: init, duplicate-init, add, generated-password add, list contents, wrong-password rejection, confirmed delete, cancelled delete, generation, and version output.

---

## Project Structure

```
cryptenium/
├── include/
│   ├── cli.hpp                  # CLI command parsing & dispatch
│   ├── vault.hpp                # Vault storage interface (binary, encrypted)
│   ├── password_generator.hpp   # CSPRNG password generation
│   └── platform.hpp             # Hidden input & clipboard helpers
├── src/
│   ├── main.cpp                 # Entry point
│   ├── cli.cpp                  # Command implementations
│   ├── vault.cpp                # Encrypted binary vault read/write
│   ├── password_generator.cpp   # Secure password generation
│   ├── platform.cpp             # OS-specific helpers
│   └── crypto/
│       ├── Crypto.h             # Crypto module declarations
│       └── Crypto.cpp           # Argon2id, AEAD, secure random, secure memory
├── tests/
│   └── run_tests.cmd            # End-to-end test suite
├── CMakeLists.txt               # CMake build configuration
├── LICENSE
└── README.md
```

---

## Roadmap

- [x] **Phase 1 — Secure Core**: encrypted vault, master password, `init` / `add` / `get` / `list` / `delete` / `generate`
- [x] **Phase 2 — Envelope encryption**: Argon2id KEK, wrapped DEK, per-entry keys, constant-time verification
- [ ] `rekey` (change master password — instant via DEK re-wrap)
- [ ] `status` / `backup` / `export` / `import`
- [ ] Recovery codes (BIP39-style)
- [ ] Progressive delay + lockdown on failed unlocks
- [ ] Vault tamper detection (canary values, Merkle root, signatures)
- [ ] Optional zero-knowledge cloud sync

---

## Security Considerations

Cryptenium makes the following trade-offs you should understand:

- **Irrecoverable master password** — by design, losing your master password means losing access to your vault. Back up the vault file and keep your master password safe.
- **Local threat model** — protection focuses on data *at rest* and in memory. A compromised OS with active monitoring is outside the threat model.
- **Audited primitives** — all cryptography is provided by libsodium, a widely audited, battle-tested library. Cryptenium never implements crypto primitives itself.
- **Constant-time operations** — verifier comparison uses `sodium_memcmp`; generation uses rejection sampling to avoid modulo bias.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository and create a feature branch.
2. Keep commits small and focused with clear messages.
3. Run the test suite before opening a pull request.
4. Discuss security-sensitive changes before implementing them.

---

## License

Distributed under the [MIT License](LICENSE). Copyright (c) 2026 Cryptenium.
