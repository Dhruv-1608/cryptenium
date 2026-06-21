# PassGuard

A secure, cloud-ready CLI password manager built in C++. PassGuard keeps your credentials encrypted locally with optional cloud sync support, designed with zero-knowledge security from the ground up.

## Features

- **Master Password Protection** — vault secured by Argon2/PBKDF2 derived keys
- **AES-256 Encryption** — all credentials encrypted before storage
- **Password Generation** — built-in secure random password generator with customizable options
- **Clipboard Integration** — passwords copied to clipboard on retrieval (auto-clears after a set duration)
- **JSON Storage** — portable vault file stored locally at `~/.passguard/vault.json`
- **Cloud-Ready Architecture** — modular storage layer designed to support PostgreSQL, MongoDB, and REST API sync

## Commands

| Command | Description |
|---------|-------------|
| `passguard init` | Initialize a new password vault |
| `passguard add --service <name> --username <user> --password <pw>` | Store a new credential |
| `passguard get --service <name>` | Retrieve credentials for a service |
| `passguard update --service <name> --new-password <pw>` | Update password for an entry |
| `passguard delete --service <name> --username <user>` | Remove a credential entry |
| `passguard list` | List all stored entries |
| `passguard generate --length <n> [--symbols]` | Generate a secure random password |

## Quick Start

```bash
# Initialize your vault
passguard init

# Add a credential
passguard add --service github --username alice --password secret123

# List all entries
passguard list

# Retrieve a credential
passguard get --service github

# Generate a password
passguard generate --length 20 --symbols
```

## Build

### Prerequisites
- C++17 compatible compiler (g++, clang, MSVC)
- CMake (optional)

### Compile from source

```bash
g++ -std=c++17 -I include src/main.cpp src/cli.cpp src/vault.cpp src/password_generator.cpp -o passguard
```

Or use CMake:

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

## Project Structure

```
passguard/
├── include/
│   ├── cli.hpp                  # CLI command parsing
│   ├── vault.hpp                # Vault storage interface
│   └── password_generator.hpp   # Password generation
├── src/
│   ├── main.cpp                 # Entry point
│   ├── cli.cpp                  # Command implementations
│   ├── vault.cpp                # JSON vault read/write
│   └── password_generator.cpp   # Secure password generation
├── CMakeLists.txt               # CMake build config
└── README.md
```

## License

Distributed under the MIT License. See `LICENSE` for more information.
