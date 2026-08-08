#include "cli.hpp"
#include "password_generator.hpp"
#include "platform.hpp"
#include "vault.hpp"

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace cryptenium {

namespace {

const std::string RESET   = "\033[0m";
const std::string GREEN   = "\033[32m";
const std::string YELLOW  = "\033[33m";
const std::string RED     = "\033[31m";
const std::string CYAN    = "\033[36m";
const std::string BOLD    = "\033[1m";

void print_green(const std::string& msg)  { std::cout << GREEN  << msg << RESET << "\n"; }
void print_yellow(const std::string& msg) { std::cout << YELLOW << msg << RESET << "\n"; }
void print_red(const std::string& msg)    { std::cout << RED    << msg << RESET << "\n"; }
void print_cyan(const std::string& msg)   { std::cout << CYAN   << msg << RESET << "\n"; }

// Prompts for the master password twice and requires a match.
std::string prompt_new_master_password() {
    while (true) {
        std::string p1 = platform::read_password("Enter master password: ");
        std::string p2 = platform::read_password("Confirm master password: ");
        if (p1 == p2) {
            return p1;
        }
        print_red("Passwords do not match. Try again.");
    }
}

// Reads a plain (echoed) line, stripping a trailing carriage return that can
// appear when stdin is piped on Windows.
std::string read_line() {
    std::string line;
    std::getline(std::cin, line);
    // Trim trailing whitespace (CR, LF, spaces) that can appear when stdin is
    // piped on Windows.
    while (!line.empty() &&
           (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) {
        line.pop_back();
    }
    return line;
}

} // anonymous namespace

int CLI::run(int argc, char* argv[]) {
    if (!crypto::init()) {
        print_red("Fatal: failed to initialize cryptography (libsodium).");
        return 1;
    }

    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::vector<std::string> args(argv + 1, argv + argc);
    std::string command = args[0];

    if (command == "init")     return cmd_init(args);
    if (command == "add")      return cmd_add(args);
    if (command == "get")      return cmd_get(args);
    if (command == "list")     return cmd_list(args);
    if (command == "delete")   return cmd_delete(args);
    if (command == "generate") return cmd_generate(args);
    if (command == "--version" || command == "version") {
        print_version();
        return 0;
    }
    if (command == "--help" || command == "help") {
        print_usage();
        return 0;
    }

    print_red("Unknown command: " + command);
    print_usage();
    return 1;
}

void CLI::print_version() {
    std::cout << "cryptenium 1.0.0 (encrypted vault, Argon2id + XChaCha20-Poly1305)\n";
}

void CLI::print_usage() {
    std::cout << BOLD << "Cryptenium " << RESET << "- CLI Password Manager (encrypted vault)\n"
              << "\n"
              << "Usage:\n"
              << "  cryptenium init                          Initialize a new encrypted vault\n"
              << "  cryptenium add --service <s> --username <u> [--password <p>|--generate]\n"
              << "                                            Store a credential (prompts master password)\n"
              << "  cryptenium get --service <s> [--username <u>]\n"
              << "                                            Retrieve a credential (copies password to clipboard)\n"
              << "  cryptenium list                          List all stored entries\n"
              << "  cryptenium delete --service <s> [--username <u>]\n"
              << "                                            Delete a credential\n"
              << "  cryptenium generate [--length <n>] [--no-digits] [--no-lower]\n"
              << "                     [--no-upper] [--symbols]\n"
              << "                                            Generate a secure random password\n"
              << "  cryptenium version                       Show version\n"
              << "  cryptenium help                          Show this help\n"
              << "\n"
              << "The vault is stored encrypted at " << Vault::default_vault_path() << "\n";
}

std::string CLI::get_flag(const std::vector<std::string>& args,
                          const std::string& key) {
    for (std::size_t i = 0; i + 1 < args.size(); ++i) {
        if (args[i] == key) {
            return args[i + 1];
        }
    }
    return "";
}

bool CLI::has_flag(const std::vector<std::string>& args,
                   const std::string& key) {
    for (const auto& a : args) {
        if (a == key) return true;
    }
    return false;
}

int CLI::cmd_init(const std::vector<std::string>& /*args*/) {
    std::string path = Vault::default_vault_path();

    if (Vault::exists(path)) {
        print_yellow("A vault already exists at " + path);
        return 0;
    }

    std::string master = prompt_new_master_password();
    if (master.empty()) {
        print_red("Master password cannot be empty.");
        return 1;
    }

    try {
        if (Vault::create(path, master)) {
            print_green("Vault initialized successfully at " + path);
            print_yellow("Remember your master password — it cannot be recovered.");
            return 0;
        }
        print_red("Failed to create vault at " + path);
        return 1;
    } catch (const std::exception& e) {
        print_red(std::string("Error: ") + e.what());
        return 1;
    }
}

int CLI::cmd_add(const std::vector<std::string>& args) {
    std::string service  = get_flag(args, "--service");
    std::string username = get_flag(args, "--username");
    std::string password = get_flag(args, "--password");

    if (service.empty() || username.empty()) {
        print_red("Usage: cryptenium add --service <s> --username <u> [--password <p>|--generate]");
        return 1;
    }

    std::string path = Vault::default_vault_path();
    if (!Vault::exists(path)) {
        print_red("No vault found. Run 'cryptenium init' first.");
        return 1;
    }

    try {
        std::string master = platform::read_password("Enter master password: ");

        Vault vault;
        vault.open(path, master);

        if (has_flag(args, "--generate") || password.empty()) {
            PasswordGenerator::Options opts;
            opts.use_symbols = has_flag(args, "--symbols");
            password = PasswordGenerator::generate_with_opts(16, opts);
            print_cyan("Generated password: " + password);
        }

        if (!vault.add({service, username, password})) {
            print_yellow("Entry for " + service + " (" + username + ") already exists.");
            return 1;
        }
        vault.save();
        print_green("Password for " + service + " (" + username + ") stored successfully.");
    } catch (const std::exception& e) {
        print_red(std::string("Error: ") + e.what());
        return 1;
    }
    return 0;
}

int CLI::cmd_get(const std::vector<std::string>& args) {
    std::string service  = get_flag(args, "--service");
    std::string username = get_flag(args, "--username");

    if (service.empty()) {
        print_red("Usage: cryptenium get --service <s> [--username <u>]");
        return 1;
    }

    std::string path = Vault::default_vault_path();
    if (!Vault::exists(path)) {
        print_red("No vault found. Run 'cryptenium init' first.");
        return 1;
    }

    try {
        std::string master = platform::read_password("Enter master password: ");

        Vault vault;
        vault.open(path, master);

        auto entry = vault.find(service, username);
        if (!entry) {
            print_red("No entry found for " + service +
                      (username.empty() ? "" : " (" + username + ")"));
            return 1;
        }

        std::cout << "Service:  " << entry->service  << "\n"
                  << "Username: " << entry->username << "\n"
                  << "Password: ";
        if (platform::clipboard_copy(entry->password)) {
            print_yellow("************ (copied to clipboard, clears in 15s)");
            std::this_thread::sleep_for(std::chrono::seconds(15));
            platform::clipboard_clear();
        } else {
            std::cout << entry->password << "\n";
        }
    } catch (const std::exception& e) {
        print_red(std::string("Error: ") + e.what());
        return 1;
    }
    return 0;
}

int CLI::cmd_list(const std::vector<std::string>& /*args*/) {
    std::string path = Vault::default_vault_path();
    if (!Vault::exists(path)) {
        print_yellow("No vault found. Run 'cryptenium init' first.");
        return 0;
    }

    try {
        std::string master = platform::read_password("Enter master password: ");

        Vault vault;
        vault.open(path, master);

        const auto& entries = vault.entries();
        if (entries.empty()) {
            print_yellow("No entries in vault. Use 'cryptenium add' to add credentials.");
            return 0;
        }
        for (std::size_t i = 0; i < entries.size(); ++i) {
            std::cout << (i + 1) << ". " << entries[i].service
                      << " (" << entries[i].username << ")\n";
        }
        std::cout << "Total entries: " << entries.size() << "\n";
    } catch (const std::exception& e) {
        print_red(std::string("Error: ") + e.what());
        return 1;
    }
    return 0;
}

int CLI::cmd_delete(const std::vector<std::string>& args) {
    std::string service  = get_flag(args, "--service");
    std::string username = get_flag(args, "--username");

    if (service.empty()) {
        print_red("Usage: cryptenium delete --service <s> [--username <u>]");
        return 1;
    }

    std::string path = Vault::default_vault_path();
    if (!Vault::exists(path)) {
        print_red("No vault found. Run 'cryptenium init' first.");
        return 1;
    }

    try {
        std::string master = platform::read_password("Enter master password: ");

        Vault vault;
        vault.open(path, master);

        auto entry = vault.find(service, username);
        if (!entry) {
            print_red("No entry found for " + service +
                      (username.empty() ? "" : " (" + username + ")"));
            return 1;
        }

        std::cout << "Are you sure you want to delete credentials for "
                  << entry->service << " (" << entry->username << ")? (y/N): ";
        std::string confirm = read_line();
        if (confirm != "y" && confirm != "Y") {
            print_yellow("Deletion cancelled.");
            return 0;
        }

        vault.remove(service, username);
        vault.save();
        print_green("Credentials for " + entry->service + " (" +
                    entry->username + ") deleted successfully.");
    } catch (const std::exception& e) {
        print_red(std::string("Error: ") + e.what());
        return 1;
    }
    return 0;
}

int CLI::cmd_generate(const std::vector<std::string>& args) {
    std::size_t length = 16;
    std::string len_str = get_flag(args, "--length");
    if (!len_str.empty()) {
        try {
            length = std::stoul(len_str);
        } catch (...) {
            print_red("Invalid --length value.");
            return 1;
        }
    }

    PasswordGenerator::Options opts;
    opts.use_lowercase = !has_flag(args, "--no-lower");
    opts.use_uppercase = !has_flag(args, "--no-upper");
    opts.use_digits    = !has_flag(args, "--no-digits");
    opts.use_symbols   =  has_flag(args, "--symbols");

    try {
        std::string pwd = PasswordGenerator::generate_with_opts(length, opts);
        std::cout << "Generated password (" << length << " chars): "
                  << CYAN << pwd << RESET << "\n";
    } catch (const std::exception& e) {
        print_red(std::string("Error: ") + e.what());
        return 1;
    }
    return 0;
}

} // namespace cryptenium
