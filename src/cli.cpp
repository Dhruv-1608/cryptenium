#include "cli.hpp"
#include "vault.hpp"
#include "password_generator.hpp"

#include <iostream>
#include <sstream>

namespace passguard {

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

std::string read_password(const std::string& prompt) {
    std::cout << prompt;
    std::string pwd;
    std::getline(std::cin, pwd);
    return pwd;
}

} // anonymous namespace

int CLI::run(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::vector<std::string> args(argv + 1, argv + argc);
    std::string command = args[0];

    if (command == "init")        return cmd_init(args);
    if (command == "add")         return cmd_add(args);
    if (command == "get")         return cmd_get(args);
    if (command == "update")      return cmd_update(args);
    if (command == "delete")      return cmd_delete(args);
    if (command == "list")        return cmd_list(args);
    if (command == "generate")    return cmd_generate(args);
    if (command == "--help" || command == "help") {
        print_usage();
        return 0;
    }

    print_red("Unknown command: " + command);
    print_usage();
    return 1;
}

void CLI::print_usage() {
    std::cout << BOLD << "PassGuard " << RESET << "- CLI Password Manager\n"
              << "\n"
              << "Usage:\n"
              << "  passguard init                           Initialize a new vault\n"
              << "  passguard add --service <s> --username <u> [--password <p>|--generate]\n"
              << "                                            Add credentials\n"
              << "  passguard get --service <s> [--username <u>]\n"
              << "                                            Retrieve credentials\n"
              << "  passguard update --service <s> [--username <u>] --new-password <p>\n"
              << "                                            Update password\n"
              << "  passguard delete --service <s> [--username <u>]\n"
              << "                                            Delete credentials\n"
              << "  passguard list                           List all entries\n"
              << "  passguard generate [--length <n>] [--no-digits] [--no-lower]\n"
              << "                     [--no-upper] [--symbols]\n"
              << "                                            Generate a random password\n"
              << "  passguard help                           Show this help\n";
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
        print_yellow("Vault already exists at " + path);
        return 0;
    }

    if (Vault::create(path)) {
        print_green("Vault initialized successfully at " + path);
        return 0;
    }

    print_red("Failed to create vault at " + path);
    return 1;
}

int CLI::cmd_add(const std::vector<std::string>& args) {
    std::string service  = get_flag(args, "--service");
    std::string username = get_flag(args, "--username");
    std::string password = get_flag(args, "--password");

    if (service.empty() || username.empty()) {
        print_red("Usage: passguard add --service <s> --username <u> [--password <p>|--generate]");
        return 1;
    }

    if (has_flag(args, "--generate") || password.empty()) {
        PasswordGenerator::Options opts;
        opts.use_symbols = has_flag(args, "--symbols");
        password = PasswordGenerator::generate_with_opts(16, opts);
        print_cyan("Generated password: " + password);
    }

    std::string path = Vault::default_vault_path();
    if (!Vault::exists(path)) {
        print_red("No vault found. Run 'passguard init' first.");
        return 1;
    }

    try {
        auto entries = Vault::load(path);
        if (!Vault::add_entry(entries, {service, username, password})) {
            print_yellow("Entry for " + service + " (" + username + ") already exists.");
            return 1;
        }
        Vault::save(path, entries);
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
        print_red("Usage: passguard get --service <s> [--username <u>]");
        return 1;
    }

    std::string path = Vault::default_vault_path();
    if (!Vault::exists(path)) {
        print_red("No vault found. Run 'passguard init' first.");
        return 1;
    }

    try {
        auto entries = Vault::load(path);
        auto entry = Vault::find(entries, service, username);
        if (!entry) {
            print_red("No entry found for " + service +
                      (username.empty() ? "" : " (" + username + ")"));
            return 1;
        }
        std::cout << "Service:  " << entry->service  << "\n"
                  << "Username: " << entry->username << "\n"
                  << "Password: " << entry->password << " (copied to clipboard)\n";
    } catch (const std::exception& e) {
        print_red(std::string("Error: ") + e.what());
        return 1;
    }
    return 0;
}

int CLI::cmd_update(const std::vector<std::string>& args) {
    std::string service     = get_flag(args, "--service");
    std::string username    = get_flag(args, "--username");
    std::string new_password = get_flag(args, "--new-password");

    if (service.empty() || new_password.empty()) {
        print_red("Usage: passguard update --service <s> [--username <u>] --new-password <p>");
        return 1;
    }

    std::string path = Vault::default_vault_path();
    if (!Vault::exists(path)) {
        print_red("No vault found. Run 'passguard init' first.");
        return 1;
    }

    try {
        auto entries = Vault::load(path);
        if (!Vault::update_entry(entries, service, username, new_password)) {
            print_red("No entry found for " + service +
                      (username.empty() ? "" : " (" + username + ")"));
            return 1;
        }
        Vault::save(path, entries);
        print_green("Password for " + service +
                    (username.empty() ? "" : " (" + username + ")") +
                    " updated successfully.");
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
        print_red("Usage: passguard delete --service <s> [--username <u>]");
        return 1;
    }

    std::string path = Vault::default_vault_path();
    if (!Vault::exists(path)) {
        print_red("No vault found. Run 'passguard init' first.");
        return 1;
    }

    try {
        auto entries = Vault::load(path);

        auto entry = Vault::find(entries, service, username);
        if (!entry) {
            print_red("No entry found for " + service +
                      (username.empty() ? "" : " (" + username + ")"));
            return 1;
        }

        std::cout << "Are you sure you want to delete credentials for "
                  << entry->service << " (" << entry->username << ")? (y/N): ";
        std::string confirm;
        std::getline(std::cin, confirm);
        if (confirm != "y" && confirm != "Y") {
            print_yellow("Deletion cancelled.");
            return 0;
        }

        Vault::delete_entry(entries, service, username);
        Vault::save(path, entries);
        print_green("Credentials for " + entry->service + " (" +
                    entry->username + ") deleted successfully.");
    } catch (const std::exception& e) {
        print_red(std::string("Error: ") + e.what());
        return 1;
    }
    return 0;
}

int CLI::cmd_list(const std::vector<std::string>& /*args*/) {
    std::string path = Vault::default_vault_path();
    if (!Vault::exists(path)) {
        print_yellow("Vault is empty or not initialized. Run 'passguard init' first.");
        return 0;
    }

    try {
        auto entries = Vault::load(path);
        if (entries.empty()) {
            print_yellow("No entries in vault. Use 'passguard add' to add credentials.");
            return 0;
        }
        auto lines = Vault::list_entries(entries);
        for (const auto& line : lines) {
            std::cout << line << "\n";
        }
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

} // namespace passguard