#ifndef PASSGUARD_VAULT_HPP
#define PASSGUARD_VAULT_HPP

#include <string>
#include <vector>
#include <optional>

namespace passguard {

struct Entry {
    std::string service;
    std::string username;
    std::string password;
};

class Vault {
public:
    static std::string default_vault_path();

    static bool exists(const std::string& path);

    static bool create(const std::string& path);

    static std::vector<Entry> load(const std::string& path);

    static bool save(const std::string& path, const std::vector<Entry>& entries);

    static bool add_entry(std::vector<Entry>& entries, const Entry& entry);

    static std::optional<Entry> find(const std::vector<Entry>& entries,
                                      const std::string& service,
                                      const std::string& username = "");

    static bool update_entry(std::vector<Entry>& entries,
                              const std::string& service,
                              const std::string& username,
                              const std::string& new_password);

    static bool delete_entry(std::vector<Entry>& entries,
                              const std::string& service,
                              const std::string& username = "");

    static std::vector<std::string> list_entries(const std::vector<Entry>& entries);
};

} // namespace passguard

#endif // PASSGUARD_VAULT_HPP