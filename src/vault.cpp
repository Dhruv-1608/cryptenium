#include "vault.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstdlib>
#include <algorithm>

namespace passguard {

namespace {

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::string entries_to_json(const std::vector<Entry>& entries) {
    std::ostringstream os;
    os << "{\n  \"entries\": [\n";
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        os << "    {\n"
           << "      \"service\": \""  << json_escape(e.service)  << "\",\n"
           << "      \"username\": \"" << json_escape(e.username) << "\",\n"
           << "      \"password\": \"" << json_escape(e.password) << "\"\n"
           << "    }";
        if (i + 1 < entries.size()) os << ",";
        os << "\n";
    }
    os << "  ]\n}\n";
    return os.str();
}

std::string parse_json_string(const std::string& json, std::size_t& pos) {
    if (pos >= json.size() || json[pos] != '"') {
        throw std::runtime_error("expected '\"' at position " + std::to_string(pos));
    }
    ++pos;
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\') {
            ++pos;
            if (pos >= json.size()) break;
            switch (json[pos]) {
                case '"':  result += '"';  break;
                case '\\': result += '\\'; break;
                case '/':  result += '/';  break;
                case 'b':  result += '\b'; break;
                case 'f':  result += '\f'; break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                case 'u': {
                    if (pos + 4 < json.size()) {
                        std::string hex = json.substr(pos + 1, 4);
                        unsigned long cp = std::stoul(hex, nullptr, 16);
                        result += static_cast<char>(cp);
                        pos += 4;
                    }
                    break;
                }
                default: result += json[pos]; break;
            }
            ++pos;
        } else {
            result += json[pos];
            ++pos;
        }
    }
    if (pos < json.size() && json[pos] == '"') ++pos;
    return result;
}

void skip_ws(const std::string& json, std::size_t& pos) {
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
                                 json[pos] == '\n' || json[pos] == '\r')) {
        ++pos;
    }
}

void expect_char(const std::string& json, std::size_t& pos, char expected) {
    skip_ws(json, pos);
    if (pos >= json.size() || json[pos] != expected) {
        throw std::runtime_error(
            std::string("expected '") + expected + "' at position " +
            std::to_string(pos) + ", got '" +
            (pos < json.size() ? std::string(1, json[pos]) : "EOF") + "'");
    }
    ++pos;
}

std::vector<Entry> json_to_entries(const std::string& json) {
    std::vector<Entry> entries;
    std::size_t pos = 0;

    skip_ws(json, pos);
    expect_char(json, pos, '{');
    skip_ws(json, pos);

    if (pos < json.size() && json[pos] == '"') {
        std::string key = parse_json_string(json, pos);
        if (key != "entries") {
            throw std::runtime_error("expected \"entries\" key");
        }
    }

    skip_ws(json, pos);
    expect_char(json, pos, ':');
    skip_ws(json, pos);
    expect_char(json, pos, '[');

    skip_ws(json, pos);
    while (pos < json.size() && json[pos] != ']') {
        expect_char(json, pos, '{');

        std::string service, username, password;

        for (int i = 0; i < 3; ++i) {
            skip_ws(json, pos);
            if (pos < json.size() && json[pos] == '}') break;

            if (json[pos] == ',') {
                ++pos;
                skip_ws(json, pos);
                if (pos < json.size() && json[pos] == '}') break;
            }

            std::string k = parse_json_string(json, pos);
            skip_ws(json, pos);
            expect_char(json, pos, ':');
            skip_ws(json, pos);
            std::string v = parse_json_string(json, pos);

            if (k == "service")  service  = v;
            if (k == "username") username = v;
            if (k == "password") password = v;
        }

        entries.push_back({service, username, password});

        skip_ws(json, pos);
        expect_char(json, pos, '}');
        skip_ws(json, pos);
        if (pos < json.size() && json[pos] == ',') ++pos;
        skip_ws(json, pos);
    }

    expect_char(json, pos, ']');
    skip_ws(json, pos);
    expect_char(json, pos, '}');

    return entries;
}

} // anonymous namespace

std::string Vault::default_vault_path() {
    const char* home = std::getenv("HOME");
#ifdef _WIN32
    if (!home) home = std::getenv("USERPROFILE");
#endif
    if (!home) home = ".";
    return std::string(home) + "/.passguard/vault.json";
}

bool Vault::exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

bool Vault::create(const std::string& path) {
    std::string dir;
    auto slash = path.find_last_of("/\\");
    if (slash != std::string::npos) {
        dir = path.substr(0, slash);
    }
    if (!dir.empty()) {
        int ret = 0;
#ifdef _WIN32
        ret = system(("if not exist \"" + dir + "\" mkdir \"" + dir + "\"").c_str());
#else
        ret = system(("mkdir -p \"" + dir + "\" 2>/dev/null").c_str());
        (void)ret;
#endif
    }

    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << "{\n  \"entries\": []\n}\n";
    return f.good();
}

std::vector<Entry> Vault::load(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        throw std::runtime_error("cannot open vault: " + path);
    }
    std::stringstream buf;
    buf << f.rdbuf();
    return json_to_entries(buf.str());
}

bool Vault::save(const std::string& path, const std::vector<Entry>& entries) {
    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << entries_to_json(entries);
    return f.good();
}

bool Vault::add_entry(std::vector<Entry>& entries, const Entry& entry) {
    auto it = std::find_if(entries.begin(), entries.end(),
        [&](const Entry& e) {
            return e.service == entry.service && e.username == entry.username;
        });
    if (it != entries.end()) return false;
    entries.push_back(entry);
    return true;
}

std::optional<Entry> Vault::find(const std::vector<Entry>& entries,
                                  const std::string& service,
                                  const std::string& username) {
    for (const auto& e : entries) {
        if (e.service == service &&
            (username.empty() || e.username == username)) {
            return e;
        }
    }
    return std::nullopt;
}

bool Vault::update_entry(std::vector<Entry>& entries,
                          const std::string& service,
                          const std::string& username,
                          const std::string& new_password) {
    for (auto& e : entries) {
        if (e.service == service &&
            (username.empty() || e.username == username)) {
            e.password = new_password;
            return true;
        }
    }
    return false;
}

bool Vault::delete_entry(std::vector<Entry>& entries,
                          const std::string& service,
                          const std::string& username) {
    auto it = std::remove_if(entries.begin(), entries.end(),
        [&](const Entry& e) {
            return e.service == service &&
                   (username.empty() || e.username == username);
        });
    if (it == entries.end()) return false;
    entries.erase(it, entries.end());
    return true;
}

std::vector<std::string> Vault::list_entries(const std::vector<Entry>& entries) {
    std::vector<std::string> result;
    result.reserve(entries.size());
    int idx = 1;
    for (const auto& e : entries) {
        result.push_back(std::to_string(idx) + ". " + e.service + " (" + e.username + ")");
        ++idx;
    }
    return result;
}

} // namespace passguard