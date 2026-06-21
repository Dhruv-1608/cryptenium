#include "password_generator.hpp"
#include <random>
#include <stdexcept>

namespace passguard {

std::string PasswordGenerator::generate_with_opts(std::size_t length, const Options& opts) {
    if (length == 0) {
        throw std::invalid_argument("password length must be greater than 0");
    }

    std::string chars;
    if (opts.use_lowercase) chars += "abcdefghijklmnopqrstuvwxyz";
    if (opts.use_uppercase) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (opts.use_digits)    chars += "0123456789";
    if (opts.use_symbols)   chars += "!@#$%^&*()_+-=[]{}|;':\",./<>?~`";

    if (chars.empty()) {
        throw std::invalid_argument("at least one character set must be enabled");
    }

    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<std::size_t> dist(0, chars.size() - 1);

    std::string result;
    result.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        result += chars[dist(gen)];
    }
    return result;
}

} // namespace passguard
