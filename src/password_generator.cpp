#include "password_generator.hpp"

#include "crypto/Crypto.h"

#include <stdexcept>

namespace cryptenium {

std::string PasswordGenerator::generate_with_opts(std::size_t length, const Options& opts) {
    if (length == 0) {
        throw std::invalid_argument("password length must be greater than 0");
    }

    std::string chars;
    if (opts.use_lowercase) chars += "abcdefghijklmnopqrstuvwxyz";
    if (opts.use_uppercase) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (opts.use_digits)    chars += "0123456789";
    if (opts.use_symbols)   chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/~";

    if (chars.empty()) {
        throw std::invalid_argument("at least one character set must be enabled");
    }

    // Uniform selection via rejection sampling from the CSPRNG.
    // Choose the smallest power of two >= chars.size() to avoid modulo bias.
    std::size_t range = 1;
    while (range < chars.size()) range <<= 1;

    std::string result;
    result.reserve(length);
    while (result.size() < length) {
        std::vector<unsigned char> buf(1);
        crypto::fill_random(buf.data(), buf.size());
        std::size_t idx = buf[0] % range;
        if (idx < chars.size()) {
            result += chars[idx];
        }
    }
    return result;
}

std::string PasswordGenerator::generate(std::size_t length) {
    Options opts;
    opts.use_symbols = true;
    return generate_with_opts(length, opts);
}

} // namespace cryptenium
