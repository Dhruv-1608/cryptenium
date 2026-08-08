#ifndef CRYPTENIUM_PASSWORD_GENERATOR_HPP
#define CRYPTENIUM_PASSWORD_GENERATOR_HPP

#include <cstddef>
#include <string>

namespace cryptenium {

// Cryptographically-secure random password generation built on libsodium's
// CSPRNG. Replaces the old std::mt19937-based generator.
class PasswordGenerator {
public:
    struct Options {
        bool use_lowercase = true;
        bool use_uppercase = true;
        bool use_digits = true;
        bool use_symbols = false;
    };

    // Generates a random password of the given length using the enabled
    // character sets. Throws std::invalid_argument if length is 0 or no
    // character set is enabled.
    static std::string generate_with_opts(std::size_t length, const Options& opts);

    // Convenience: all sets on (symbols too).
    static std::string generate(std::size_t length);
};

} // namespace cryptenium

#endif // CRYPTENIUM_PASSWORD_GENERATOR_HPP
