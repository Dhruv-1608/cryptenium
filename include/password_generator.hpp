#ifndef PASSGUARD_PASSWORD_GENERATOR_HPP
#define PASSGUARD_PASSWORD_GENERATOR_HPP

#include <string>

namespace passguard {

class PasswordGenerator {
public:
    struct Options {
        bool use_lowercase = true;
        bool use_uppercase = true;
        bool use_digits = true;
        bool use_symbols = false;
    };

    static std::string generate_with_opts(std::size_t length, const Options& opts);
};

} // namespace passguard

#endif // PASSGUARD_PASSWORD_GENERATOR_HPP