#include "cli.hpp"
#include "crypto/Crypto.h"

#include <iostream>

int main(int argc, char* argv[]) {
    if (!cryptenium::crypto::init()) {
        std::cerr << "Fatal: failed to initialize cryptography (libsodium).\n";
        return 1;
    }
    return cryptenium::CLI::run(argc, argv);
}
