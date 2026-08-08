cmake_minimum_required(VERSION 3.14)
project(Cryptenium VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Sources
set(SOURCES
    src/main.cpp
    src/cli.cpp
    src/vault.cpp
    src/platform.cpp
    src/password_generator.cpp
    src/crypto/Crypto.cpp
)

set(HEADERS
    include/cli.hpp
    include/vault.hpp
    include/platform.hpp
    include/password_generator.hpp
    src/crypto/Crypto.h
)

add_executable(cryptenium ${SOURCES} ${HEADERS})
target_include_directories(cryptenium PRIVATE include src)

# libsodium (crypto backend: Argon2id + XChaCha20-Poly1305 + CSPRNG)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBSODIUM QUIET IMPORTED_TARGET libsodium)
endif()
if(TARGET PkgConfig::LIBSODIUM)
    target_link_libraries(cryptenium PRIVATE PkgConfig::LIBSODIUM)
else()
    find_path(LIBSODIUM_INCLUDE_DIR sodium.h PATH_SUFFIXES sodium)
    find_library(LIBSODIUM_LIBRARY NAMES sodium libsodium)
    if(NOT LIBSODIUM_INCLUDE_DIR OR NOT LIBSODIUM_LIBRARY)
        message(FATAL_ERROR "libsodium not found. Install it (e.g. pacman -S mingw-w64-ucrt-x86_64-libsodium).")
    endif()
    target_include_directories(cryptenium PRIVATE ${LIBSODIUM_INCLUDE_DIR})
    target_link_libraries(cryptenium PRIVATE ${LIBSODIUM_LIBRARY})
endif()

# Security hardening (best-effort; harmless if unsupported by the compiler)
include(CheckCXXCompilerFlag)
foreach(flag -fstack-protector-strong -fPIE -Wl,-z,relro,-z,now -fcf-protection=full)
    check_cxx_compiler_flag(${flag} HAS_${flag})
    if(HAS_${flag})
        target_compile_options(cryptenium PRIVATE ${flag})
    endif()
endforeach()

if(MSVC)
    target_compile_options(cryptenium PRIVATE /W4)
else()
    target_compile_options(cryptenium PRIVATE -Wall -Wextra)
endif()
