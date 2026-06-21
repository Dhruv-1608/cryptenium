cmake_minimum_required(VERSION 3.14)
project(PassGuard VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Sources
set(SOURCES
    src/main.cpp
    src/cli.cpp
    src/vault.cpp
    src/password_generator.cpp
)

set(HEADERS
    include/cli.hpp
    include/vault.hpp
    include/password_generator.hpp
)

add_executable(passguard ${SOURCES} ${HEADERS})

target_include_directories(passguard PRIVATE include)