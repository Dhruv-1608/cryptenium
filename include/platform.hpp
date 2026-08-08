#ifndef CRYPTENIUM_PLATFORM_HPP
#define CRYPTENIUM_PLATFORM_HPP

#include <string>

namespace cryptenium::platform {

// Reads a line from stdin without echoing characters to the terminal.
// Falls back to plain getline if the platform can't disable echo.
std::string read_password(const std::string& prompt);

// Copies text to the OS clipboard. Returns false on failure.
bool clipboard_copy(const std::string& text);

// Best-effort clipboard clear. Returns false on failure.
bool clipboard_clear();

} // namespace cryptenium::platform

#endif // CRYPTENIUM_PLATFORM_HPP
