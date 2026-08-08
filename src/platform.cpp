#include "platform.hpp"

#include <iostream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <cstdio>
#include <termios.h>
#include <unistd.h>
#endif

namespace cryptenium::platform {

std::string read_password(const std::string& prompt) {
    std::cout << prompt << std::flush;

    std::string pwd;
#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD old_mode = 0;
    bool changed = false;
    if (hStdin != INVALID_HANDLE_VALUE &&
        GetConsoleMode(hStdin, &old_mode)) {
        SetConsoleMode(hStdin, old_mode & (~ENABLE_ECHO_INPUT));
        changed = true;
    }
    std::getline(std::cin, pwd);
    if (changed) {
        SetConsoleMode(hStdin, old_mode);
    }
#else
    struct termios oldt, newt;
    bool changed = false;
    if (tcgetattr(STDIN_FILENO, &oldt) == 0) {
        newt = oldt;
        newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) == 0) {
            changed = true;
        }
    }
    std::getline(std::cin, pwd);
    if (changed) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
    }
#endif
    std::cout << "\n";
    // Trim trailing whitespace (CR, LF, spaces) that can appear when stdin is
    // piped on Windows.
    while (!pwd.empty() &&
           (pwd.back() == '\r' || pwd.back() == '\n' || pwd.back() == ' ')) {
        pwd.pop_back();
    }
    return pwd;
}

bool clipboard_copy(const std::string& text) {
    if (text.empty()) return true;
#ifdef _WIN32
    if (!OpenClipboard(nullptr)) return false;
    EmptyClipboard();
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (hMem == nullptr) {
        CloseClipboard();
        return false;
    }
    char* dst = static_cast<char*>(GlobalLock(hMem));
    if (dst != nullptr) {
        std::copy(text.begin(), text.end(), dst);
        dst[text.size()] = '\0';
        GlobalUnlock(hMem);
    }
    SetClipboardData(CF_TEXT, hMem);
    CloseClipboard();
    return true;
#elif defined(__APPLE__)
    // Direct NSPasteboard requires Objective-C; fall back to pbcopy (Phase 3
    // can replace this with a native implementation).
    std::string cmd = "printf '%s' '" + text + "' | pbcopy";
    return std::system(cmd.c_str()) == 0;
#else
    // X11 via xclip (Phase 3 can use X11/XCB directly).
    std::string cmd = "printf '%s' '" + text + "' | xclip -selection clipboard";
    return std::system(cmd.c_str()) == 0;
#endif
}

bool clipboard_clear() {
#ifdef _WIN32
    if (!OpenClipboard(nullptr)) return false;
    EmptyClipboard();
    CloseClipboard();
    return true;
#else
    return clipboard_copy("");
#endif
}

} // namespace cryptenium::platform
