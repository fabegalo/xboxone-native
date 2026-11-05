// SPDX-License-Identifier: BSD-3-Clause
#include "xboxone_native/appmodel.h"
#include <iostream>
int main() {
    int failures = 0, checks = 0;
    std::filesystem::path path;
    for (const auto* p : {"", "/a", "\\a", "C:/a", "C:a", "a/../b", "a/./b", "a//b", "../a", "a/", "a:stream", "a.", "a ",
                          "CON", "nul.txt", "com1.exe", "LPT0", "CON .txt", "COM\xc2\xb9.exe", "LPT\xc2\xb2.txt",
                          "%TEMP%/a", "a?b", "a*b", "a\nb"}) {
        ++checks;
        if (xboxone::appmodel::package_relative_path(p, path)) { ++failures; std::cerr << "accepted unsafe path: " << p << '\n'; }
    }
    for (const auto* p : {"owned.exe", "bin/owned.exe", "bin\\owned.exe", "assets/logo.png"}) {
        ++checks;
        if (!xboxone::appmodel::package_relative_path(p, path)) ++failures;
    }
#ifndef _WIN32
    xboxone::appmodel::Manifest manifest;
    std::string error;
    ++checks;
    if (xboxone::appmodel::read_manifest("missing", "", manifest, error) || error.find("Windows required") == std::string::npos) ++failures;
#endif
    std::cout << checks << " checks; failures=" << failures << '\n';
    return failures ? 1 : 0;
}
