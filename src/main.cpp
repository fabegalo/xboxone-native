// SPDX-License-Identifier: BSD-3-Clause
#include "xboxone_native/inspection.h"

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>

namespace {
std::string escape_json(std::string_view s) {
    std::string result;
    result.reserve(s.size() + 8);
    constexpr char hex[] = "0123456789abcdef";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { result += '\\'; result += static_cast<char>(c); }
        else if (c < 0x20) {
            result += "\\u00";
            result += hex[c >> 4];
            result += hex[c & 15];
        } else result += static_cast<char>(c);
    }
    return result;
}

void print_report(const xboxone::inspection::Report& report, bool json) {
    using xboxone::inspection::Kind;
    if (json) {
        std::cout << "{\"kind\":\"" << (report.kind == Kind::xvd ? "xvd" : "pe64")
                  << "\",\"file_size\":" << report.file_size;
        if (report.kind == Kind::xvd) {
            const auto& x = report.xvd;
            std::cout << ",\"format_version\":" << x.format_version
                      << ",\"content_type\":" << x.content_type
                      << ",\"block_size\":" << x.block_size
                      << ",\"declared_drive_size\":" << x.declared_drive_size
                      << ",\"required_system_version\":" << x.required_system_version
                      << ",\"signature_verified\":false,\"decrypted\":false";
        } else {
            const auto& p = report.pe;
            std::cout << ",\"machine\":" << p.machine << ",\"subsystem\":" << p.subsystem
                      << ",\"section_count\":" << p.sections
                      << ",\"entry_point_rva\":" << p.entry_point_rva
                      << ",\"image_base\":" << p.image_base << ",\"imports\":[";
            bool first = true;
            for (const auto& library : p.imports) {
                if (!first) std::cout << ',';
                first = false;
                std::cout << "{\"library\":\"" << escape_json(library.library) << "\",\"symbols\":[";
                bool first_symbol = true;
                for (const auto& symbol : library.functions) {
                    if (!first_symbol) std::cout << ',';
                    first_symbol = false;
                    std::cout << '"' << escape_json(symbol) << '"';
                }
                std::cout << "]}";
            }
            std::cout << "]";
        }
        std::cout << "}\n";
        return;
    }
    std::cout << "File size: " << report.file_size << " bytes\n";
    if (report.kind == Kind::xvd) {
        const auto& x = report.xvd;
        std::cout << "XVD header recognized (not authenticated/decrypted)\n"
                  << "Format version: " << x.format_version << "\n"
                  << "Content type: " << x.content_type << "\n"
                  << "Block size: " << x.block_size << "\n"
                  << "Declared drive size: " << x.declared_drive_size << "\n"
                  << "Required system version (raw): " << x.required_system_version << "\n";
    } else {
        const auto& p = report.pe;
        std::cout << "PE32+ x86-64 image (not identified as an Xbox executable by itself)\n"
                  << "Machine: 0x" << std::hex << p.machine << std::dec << "\n"
                  << "Subsystem: " << p.subsystem << "\n"
                  << "Sections: " << p.sections << "\n"
                  << "Entry point RVA: 0x" << std::hex << p.entry_point_rva << std::dec << "\n";
        for (const auto& library : p.imports) {
            std::cout << "Import: " << library.library << "\n";
            for (const auto& symbol : library.functions) std::cout << "  " << symbol << "\n";
        }
    }
}

void help() {
    std::cout << "xboxone-native M0: read-only original content inspector\n"
              << "Usage: xboxone-native inspect <file> [--json]\n"
              << "Supported: PE32+ x86-64 and XVD headers. No execution/decryption.\n";
}

int run(int argc, const auto* const* argv) {
    if (argc == 2 && (std::basic_string_view(argv[1]) == "--help" ||
                      std::basic_string_view(argv[1]) == "-h")) {
        help(); return 0;
    }
    if (argc != 3 && argc != 4) { help(); return 2; }
    if (std::basic_string_view(argv[1]) != "inspect") { help(); return 2; }
    const bool json = argc == 4;
    if (json && std::basic_string_view(argv[3]) != "--json") { help(); return 2; }
    xboxone::inspection::Report report;
    std::string error;
    if (!xboxone::inspection::inspect(std::filesystem::path(argv[2]), report, error)) {
        std::cerr << "Inspection failed: " << error << "\n";
        return 1;
    }
    print_report(report, json);
    return 0;
}
} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) { return run(argc, argv); }
#else
int main(int argc, char** argv) { return run(argc, argv); }
#endif
