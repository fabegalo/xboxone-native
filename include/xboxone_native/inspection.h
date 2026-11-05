// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace xboxone::inspection {

enum class Kind { pe64, xvd };

struct Import {
    std::string library;
    std::vector<std::string> functions;
};

struct PeInfo {
    std::uint16_t machine = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t sections = 0;
    std::uint64_t image_base = 0;
    std::uint32_t entry_point_rva = 0;
    std::vector<Import> imports;
};

struct XvdInfo {
    std::uint32_t format_version = 0;
    std::uint32_t content_type = 0;
    std::uint32_t block_size = 0;
    std::uint64_t declared_drive_size = 0;
    std::uint64_t required_system_version = 0;
};

struct Report {
    Kind kind = Kind::pe64;
    std::uint64_t file_size = 0;
    PeInfo pe;
    XvdInfo xvd;
};

// No execution, decryption, signature validation, or writes to the input.
// false means error contains a specific reason; report is not trustworthy then.
bool inspect(const std::filesystem::path& path, Report& report, std::string& error);

} // namespace xboxone::inspection
