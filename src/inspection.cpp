// SPDX-License-Identifier: BSD-3-Clause
#include "xboxone_native/inspection.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace xboxone::inspection {
namespace {

std::uint16_t u16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0]) |
           static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[1]) << 8);
}
std::uint32_t u32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(u16(p)) |
           (static_cast<std::uint32_t>(u16(p + 2)) << 16);
}
std::uint64_t u64(const std::uint8_t* p) {
    return static_cast<std::uint64_t>(u32(p)) |
           (static_cast<std::uint64_t>(u32(p + 4)) << 32);
}

class Reader {
public:
    explicit Reader(const std::filesystem::path& path) : file_(path, std::ios::binary | std::ios::ate) {
        if (file_) {
            const auto end = file_.tellg();
            if (end >= 0) {
                size_ = static_cast<std::uint64_t>(end);
                valid_ = true;
            }
        }
    }
    bool valid() const { return valid_; }
    std::uint64_t size() const { return size_; }

    bool read(std::uint64_t at, std::span<std::uint8_t> out) {
        if (!valid_ || at > size_ || out.size() > size_ - at ||
            at > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
            return false;
        }
        file_.clear();
        file_.seekg(static_cast<std::streamoff>(at), std::ios::beg);
        if (!file_) return false;
        file_.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
        return file_.gcount() == static_cast<std::streamsize>(out.size());
    }

    std::optional<std::string> cstring(std::uint64_t at, std::size_t max_len = 256) {
        if (at >= size_) return std::nullopt;
        const auto available = static_cast<std::size_t>(std::min<std::uint64_t>(max_len, size_ - at));
        std::vector<std::uint8_t> bytes(available);
        if (!read(at, bytes)) return std::nullopt;
        const auto stop = std::find(bytes.begin(), bytes.end(), 0);
        if (stop == bytes.end()) return std::nullopt;
        return std::string(bytes.begin(), stop);
    }

private:
    std::ifstream file_;
    std::uint64_t size_ = 0;
    bool valid_ = false;
};

struct Section {
    std::uint32_t virtual_address;
    std::uint32_t virtual_size;
    std::uint32_t raw_offset;
    std::uint32_t raw_size;
};

std::optional<std::uint64_t> rva_offset(std::uint32_t rva,
                                        std::uint32_t size_of_headers,
                                        const std::vector<Section>& sections,
                                        std::uint64_t size) {
    if (rva < size_of_headers && rva < size) return rva;
    for (const auto& section : sections) {
        if (rva < section.virtual_address) continue;
        const auto delta = static_cast<std::uint64_t>(rva) - section.virtual_address;
        if (delta >= std::max(section.virtual_size, section.raw_size) || delta >= section.raw_size) continue;
        const auto absolute = static_cast<std::uint64_t>(section.raw_offset) + delta;
        if (absolute < size) return absolute;
    }
    return std::nullopt;
}

bool parse_pe(Reader& file, Report& report, std::string& error) {
    std::array<std::uint8_t, 64> dos{};
    if (!file.read(0, dos) || dos[0] != 'M' || dos[1] != 'Z') {
        error = "invalid DOS/PE header";
        return false;
    }
    const std::uint64_t pe_offset = u32(dos.data() + 0x3c);
    std::array<std::uint8_t, 24> coff{};
    if (!file.read(pe_offset, coff) || coff[0] != 'P' || coff[1] != 'E' || coff[2] || coff[3]) {
        error = "invalid PE signature or truncated COFF header";
        return false;
    }
    const auto machine = u16(coff.data() + 4);
    const auto nsections = u16(coff.data() + 6);
    const auto optional_size = u16(coff.data() + 20);
    if (machine != 0x8664 || nsections == 0 || nsections > 96 || optional_size < 0x70) {
        error = "unsupported PE machine, section count, or optional header";
        return false;
    }
    if (pe_offset > std::numeric_limits<std::uint64_t>::max() - 24) {
        error = "PE offset overflow";
        return false;
    }
    const auto optional_offset = pe_offset + 24;
    std::vector<std::uint8_t> optional(optional_size);
    if (!file.read(optional_offset, optional) || u16(optional.data()) != 0x20b) {
        error = "not a complete PE32+ image";
        return false;
    }
    if (optional_offset > std::numeric_limits<std::uint64_t>::max() - optional_size) {
        error = "optional header offset overflow";
        return false;
    }
    const auto section_offset = optional_offset + optional_size;
    std::vector<Section> sections;
    sections.reserve(nsections);
    for (std::uint32_t i = 0; i < nsections; ++i) {
        std::array<std::uint8_t, 40> sec{};
        if (!file.read(section_offset + i * 40, sec)) {
            error = "truncated section table";
            return false;
        }
        sections.push_back({u32(sec.data() + 12), u32(sec.data() + 8),
                            u32(sec.data() + 20), u32(sec.data() + 16)});
    }
    report.kind = Kind::pe64;
    report.pe.machine = machine;
    report.pe.characteristics = u16(coff.data() + 22);
    report.pe.sections = nsections;
    report.pe.subsystem = u16(optional.data() + 0x44);
    report.pe.image_base = u64(optional.data() + 0x18);
    report.pe.entry_point_rva = u32(optional.data() + 0x10);
    const auto directories = u32(optional.data() + 0x6c);
    if (directories > (optional_size - 0x70U) / 8U) {
        error = "data directories exceed optional header";
        return false;
    }
    const auto has_directory = [&](unsigned index) {
        return directories > index &&
            (u32(optional.data() + 0x70 + index * 8) != 0 ||
             u32(optional.data() + 0x74 + index * 8) != 0);
    };
    report.pe.has_delay_imports = has_directory(13);
    report.pe.has_clr_header = has_directory(14);

    // Import Directory (data directory #1); no imports is valid.
    if (optional_size < 0x80 || u32(optional.data() + 0x6c) < 2) return true;
    const auto import_rva = u32(optional.data() + 0x78);
    const auto import_size = u32(optional.data() + 0x7c);
    if (import_rva == 0 || import_size == 0) return true;
    if (import_size > 20 * 1024) {
        error = "import descriptor table exceeds safety limit";
        return false;
    }
    const auto headers_size = u32(optional.data() + 0x3c);
    const auto locate = [&](std::uint32_t rva) {
        return rva_offset(rva, headers_size, sections, file.size());
    };
    bool terminated = false;
    for (std::uint32_t pos = 0; pos + 20 <= import_size; pos += 20) {
        const auto descriptor_rva = static_cast<std::uint64_t>(import_rva) + pos;
        if (descriptor_rva > UINT32_MAX) {
            error = "import descriptor RVA overflow";
            return false;
        }
        const auto mapped = locate(static_cast<std::uint32_t>(descriptor_rva));
        std::array<std::uint8_t, 20> descriptor{};
        if (!mapped || !file.read(*mapped, descriptor)) {
            error = "invalid import descriptor RVA";
            return false;
        }
        bool zero = std::all_of(descriptor.begin(), descriptor.end(), [](auto b) { return b == 0; });
        if (zero) { terminated = true; break; }
        const auto name_rva = u32(descriptor.data() + 12);
        const auto thunk_rva = u32(descriptor.data());
        const auto iat_rva = u32(descriptor.data() + 16);
        const auto name_at = locate(name_rva);
        const auto name = name_at ? file.cstring(*name_at) : std::nullopt;
        if (!name || name->empty()) {
            error = "invalid imported library name";
            return false;
        }
        Import import{*name, {}};
        const std::uint64_t table_rva = thunk_rva ? thunk_rva : iat_rva;
        if (table_rva == 0) {
            error = "missing import thunk table";
            return false;
        }
        bool thunks_terminated = false;
        for (std::uint32_t t = 0; t < 8192; ++t) {
            const auto entry_rva = table_rva + static_cast<std::uint64_t>(t) * 8;
            if (entry_rva > UINT32_MAX) break;
            const auto entry_at = locate(static_cast<std::uint32_t>(entry_rva));
            std::array<std::uint8_t, 8> value{};
            if (!entry_at || !file.read(*entry_at, value)) break;
            const auto thunk = u64(value.data());
            if (thunk == 0) { thunks_terminated = true; break; }
            if (thunk & (1ULL << 63)) {
                import.functions.push_back("#" + std::to_string(thunk & 0xffff));
            } else {
                if (thunk > UINT32_MAX || thunk + 2 > UINT32_MAX) break;
                const auto hint_name_at = locate(static_cast<std::uint32_t>(thunk + 2));
                const auto func = hint_name_at ? file.cstring(*hint_name_at) : std::nullopt;
                if (!func || func->empty()) break;
                import.functions.push_back(*func);
            }
        }
        if (!thunks_terminated) {
            error = "invalid or unterminated import thunk table";
            return false;
        }
        report.pe.imports.push_back(std::move(import));
    }
    if (!terminated) {
        error = "unterminated import directory";
        return false;
    }
    return true;
}

bool parse_xvd(Reader& file, Report& report, std::string& error) {
    // XVD has a 0x200-byte signature area followed by the 'msft-xvd' header.
    // This is identification ONLY; an authentic signature is NOT verified.
    std::array<std::uint8_t, xvd_probe_size> prefix{};
    if (!file.read(0, prefix)) {
        error = "truncated XVD metadata prefix (requires at least 0xE00 bytes)";
        return false;
    }
    return inspect_xvd_prefix(prefix, file.size(), report, error);
}

} // namespace

bool inspect_xvd_prefix(std::span<const std::uint8_t> prefix, std::uint64_t declared_file_size,
                        Report& report, std::string& error) {
    report = {};
    error.clear();
    if (prefix.size() < xvd_probe_size || declared_file_size < prefix.size()) {
        error = "truncated XVD metadata prefix or inconsistent declared file size";
        return false;
    }
    const auto* header = prefix.data() + 0x200;
    if (std::string_view(reinterpret_cast<const char*>(header), 8) != "msft-xvd") {
        error = "invalid XVD magic";
        return false;
    }
    report.kind = Kind::xvd;
    report.file_size = declared_file_size;
    report.xvd.volume_flags = u32(header + 0x08);
    report.xvd.format_version = u32(header + 0x0c);
    report.xvd.created_filetime_raw = u64(header + 0x10);
    report.xvd.declared_drive_size = u64(header + 0x18);
    report.xvd.content_type = u32(header + 0x84);
    report.xvd.block_size = u32(header + 0x98);
    report.xvd.package_version_raw = u64(header + 0x1bc);
    report.xvd.required_system_version = u64(header + 0x294);
    return true;
}

bool inspect(const std::filesystem::path& path, Report& report, std::string& error) {
    error.clear();
    report = {};
    Reader file(path);
    if (!file.valid()) {
        error = "cannot open file";
        return false;
    }
    report.file_size = file.size();
    std::array<std::uint8_t, 2> prefix{};
    if (file.read(0, prefix) && prefix[0] == 'M' && prefix[1] == 'Z') {
        return parse_pe(file, report, error);
    }
    std::array<std::uint8_t, 8> magic{};
    if (file.read(0x200, magic) &&
        std::string_view(reinterpret_cast<const char*>(magic.data()), 8) == "msft-xvd") {
        return parse_xvd(file, report, error);
    }
    error = "unsupported input (expected PE32+ x86-64 or XVD header)";
    return false;
}

} // namespace xboxone::inspection
