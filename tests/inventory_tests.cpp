// SPDX-License-Identifier: BSD-3-Clause
#include "xboxone_native/inventory.h"
#include "sha256.h"
#include "file_path.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
namespace {
int failures = 0;
void check(bool value, std::string_view message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
}
void write(const fs::path& path, std::string_view bytes) {
    std::ofstream out(path, std::ios::binary);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}
void put(std::string& data, std::size_t at, std::uint64_t value, unsigned bytes) {
    for (unsigned i = 0; i < bytes; ++i) data[at + i] = static_cast<char>(value >> (i * 8));
}
std::string image(std::string_view library = {}) {
    std::string bytes(0x400, '\0');
    bytes.replace(0, 2, "MZ"); put(bytes, 0x3c, 0x80, 4);
    bytes.replace(0x80, 2, "PE");
    put(bytes, 0x84, 0x8664, 2); put(bytes, 0x86, 1, 2); put(bytes, 0x94, 0xf0, 2);
    put(bytes, 0x98, 0x20b, 2); put(bytes, 0xd4, 0x200, 4); put(bytes, 0x104, 16, 4);
    put(bytes, 0x190, 0x200, 4); put(bytes, 0x194, 0x2000, 4);
    put(bytes, 0x198, 0x200, 4); put(bytes, 0x19c, 0x200, 4);
    if (!library.empty()) {
        put(bytes, 0x110, 0x2000, 4); put(bytes, 0x114, 40, 4);
        put(bytes, 0x200, 0x2060, 4); put(bytes, 0x20c, 0x2080, 4); put(bytes, 0x210, 0x2060, 4);
        put(bytes, 0x260, 0x20a0, 8);
        bytes.replace(0x280, library.size(), library);
        bytes.replace(0x2a2, 5, "Start");
    }
    return bytes;
}
std::string hash(std::string_view input, std::size_t chunk = 7) {
    xboxone::detail::Sha256 sha;
    while (!input.empty()) {
        const auto size = std::min(input.size(), chunk);
        sha.update({reinterpret_cast<const std::uint8_t*>(input.data()), size});
        input.remove_prefix(size);
    }
    return sha.finish();
}
} // namespace

int main() {
    check(hash("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256 empty");
    check(hash("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA256 abc");
    check(hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "SHA256 two-block padding");
    check(hash(std::string(1000000, 'a'), 65536) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "SHA256 million a, streaming");

    const auto temp = fs::canonical(fs::temp_directory_path()) /
        ("xboxone_inventory_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    const auto root = temp / "input";
    fs::create_directories(root / "sub");
    const auto source = image("EXAMPLE.dll");
    write(root / "z.exe", source);
    write(root / "sub" / "example.DLL", image());
    write(root / "ignored.txt", "not an image");
    write(root / "ignored.zip", "not traversed");
    xboxone::inventory::Report report;
    std::string error;
    check(xboxone::inventory::scan(root, report, error), "scan valid directory");
    check(report.complete && report.files.size() == 2 && report.hashed_bytes == 0x800, "allowlist, size and complete");
    check(report.files.size() == 2 && report.files[0].path == "sub/example.DLL" && report.files[1].path == "z.exe", "deterministic relative paths");
    check(report.files.size() == 2 && report.files[1].sha256 == hash(source), "file SHA256");
    check(report.dependencies.size() == 1, "dependency grouping");
    if (report.dependencies.size() == 1) {
        const auto& d = report.dependencies[0];
        check(d.library == "example.dll" && d.status == "present_unverified", "case-insensitive presence, no compatibility claim");
        check(d.required_by == std::vector<std::string>{"z.exe"} &&
              d.candidates == std::vector<std::string>{"sub/example.DLL"} &&
              d.symbols == std::vector<std::string>{"Start"}, "dependency evidence");
    }
    write(root / "sub" / "second.exe", source);
    write(root / "example.dll", image());
    check(xboxone::inventory::scan(root, report, error), "scan duplicate DLL basenames");
    check(report.dependencies.size() == 1 && report.dependencies[0].status == "ambiguous" &&
          report.dependencies[0].required_by.size() == 2, "no silent basename selection, deduplicate imports");
    fs::remove(root / "example.dll");
    fs::remove(root / "sub" / "example.DLL");
    check(xboxone::inventory::scan(root, report, error), "scan absent dependency");
    check(report.dependencies.size() == 1 && report.dependencies[0].status == "not_in_inventory", "absent means inventory only, not host search");
    write(root / "broken.sys", "abc");
    check(xboxone::inventory::scan(root, report, error) && !report.complete, "preserve malformed PE error");
    check(!report.files.empty() && !report.files[0].error.empty() && report.files[0].sha256 == hash("abc"), "failed image still has identity");
    fs::remove(root / "broken.sys");
    auto limits = xboxone::inventory::Limits{};
    limits.max_file_bytes = source.size() - 1;
    check(!xboxone::inventory::scan(root, report, error, limits), "per-file bound");
    limits = {}; limits.max_total_bytes = source.size();
    check(!xboxone::inventory::scan(root, report, error, limits), "total byte bound");
    limits = {}; limits.max_files = 1;
    check(!xboxone::inventory::scan(root, report, error, limits), "file count bound");
    limits = {}; limits.max_entries = 1;
    check(!xboxone::inventory::scan(root, report, error, limits), "entry count bound");
    limits = {}; limits.max_depth = 0;
    check(!xboxone::inventory::scan(root, report, error, limits), "depth bound");
    check(!xboxone::inventory::scan(root / "z.exe", report, error), "reject file root");
    check(!xboxone::inventory::scan(temp / "missing", report, error), "reject missing root");

    fs::create_directories(temp / "outside");
    write(temp / "outside" / "escape.exe", image());
    std::error_code ec;
    fs::create_directory_symlink(temp / "outside", root / "escape", ec);
    if (!ec) {
        check(xboxone::inventory::scan(root, report, error) && report.files.size() == 2 && report.excluded.size() == 1,
              "directory symlink excluded without traversal");
        check(!xboxone::inventory::scan(root / "escape", report, error), "reject symlink root");
        check(!xboxone::inventory::scan(root / "escape" / "..", report, error), "reject symlink ancestor before dot-dot normalization");
        check(!xboxone::inventory::scan(root / "escape" / ".." / "escape", report, error), "reject normalized symlink root");
        const auto previous = fs::current_path();
        fs::current_path(root);
        check(!xboxone::inventory::scan("escape/..", report, error) && error.find("symlink") != std::string::npos,
              "reject relative symlink before dot-dot normalization");
        fs::current_path(previous);
        std::string digest;
        check(!xboxone::inventory::fingerprint(root / "escape" / ".." / "z.exe", digest, error) && error.find("linked") != std::string::npos,
              "fingerprint rejects symlink ancestor before dot-dot normalization");
#ifdef _WIN32
        const auto extended = xboxone::detail::file_path(root);
        check(!xboxone::inventory::scan(extended / "escape" / "..", report, error),
              "extended root rejects symlink before dot-dot normalization");
        check(!xboxone::inventory::fingerprint(extended / "escape" / ".." / "z.exe", digest, error),
              "extended fingerprint rejects symlink before dot-dot normalization");
#endif
        fs::remove(root / "escape");
    } else {
        check(!std::getenv("XBOXONE_REQUIRE_SYMLINKS"), "CI requires directory symlink coverage: " + ec.message());
        std::cout << "Directory symlink unavailable: " << ec.message() << '\n';
    }
    fs::create_symlink(temp / "outside" / "escape.exe", root / "linked.exe", ec);
    if (!ec) {
        check(xboxone::inventory::scan(root, report, error) && report.files.size() == 2 && report.excluded.size() == 1,
              "file symlink excluded");
        fs::remove(root / "linked.exe");
    } else {
        check(!std::getenv("XBOXONE_REQUIRE_SYMLINKS"), "CI requires file symlink coverage: " + ec.message());
        std::cout << "File symlink unavailable: " << ec.message() << '\n';
    }
#ifndef _WIN32
    write(root / "Z.exe", source);
    // Case-sensitive filesystems can represent this collision. Other hosts
    // simply replaced z.exe and have nothing distinct to reject.
    if (!fs::equivalent(root / "Z.exe", root / "z.exe"))
        check(!xboxone::inventory::scan(root, report, error), "reject case-folded relative path collision");
    fs::remove(root / "Z.exe");
#endif
    std::ifstream after(root / "sub" / "second.exe", std::ios::binary);
    const std::string contents((std::istreambuf_iterator<char>(after)), {});
    after.close();
    check(contents == source, "input bytes unchanged");
    // Only this unique, test-created directory is removed.
    fs::remove_all(temp);
    return failures ? 1 : 0;
}
