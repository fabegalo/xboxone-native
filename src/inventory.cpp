// SPDX-License-Identifier: BSD-3-Clause
#include "xboxone_native/inventory.h"
#include "sha256.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <map>
#include <set>
#include <system_error>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace xboxone::inventory {
namespace {
namespace fs = std::filesystem;

std::string utf8(const fs::path& path) {
    const auto value = path.generic_u8string();
    return {reinterpret_cast<const char*>(value.data()), value.size()};
}

std::string fold(std::string value) {
    for (auto& c : value) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return value;
}

bool link_or_reparse(const fs::path& path) {
    // symlink_status alone does not cover every kind of Windows reparse point.
#ifdef _WIN32
    const auto attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES)
        throw fs::filesystem_error("cannot read file attributes", path,
                                  std::error_code(static_cast<int>(GetLastError()), std::system_category()));
    return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    return fs::is_symlink(fs::symlink_status(path));
#endif
}

bool linked_ancestor(const fs::path& path) {
    fs::path current;
    for (const auto& component : path) {
        current /= component;
        if (current == path.root_name()) continue;
        if (link_or_reparse(current)) return true;
    }
    return false;
}

bool approved(const fs::path& path) {
    const auto extension = fold(utf8(path.extension()));
    return extension == ".exe" || extension == ".dll" || extension == ".sys" || extension == ".xvd";
}

bool hash_file(const fs::path& path, std::uint64_t expected_size, std::string& digest) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    detail::Sha256 hash;
    std::array<std::uint8_t, 65536> buffer{};
    auto remaining = expected_size;
    while (remaining) {
        const auto amount = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), remaining));
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(amount));
        if (input.gcount() != static_cast<std::streamsize>(amount)) return false;
        hash.update(std::span(buffer.data(), amount));
        remaining -= amount;
    }
    // Reject growth as well as truncation, keeping the actual read bounded.
    if (input.peek() != std::char_traits<char>::eof() || input.bad()) return false;
    digest = hash.finish();
    return true;
}

template<class T> void sort_unique(T& values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

void dependencies(Report& report) {
    std::map<std::string, std::vector<std::string>> providers;
    std::map<std::string, Dependency> groups;
    for (const auto& file : report.files) {
        if (!file.error.empty() || file.image.kind != inspection::Kind::pe64) continue;
        const auto slash = file.path.find_last_of('/');
        providers[fold(file.path.substr(slash == std::string::npos ? 0 : slash + 1))].push_back(file.path);
        for (const auto& imported : file.image.pe.imports) {
            auto& dependency = groups[fold(imported.library)];
            dependency.library = fold(imported.library);
            dependency.required_by.push_back(file.path);
            dependency.symbols.insert(dependency.symbols.end(), imported.functions.begin(), imported.functions.end());
        }
    }
    for (auto& [name, dependency] : groups) {
        sort_unique(dependency.required_by);
        sort_unique(dependency.symbols);
        dependency.candidates = providers[name];
        sort_unique(dependency.candidates);
        dependency.status = dependency.candidates.empty() ? "not_in_inventory" :
                            dependency.candidates.size() == 1 ? "present_unverified" : "ambiguous";
        report.dependencies.push_back(std::move(dependency));
    }
}
} // namespace

bool fingerprint(const fs::path& path, std::string& sha256, std::string& error,
                 std::uint64_t max_bytes) {
    sha256.clear();
    error.clear();
    try {
        if (linked_ancestor(fs::absolute(path)) || !fs::is_regular_file(path)) {
            error = "artifact is not a regular, non-linked file";
            return false;
        }
        const auto size = fs::file_size(path);
        if (size > max_bytes) { error = "artifact byte limit exceeded"; return false; }
        if (!hash_file(path, size, sha256)) {
            error = "cannot hash artifact or input changed during read";
            return false;
        }
        return true;
    } catch (const fs::filesystem_error& e) {
        error = e.what();
        return false;
    }
}

bool scan(const fs::path& root, Report& report, std::string& error, const Limits& limits) {
    report = {};
    error.clear();
    try {
        const auto supplied = fs::absolute(root);
        if (linked_ancestor(supplied)) { error = "inventory root contains a symlink or reparse point"; return false; }
        const auto absolute = fs::canonical(supplied);
        if (!fs::is_directory(absolute)) { error = "inventory root is not a directory"; return false; }
        std::vector<fs::path> candidates;
        std::set<std::string> path_keys;
        std::size_t entries = 0;
        for (fs::recursive_directory_iterator it(absolute), end; it != end; ++it) {
            if (++entries > limits.max_entries) { error = "inventory entry limit exceeded"; return false; }
            const auto path = it->path();
            const auto relative = path.lexically_relative(absolute);
            if (relative.empty() || *relative.begin() == "..") { error = "path escapes inventory root"; return false; }
            const auto name = utf8(relative);
            if (link_or_reparse(path)) {
                it.disable_recursion_pending();
                report.excluded.push_back({name, "symlink_or_reparse_point"});
                continue;
            }
            if (static_cast<std::size_t>(it.depth()) > limits.max_depth) {
                error = "inventory depth limit exceeded"; return false;
            }
            if (!it->is_regular_file() || !approved(path)) continue;
            if (!path_keys.insert(fold(name)).second) {
                error = "case-insensitive inventory path collision: " + name; return false;
            }
            if (candidates.size() >= limits.max_files) { error = "inventory file limit exceeded"; return false; }
            candidates.push_back(relative);
        }
        std::sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) { return utf8(a) < utf8(b); });
        std::sort(report.excluded.begin(), report.excluded.end(), [](const auto& a, const auto& b) { return a.path < b.path; });
        for (const auto& relative : candidates) {
            const auto path = absolute / relative;
            if (linked_ancestor(path)) { error = "inventory path changed to a link or reparse point"; return false; }
            const auto size = fs::file_size(path);
            const auto modified = fs::last_write_time(path);
            if (size > limits.max_file_bytes) { error = "inventory per-file byte limit exceeded: " + utf8(relative); return false; }
            if (size > limits.max_total_bytes - report.hashed_bytes) { error = "inventory total byte limit exceeded"; return false; }
            File file;
            file.path = utf8(relative);
            if (!hash_file(path, size, file.sha256)) {
                error = "cannot hash file or input changed: " + file.path; return false;
            }
            report.hashed_bytes += size;
            inspection::inspect(path, file.image, file.error);
            if (linked_ancestor(path) || fs::file_size(path) != size || fs::last_write_time(path) != modified) {
                error = "input changed during inventory: " + file.path; return false;
            }
            if (!file.error.empty()) report.complete = false;
            report.files.push_back(std::move(file));
        }
        dependencies(report);
        return true;
    } catch (const fs::filesystem_error& ex) {
        error = std::string("inventory filesystem error: ") + ex.what();
        return false;
    }
}

} // namespace xboxone::inventory
