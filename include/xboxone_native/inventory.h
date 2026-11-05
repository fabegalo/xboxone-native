// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "xboxone_native/inspection.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace xboxone::inventory {

struct Limits {
    std::uint64_t max_file_bytes = 256ULL * 1024 * 1024;
    std::uint64_t max_total_bytes = 1024ULL * 1024 * 1024;
    std::size_t max_entries = 100000;
    std::size_t max_files = 10000;
    std::size_t max_depth = 64;
};

struct File {
    std::string path; // UTF-8, relative to the supplied root, '/' separators.
    std::string sha256;
    inspection::Report image;
    std::string error; // Nonempty if this file could not be inspected.
};

struct Exclusion {
    std::string path;
    std::string reason;
};

struct Dependency {
    std::string library; // ASCII case-folded import name.
    std::vector<std::string> required_by;
    std::vector<std::string> symbols;
    std::vector<std::string> candidates;
    // Presence is NOT proof of loader search order, exports, version or ABI.
    std::string status;
};

struct Report {
    std::vector<File> files;
    std::vector<Exclusion> excluded;
    std::vector<Dependency> dependencies;
    std::uint64_t hashed_bytes = 0;
    bool complete = true;
};

// Explicit recursive opt-in; only .exe/.dll/.sys/.xvd are read. Does not follow
// symlinks or Windows reparse points. No execution, source copies or disk writes.
// false denotes a fatal traversal/limit error; do not use that partial report.
// true with complete=false preserves per-file failures for diagnosis.
bool scan(const std::filesystem::path& root, Report& report, std::string& error,
          const Limits& limits = {});

} // namespace xboxone::inventory
