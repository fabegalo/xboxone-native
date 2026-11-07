// SPDX-License-Identifier: BSD-3-Clause
#pragma once
#include <filesystem>

namespace xboxone::detail {
// I/O spelling only. Callers must check supplied ancestors before normalization.
inline std::filesystem::path file_path(const std::filesystem::path& path) {
#ifdef _WIN32
    if (path.empty() || (path.has_root_path() && !path.is_absolute())) return path;
    auto absolute = path.is_absolute() ? path : std::filesystem::current_path() / path;
    auto value = absolute.make_preferred().native();
    if (value.starts_with(L"\\\\?\\") || value.starts_with(L"\\\\.\\")) return absolute;
    value = absolute.lexically_normal().make_preferred().native();
    if (value.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + value.substr(2);
    return L"\\\\?\\" + value;
#else
    return path;
#endif
}
} // namespace xboxone::detail
