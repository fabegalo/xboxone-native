// SPDX-License-Identifier: BSD-3-Clause
#pragma once
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wrl/client.h>
#include <string>
#include <stdexcept>

namespace xboxone::appmodel::windows {
template<class T> using Com = Microsoft::WRL::ComPtr<T>;
inline void require(HRESULT hr, const char* api) {
    if (FAILED(hr)) throw std::runtime_error(std::string(api) + "; HRESULT=" + std::to_string(static_cast<std::uint32_t>(hr)));
}
struct Apartment {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    Apartment() { if (hr != RPC_E_CHANGED_MODE) require(hr, "CoInitializeEx"); }
    ~Apartment() { if (SUCCEEDED(hr)) CoUninitialize(); }
};
inline std::string utf8(const wchar_t* value) {
    if (!value || !*value) return {};
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, nullptr, 0, nullptr, nullptr);
    if (!count) throw std::runtime_error("invalid UTF-16");
    std::string result(static_cast<std::size_t>(count), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, result.data(), count, nullptr, nullptr))
        throw std::runtime_error("UTF-16 conversion failed");
    result.pop_back();
    return result;
}
inline std::wstring wide(const std::string& value) {
    if (value.empty()) return {};
    const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (!count) throw std::runtime_error("invalid UTF-8");
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count))
        throw std::runtime_error("UTF-8 conversion failed");
    return result;
}
template<class Getter> std::string string_value(Getter get) {
    LPWSTR value = nullptr;
    const auto hr = get(&value);
    struct Free { LPWSTR p; ~Free() { CoTaskMemFree(p); } } free{value};
    require(hr, "Appx string property");
    return utf8(value);
}
template<class E, class F> void each(E* items, F visit) {
    BOOL more = FALSE;
    require(items->GetHasCurrent(&more), "GetHasCurrent");
    unsigned count = 0;
    while (more) {
        if (++count > 256) throw std::runtime_error("Appx collection exceeds 256 entries");
        visit(items);
        require(items->MoveNext(&more), "MoveNext");
    }
}
} // namespace xboxone::appmodel::windows
#endif
