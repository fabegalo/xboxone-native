// SPDX-License-Identifier: BSD-3-Clause
// Opt-in host diagnostic; never loads or executes code from the mounted image.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <appmodel.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring(argv[1]) == L"--help") {
        std::cout << "XVD host diagnostic: --diagnose|--mount-readonly|--unmount-owned <provider> <image> <log>\n"
                     "Use tools/probe_xvd_readonly.ps1 for the installed Gaming Services context.\n";
        return 0;
    }
    if (argc != 4 && argc != 5) return 2;
    struct Output {
        std::ofstream file;
        std::streambuf* previous = nullptr;
        ~Output() { std::cout << "probe_completed=1" << std::endl; if (previous) std::cout.rdbuf(previous); }
    } output;
    if (argc == 5) {
        output.file.open(std::filesystem::path(argv[4]));
        if (!output.file) return 2;
        output.previous = std::cout.rdbuf(output.file.rdbuf());
        std::cout << std::unitbuf;
    }
    HANDLE token = nullptr;
    TOKEN_ELEVATION elevation{};
    DWORD bytes = 0;
    bool identity = false;
    DWORD app_container = 0;
    bool restricted = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        identity = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &bytes) != FALSE;
        GetTokenInformation(token, TokenIsAppContainer, &app_container, sizeof(app_container), &bytes);
        restricted = IsTokenRestricted(token) != FALSE;
        CloseHandle(token);
    }
    std::cout << "identity_query_ok=" << identity << "; elevated=" << elevation.TokenIsElevated << std::endl;
    std::cout << "app_container=" << app_container << std::endl;
    std::cout << "restricted_token=" << restricted << std::endl;
    UINT32 package_length = 0;
    const LONG package_status = GetCurrentPackageFullName(&package_length, nullptr);
    std::cout << "package_identity_status=" << package_status << std::endl;
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature{};
    const bool signature_known = GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy, &signature, sizeof(signature)) != FALSE;
    std::cout << "signature_policy_known=" << signature_known << "; microsoft_signed_only=" << signature.MicrosoftSignedOnly
              << "; store_signed_only=" << signature.StoreSignedOnly << std::endl;
    const bool cleanup = std::wstring(argv[1]) == L"--unmount-owned";
    const bool diagnose = std::wstring(argv[1]) == L"--diagnose";
    if (!cleanup && !diagnose && std::wstring(argv[1]) != L"--mount-readonly") return 2;
    if (!diagnose) {
        wchar_t family[256]{};
        UINT32 length = 256;
        if (GetCurrentPackageFamilyName(&length, family) != ERROR_SUCCESS ||
            std::wstring(family) != L"Microsoft.GamingServices_8wekyb3d8bbwe") {
            std::cout << "refused=gaming_services_package_context_required" << std::endl;
            return 2;
        }
    }
    for (DWORD access : {DWORD{GENERIC_READ}, DWORD{GENERIC_EXECUTE}}) {
        HANDLE file = CreateFileW(argv[2], access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        const DWORD error = file == INVALID_HANDLE_VALUE ? GetLastError() : 0;
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        std::cout << (access == GENERIC_READ ? "provider_read_win32=" : "provider_execute_win32=") << error << std::endl;
    }
    // A fixed, currently unused letter keeps the attempt separate from existing disks.
    constexpr wchar_t drive[] = L"Q:\\";
    if (!cleanup && !diagnose && GetDriveTypeW(drive) != DRIVE_NO_ROOT_DIR) {
        std::cout << "refused: Q: is already in use\n";
        return 2;
    }
    HMODULE provider = LoadLibraryExW(argv[2], nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!provider) { std::cout << "provider_load_win32=" << GetLastError() << '\n'; return 1; }
    std::cout << "provider_loaded=1" << std::endl;
    if (diagnose) { FreeLibrary(provider); return 0; }
    using Open = DWORD(WINAPI*)(HANDLE*);
    using Close = DWORD(WINAPI*)(HANDLE);
    using Mount = DWORD(WINAPI*)(HANDLE*, int*, HANDLE, const wchar_t*, LONGLONG, const wchar_t*, int);
    using Unmount = DWORD(WINAPI*)(HANDLE, const wchar_t*);
    const auto open = reinterpret_cast<Open>(GetProcAddress(provider, "XvdOpenAdapter"));
    const auto close = reinterpret_cast<Close>(GetProcAddress(provider, "XvdCloseAdapter"));
    const auto mount = reinterpret_cast<Mount>(GetProcAddress(provider, "XvdMount"));
    const auto unmount = reinterpret_cast<Unmount>(GetProcAddress(provider, "XvdUnmountFile"));
    if (!open || !close || !mount || !unmount) { FreeLibrary(provider); return 2; }
    HANDLE adapter = nullptr;
    const DWORD opened = open(&adapter);
    std::cout << "open_adapter=0x" << std::hex << opened << std::endl;
    std::cout << "adapter_handle_valid=" << (adapter && adapter != INVALID_HANDLE_VALUE) << std::endl;
    if (opened != ERROR_SUCCESS || !adapter || adapter == INVALID_HANDLE_VALUE) { FreeLibrary(provider); return 1; }
    if (cleanup) {
        const DWORD status = unmount(adapter, argv[3]);
        std::cout << "cleanup_unmount=0x" << std::hex << status << std::endl;
        close(adapter);
        FreeLibrary(provider);
        std::cout << "drive_removed=" << (GetDriveTypeW(drive) == DRIVE_NO_ROOT_DIR) << std::endl;
        return status == 0 ? 0 : 1;
    }
    HANDLE disk = nullptr;
    int number = -1;
    std::cout << "mount_started=1" << std::endl;
    const DWORD mounted = mount(&disk, &number, adapter, argv[3], 0, L"Q:", 1); // ReadOnly flag.
    std::cout << "mount_readonly=0x" << std::hex << mounted << "; disk=" << std::dec << number << std::endl;
    DWORD detached = 0;
    bool readable = false;
    if (mounted == 0) {
        WIN32_FIND_DATAW entry{};
        HANDLE listing = FindFirstFileW(L"Q:\\*", &entry);
        readable = listing != INVALID_HANDLE_VALUE;
        std::cout << "root_readable=" << readable << std::endl;
        if (listing != INVALID_HANDLE_VALUE) FindClose(listing);
        detached = unmount(adapter, argv[3]);
        std::cout << "unmount=0x" << std::hex << detached << std::endl;
    }
    if (disk && disk != INVALID_HANDLE_VALUE) CloseHandle(disk);
    const DWORD closed = close(adapter);
    std::cout << "close_adapter=0x" << std::hex << closed << std::endl;
    FreeLibrary(provider);
    const bool removed = GetDriveTypeW(drive) == DRIVE_NO_ROOT_DIR;
    std::cout << "drive_removed=" << removed << std::endl;
    return mounted == 0 && readable && detached == 0 && removed ? 0 : 1;
}
