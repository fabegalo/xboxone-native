// SPDX-License-Identifier: BSD-3-Clause
// Owned native-loader fixture. No CRT, Xbox code, graphics or content writes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern "C" {
unsigned long _tls_index = 0;
#pragma section(".tls", read, write)
#pragma section(".tls$ZZZ", read, write)
__declspec(allocate(".tls")) char tls_start = 0;
__declspec(thread) volatile DWORD tls_value = 0x51a7b007;
__declspec(thread) volatile DWORD tls_zero = 0;
__declspec(allocate(".tls$ZZZ")) char tls_end = 0;
}
static volatile LONG process_attach = 0, thread_attach = 0, thread_detach = 0, callback_error = 0;

static void NTAPI on_tls(void*, DWORD reason, void*) {
    if (reason == DLL_PROCESS_ATTACH || reason == DLL_THREAD_ATTACH) {
        if (tls_value != 0x51a7b007 || tls_zero != 0) InterlockedExchange(&callback_error, 1);
        tls_value = 37;
        if (reason == DLL_PROCESS_ATTACH) InterlockedIncrement(&process_attach);
        else InterlockedIncrement(&thread_attach);
    } else if (reason == DLL_THREAD_DETACH) {
        if (tls_value != 99 || tls_zero != 19) InterlockedExchange(&callback_error, 2);
        InterlockedIncrement(&thread_detach);
    }
}

static const PIMAGE_TLS_CALLBACK callbacks[] = {on_tls, nullptr};
extern "C" const IMAGE_TLS_DIRECTORY64 _tls_used = {
    reinterpret_cast<ULONGLONG>(&tls_start), reinterpret_cast<ULONGLONG>(&tls_end),
    reinterpret_cast<ULONGLONG>(&_tls_index), reinterpret_cast<ULONGLONG>(callbacks), 0, 0
};

static DWORD WINAPI worker(void*) {
    if (tls_value != 37 || tls_zero != 0) return 10;
    tls_value = 99;
    tls_zero = 19;
    return 0;
}

extern "C" void bootstrap_tls_entry() {
    if (process_attach != 1 || callback_error || tls_value != 37 || tls_zero != 0) ExitProcess(20);
    tls_value = 123;
    tls_zero = 456;
    for (unsigned i = 0; i < 2; ++i) {
        HANDLE thread = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
        if (!thread || WaitForSingleObject(thread, 2000) != WAIT_OBJECT_0) ExitProcess(21);
        DWORD code = 1;
        if (!GetExitCodeThread(thread, &code) || code || !CloseHandle(thread)) ExitProcess(22);
        if (tls_value != 123 || tls_zero != 456 || callback_error ||
            thread_attach != static_cast<LONG>(i + 1) || thread_detach != static_cast<LONG>(i + 1)) ExitProcess(23);
    }
    ExitProcess(0);
}
