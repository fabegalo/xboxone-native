// SPDX-License-Identifier: BSD-3-Clause
// Owned synthetic Win32 PE. No CRT, Xbox code, graphics, disk writes or assets.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static DWORD WINAPI exercise_memory(void* memory) {
    auto* words = static_cast<volatile DWORD*>(memory);
    for (DWORD i = 0; i < 1024; ++i) words[i] = i ^ 0x51a7b007U;
    return 37;
}

extern "C" void bootstrap_test_entry() {
#ifdef BOOTSTRAP_TEST_HANG
    Sleep(INFINITE);
    ExitProcess(99);
#elif defined(BOOTSTRAP_TEST_FAIL)
    ExitProcess(27);
#else
    auto* memory = VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!memory) ExitProcess(10);
    auto thread = CreateThread(nullptr, 0, exercise_memory, memory, 0, nullptr);
    if (!thread) ExitProcess(11);
    if (WaitForSingleObject(thread, 2000) != WAIT_OBJECT_0) ExitProcess(12);
    DWORD result = 0;
    if (!GetExitCodeThread(thread, &result) || result != 37) ExitProcess(13);
    const auto* words = static_cast<volatile DWORD*>(memory);
    for (DWORD i = 0; i < 1024; ++i) if (words[i] != (i ^ 0x51a7b007U)) ExitProcess(14);
    DWORD old = 0;
    if (!VirtualProtect(memory, 4096, PAGE_READONLY, &old)) ExitProcess(15);
    if (!CloseHandle(thread) || !VirtualFree(memory, 0, MEM_RELEASE)) ExitProcess(16);
    ExitProcess(0); // Only after real memory, thread and import calls succeeded.
#endif
}
