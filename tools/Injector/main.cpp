#include <Windows.h>

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        std::wcerr << L"Usage: Injector.exe <pid> <full-dll-path>\n";
        return 1;
    }

    const DWORD pid = std::wcstoul(argv[1], nullptr, 10);
    const std::wstring dllPath = argv[2];
    if (!std::filesystem::exists(dllPath)) {
        std::wcerr << L"DLL not found: " << dllPath << L"\n";
        return 1;
    }

    const HANDLE process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid);
    if (process == nullptr) {
        std::wcerr << L"OpenProcess failed: " << GetLastError() << L"\n";
        return 1;
    }

    const auto allocationSize = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remoteBuffer = VirtualAllocEx(process, nullptr, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteBuffer == nullptr) {
        std::wcerr << L"VirtualAllocEx failed: " << GetLastError() << L"\n";
        CloseHandle(process);
        return 1;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(process, remoteBuffer, dllPath.c_str(), allocationSize, &bytesWritten)) {
        std::wcerr << L"WriteProcessMemory failed: " << GetLastError() << L"\n";
        VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    const HMODULE kernel32 = GetModuleHandleW(L"Kernel32.dll");
    const auto loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryW"));
    const HANDLE thread = CreateRemoteThread(process, nullptr, 0, loadLibrary, remoteBuffer, 0, nullptr);
    if (thread == nullptr) {
        std::wcerr << L"CreateRemoteThread failed: " << GetLastError() << L"\n";
        VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    WaitForSingleObject(thread, INFINITE);

    DWORD remoteThreadExitCode = 0;
    GetExitCodeThread(thread, &remoteThreadExitCode);
    std::wcout << L"Injected DLL into PID " << pid << L". LoadLibraryW thread exit code: 0x"
               << std::hex << remoteThreadExitCode << L"\n";

    CloseHandle(thread);
    VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(process);
    return 0;
}
