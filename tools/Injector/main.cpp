#include <Windows.h>

#include <TlHelp32.h>

#include <cstdlib>
#include <cwctype>
#include <filesystem>
#include <iostream>
#include <string>

namespace {

constexpr DWORD kProcessAccess =
    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
constexpr DWORD kUnloadWaitTimeoutMs = 10000;
constexpr int kExitModuleNotFound = 3;
constexpr int kExitExportNotFound = 4;
constexpr int kExitRemoteThreadFailed = 5;
constexpr int kExitUnloadTimeout = 6;
constexpr char kUnloadExportName[] = "InternalDebuggerRequestUnload";

struct RemoteModule {
    std::wstring name;
    std::wstring path;
    std::uintptr_t baseAddress{0};
};

std::wstring ToLower(std::wstring value) {
    for (auto& ch : value) {
        ch = static_cast<wchar_t>(std::towlower(ch));
    }
    return value;
}

std::wstring BaseName(const std::wstring& path) {
    return std::filesystem::path(path).filename().wstring();
}

bool MatchesModule(const RemoteModule& module, const std::wstring& requestedPath) {
    const auto requestedLower = ToLower(requestedPath);
    const auto requestedBaseLower = ToLower(BaseName(requestedPath));
    return ToLower(module.path) == requestedLower || ToLower(module.name) == requestedBaseLower;
}

bool TryFindRemoteModule(const DWORD pid, const std::wstring& requestedPath, RemoteModule& module) {
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }

    do {
        RemoteModule candidate{
            .name = entry.szModule,
            .path = entry.szExePath,
            .baseAddress = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr),
        };
        if (MatchesModule(candidate, requestedPath)) {
            module = std::move(candidate);
            CloseHandle(snapshot);
            return true;
        }
    } while (Module32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return false;
}

std::uintptr_t ResolveRemoteExportAddress(const std::wstring& modulePath, const std::uintptr_t remoteBaseAddress) {
    const HMODULE localModule = LoadLibraryExW(modulePath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (localModule == nullptr) {
        return 0;
    }

    const FARPROC localProcedure = GetProcAddress(localModule, kUnloadExportName);
    if (localProcedure == nullptr) {
        FreeLibrary(localModule);
        return 0;
    }

    const auto offset = reinterpret_cast<std::uintptr_t>(localProcedure) - reinterpret_cast<std::uintptr_t>(localModule);
    FreeLibrary(localModule);
    return remoteBaseAddress + offset;
}

bool WaitForModuleUnload(const DWORD pid, const std::wstring& requestedPath, const DWORD timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    RemoteModule module;
    while (GetTickCount64() < deadline) {
        if (!TryFindRemoteModule(pid, requestedPath, module)) {
            return true;
        }
        Sleep(100);
    }

    return !TryFindRemoteModule(pid, requestedPath, module);
}

int InjectDll(const DWORD pid, const std::wstring& dllPath) {
    if (!std::filesystem::exists(dllPath)) {
        std::wcerr << L"DLL not found: " << dllPath << L"\n";
        return 1;
    }

    const HANDLE process = OpenProcess(kProcessAccess, FALSE, pid);
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

int EjectDll(const DWORD pid, const std::wstring& requestedPath) {
    const HANDLE process = OpenProcess(kProcessAccess, FALSE, pid);
    if (process == nullptr) {
        std::wcerr << L"OpenProcess failed: " << GetLastError() << L"\n";
        return 1;
    }

    RemoteModule module;
    if (!TryFindRemoteModule(pid, requestedPath, module)) {
        std::wcerr << L"Debugger DLL not loaded in PID " << pid << L": " << requestedPath << L"\n";
        CloseHandle(process);
        return kExitModuleNotFound;
    }

    const auto unloadAddress = ResolveRemoteExportAddress(module.path, module.baseAddress);
    if (unloadAddress == 0) {
        std::wcerr << L"Unload export not found in " << module.path << L"\n";
        CloseHandle(process);
        return kExitExportNotFound;
    }

    const HANDLE thread = CreateRemoteThread(
        process,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(unloadAddress),
        nullptr,
        0,
        nullptr);
    if (thread == nullptr) {
        std::wcerr << L"CreateRemoteThread failed: " << GetLastError() << L"\n";
        CloseHandle(process);
        return kExitRemoteThreadFailed;
    }

    WaitForSingleObject(thread, INFINITE);

    DWORD remoteThreadExitCode = 0;
    GetExitCodeThread(thread, &remoteThreadExitCode);
    CloseHandle(thread);

    if (remoteThreadExitCode != ERROR_SUCCESS && remoteThreadExitCode != ERROR_ALREADY_EXISTS) {
        std::wcerr << L"Unload request failed. Thread exit code: " << remoteThreadExitCode << L"\n";
        CloseHandle(process);
        return kExitRemoteThreadFailed;
    }

    const bool unloaded = WaitForModuleUnload(pid, requestedPath, kUnloadWaitTimeoutMs);
    CloseHandle(process);
    if (!unloaded) {
        std::wcerr << L"Timed out waiting for DLL unload in PID " << pid << L": " << requestedPath << L"\n";
        return kExitUnloadTimeout;
    }

    std::wcout << L"Ejected DLL from PID " << pid << L": " << module.path << L"\n";
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
    if (argc == 4 && std::wstring_view(argv[1]) == L"--eject") {
        const DWORD pid = std::wcstoul(argv[2], nullptr, 10);
        return EjectDll(pid, argv[3]);
    }

    if (argc != 3) {
        std::wcerr << L"Usage: Injector.exe <pid> <full-dll-path>\n";
        std::wcerr << L"   or: Injector.exe --eject <pid> <dll-path-or-name>\n";
        return 1;
    }

    const DWORD pid = std::wcstoul(argv[1], nullptr, 10);
    return InjectDll(pid, argv[2]);
}
