#include <Windows.h>

#include "DebuggerService.h"

BOOL APIENTRY DllMain(HMODULE moduleHandle, DWORD reason, LPVOID) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(moduleHandle);
            idmcp::DebuggerService::Instance().Start(moduleHandle);
            break;
        case DLL_PROCESS_DETACH:
            idmcp::DebuggerService::Instance().OnProcessDetach();
            break;
        default:
            break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) DWORD WINAPI InternalDebuggerRequestUnload(void*) {
    return idmcp::DebuggerService::Instance().RequestUnload() ? ERROR_SUCCESS : GetLastError();
}
