#include <Windows.h>

#include "DebuggerService.h"

BOOL APIENTRY DllMain(HMODULE moduleHandle, DWORD reason, LPVOID) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(moduleHandle);
            idmcp::DebuggerService::Instance().Start(moduleHandle);
            break;
        case DLL_PROCESS_DETACH:
            idmcp::DebuggerService::Instance().Stop();
            break;
        default:
            break;
    }
    return TRUE;
}
