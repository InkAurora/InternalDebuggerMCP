#pragma once

#include <Windows.h>

#include <atomic>
#include <memory>
#include <string>

#include "DebuggerProtocol.h"
#include "Disassembler.h"
#include "IpcServer.h"
#include "MemoryReader.h"
#include "PatternScanner.h"
#include "WatchManager.h"

namespace idmcp {

class DebuggerService {
public:
    static DebuggerService& Instance();

    void Start(HMODULE moduleHandle);
    void Stop();
    [[nodiscard]] std::string Dispatch(const std::string& request);

private:
    DebuggerService();
    ~DebuggerService();

    static DWORD WINAPI BootstrapThreadProc(LPVOID context);
    void Bootstrap();
    [[nodiscard]] std::string HandlePing() const;
    [[nodiscard]] std::string HandleReadMemory(const ParsedMessage& message) const;
    [[nodiscard]] std::string HandleDereference(const ParsedMessage& message) const;
    [[nodiscard]] std::string HandleListModules() const;
    [[nodiscard]] std::string HandlePatternScan(const ParsedMessage& message) const;
    [[nodiscard]] std::string HandleWatchAddress(const ParsedMessage& message);
    [[nodiscard]] std::string HandleUnwatchAddress(const ParsedMessage& message);
    [[nodiscard]] std::string HandlePollWatchEvents(const ParsedMessage& message);
    [[nodiscard]] std::string HandleDisassemble(const ParsedMessage& message) const;
    [[nodiscard]] std::string HandleRegisters() const;

    [[nodiscard]] static std::string MakeError(const std::string& code, const std::string& detail);
    [[nodiscard]] static std::string MakeOk(std::vector<MessageField> fields);
    [[nodiscard]] static std::string MakeWatchId(std::uintptr_t address);

    HMODULE moduleHandle_{nullptr};
    std::atomic<bool> bootstrapped_{false};
    std::atomic<bool> stopRequested_{false};
    HANDLE bootstrapThread_{nullptr};
    std::string pipeName_;
    MemoryReader memoryReader_;
    PatternScanner patternScanner_;
    WatchManager watchManager_;
    Disassembler disassembler_;
    std::unique_ptr<IpcServer> ipcServer_;
};

}  // namespace idmcp
