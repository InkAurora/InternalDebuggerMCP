#include "DebuggerService.h"

#include <Windows.h>
#include <Psapi.h>

#include <chrono>
#include <format>
#include <sstream>

#include "DebuggerProtocol.h"

namespace idmcp {

namespace {

[[nodiscard]] std::string Join(const std::vector<std::string>& items, const std::string_view separator) {
    std::ostringstream stream;
    for (std::size_t index = 0; index < items.size(); ++index) {
        if (index != 0) {
            stream << separator;
        }
        stream << items[index];
    }
    return stream.str();
}

[[nodiscard]] std::string HexOrEmpty(const std::vector<std::uint8_t>& bytes) {
    return bytes.empty() ? std::string{} : HexEncode(bytes);
}

}  // namespace

DebuggerService& DebuggerService::Instance() {
    static DebuggerService instance;
    return instance;
}

DebuggerService::DebuggerService()
    : patternScanner_(memoryReader_), watchManager_(memoryReader_) {}

DebuggerService::~DebuggerService() {
    Stop();
}

void DebuggerService::Start(HMODULE moduleHandle) {
    moduleHandle_ = moduleHandle;
    if (bootstrapThread_ != nullptr || bootstrapped_.load()) {
        return;
    }
    stopRequested_.store(false);
    bootstrapThread_ = CreateThread(nullptr, 0, &DebuggerService::BootstrapThreadProc, this, 0, nullptr);
}

void DebuggerService::Stop() {
    stopRequested_.store(true);

    if (ipcServer_) {
        ipcServer_->Stop();
        ipcServer_.reset();
    }
    watchManager_.Stop();

    if (bootstrapThread_ != nullptr) {
        WaitForSingleObject(bootstrapThread_, 2000);
        CloseHandle(bootstrapThread_);
        bootstrapThread_ = nullptr;
    }

    bootstrapped_.store(false);
}

DWORD WINAPI DebuggerService::BootstrapThreadProc(LPVOID context) {
    static_cast<DebuggerService*>(context)->Bootstrap();
    return 0;
}

void DebuggerService::Bootstrap() {
    pipeName_ = std::format("{}{}", kPipePrefix, GetCurrentProcessId());
    watchManager_.Start();
    ipcServer_ = std::make_unique<IpcServer>(pipeName_, [this](const std::string& request) {
        return Dispatch(request);
    });
    ipcServer_->Start();
    bootstrapped_.store(true);

    while (!stopRequested_.load()) {
        Sleep(100);
    }
}

std::string DebuggerService::Dispatch(const std::string& request) {
    const auto message = ParseMessage(request);
    const auto command = message.GetFirst("command");
    if (!command.has_value()) {
        return MakeError("missing_command", "command field is required");
    }

    if (*command == "ping") {
        return HandlePing();
    }
    if (*command == "read_memory") {
        return HandleReadMemory(message);
    }
    if (*command == "dereference") {
        return HandleDereference(message);
    }
    if (*command == "list_modules") {
        return HandleListModules();
    }
    if (*command == "pattern_scan") {
        return HandlePatternScan(message);
    }
    if (*command == "watch_address") {
        return HandleWatchAddress(message);
    }
    if (*command == "unwatch_address") {
        return HandleUnwatchAddress(message);
    }
    if (*command == "poll_watch_events") {
        return HandlePollWatchEvents(message);
    }
    if (*command == "disassemble") {
        return HandleDisassemble(message);
    }
    if (*command == "registers") {
        return HandleRegisters();
    }

    return MakeError("unknown_command", *command);
}

std::string DebuggerService::HandlePing() const {
    return MakeOk({
        {"pid", std::to_string(GetCurrentProcessId())},
        {"pipe_name", pipeName_},
        {"watch_count", std::to_string(watchManager_.WatchCount())},
    });
}

std::string DebuggerService::HandleReadMemory(const ParsedMessage& message) const {
    const auto address = ParseAddress(message.GetFirst("address").value_or(""));
    const auto size = ParseUnsigned(message.GetFirst("size").value_or(""));
    if (!address.has_value() || !size.has_value()) {
        return MakeError("invalid_arguments", "address and size are required");
    }
    if (*size == 0 || *size > kMaxReadSize) {
        return MakeError("invalid_size", "size exceeds maximum read limit");
    }

    std::vector<std::uint8_t> bytes;
    if (!memoryReader_.ReadBytes(*address, static_cast<std::size_t>(*size), bytes)) {
        return MakeError("memory_read_failed", "unable to read requested range");
    }

    return MakeOk({
        {"address", ToHex(*address)},
        {"size", std::to_string(*size)},
        {"bytes", HexEncode(bytes)},
    });
}

std::string DebuggerService::HandleDereference(const ParsedMessage& message) const {
    const auto address = ParseAddress(message.GetFirst("address").value_or(""));
    const auto depth = ParseUnsigned(message.GetFirst("depth").value_or("3"));
    const auto pointerSize = ParseUnsigned(message.GetFirst("pointer_size").value_or(std::to_string(sizeof(void*))));
    if (!address.has_value() || !depth.has_value() || !pointerSize.has_value()) {
        return MakeError("invalid_arguments", "address, depth, and pointer_size are required");
    }
    if (*depth == 0 || *depth > 8) {
        return MakeError("invalid_depth", "depth must be between 1 and 8");
    }

    const auto steps = memoryReader_.DereferenceChain(
        *address,
        static_cast<std::size_t>(*depth),
        static_cast<std::size_t>(*pointerSize));

    std::vector<MessageField> fields{{"start_address", ToHex(*address)}};
    for (const auto& step : steps) {
        fields.emplace_back(
            "step",
            std::format("{}|{}|{}", ToHex(step.address), ToHex(step.value), step.success ? "ok" : "error"));
    }
    return MakeOk(std::move(fields));
}

std::string DebuggerService::HandleListModules() const {
    HMODULE modules[1024]{};
    DWORD bytesNeeded = 0;
    if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &bytesNeeded)) {
        return MakeError("module_enum_failed", "EnumProcessModules failed");
    }

    const auto count = bytesNeeded / sizeof(HMODULE);
    std::vector<MessageField> fields{{"module_count", std::to_string(count)}};
    for (DWORD index = 0; index < count; ++index) {
        MODULEINFO moduleInfo{};
        char modulePath[MAX_PATH]{};
        if (!GetModuleInformation(GetCurrentProcess(), modules[index], &moduleInfo, sizeof(moduleInfo))) {
            continue;
        }
        GetModuleFileNameExA(GetCurrentProcess(), modules[index], modulePath, MAX_PATH);
        std::string moduleName = modulePath;
        const auto lastSlash = moduleName.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            moduleName = moduleName.substr(lastSlash + 1);
        }

        fields.emplace_back(
            "module",
            std::format(
                "{}|{}|{}|{}",
                moduleName,
                ToHex(reinterpret_cast<std::uintptr_t>(moduleInfo.lpBaseOfDll)),
                moduleInfo.SizeOfImage,
                modulePath));
    }
    return MakeOk(std::move(fields));
}

std::string DebuggerService::HandlePatternScan(const ParsedMessage& message) const {
    const auto patternText = message.GetFirst("pattern");
    if (!patternText.has_value()) {
        return MakeError("invalid_arguments", "pattern is required");
    }

    std::vector<PatternByte> pattern;
    if (!patternScanner_.ParsePattern(*patternText, pattern)) {
        return MakeError("invalid_pattern", "pattern must be space-separated hex bytes or ?? wildcards");
    }

    const auto start = ParseAddress(message.GetFirst("start").value_or(""));
    const auto size = ParseUnsigned(message.GetFirst("size").value_or(""));
    const auto limit = ParseUnsigned(message.GetFirst("limit").value_or(std::to_string(kMaxPatternResults)));
    const auto matches = patternScanner_.Scan(
        pattern,
        start,
        size.has_value() ? std::optional<std::size_t>(static_cast<std::size_t>(*size)) : std::nullopt,
        static_cast<std::size_t>(std::min<std::uint64_t>(limit.value_or(kMaxPatternResults), kMaxPatternResults)));

    std::vector<MessageField> fields{{"match_count", std::to_string(matches.size())}};
    for (const auto match : matches) {
        fields.emplace_back("match", ToHex(match));
    }
    return MakeOk(std::move(fields));
}

std::string DebuggerService::HandleWatchAddress(const ParsedMessage& message) {
    const auto address = ParseAddress(message.GetFirst("address").value_or(""));
    const auto size = ParseUnsigned(message.GetFirst("size").value_or(""));
    const auto intervalMs = ParseUnsigned(message.GetFirst("interval_ms").value_or("250"));
    if (!address.has_value() || !size.has_value()) {
        return MakeError("invalid_arguments", "address and size are required");
    }

    const auto providedId = message.GetFirst("watch_id");
    const auto watchId = providedId.value_or(MakeWatchId(*address));
    std::string error;
    if (!watchManager_.AddWatch(
            watchId,
            *address,
            static_cast<std::size_t>(*size),
            static_cast<std::uint32_t>(intervalMs.value_or(250)),
            error)) {
        return MakeError(error, "unable to arm watch");
    }

    return MakeOk({
        {"watch_id", watchId},
        {"address", ToHex(*address)},
        {"size", std::to_string(*size)},
    });
}

std::string DebuggerService::HandleUnwatchAddress(const ParsedMessage& message) {
    const auto watchId = message.GetFirst("watch_id");
    if (!watchId.has_value()) {
        return MakeError("invalid_arguments", "watch_id is required");
    }
    if (!watchManager_.RemoveWatch(*watchId)) {
        return MakeError("watch_not_found", *watchId);
    }
    return MakeOk({{"watch_id", *watchId}});
}

std::string DebuggerService::HandlePollWatchEvents(const ParsedMessage& message) {
    const auto limit = ParseUnsigned(message.GetFirst("limit").value_or(std::to_string(kDefaultPollLimit)));
    const auto events = watchManager_.DrainEvents(static_cast<std::size_t>(limit.value_or(kDefaultPollLimit)));

    std::vector<MessageField> fields{{"event_count", std::to_string(events.size())}};
    for (const auto& event : events) {
        fields.emplace_back(
            "event",
            std::format(
                "{}|{}|{}|{}|{}",
                event.watchId,
                ToHex(event.address),
                HexOrEmpty(event.oldValue),
                HexOrEmpty(event.newValue),
                event.timestampMs));
    }
    return MakeOk(std::move(fields));
}

std::string DebuggerService::HandleDisassemble(const ParsedMessage& message) const {
    const auto address = ParseAddress(message.GetFirst("address").value_or(""));
    const auto size = ParseUnsigned(message.GetFirst("size").value_or("64"));
    const auto maxInstructions = ParseUnsigned(message.GetFirst("max_instructions").value_or("16"));
    if (!address.has_value() || !size.has_value()) {
        return MakeError("invalid_arguments", "address and size are required");
    }

    std::vector<std::uint8_t> bytes;
    if (!memoryReader_.ReadBytes(*address, static_cast<std::size_t>(*size), bytes)) {
        return MakeError("memory_read_failed", "unable to read instruction bytes");
    }

    const auto instructions = disassembler_.Disassemble(
        *address,
        bytes,
        static_cast<std::size_t>(maxInstructions.value_or(16)));

    std::vector<MessageField> fields{{"instruction_count", std::to_string(instructions.size())}};
    for (const auto& instruction : instructions) {
        fields.emplace_back(
            "instruction",
            std::format(
                "{}|{}|{}|{}",
                ToHex(instruction.address),
                HexEncode(instruction.bytes),
                instruction.mnemonic,
                instruction.operands));
    }
    return MakeOk(std::move(fields));
}

std::string DebuggerService::HandleRegisters() const {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_ALL;
    RtlCaptureContext(&context);

    return MakeOk({
        {"mode", "current_thread_only"},
        {"register", std::format("rip|{}", ToHex(context.Rip))},
        {"register", std::format("rsp|{}", ToHex(context.Rsp))},
        {"register", std::format("rbp|{}", ToHex(context.Rbp))},
        {"register", std::format("rax|{}", ToHex(context.Rax))},
        {"register", std::format("rbx|{}", ToHex(context.Rbx))},
        {"register", std::format("rcx|{}", ToHex(context.Rcx))},
        {"register", std::format("rdx|{}", ToHex(context.Rdx))},
    });
}

std::string DebuggerService::MakeError(const std::string& code, const std::string& detail) {
    return BuildMessage({
        {"status", "error"},
        {"code", code},
        {"detail", detail},
    });
}

std::string DebuggerService::MakeOk(std::vector<MessageField> fields) {
    fields.insert(fields.begin(), {"status", "ok"});
    return BuildMessage(fields);
}

std::string DebuggerService::MakeWatchId(const std::uintptr_t address) {
    const auto stamp = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    return std::format("watch_{:X}_{}", address, stamp);
}

}  // namespace idmcp
