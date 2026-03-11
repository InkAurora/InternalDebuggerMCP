#include "DebuggerService.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <format>
#include <optional>
#include <sstream>
#include <string_view>

#include "DebuggerProtocol.h"

namespace idmcp {

namespace {

struct ModuleRecord {
    std::string name;
    std::uintptr_t baseAddress;
    std::uint32_t imageSize;
    std::string path;
};

struct InvokeArgumentState {
    std::uint64_t value{0};
    std::vector<std::uint8_t> storage;
    std::optional<std::pair<std::size_t, std::string>> output;
};

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

[[nodiscard]] std::wstring_view BoundedWideView(const wchar_t* text, const std::size_t capacity) {
    if (text == nullptr || capacity == 0 || *text == L'\0') {
        return {};
    }

    std::size_t length = 0;
    while (length < capacity && text[length] != L'\0') {
        ++length;
    }
    return std::wstring_view(text, length);
}

[[nodiscard]] std::string WideToUtf8(const std::wstring_view text) {
    if (text.empty()) {
        return {};
    }

    const int sourceLength = static_cast<int>(text.size());
    const int required = WideCharToMultiByte(CP_UTF8, 0, text.data(), sourceLength, nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }

    std::string converted(static_cast<std::size_t>(required), '\0');
    const int written = WideCharToMultiByte(CP_UTF8, 0, text.data(), sourceLength, converted.data(), required, nullptr, nullptr);
    if (written <= 0) {
        return {};
    }

    converted.resize(static_cast<std::size_t>(written));
    return converted;
}

[[nodiscard]] std::string DescribeWin32Error(const DWORD error) {
    if (error == ERROR_SUCCESS) {
        return "success";
    }

    LPSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = FormatMessageA(
        flags,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buffer),
        0,
        nullptr);
    if (length == 0 || buffer == nullptr) {
        return std::format("Win32 error {}", error);
    }

    std::string message(buffer, buffer + length);
    LocalFree(buffer);
    while (!message.empty() && (message.back() == '\r' || message.back() == '\n' || message.back() == ' ' || message.back() == '.')) {
        message.pop_back();
    }
    return message;
}

[[nodiscard]] std::string BaseName(std::string_view path) {
    const auto lastSlash = path.find_last_of("\\/");
    if (lastSlash == std::string_view::npos) {
        return std::string(path);
    }
    return std::string(path.substr(lastSlash + 1));
}

[[nodiscard]] bool EqualsIgnoreCase(std::string_view left, std::string_view right) {
    if (left.size() != right.size()) {
        return false;
    }

    for (std::size_t index = 0; index < left.size(); ++index) {
        if (std::tolower(static_cast<unsigned char>(left[index])) !=
            std::tolower(static_cast<unsigned char>(right[index]))) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::vector<ModuleRecord> SnapshotModules() {
    std::vector<ModuleRecord> modules;

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        return modules;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return modules;
    }

    do {
        modules.push_back(ModuleRecord{
            .name = WideToUtf8(BoundedWideView(entry.szModule, std::size(entry.szModule))),
            .baseAddress = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr),
            .imageSize = entry.modBaseSize,
            .path = WideToUtf8(BoundedWideView(entry.szExePath, std::size(entry.szExePath))),
        });
    } while (Module32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return modules;
}

[[nodiscard]] std::optional<ModuleRecord> FindModuleByName(std::string_view requestedName) {
    const auto modules = SnapshotModules();
    for (const auto& module : modules) {
        if (EqualsIgnoreCase(module.name, requestedName) ||
            EqualsIgnoreCase(module.path, requestedName) ||
            EqualsIgnoreCase(BaseName(module.path), requestedName)) {
            return module;
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool ParseInvokeAddress(
    const ParsedMessage& message,
    std::uintptr_t& address,
    std::string& errorDetail) {
    const auto addressText = message.GetFirst("address");
    const auto moduleName = message.GetFirst("module");
    const auto exportName = message.GetFirst("export");

    if (addressText.has_value()) {
        const auto parsed = ParseAddress(*addressText);
        if (!parsed.has_value()) {
            errorDetail = "address must be a valid hexadecimal pointer";
            return false;
        }
        address = *parsed;
        return true;
    }

    if (!moduleName.has_value() || !exportName.has_value()) {
        errorDetail = "either address or module plus export are required";
        return false;
    }

    const auto module = FindModuleByName(*moduleName);
    if (!module.has_value()) {
        errorDetail = std::format("module not loaded: {}", *moduleName);
        return false;
    }

    const FARPROC procedure = GetProcAddress(reinterpret_cast<HMODULE>(module->baseAddress), exportName->c_str());
    if (procedure == nullptr) {
        errorDetail = std::format("export not found: {}!{}", module->name, *exportName);
        return false;
    }

    address = reinterpret_cast<std::uintptr_t>(procedure);
    return true;
}

[[nodiscard]] bool ParseInvokeArguments(
    const ParsedMessage& message,
    std::vector<InvokeArgumentState>& arguments,
    std::string& errorDetail) {
    const auto argCount = ParseUnsigned(message.GetFirst("arg_count").value_or("0"));
    if (!argCount.has_value()) {
        errorDetail = "arg_count must be an unsigned integer";
        return false;
    }
    if (*argCount > kMaxInvokeArguments) {
        errorDetail = std::format("arg_count exceeds maximum of {}", kMaxInvokeArguments);
        return false;
    }

    arguments.clear();
    arguments.reserve(static_cast<std::size_t>(*argCount));
    for (std::size_t index = 0; index < *argCount; ++index) {
        const auto kindKey = std::format("arg{}_kind", index);
        const auto valueKey = std::format("arg{}_value", index);
        const auto sizeKey = std::format("arg{}_size", index);
        const auto kind = message.GetFirst(kindKey);
        if (!kind.has_value()) {
            errorDetail = std::format("{} is required", kindKey);
            return false;
        }

        InvokeArgumentState state;
        if (*kind == "u64") {
            const auto parsed = ParseUnsigned(message.GetFirst(valueKey).value_or(""));
            if (!parsed.has_value()) {
                errorDetail = std::format("{} must be an unsigned integer", valueKey);
                return false;
            }
            state.value = *parsed;
        } else if (*kind == "pointer") {
            const auto parsed = ParseAddress(message.GetFirst(valueKey).value_or(""));
            if (!parsed.has_value()) {
                errorDetail = std::format("{} must be a hexadecimal pointer", valueKey);
                return false;
            }
            state.value = static_cast<std::uint64_t>(*parsed);
        } else if (*kind == "bytes" || *kind == "utf8" || *kind == "utf16" || *kind == "inout_buffer") {
            if (!ParseHexBytes(message.GetFirst(valueKey).value_or(""), state.storage)) {
                errorDetail = std::format("{} must contain space-separated hex bytes", valueKey);
                return false;
            }
            if (state.storage.size() > kMaxInvokeBufferSize) {
                errorDetail = std::format("{} exceeds maximum buffer size", valueKey);
                return false;
            }

            state.value = reinterpret_cast<std::uint64_t>(state.storage.data());
            if (*kind == "inout_buffer") {
                state.output = std::make_pair(index, *kind);
            }
            arguments.push_back(std::move(state));
            continue;
        } else if (*kind == "out_buffer") {
            const auto parsedSize = ParseUnsigned(message.GetFirst(sizeKey).value_or(""));
            if (!parsedSize.has_value() || *parsedSize == 0 || *parsedSize > kMaxInvokeBufferSize) {
                errorDetail = std::format("{} must be between 1 and {}", sizeKey, kMaxInvokeBufferSize);
                return false;
            }

            state.storage = std::vector<std::uint8_t>(static_cast<std::size_t>(*parsedSize), 0);
            state.value = reinterpret_cast<std::uint64_t>(state.storage.data());
            state.output = std::make_pair(index, *kind);
        } else {
            errorDetail = std::format("unsupported argument kind: {}", *kind);
            return false;
        }

        arguments.push_back(std::move(state));
    }

    return true;
}

[[nodiscard]] bool InvokeFunction(
    const std::uintptr_t address,
    const std::vector<InvokeArgumentState>& arguments,
    std::uint64_t& returnValue,
    DWORD& lastError,
    DWORD& exceptionCode) {
    returnValue = 0;
    lastError = 0;
    exceptionCode = 0;

    SetLastError(ERROR_SUCCESS);
    __try {
        switch (arguments.size()) {
        case 0: {
            using Fn = std::uint64_t(*)();
            returnValue = reinterpret_cast<Fn>(address)();
            break;
        }
        case 1: {
            using Fn = std::uint64_t(*)(std::uint64_t);
            returnValue = reinterpret_cast<Fn>(address)(arguments[0].value);
            break;
        }
        case 2: {
            using Fn = std::uint64_t(*)(std::uint64_t, std::uint64_t);
            returnValue = reinterpret_cast<Fn>(address)(arguments[0].value, arguments[1].value);
            break;
        }
        case 3: {
            using Fn = std::uint64_t(*)(std::uint64_t, std::uint64_t, std::uint64_t);
            returnValue = reinterpret_cast<Fn>(address)(arguments[0].value, arguments[1].value, arguments[2].value);
            break;
        }
        case 4: {
            using Fn = std::uint64_t(*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
            returnValue = reinterpret_cast<Fn>(address)(arguments[0].value, arguments[1].value, arguments[2].value, arguments[3].value);
            break;
        }
        case 5: {
            using Fn = std::uint64_t(*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
            returnValue = reinterpret_cast<Fn>(address)(arguments[0].value, arguments[1].value, arguments[2].value, arguments[3].value, arguments[4].value);
            break;
        }
        case 6: {
            using Fn = std::uint64_t(*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
            returnValue = reinterpret_cast<Fn>(address)(arguments[0].value, arguments[1].value, arguments[2].value, arguments[3].value, arguments[4].value, arguments[5].value);
            break;
        }
        default:
            return false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        exceptionCode = GetExceptionCode();
        return false;
    }

    lastError = GetLastError();
    return true;
}

}  // namespace

DebuggerService& DebuggerService::Instance() {
    static DebuggerService instance;
    return instance;
}

DebuggerService::DebuggerService()
    : patternScanner_(memoryReader_),
      watchManager_(memoryReader_),
      patternGenerator_(memoryReader_, patternScanner_, disassembler_),
      accessWatchManager_(memoryReader_, disassembler_) {}

DebuggerService::~DebuggerService() = default;

void DebuggerService::Start(HMODULE moduleHandle) {
    moduleHandle_ = moduleHandle;
    if (bootstrapThread_ != nullptr || bootstrapped_.load()) {
        return;
    }
    stopCompleted_.store(false);
    stopInProgress_.store(false);
    stopRequested_.store(false);
    unloadRequested_.store(false);
    bootstrapThread_ = CreateThread(nullptr, 0, &DebuggerService::BootstrapThreadProc, this, 0, nullptr);
}

void DebuggerService::Stop() {
    if (stopCompleted_.load()) {
        return;
    }

    if (stopInProgress_.exchange(true)) {
        return;
    }

    stopRequested_.store(true);

    if (ipcServer_) {
        ipcServer_->Stop();
        ipcServer_.reset();
    }
    accessWatchManager_.Stop();
    watchManager_.Stop();

    if (bootstrapThread_ != nullptr) {
        WaitForSingleObject(bootstrapThread_, 2000);
        CloseHandle(bootstrapThread_);
        bootstrapThread_ = nullptr;
    }

    bootstrapped_.store(false);
    stopCompleted_.store(true);
}

void DebuggerService::OnProcessDetach() {
    stopRequested_.store(true);
    bootstrapped_.store(false);
    moduleHandle_ = nullptr;
}

bool DebuggerService::RequestUnload() {
    if (moduleHandle_ == nullptr) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    if (unloadRequested_.exchange(true)) {
        SetLastError(ERROR_ALREADY_EXISTS);
        return false;
    }

    const HANDLE unloadThread = CreateThread(nullptr, 0, &DebuggerService::UnloadThreadProc, this, 0, nullptr);
    if (unloadThread == nullptr) {
        unloadRequested_.store(false);
        return false;
    }

    CloseHandle(unloadThread);
    return true;
}

DWORD WINAPI DebuggerService::BootstrapThreadProc(LPVOID context) {
    static_cast<DebuggerService*>(context)->Bootstrap();
    return 0;
}

DWORD WINAPI DebuggerService::UnloadThreadProc(LPVOID context) {
    static_cast<DebuggerService*>(context)->RunExplicitUnload();
    return 0;
}

void DebuggerService::Bootstrap() {
    AccessWatchManager::ScopedInternalContext accessWatchInternal(accessWatchManager_);
    pipeName_ = std::format("{}{}", kPipePrefix, GetCurrentProcessId());
    watchManager_.Start();
    accessWatchManager_.Start();
    ipcServer_ = std::make_unique<IpcServer>(pipeName_, [this](const std::string& request) {
        return Dispatch(request);
    });
    ipcServer_->Start();
    bootstrapped_.store(true);

    while (!stopRequested_.load()) {
        Sleep(100);
    }
}

void DebuggerService::RunExplicitUnload() {
    AccessWatchManager::ScopedInternalContext accessWatchInternal(accessWatchManager_);
    const HMODULE moduleHandle = moduleHandle_;
    Stop();
    if (moduleHandle != nullptr) {
        FreeLibraryAndExitThread(moduleHandle, ERROR_SUCCESS);
    }
}

std::string DebuggerService::Dispatch(const std::string& request) {
    AccessWatchManager::ScopedInternalContext accessWatchInternal(accessWatchManager_);
    const auto message = ParseMessage(request);
    const auto command = message.GetFirst("command");
    if (!command.has_value()) {
        return MakeError("missing_command", "command field is required");
    }

    if (*command == "ping") {
        return HandlePing();
    }
    if (*command == "eject") {
        return HandleEject();
    }
    if (*command == "read_memory") {
        return HandleReadMemory(message);
    }
    if (*command == "write_memory") {
        return HandleWriteMemory(message);
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
    if (*command == "create_aob_pattern") {
        return HandleCreateAobPattern(message);
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
    if (*command == "watch_memory_reads") {
        return HandleWatchMemoryReads(message);
    }
    if (*command == "watch_memory_writes") {
        return HandleWatchMemoryWrites(message);
    }
    if (*command == "unwatch_access_watch") {
        return HandleUnwatchAccessWatch(message);
    }
    if (*command == "poll_access_watch_results") {
        return HandlePollAccessWatchResults(message);
    }
    if (*command == "disassemble") {
        return HandleDisassemble(message);
    }
    if (*command == "invoke_function") {
        return HandleInvokeFunction(message);
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

std::string DebuggerService::HandleEject() {
    if (RequestUnload()) {
        return MakeOk({
            {"eject_status", "scheduled"},
        });
    }

    const DWORD error = GetLastError();
    if (error == ERROR_ALREADY_EXISTS) {
        return MakeOk({
            {"eject_status", "already_requested"},
        });
    }

    return MakeError(
        "eject_failed",
        std::format("unable to schedule unload: {}", DescribeWin32Error(error)));
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

std::string DebuggerService::HandleWriteMemory(const ParsedMessage& message) const {
    const auto address = ParseAddress(message.GetFirst("address").value_or(""));
    if (!address.has_value()) {
        return MakeError("invalid_arguments", "address is required");
    }

    std::vector<std::uint8_t> bytes;
    if (!ParseHexBytes(message.GetFirst("bytes").value_or(""), bytes)) {
        return MakeError("invalid_arguments", "bytes must be space-separated hex byte values");
    }
    if (bytes.size() > kMaxWriteSize) {
        return MakeError("invalid_size", "byte payload exceeds maximum write limit");
    }

    if (!memoryReader_.WriteBytes(*address, bytes)) {
        return MakeError("memory_write_failed", "unable to write requested range");
    }

    std::vector<MessageField> fields{
        {"address", ToHex(*address)},
        {"requested_size", std::to_string(bytes.size())},
        {"bytes_written", std::to_string(bytes.size())},
        {"bytes", HexEncode(bytes)},
    };

    if (ParseBool(message.GetFirst("read_back").value_or("false")).value_or(false)) {
        std::vector<std::uint8_t> readBack;
        if (!memoryReader_.ReadBytes(*address, bytes.size(), readBack)) {
            return MakeError("memory_verify_failed", "memory write succeeded but read-back verification failed");
        }
        fields.emplace_back("read_back", HexEncode(readBack));
    }

    return MakeOk(std::move(fields));
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
    const auto modules = SnapshotModules();
    if (modules.empty()) {
        return MakeError("module_enum_failed", "unable to snapshot loaded modules");
    }

    std::vector<MessageField> fields{
        {"module_count", std::to_string(modules.size())},
        {"enumeration_method", "toolhelp_snapshot"},
    };
    for (const auto& module : modules) {
        fields.emplace_back(
            "module",
            std::format(
                "{}|{}|{}|{}",
                module.name,
                ToHex(module.baseAddress),
                module.imageSize,
                module.path));
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

std::string DebuggerService::HandleCreateAobPattern(const ParsedMessage& message) const {
    const auto address = ParseAddress(message.GetFirst("address").value_or(""));
    const auto maxBytes = ParseUnsigned(message.GetFirst("max_bytes").value_or(std::to_string(kDefaultGeneratedPatternBytes)));
    const auto includeMask = ParseBool(message.GetFirst("include_mask").value_or("false")).value_or(false);
    const auto includeOffset = ParseBool(message.GetFirst("include_offset").value_or("false")).value_or(false);
    if (!address.has_value() || !maxBytes.has_value()) {
        return MakeError("invalid_arguments", "address and max_bytes are required");
    }

    GeneratedPatternResult result{};
    std::string error;
    if (!patternGenerator_.Generate(*address, static_cast<std::size_t>(*maxBytes), result, error)) {
        return MakeError(error, "unable to generate a unique AOB pattern");
    }

    std::vector<MessageField> fields{
        {"address", ToHex(result.address)},
        {"pattern", PatternGenerator::FormatPattern(result.pattern)},
        {"pattern_start", ToHex(result.patternStart)},
        {"match_count", std::to_string(result.matchCount)},
        {"byte_count", std::to_string(result.pattern.size())},
        {"wildcard_count", std::to_string(PatternGenerator::CountWildcards(result.pattern))},
    };
    if (includeMask) {
        fields.emplace_back("mask", PatternGenerator::FormatMask(result.pattern));
    }
    if (includeOffset) {
        fields.emplace_back("target_offset", std::to_string(result.targetOffset));
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

std::string DebuggerService::HandleWatchMemoryReads(const ParsedMessage& message) {
    const auto address = ParseAddress(message.GetFirst("address").value_or(""));
    const auto size = ParseUnsigned(message.GetFirst("size").value_or(""));
    if (!address.has_value() || !size.has_value()) {
        return MakeError("invalid_arguments", "address and size are required");
    }

    const auto providedId = message.GetFirst("watch_id");
    const auto watchId = providedId.value_or(MakeWatchId(*address));
    std::string error;
    if (!accessWatchManager_.AddWatch(watchId, *address, static_cast<std::size_t>(*size), AccessWatchMode::Read, error)) {
        return MakeError(error, "unable to arm read watch");
    }

    return MakeOk({
        {"watch_id", watchId},
        {"address", ToHex(*address)},
        {"size", std::to_string(*size)},
        {"mode", "read"},
        {"idle_timeout_s", std::to_string(kAccessWatchIdleTimeoutMs / 1000)},
        {"state", "active"},
    });
}

std::string DebuggerService::HandleWatchMemoryWrites(const ParsedMessage& message) {
    const auto address = ParseAddress(message.GetFirst("address").value_or(""));
    const auto size = ParseUnsigned(message.GetFirst("size").value_or(""));
    if (!address.has_value() || !size.has_value()) {
        return MakeError("invalid_arguments", "address and size are required");
    }

    const auto providedId = message.GetFirst("watch_id");
    const auto watchId = providedId.value_or(MakeWatchId(*address));
    std::string error;
    if (!accessWatchManager_.AddWatch(watchId, *address, static_cast<std::size_t>(*size), AccessWatchMode::Write, error)) {
        return MakeError(error, "unable to arm write watch");
    }

    return MakeOk({
        {"watch_id", watchId},
        {"address", ToHex(*address)},
        {"size", std::to_string(*size)},
        {"mode", "write"},
        {"idle_timeout_s", std::to_string(kAccessWatchIdleTimeoutMs / 1000)},
        {"state", "active"},
    });
}

std::string DebuggerService::HandleUnwatchAccessWatch(const ParsedMessage& message) {
    const auto watchId = message.GetFirst("watch_id");
    if (!watchId.has_value()) {
        return MakeError("invalid_arguments", "watch_id is required");
    }

    std::string error;
    if (!accessWatchManager_.RemoveWatch(*watchId, error)) {
        return MakeError(error, *watchId);
    }

    return MakeOk({
        {"watch_id", *watchId},
        {"removed", "true"},
    });
}

std::string DebuggerService::HandlePollAccessWatchResults(const ParsedMessage& message) {
    const auto watchId = message.GetFirst("watch_id");
    if (!watchId.has_value()) {
        return MakeError("invalid_arguments", "watch_id is required");
    }

    std::string error;
    const auto result = accessWatchManager_.PollResults(*watchId, error);
    if (!result.has_value()) {
        return MakeError(error, *watchId);
    }

    std::vector<MessageField> fields{
        {"watch_id", result->watchId},
        {"mode", result->mode == AccessWatchMode::Read ? "read" : "write"},
        {"address", ToHex(result->address)},
        {"size", std::to_string(result->size)},
        {"state", result->active ? "active" : "expired_snapshot"},
        {"timed_out", result->timedOut ? "true" : "false"},
        {"total_hit_count", std::to_string(result->totalHitCount)},
        {"source_count", std::to_string(result->sources.size())},
    };
    for (const auto& source : result->sources) {
        fields.emplace_back(
            "source",
            std::format(
                "{}|{}|{}|{}|{}|{}",
                ToHex(source.instructionAddress),
                HexEncode(source.instructionBytes),
                source.instructionText,
                source.hitCount,
                source.lastThreadId,
                ToHex(source.lastAccessAddress)));
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

std::string DebuggerService::HandleInvokeFunction(const ParsedMessage& message) const {
    std::uintptr_t address = 0;
    std::string errorDetail;
    if (!ParseInvokeAddress(message, address, errorDetail)) {
        return MakeError("invalid_arguments", errorDetail);
    }

    std::vector<InvokeArgumentState> arguments;
    if (!ParseInvokeArguments(message, arguments, errorDetail)) {
        return MakeError("invalid_arguments", errorDetail);
    }

    std::uint64_t returnValue = 0;
    DWORD lastError = 0;
    DWORD exceptionCode = 0;
    if (!InvokeFunction(address, arguments, returnValue, lastError, exceptionCode)) {
        if (exceptionCode != 0) {
            return MakeError("invoke_exception", std::format("function raised exception 0x{:08X}", exceptionCode));
        }
        return MakeError("invoke_failed", "function invocation failed");
    }

    std::vector<MessageField> fields{
        {"resolved_address", ToHex(address)},
        {"return_value", std::to_string(returnValue)},
        {"last_error", std::to_string(lastError)},
    };

    for (const auto& argument : arguments) {
        if (!argument.output.has_value()) {
            continue;
        }
        fields.emplace_back(
            "output",
            std::format(
                "{}|{}|{}|{}|{}",
                argument.output->first,
                argument.output->second,
                ToHex(static_cast<std::uintptr_t>(argument.value)),
                argument.storage.size(),
                HexEncode(argument.storage)));
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
