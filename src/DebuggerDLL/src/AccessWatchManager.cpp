#include "AccessWatchManager.h"

#include <TlHelp32.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <format>

#include "DebuggerProtocol.h"

namespace idmcp {

namespace {

thread_local bool g_accessWatchInternalContext = false;
std::atomic<AccessWatchManager*> g_activeManager{nullptr};
constexpr DWORD kHardwareBreakpointThreadAccess = THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME;

[[nodiscard]] bool IsReadableProtection(const DWORD protect) {
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) {
        return false;
    }

    const DWORD baseProtect = protect & 0xFFU;
    return baseProtect == PAGE_READONLY ||
           baseProtect == PAGE_READWRITE ||
           baseProtect == PAGE_WRITECOPY ||
           baseProtect == PAGE_EXECUTE_READ ||
           baseProtect == PAGE_EXECUTE_READWRITE ||
           baseProtect == PAGE_EXECUTE_WRITECOPY ||
           baseProtect == PAGE_EXECUTE;
}

[[nodiscard]] bool IsWritableProtection(const DWORD protect) {
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) {
        return false;
    }

    const DWORD baseProtect = protect & 0xFFU;
    return baseProtect == PAGE_READWRITE ||
           baseProtect == PAGE_WRITECOPY ||
           baseProtect == PAGE_EXECUTE_READWRITE ||
           baseProtect == PAGE_EXECUTE_WRITECOPY;
}

}  // namespace

AccessWatchManager::ScopedInternalContext::ScopedInternalContext(AccessWatchManager& manager) : manager_(manager) {
    manager_.MarkCurrentThreadInternal();
}

AccessWatchManager::ScopedInternalContext::~ScopedInternalContext() {
    manager_.UnmarkCurrentThreadInternal();
}

AccessWatchManager::AccessWatchManager(const MemoryReader& memoryReader, const Disassembler& disassembler)
    : memoryReader_(memoryReader), disassembler_(disassembler) {}

AccessWatchManager::~AccessWatchManager() {
    Stop();
}

void AccessWatchManager::Start() {
    if (running_.exchange(true)) {
        return;
    }

    g_activeManager.store(this);
    vehHandle_ = AddVectoredExceptionHandler(1, &AccessWatchManager::VectoredHandler);
    worker_ = std::thread(&AccessWatchManager::Run, this);
}

void AccessWatchManager::Stop() {
    if (!running_.exchange(false)) {
        return;
    }

    if (worker_.joinable()) {
        worker_.join();
    }

    {
        std::scoped_lock lock(mutex_);
        activeWatches_.clear();
        retainedSnapshots_.clear();
        for (const auto& [pageBase, page] : managedPages_) {
            DWORD previousProtect = 0;
            VirtualProtect(reinterpret_cast<void*>(pageBase), page.size, page.originalProtect, &previousProtect);
        }
        managedPages_.clear();
    }

    const bool clearedHardwareBreakpoints = SyncHardwareBreakpoints(true);
    (void)clearedHardwareBreakpoints;

    while (true) {
        {
            std::scoped_lock lock(mutex_);
            if (pendingRearms_.empty()) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    {
        std::scoped_lock lock(mutex_);
        pendingRearms_.clear();
    }

    if (vehHandle_ != nullptr) {
        RemoveVectoredExceptionHandler(vehHandle_);
        vehHandle_ = nullptr;
    }
    g_activeManager.store(nullptr);
}

void AccessWatchManager::MarkCurrentThreadInternal() {
    g_accessWatchInternalContext = true;
}

void AccessWatchManager::UnmarkCurrentThreadInternal() {
    g_accessWatchInternalContext = false;
}

bool AccessWatchManager::AddWatch(
    const std::string& watchId,
    const std::uintptr_t address,
    const std::size_t size,
    const AccessWatchMode mode,
    std::string& error,
    MemoryAccessDiagnostics* diagnostics) {
    error.clear();
    if (diagnostics != nullptr) {
        *diagnostics = {};
        diagnostics->address = address;
        diagnostics->size = size;
    }
    if (watchId.empty()) {
        error = "watch_id_required";
        return false;
    }
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        error = "unsupported_watch_size";
        return false;
    }

    if (mode == AccessWatchMode::Write && !IsHardwareBreakpointAligned(address, size)) {
        error = "unsupported_watch_alignment";
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT) {
        if (diagnostics != nullptr) {
            if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
                diagnostics->hasRegion = true;
                diagnostics->regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                diagnostics->regionSize = mbi.RegionSize;
                diagnostics->state = mbi.State;
                diagnostics->protect = mbi.Protect;
                diagnostics->reason = mbi.State == MEM_COMMIT ? "memory_read_failed" : "region_not_committed";
            } else {
                diagnostics->reason = "virtual_query_failed";
                diagnostics->queryError = GetLastError();
            }
        }
        error = "memory_read_failed";
        return false;
    }

    if (diagnostics != nullptr) {
        diagnostics->hasRegion = true;
        diagnostics->regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        diagnostics->regionSize = mbi.RegionSize;
        diagnostics->state = mbi.State;
        diagnostics->protect = mbi.Protect;
    }

    const auto pageBase = PageBaseForAddress(address);
    if (mode == AccessWatchMode::Read && PageBaseForAddress(address + size - 1) != pageBase) {
        error = "cross_page_watch_unsupported";
        return false;
    }

    bool requiresHardwareSync = false;
    {
        std::scoped_lock lock(mutex_);
        if (activeWatches_.contains(watchId) || retainedSnapshots_.contains(watchId)) {
            error = "duplicate_watch_id";
            return false;
        }
        if (activeWatches_.size() >= kMaxAccessWatchCount) {
            error = "access_watch_limit_exceeded";
            return false;
        }

        if (mode == AccessWatchMode::Write) {
            const DWORD effectiveProtect = mbi.Protect & ~PAGE_GUARD;
            if (!IsWritableProtection(effectiveProtect)) {
                if (diagnostics != nullptr) {
                    diagnostics->reason = ((effectiveProtect & PAGE_NOACCESS) != 0) ? "no_access" : "protection_not_writable";
                }
                error = "memory_write_failed";
                return false;
            }

            const int hardwareSlot = AllocateHardwareSlotLocked();
            if (hardwareSlot < 0) {
                error = "access_watch_limit_exceeded";
                return false;
            }

            activeWatches_[watchId] = WatchEntry{
                .watchId = watchId,
                .backend = AccessWatchBackend::HardwareBreakpoint,
                .mode = mode,
                .address = address,
                .size = size,
                .pageBase = 0,
                .hardwareSlot = hardwareSlot,
                .lastPollMs = NowMs(),
                .totalHitCount = 0,
            };
            requiresHardwareSync = true;
        } else {
            auto page = managedPages_.find(pageBase);
            const DWORD effectiveProtect = page == managedPages_.end() ? (mbi.Protect & ~PAGE_GUARD) : page->second.originalProtect;
            if (!IsReadableProtection(effectiveProtect)) {
                if (diagnostics != nullptr) {
                    diagnostics->reason = ((effectiveProtect & PAGE_NOACCESS) != 0) ? "no_access" : "protection_not_readable";
                }
                error = "memory_read_failed";
                return false;
            }

            if (page == managedPages_.end()) {
                page = managedPages_.emplace(
                    pageBase,
                    ManagedPage{
                        .baseAddress = pageBase,
                        .size = SystemPageSize(),
                        .originalProtect = mbi.Protect & ~PAGE_GUARD,
                        .refCount = 0,
                    }).first;
            }
            page->second.refCount += 1;
            if (!ArmPageGuardLocked(pageBase)) {
                page->second.refCount -= 1;
                if (page->second.refCount == 0) {
                    managedPages_.erase(page);
                }
                error = "page_guard_failed";
                return false;
            }

            activeWatches_[watchId] = WatchEntry{
                .watchId = watchId,
                .backend = AccessWatchBackend::GuardPage,
                .mode = mode,
                .address = address,
                .size = size,
                .pageBase = pageBase,
                .hardwareSlot = -1,
                .lastPollMs = NowMs(),
                .totalHitCount = 0,
            };
        }
    }

    if (requiresHardwareSync && !SyncHardwareBreakpoints(false)) {
        std::scoped_lock lock(mutex_);
        auto active = activeWatches_.find(watchId);
        if (active != activeWatches_.end()) {
            activeWatches_.erase(active);
        }
        error = "hardware_watch_failed";
        return false;
    }
    return true;
}

bool AccessWatchManager::RemoveWatch(const std::string& watchId, std::string& error) {
    error.clear();
    bool requiresHardwareSync = false;
    {
        std::scoped_lock lock(mutex_);
        if (retainedSnapshots_.erase(watchId) > 0) {
            return true;
        }
        const auto active = activeWatches_.find(watchId);
        if (active == activeWatches_.end()) {
            error = "watch_not_found";
            return false;
        }
        requiresHardwareSync = active->second.backend == AccessWatchBackend::HardwareBreakpoint;
        if (active->second.backend == AccessWatchBackend::GuardPage) {
            ReleasePageLocked(active->second.pageBase);
        }
        activeWatches_.erase(active);
    }

    if (requiresHardwareSync) {
        const bool syncedHardwareBreakpoints = SyncHardwareBreakpoints(false);
        (void)syncedHardwareBreakpoints;
    }
    return true;
}

std::optional<AccessWatchPollResult> AccessWatchManager::PollResults(const std::string& watchId, std::string& error) {
    error.clear();
    std::scoped_lock lock(mutex_);
    if (auto retained = retainedSnapshots_.find(watchId); retained != retainedSnapshots_.end()) {
        auto result = retained->second;
        retainedSnapshots_.erase(retained);
        return result;
    }

    const auto active = activeWatches_.find(watchId);
    if (active == activeWatches_.end()) {
        error = "watch_not_found";
        return std::nullopt;
    }

    active->second.lastPollMs = NowMs();
    return BuildPollResultLocked(active->second, true, false);
}

std::size_t AccessWatchManager::ActiveWatchCount() const {
    std::scoped_lock lock(mutex_);
    return activeWatches_.size();
}

LONG CALLBACK AccessWatchManager::VectoredHandler(EXCEPTION_POINTERS* exceptionPointers) {
    auto* manager = g_activeManager.load();
    if (manager == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return manager->HandleException(exceptionPointers);
}

LONG AccessWatchManager::HandleException(EXCEPTION_POINTERS* exceptionPointers) {
    if (exceptionPointers == nullptr || exceptionPointers->ExceptionRecord == nullptr || exceptionPointers->ContextRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (exceptionPointers->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        return HandleGuardPageViolation(exceptionPointers);
    }
    if (exceptionPointers->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
        return HandleSingleStep(exceptionPointers);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

LONG AccessWatchManager::HandleGuardPageViolation(EXCEPTION_POINTERS* exceptionPointers) {
    const DWORD threadId = GetCurrentThreadId();
    const auto* record = exceptionPointers->ExceptionRecord;
    if (record->NumberParameters < 2) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto accessType = static_cast<std::uint64_t>(record->ExceptionInformation[0]);
    const auto accessAddress = static_cast<std::uintptr_t>(record->ExceptionInformation[1]);
    const auto pageBase = PageBaseForAddress(accessAddress);

    std::scoped_lock lock(mutex_);
    if (!managedPages_.contains(pageBase)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    pendingRearms_[threadId].insert(pageBase);
    exceptionPointers->ContextRecord->EFlags |= 0x100U;

    if (g_accessWatchInternalContext) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    for (auto& [_, watch] : activeWatches_) {
        if (watch.backend != AccessWatchBackend::GuardPage || watch.pageBase != pageBase) {
            continue;
        }
        const auto watchEnd = watch.address + watch.size;
        if (accessAddress < watch.address || accessAddress >= watchEnd) {
            continue;
        }

        const bool isReadAccess = accessType == 0;
        const bool isWriteAccess = accessType == 1;
        if ((watch.mode == AccessWatchMode::Read && !isReadAccess) ||
            (watch.mode == AccessWatchMode::Write && !isWriteAccess)) {
            continue;
        }

        auto& source = watch.sources[static_cast<std::uintptr_t>(exceptionPointers->ContextRecord->Rip)];
        if (source.hitCount == 0) {
            source.instructionAddress = static_cast<std::uintptr_t>(exceptionPointers->ContextRecord->Rip);
        }
        source.hitCount += 1;
        source.lastThreadId = threadId;
        source.lastAccessAddress = accessAddress;
        watch.totalHitCount += 1;
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

LONG AccessWatchManager::HandleSingleStep(EXCEPTION_POINTERS* exceptionPointers) {
    const DWORD threadId = GetCurrentThreadId();
    std::scoped_lock lock(mutex_);
    const bool handledHardwareBreakpoint = HandleHardwareBreakpointsLocked(exceptionPointers, threadId);
    const auto pending = pendingRearms_.find(threadId);
    if (pending == pendingRearms_.end() && !handledHardwareBreakpoint) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (pending != pendingRearms_.end()) {
        for (const auto pageBase : pending->second) {
            const auto rearmed = ArmPageGuardLocked(pageBase);
            (void)rearmed;
        }
        pendingRearms_.erase(pending);
        exceptionPointers->ContextRecord->EFlags &= ~0x100U;
    }
    if (handledHardwareBreakpoint) {
        exceptionPointers->ContextRecord->Dr6 = 0;
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

void AccessWatchManager::Run() {
    ScopedInternalContext internal(*this);
    while (running_.load()) {
        bool requiresHardwareSync = false;
        {
            std::scoped_lock lock(mutex_);
            for (const auto& [_, watch] : activeWatches_) {
                if (watch.backend == AccessWatchBackend::HardwareBreakpoint) {
                    requiresHardwareSync = true;
                    break;
                }
            }
            ExpireIdleWatchesLocked(NowMs());
            if (!requiresHardwareSync) {
                for (const auto& [_, watch] : activeWatches_) {
                    if (watch.backend == AccessWatchBackend::HardwareBreakpoint) {
                        requiresHardwareSync = true;
                        break;
                    }
                }
            }
        }
        if (requiresHardwareSync) {
            const bool syncedHardwareBreakpoints = SyncHardwareBreakpoints(false);
            (void)syncedHardwareBreakpoints;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

bool AccessWatchManager::SyncHardwareBreakpoints(const bool clearAll) {
    std::vector<HardwareWatchConfig> configs;
    {
        std::scoped_lock lock(mutex_);
        configs = CollectHardwareConfigsLocked();
    }

    const auto threadIds = EnumerateProcessThreadIds();
    const DWORD currentThreadId = GetCurrentThreadId();
    bool appliedAny = false;
    for (const DWORD threadId : threadIds) {
        if (threadId == currentThreadId) {
            continue;
        }

        const HANDLE threadHandle = OpenThread(kHardwareBreakpointThreadAccess, FALSE, threadId);
        if (threadHandle == nullptr) {
            continue;
        }

        const DWORD suspendCount = SuspendThread(threadHandle);
        if (suspendCount == static_cast<DWORD>(-1)) {
            CloseHandle(threadHandle);
            continue;
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(threadHandle, &context) != 0) {
            context.Dr0 = 0;
            context.Dr1 = 0;
            context.Dr2 = 0;
            context.Dr3 = 0;
            context.Dr6 = 0;
            context.Dr7 = 0;

            if (!clearAll) {
                for (const auto& config : configs) {
                    AssignHardwareBreakpointAddress(context, config.slot, config.address);
                }
                context.Dr7 = EncodeHardwareBreakpointControl(configs);
            }

            if (SetThreadContext(threadHandle, &context) != 0) {
                appliedAny = true;
            }
        }

        ResumeThread(threadHandle);
        CloseHandle(threadHandle);
    }

    return clearAll || configs.empty() || appliedAny;
}

bool AccessWatchManager::HandleHardwareBreakpointsLocked(EXCEPTION_POINTERS* exceptionPointers, const DWORD threadId) {
    const DWORD64 dr6 = exceptionPointers->ContextRecord->Dr6;
    bool handled = false;
    for (int slot = 0; slot < 4; ++slot) {
        if ((dr6 & (1ULL << slot)) == 0) {
            continue;
        }

        handled = true;

        for (auto& [_, watch] : activeWatches_) {
            if (watch.backend != AccessWatchBackend::HardwareBreakpoint || watch.hardwareSlot != slot) {
                continue;
            }

            if (g_accessWatchInternalContext) {
                break;
            }

            auto& source = watch.sources[static_cast<std::uintptr_t>(exceptionPointers->ContextRecord->Rip)];
            if (source.hitCount == 0) {
                source.instructionAddress = static_cast<std::uintptr_t>(exceptionPointers->ContextRecord->Rip);
            }
            source.hitCount += 1;
            source.lastThreadId = threadId;
            source.lastAccessAddress = watch.address;
            watch.totalHitCount += 1;
            break;
        }
    }
    return handled;
}

std::vector<AccessWatchManager::HardwareWatchConfig> AccessWatchManager::CollectHardwareConfigsLocked() const {
    std::vector<HardwareWatchConfig> configs;
    configs.reserve(activeWatches_.size());
    for (const auto& [_, watch] : activeWatches_) {
        if (watch.backend != AccessWatchBackend::HardwareBreakpoint) {
            continue;
        }
        configs.push_back(HardwareWatchConfig{
            .slot = watch.hardwareSlot,
            .address = watch.address,
            .size = watch.size,
        });
    }
    return configs;
}

int AccessWatchManager::AllocateHardwareSlotLocked() const {
    std::array<bool, 4> usedSlots{false, false, false, false};
    for (const auto& [_, watch] : activeWatches_) {
        if (watch.backend == AccessWatchBackend::HardwareBreakpoint && watch.hardwareSlot >= 0 && watch.hardwareSlot < 4) {
            usedSlots[static_cast<std::size_t>(watch.hardwareSlot)] = true;
        }
    }

    for (int slot = 0; slot < 4; ++slot) {
        if (!usedSlots[static_cast<std::size_t>(slot)]) {
            return slot;
        }
    }
    return -1;
}

bool AccessWatchManager::ArmPageGuardLocked(const std::uintptr_t pageBase) {
    const auto page = managedPages_.find(pageBase);
    if (page == managedPages_.end()) {
        return false;
    }

    DWORD previousProtect = 0;
    return VirtualProtect(
               reinterpret_cast<void*>(pageBase),
               page->second.size,
               page->second.originalProtect | PAGE_GUARD,
               &previousProtect) != 0;
}

void AccessWatchManager::ReleasePageLocked(const std::uintptr_t pageBase) {
    auto page = managedPages_.find(pageBase);
    if (page == managedPages_.end()) {
        return;
    }

    if (page->second.refCount > 1) {
        page->second.refCount -= 1;
        return;
    }

    DWORD previousProtect = 0;
    VirtualProtect(reinterpret_cast<void*>(pageBase), page->second.size, page->second.originalProtect, &previousProtect);
    managedPages_.erase(page);
}

void AccessWatchManager::ExpireIdleWatchesLocked(const std::uint64_t nowMs) {
    std::vector<std::string> expiredIds;
    for (const auto& [watchId, watch] : activeWatches_) {
        if (nowMs >= watch.lastPollMs + kAccessWatchIdleTimeoutMs) {
            expiredIds.push_back(watchId);
        }
    }

    for (const auto& watchId : expiredIds) {
        const auto it = activeWatches_.find(watchId);
        if (it == activeWatches_.end()) {
            continue;
        }
        StoreRetainedSnapshotLocked(it->second, true);
        if (it->second.backend == AccessWatchBackend::GuardPage) {
            ReleasePageLocked(it->second.pageBase);
        }
        activeWatches_.erase(it);
    }
}

void AccessWatchManager::StoreRetainedSnapshotLocked(const WatchEntry& watch, const bool timedOut) {
    retainedSnapshots_[watch.watchId] = BuildPollResultLocked(watch, false, timedOut);
}

AccessWatchPollResult AccessWatchManager::BuildPollResultLocked(const WatchEntry& watch, const bool active, const bool timedOut) const {
    AccessWatchPollResult result{
        .watchId = watch.watchId,
        .mode = watch.mode,
        .address = watch.address,
        .size = watch.size,
        .active = active,
        .timedOut = timedOut,
        .totalHitCount = watch.totalHitCount,
    };

    result.sources.reserve(watch.sources.size());
    for (const auto& [_, source] : watch.sources) {
        result.sources.push_back(BuildSourceResult(source));
    }

    std::sort(result.sources.begin(), result.sources.end(), [](const AccessWatchSource& left, const AccessWatchSource& right) {
        if (left.hitCount != right.hitCount) {
            return left.hitCount > right.hitCount;
        }
        return left.instructionAddress < right.instructionAddress;
    });
    return result;
}

AccessWatchSource AccessWatchManager::BuildSourceResult(const SourceAggregate& source) const {
    AccessWatchSource result{
        .instructionAddress = source.instructionAddress,
        .hitCount = source.hitCount,
        .lastThreadId = source.lastThreadId,
        .lastAccessAddress = source.lastAccessAddress,
    };

    if (source.instructionAddress == 0) {
        result.instructionText = "unknown";
        return result;
    }

    std::vector<std::uint8_t> instructionWindow;
    if (!memoryReader_.ReadBytes(source.instructionAddress, kAccessWatchInstructionBytes, instructionWindow)) {
        result.instructionText = "unknown";
        return result;
    }

    const auto instructions = disassembler_.Disassemble(source.instructionAddress, instructionWindow, 1);
    if (!instructions.empty()) {
        result.instructionBytes = instructions.front().bytes;
        result.instructionText = FormatInstruction(instructions.front());
        return result;
    }

    if (!instructionWindow.empty()) {
        result.instructionBytes = {instructionWindow.front()};
        result.instructionText = std::format("{:02X} - db", instructionWindow.front());
        return result;
    }

    result.instructionText = "unknown";
    return result;
}

std::uint64_t AccessWatchManager::NowMs() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::string AccessWatchManager::FormatInstruction(const Instruction& instruction) {
    const auto bytes = HexEncode(instruction.bytes);
    if (instruction.operands.empty()) {
        return std::format("{} - {}", bytes, instruction.mnemonic);
    }
    return std::format("{} - {} {}", bytes, instruction.mnemonic, instruction.operands);
}

std::vector<DWORD> AccessWatchManager::EnumerateProcessThreadIds() {
    std::vector<DWORD> threadIds;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return threadIds;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry) != 0) {
        const DWORD currentProcessId = GetCurrentProcessId();
        do {
            if (entry.th32OwnerProcessID == currentProcessId) {
                threadIds.push_back(entry.th32ThreadID);
            }
        } while (Thread32Next(snapshot, &entry) != 0);
    }

    CloseHandle(snapshot);
    return threadIds;
}

bool AccessWatchManager::IsHardwareBreakpointAligned(const std::uintptr_t address, const std::size_t size) {
    return (address % size) == 0;
}

DWORD64 AccessWatchManager::EncodeHardwareBreakpointControl(const std::vector<HardwareWatchConfig>& configs) {
    DWORD64 dr7 = 0;
    for (const auto& config : configs) {
        dr7 |= (1ULL << (config.slot * 2));

        DWORD64 lengthBits = 0;
        switch (config.size) {
            case 1:
                lengthBits = 0b00;
                break;
            case 2:
                lengthBits = 0b01;
                break;
            case 4:
                lengthBits = 0b11;
                break;
            case 8:
                lengthBits = 0b10;
                break;
            default:
                continue;
        }

        const DWORD64 controlBits = 0b01 | (lengthBits << 2);
        dr7 |= (controlBits << (16 + (config.slot * 4)));
    }
    return dr7;
}

void AccessWatchManager::AssignHardwareBreakpointAddress(CONTEXT& context, const int slot, const std::uintptr_t address) {
    switch (slot) {
        case 0:
            context.Dr0 = address;
            break;
        case 1:
            context.Dr1 = address;
            break;
        case 2:
            context.Dr2 = address;
            break;
        case 3:
            context.Dr3 = address;
            break;
        default:
            break;
    }
}

std::uintptr_t AccessWatchManager::PageBaseForAddress(const std::uintptr_t address) {
    const auto pageSize = static_cast<std::uintptr_t>(SystemPageSize());
    return address - (address % pageSize);
}

std::size_t AccessWatchManager::SystemPageSize() {
    static const std::size_t pageSize = [] {
        SYSTEM_INFO systemInfo{};
        GetSystemInfo(&systemInfo);
        return static_cast<std::size_t>(systemInfo.dwPageSize);
    }();
    return pageSize;
}

}  // namespace idmcp