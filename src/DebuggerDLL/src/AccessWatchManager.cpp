#include "AccessWatchManager.h"

#include <algorithm>
#include <chrono>
#include <format>

#include "DebuggerProtocol.h"

namespace idmcp {

namespace {

thread_local bool g_accessWatchInternalContext = false;
std::atomic<AccessWatchManager*> g_activeManager{nullptr};

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
        pendingRearms_.clear();
        for (const auto& [pageBase, page] : managedPages_) {
            DWORD previousProtect = 0;
            VirtualProtect(reinterpret_cast<void*>(pageBase), page.size, page.originalProtect, &previousProtect);
        }
        managedPages_.clear();
    }

    if (vehHandle_ != nullptr) {
        RemoveVectoredExceptionHandler(vehHandle_);
        vehHandle_ = nullptr;
    }
    g_activeManager.store(nullptr);
}

void AccessWatchManager::MarkCurrentThreadInternal() {
    g_accessWatchInternalContext = true;
    std::scoped_lock lock(mutex_);
    internalThreadIds_.insert(GetCurrentThreadId());
}

void AccessWatchManager::UnmarkCurrentThreadInternal() {
    g_accessWatchInternalContext = false;
}

bool AccessWatchManager::AddWatch(
    const std::string& watchId,
    const std::uintptr_t address,
    const std::size_t size,
    const AccessWatchMode mode,
    std::string& error) {
    error.clear();
    if (watchId.empty()) {
        error = "watch_id_required";
        return false;
    }
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        error = "unsupported_watch_size";
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT) {
        error = "memory_read_failed";
        return false;
    }

    const auto pageBase = PageBaseForAddress(address);
    if (PageBaseForAddress(address + size - 1) != pageBase) {
        error = "cross_page_watch_unsupported";
        return false;
    }

    std::scoped_lock lock(mutex_);
    if (activeWatches_.contains(watchId) || retainedSnapshots_.contains(watchId)) {
        error = "duplicate_watch_id";
        return false;
    }
    if (activeWatches_.size() >= kMaxAccessWatchCount) {
        error = "access_watch_limit_exceeded";
        return false;
    }

    auto page = managedPages_.find(pageBase);
    const DWORD effectiveProtect = page == managedPages_.end() ? (mbi.Protect & ~PAGE_GUARD) : page->second.originalProtect;
    if (!IsReadableProtection(effectiveProtect)) {
        error = "memory_read_failed";
        return false;
    }
    if (mode == AccessWatchMode::Write && !IsWritableProtection(effectiveProtect)) {
        error = "memory_write_failed";
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
        .mode = mode,
        .address = address,
        .size = size,
        .pageBase = pageBase,
        .lastPollMs = NowMs(),
        .totalHitCount = 0,
    };
    return true;
}

bool AccessWatchManager::RemoveWatch(const std::string& watchId, std::string& error) {
    error.clear();
    std::scoped_lock lock(mutex_);
    if (retainedSnapshots_.erase(watchId) > 0) {
        return true;
    }
    const auto active = activeWatches_.find(watchId);
    if (active == activeWatches_.end()) {
        error = "watch_not_found";
        return false;
    }
    ReleasePageLocked(active->second.pageBase);
    activeWatches_.erase(active);
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

    const bool isInternalThread = g_accessWatchInternalContext || internalThreadIds_.contains(threadId);
    if (isInternalThread) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    std::vector<std::uint8_t> instructionWindow;
    if (!memoryReader_.ReadBytes(static_cast<std::uintptr_t>(exceptionPointers->ContextRecord->Rip), kAccessWatchInstructionBytes, instructionWindow)) {
        instructionWindow.clear();
    }
    const auto instructions = disassembler_.Disassemble(
        static_cast<std::uintptr_t>(exceptionPointers->ContextRecord->Rip),
        instructionWindow,
        1);

    std::vector<std::uint8_t> instructionBytes;
    std::string instructionText = "unknown";
    if (!instructions.empty()) {
        instructionBytes = instructions.front().bytes;
        instructionText = FormatInstruction(instructions.front());
    } else if (!instructionWindow.empty()) {
        instructionBytes = {instructionWindow.front()};
        instructionText = std::format("{:02X} - db", instructionWindow.front());
    }

    for (auto& [_, watch] : activeWatches_) {
        if (watch.pageBase != pageBase) {
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
            source.instructionBytes = instructionBytes;
            source.instructionText = instructionText;
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
    const auto pending = pendingRearms_.find(threadId);
    if (pending == pendingRearms_.end()) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    for (const auto pageBase : pending->second) {
        const auto rearmed = ArmPageGuardLocked(pageBase);
        (void)rearmed;
    }
    pendingRearms_.erase(pending);
    exceptionPointers->ContextRecord->EFlags &= ~0x100U;
    return EXCEPTION_CONTINUE_EXECUTION;
}

void AccessWatchManager::Run() {
    ScopedInternalContext internal(*this);
    while (running_.load()) {
        {
            std::scoped_lock lock(mutex_);
            ExpireIdleWatchesLocked(NowMs());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
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

    for (auto pending = pendingRearms_.begin(); pending != pendingRearms_.end();) {
        pending->second.erase(pageBase);
        if (pending->second.empty()) {
            pending = pendingRearms_.erase(pending);
            continue;
        }
        ++pending;
    }
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
        ReleasePageLocked(it->second.pageBase);
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
        result.sources.push_back(AccessWatchSource{
            .instructionAddress = source.instructionAddress,
            .instructionBytes = source.instructionBytes,
            .instructionText = source.instructionText,
            .hitCount = source.hitCount,
            .lastThreadId = source.lastThreadId,
            .lastAccessAddress = source.lastAccessAddress,
        });
    }

    std::sort(result.sources.begin(), result.sources.end(), [](const AccessWatchSource& left, const AccessWatchSource& right) {
        if (left.hitCount != right.hitCount) {
            return left.hitCount > right.hitCount;
        }
        return left.instructionAddress < right.instructionAddress;
    });
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