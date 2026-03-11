#pragma once

#include <Windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "Disassembler.h"
#include "MemoryReader.h"

namespace idmcp {

enum class AccessWatchMode {
    Read,
    Write,
};

struct AccessWatchSource {
    std::uintptr_t instructionAddress;
    std::vector<std::uint8_t> instructionBytes;
    std::string instructionText;
    std::uint64_t hitCount;
    std::uint32_t lastThreadId;
    std::uintptr_t lastAccessAddress;
};

struct AccessWatchPollResult {
    std::string watchId;
    AccessWatchMode mode;
    std::uintptr_t address;
    std::size_t size;
    bool active;
    bool timedOut;
    std::uint64_t totalHitCount;
    std::vector<AccessWatchSource> sources;
};

class AccessWatchManager {
public:
    class ScopedInternalContext {
    public:
        explicit ScopedInternalContext(AccessWatchManager& manager);
        ~ScopedInternalContext();

        ScopedInternalContext(const ScopedInternalContext&) = delete;
        ScopedInternalContext& operator=(const ScopedInternalContext&) = delete;

    private:
        AccessWatchManager& manager_;
    };

    AccessWatchManager(const MemoryReader& memoryReader, const Disassembler& disassembler);
    ~AccessWatchManager();

    void Start();
    void Stop();

    void MarkCurrentThreadInternal();
    void UnmarkCurrentThreadInternal();

    [[nodiscard]] bool AddWatch(
        const std::string& watchId,
        std::uintptr_t address,
        std::size_t size,
        AccessWatchMode mode,
        std::string& error);
    [[nodiscard]] bool RemoveWatch(const std::string& watchId, std::string& error);
    [[nodiscard]] std::optional<AccessWatchPollResult> PollResults(const std::string& watchId, std::string& error);
    [[nodiscard]] std::size_t ActiveWatchCount() const;

private:
    struct SourceAggregate {
        std::uintptr_t instructionAddress{0};
        std::vector<std::uint8_t> instructionBytes;
        std::string instructionText;
        std::uint64_t hitCount{0};
        std::uint32_t lastThreadId{0};
        std::uintptr_t lastAccessAddress{0};
    };

    struct WatchEntry {
        std::string watchId;
        AccessWatchMode mode;
        std::uintptr_t address;
        std::size_t size;
        std::uintptr_t pageBase;
        std::uint64_t lastPollMs;
        std::uint64_t totalHitCount;
        std::unordered_map<std::uintptr_t, SourceAggregate> sources;
    };

    struct ManagedPage {
        std::uintptr_t baseAddress;
        std::size_t size;
        DWORD originalProtect;
        std::size_t refCount;
    };

    static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* exceptionPointers);
    [[nodiscard]] LONG HandleException(EXCEPTION_POINTERS* exceptionPointers);

    void Run();
    [[nodiscard]] LONG HandleGuardPageViolation(EXCEPTION_POINTERS* exceptionPointers);
    [[nodiscard]] LONG HandleSingleStep(EXCEPTION_POINTERS* exceptionPointers);
    [[nodiscard]] bool ArmPageGuardLocked(std::uintptr_t pageBase);
    void ReleasePageLocked(std::uintptr_t pageBase);
    void ExpireIdleWatchesLocked(std::uint64_t nowMs);
    void StoreRetainedSnapshotLocked(const WatchEntry& watch, bool timedOut);
    [[nodiscard]] AccessWatchPollResult BuildPollResultLocked(const WatchEntry& watch, bool active, bool timedOut) const;
    [[nodiscard]] static std::uint64_t NowMs();
    [[nodiscard]] static std::string FormatInstruction(const Instruction& instruction);
    [[nodiscard]] static std::uintptr_t PageBaseForAddress(std::uintptr_t address);
    [[nodiscard]] static std::size_t SystemPageSize();

    const MemoryReader& memoryReader_;
    const Disassembler& disassembler_;
    std::atomic<bool> running_{false};
    mutable std::mutex mutex_;
    std::thread worker_;
    PVOID vehHandle_{nullptr};
    std::unordered_map<std::string, WatchEntry> activeWatches_;
    std::unordered_map<std::string, AccessWatchPollResult> retainedSnapshots_;
    std::unordered_map<std::uintptr_t, ManagedPage> managedPages_;
    std::unordered_map<DWORD, std::unordered_set<std::uintptr_t>> pendingRearms_;
    std::unordered_set<DWORD> internalThreadIds_;
};

}  // namespace idmcp