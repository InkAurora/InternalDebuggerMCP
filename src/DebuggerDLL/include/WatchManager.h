#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "MemoryReader.h"

namespace idmcp {

struct WatchEvent {
    std::string watchId;
    std::uintptr_t address;
    std::vector<std::uint8_t> oldValue;
    std::vector<std::uint8_t> newValue;
    std::uint64_t timestampMs;
};

class WatchManager {
public:
    explicit WatchManager(const MemoryReader& memoryReader);
    ~WatchManager();

    void Start();
    void Stop();

    [[nodiscard]] bool AddWatch(
        const std::string& watchId,
        std::uintptr_t address,
        std::size_t size,
        std::uint32_t intervalMs,
        std::string& error);
    [[nodiscard]] bool RemoveWatch(const std::string& watchId);
    [[nodiscard]] std::vector<WatchEvent> DrainEvents(std::size_t limit);
    [[nodiscard]] std::size_t WatchCount() const;

private:
    struct WatchEntry {
        std::string watchId;
        std::uintptr_t address;
        std::size_t size;
        std::uint32_t intervalMs;
        std::vector<std::uint8_t> lastValue;
        std::uint64_t nextSampleMs;
    };

    void Run();
    [[nodiscard]] static std::uint64_t NowMs();

    const MemoryReader& memoryReader_;
    std::atomic<bool> running_{false};
    mutable std::mutex mutex_;
    std::thread worker_;
    std::unordered_map<std::string, WatchEntry> watches_;
    std::vector<WatchEvent> events_;
};

}  // namespace idmcp
