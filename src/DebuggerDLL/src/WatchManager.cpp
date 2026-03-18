#include "WatchManager.h"

#include <algorithm>
#include <chrono>

#include "DebuggerProtocol.h"

namespace idmcp {

WatchManager::WatchManager(const MemoryReader& memoryReader) : memoryReader_(memoryReader) {}

WatchManager::~WatchManager() {
    Stop();
}

void WatchManager::Start() {
    if (running_.exchange(true)) {
        return;
    }
    worker_ = std::thread(&WatchManager::Run, this);
}

void WatchManager::Stop() {
    if (!running_.exchange(false)) {
        return;
    }
    if (worker_.joinable()) {
        worker_.join();
    }
}

bool WatchManager::AddWatch(
    const std::string& watchId,
    const std::uintptr_t address,
    const std::size_t size,
    const std::uint32_t intervalMs,
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
    if (size == 0 || size > 64) {
        error = "invalid_size";
        return false;
    }

    std::vector<std::uint8_t> initialValue;
    if (!memoryReader_.ReadBytes(address, size, initialValue, diagnostics)) {
        error = "memory_read_failed";
        return false;
    }

    std::scoped_lock lock(mutex_);
    if (watches_.size() >= kMaxWatchCount && !watches_.contains(watchId)) {
        error = "watch_limit_exceeded";
        return false;
    }

    watches_[watchId] = WatchEntry{
        .watchId = watchId,
        .address = address,
        .size = size,
        .intervalMs = std::max<std::uint32_t>(intervalMs, 50),
        .lastValue = std::move(initialValue),
        .nextSampleMs = NowMs(),
    };
    return true;
}

bool WatchManager::RemoveWatch(const std::string& watchId) {
    std::scoped_lock lock(mutex_);
    return watches_.erase(watchId) > 0;
}

std::vector<WatchEvent> WatchManager::DrainEvents(const std::size_t limit) {
    std::scoped_lock lock(mutex_);
    const auto count = std::min(limit, events_.size());
    std::vector<WatchEvent> drained(events_.begin(), events_.begin() + static_cast<std::ptrdiff_t>(count));
    events_.erase(events_.begin(), events_.begin() + static_cast<std::ptrdiff_t>(count));
    return drained;
}

std::size_t WatchManager::WatchCount() const {
    std::scoped_lock lock(mutex_);
    return watches_.size();
}

void WatchManager::Run() {
    while (running_.load()) {
        std::vector<WatchEvent> newEvents;
        {
            std::scoped_lock lock(mutex_);
            const auto now = NowMs();
            for (auto& [_, watch] : watches_) {
                if (now < watch.nextSampleMs) {
                    continue;
                }

                watch.nextSampleMs = now + watch.intervalMs;
                std::vector<std::uint8_t> currentValue;
                if (!memoryReader_.ReadBytes(watch.address, watch.size, currentValue)) {
                    continue;
                }
                if (currentValue == watch.lastValue) {
                    continue;
                }

                newEvents.push_back(WatchEvent{
                    .watchId = watch.watchId,
                    .address = watch.address,
                    .oldValue = watch.lastValue,
                    .newValue = currentValue,
                    .timestampMs = now,
                });
                watch.lastValue = std::move(currentValue);
            }
            if (!newEvents.empty()) {
                events_.insert(events_.end(), newEvents.begin(), newEvents.end());
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
}

std::uint64_t WatchManager::NowMs() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

}  // namespace idmcp
