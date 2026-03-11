#include <Windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <thread>

namespace {

struct Node {
    Node* next;
    std::uint64_t value;
};

std::atomic<std::uint32_t> g_counter{0x12345678};
std::uint64_t g_write_target = 0x0123456789ABCDEFULL;
volatile std::uint64_t g_read_watch_target = 0x0102030405060708ULL;
volatile std::uint64_t g_read_watch_sink = 0;
volatile std::uint64_t g_write_watch_target = 0x8877665544332211ULL;
char g_pattern[] = "INTERNAL_DEBUGGER_MCP_PATTERN";
std::uint8_t g_bytes[] = {0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3};
Node g_tail{nullptr, 0xDEADBEEFCAFEBABEULL};
Node g_head{&g_tail, 0x1111111122222222ULL};

__declspec(noinline) std::uint64_t SampleFunction(std::uint64_t value) {
    return value + 7;
}

extern "C" __declspec(dllexport) std::uint64_t ExportedStoreValue(std::uint64_t value) {
    g_write_target = value;
    return g_write_target;
}

__declspec(noinline) std::uint64_t TickReadWatchTarget() {
    const auto value = g_read_watch_target;
    g_read_watch_sink = value;
    return value;
}

__declspec(noinline) std::uint64_t TickWriteWatchTarget(std::uint64_t value) {
    g_write_watch_target = value;
    return g_write_watch_target;
}

extern "C" __declspec(dllexport) std::uint64_t ExportedFillBuffer(
    std::uint8_t* buffer,
    std::uint64_t size,
    std::uint64_t seed) {
    if (buffer == nullptr) {
        return 0;
    }

    for (std::uint64_t index = 0; index < size; ++index) {
        buffer[index] = static_cast<std::uint8_t>((seed + index) & 0xFFU);
    }
    return size;
}

void PrintAddress(const char* label, const void* value) {
    std::cout << std::left << std::setw(20) << label << ": 0x"
              << std::hex << reinterpret_cast<std::uintptr_t>(value) << std::dec << '\n';
}

}  // namespace

int main() {
    std::cout << "TestTarget PID: " << GetCurrentProcessId() << '\n';
    PrintAddress("g_counter", &g_counter);
    PrintAddress("g_write_target", &g_write_target);
    PrintAddress("g_read_watch_target", const_cast<std::uint64_t*>(&g_read_watch_target));
    PrintAddress("g_write_watch_target", const_cast<std::uint64_t*>(&g_write_watch_target));
    PrintAddress("g_pattern", g_pattern);
    PrintAddress("g_bytes", g_bytes);
    PrintAddress("g_head", &g_head);
    PrintAddress("SampleFunction", reinterpret_cast<void*>(&SampleFunction));
    PrintAddress("ExportedStoreValue", reinterpret_cast<void*>(&ExportedStoreValue));
    PrintAddress("ExportedFillBuffer", reinterpret_cast<void*>(&ExportedFillBuffer));
    PrintAddress("TickReadWatchTarget", reinterpret_cast<void*>(&TickReadWatchTarget));
    PrintAddress("TickWriteWatchTarget", reinterpret_cast<void*>(&TickWriteWatchTarget));
    std::cout << "Pointer chain head->next->value = 0x" << std::hex << g_head.next->value << std::dec << '\n';
    std::cout << "Mutating g_counter every second. Press Ctrl+C to exit.\n";
    std::cout << "READY\n" << std::flush;

    std::uint64_t writeSeed = 0x1000;
    while (true) {
        g_counter.fetch_add(1, std::memory_order_relaxed);
        TickReadWatchTarget();
        TickWriteWatchTarget(writeSeed++);
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
}