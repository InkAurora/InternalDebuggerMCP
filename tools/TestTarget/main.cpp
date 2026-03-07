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
char g_pattern[] = "INTERNAL_DEBUGGER_MCP_PATTERN";
std::uint8_t g_bytes[] = {0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3};
Node g_tail{nullptr, 0xDEADBEEFCAFEBABEULL};
Node g_head{&g_tail, 0x1111111122222222ULL};

__declspec(noinline) int SampleFunction(int value) {
    return value + 7;
}

void PrintAddress(const char* label, const void* value) {
    std::cout << std::left << std::setw(20) << label << ": 0x"
              << std::hex << reinterpret_cast<std::uintptr_t>(value) << std::dec << '\n';
}

}  // namespace

int main() {
    std::cout << "TestTarget PID: " << GetCurrentProcessId() << '\n';
    PrintAddress("g_counter", &g_counter);
    PrintAddress("g_pattern", g_pattern);
    PrintAddress("g_bytes", g_bytes);
    PrintAddress("g_head", &g_head);
    PrintAddress("SampleFunction", reinterpret_cast<void*>(&SampleFunction));
    std::cout << "Pointer chain head->next->value = 0x" << std::hex << g_head.next->value << std::dec << '\n';
    std::cout << "Mutating g_counter every second. Press Ctrl+C to exit.\n";

    while (true) {
        g_counter.fetch_add(1, std::memory_order_relaxed);
        const auto value = SampleFunction(static_cast<int>(g_counter.load(std::memory_order_relaxed)));
        std::cout << "g_counter=0x" << std::hex << g_counter.load(std::memory_order_relaxed)
                  << " sample=" << value << std::dec << '\n';
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}