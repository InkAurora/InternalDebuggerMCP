#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace idmcp {

struct DereferenceStep {
    std::uintptr_t address;
    std::uintptr_t value;
    bool success;
};

class MemoryReader {
public:
    [[nodiscard]] bool IsReadable(std::uintptr_t address, std::size_t size) const;
    [[nodiscard]] bool ReadBytes(std::uintptr_t address, std::size_t size, std::vector<std::uint8_t>& output) const;
    [[nodiscard]] bool ReadPointer(std::uintptr_t address, std::size_t pointerSize, std::uintptr_t& value) const;
    [[nodiscard]] std::vector<DereferenceStep> DereferenceChain(
        std::uintptr_t address,
        std::size_t depth,
        std::size_t pointerSize) const;
    [[nodiscard]] std::vector<MEMORY_BASIC_INFORMATION> EnumerateReadableRegions(
        std::optional<std::uintptr_t> start,
        std::optional<std::size_t> length) const;
};

}  // namespace idmcp
