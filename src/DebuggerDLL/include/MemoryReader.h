#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace idmcp {

struct DereferenceStep {
    std::uintptr_t address;
    std::uintptr_t value;
    bool success;
};

struct MemoryAccessDiagnostics {
    std::uintptr_t address{0};
    std::size_t size{0};
    std::uintptr_t regionBase{0};
    std::size_t regionSize{0};
    DWORD state{0};
    DWORD protect{0};
    DWORD queryError{ERROR_SUCCESS};
    DWORD copyExceptionCode{0};
    bool hasRegion{false};
    std::string reason;
};

class MemoryReader {
public:
    [[nodiscard]] bool IsReadable(
        std::uintptr_t address,
        std::size_t size,
        MemoryAccessDiagnostics* diagnostics = nullptr) const;
    [[nodiscard]] bool IsWritable(
        std::uintptr_t address,
        std::size_t size,
        MemoryAccessDiagnostics* diagnostics = nullptr) const;
    [[nodiscard]] bool ReadBytes(
        std::uintptr_t address,
        std::size_t size,
        std::vector<std::uint8_t>& output,
        MemoryAccessDiagnostics* diagnostics = nullptr) const;
    [[nodiscard]] bool WriteBytes(
        std::uintptr_t address,
        const std::vector<std::uint8_t>& bytes,
        MemoryAccessDiagnostics* diagnostics = nullptr) const;
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
