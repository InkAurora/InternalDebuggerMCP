#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "MemoryReader.h"

namespace idmcp {

struct PatternByte {
    std::uint8_t value;
    bool wildcard;
};

using ReadableMemoryRegions = std::vector<MEMORY_BASIC_INFORMATION>;

class PatternScanner {
public:
    explicit PatternScanner(const MemoryReader& memoryReader);

    [[nodiscard]] bool ParsePattern(
        const std::string& patternText,
        const std::optional<std::string>& maskText,
        std::vector<PatternByte>& pattern,
        std::string& error) const;
    [[nodiscard]] std::vector<std::uintptr_t> Scan(
        const std::vector<PatternByte>& pattern,
        std::optional<std::uintptr_t> start,
        std::optional<std::size_t> length,
        std::size_t limit) const;
    [[nodiscard]] std::vector<std::uintptr_t> ScanPrepared(
        const std::vector<PatternByte>& pattern,
        const ReadableMemoryRegions& regions,
        std::size_t limit) const;

private:
    const MemoryReader& memoryReader_;
};

}  // namespace idmcp
