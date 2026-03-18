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

struct ExactPatternByte {
    std::size_t offset;
    std::uint8_t value;
};

struct CompiledPattern {
    std::vector<PatternByte> pattern;
    std::vector<ExactPatternByte> exactBytes;
    std::size_t anchorOffset{0};
    std::size_t anchorLength{0};
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
    [[nodiscard]] CompiledPattern CompilePattern(const std::vector<PatternByte>& pattern) const;
    [[nodiscard]] std::vector<std::uintptr_t> Scan(
        const std::vector<PatternByte>& pattern,
        std::optional<std::uintptr_t> start,
        std::optional<std::size_t> length,
        std::size_t limit) const;
    [[nodiscard]] std::vector<std::uintptr_t> ScanCompiled(
        const CompiledPattern& pattern,
        std::optional<std::uintptr_t> start,
        std::optional<std::size_t> length,
        std::size_t limit) const;
    [[nodiscard]] std::vector<std::uintptr_t> ScanPrepared(
        const std::vector<PatternByte>& pattern,
        const ReadableMemoryRegions& regions,
        std::size_t limit) const;
    [[nodiscard]] std::vector<std::uintptr_t> ScanCompiledPrepared(
        const CompiledPattern& pattern,
        const ReadableMemoryRegions& regions,
        std::size_t limit) const;

private:
    const MemoryReader& memoryReader_;
};

}  // namespace idmcp
