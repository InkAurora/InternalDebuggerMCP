#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "Disassembler.h"
#include "PatternScanner.h"

namespace idmcp {

struct GeneratedPatternResult {
    std::uintptr_t address;
    std::uintptr_t patternStart;
    std::size_t targetOffset;
    std::vector<PatternByte> pattern;
    std::size_t matchCount;
};

class MemoryReader;

class PatternGenerator {
public:
    PatternGenerator(const MemoryReader& memoryReader, const PatternScanner& patternScanner, const Disassembler& disassembler);

    [[nodiscard]] bool Generate(
        std::uintptr_t address,
        std::size_t maxBytes,
        GeneratedPatternResult& result,
        std::string& error) const;

    [[nodiscard]] static std::string FormatPattern(const std::vector<PatternByte>& pattern);
    [[nodiscard]] static std::string FormatMask(const std::vector<PatternByte>& pattern);
    [[nodiscard]] static std::size_t CountWildcards(const std::vector<PatternByte>& pattern);

private:
    [[nodiscard]] bool IsUniqueCandidate(
        const std::vector<PatternByte>& pattern,
        std::uintptr_t expectedMatch,
        const ReadableMemoryRegions& regions) const;
    [[nodiscard]] bool IsExecutableAddress(std::uintptr_t address) const;
    [[nodiscard]] std::vector<PatternByte> BuildExactPattern(const std::vector<std::uint8_t>& bytes) const;
    [[nodiscard]] std::vector<PatternByte> BuildCodeAwarePattern(std::uintptr_t start, const std::vector<std::uint8_t>& bytes) const;

    const MemoryReader& memoryReader_;
    const PatternScanner& patternScanner_;
    const Disassembler& disassembler_;
};

}  // namespace idmcp