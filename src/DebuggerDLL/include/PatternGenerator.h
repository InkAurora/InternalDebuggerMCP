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
struct MemoryAccessDiagnostics;

class PatternGenerator {
public:
    PatternGenerator(const MemoryReader& memoryReader, const PatternScanner& patternScanner, const Disassembler& disassembler);

    [[nodiscard]] bool Generate(
        std::uintptr_t address,
        std::size_t maxBytes,
        GeneratedPatternResult& result,
        std::string& error,
        MemoryAccessDiagnostics* diagnostics = nullptr) const;

    [[nodiscard]] static std::string FormatPattern(const std::vector<PatternByte>& pattern);
    [[nodiscard]] static std::string FormatMask(const std::vector<PatternByte>& pattern);
    [[nodiscard]] static std::size_t CountWildcards(const std::vector<PatternByte>& pattern);

private:
    [[nodiscard]] bool IsUniqueCandidate(
        const std::vector<PatternByte>& pattern,
        std::uintptr_t expectedMatch,
        const ReadableMemoryRegions& regions) const;
    void BuildExactPattern(const std::vector<std::uint8_t>& bytes, std::vector<PatternByte>& pattern) const;
    [[nodiscard]] bool BuildCodeAwarePattern(
        std::uintptr_t start,
        const std::vector<std::uint8_t>& bytes,
        std::vector<PatternByte>& pattern) const;

    const MemoryReader& memoryReader_;
    const PatternScanner& patternScanner_;
    const Disassembler& disassembler_;
};

}  // namespace idmcp