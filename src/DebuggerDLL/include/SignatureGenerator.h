#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "Disassembler.h"
#include "PatternScanner.h"

namespace idmcp {

struct GeneratedSignatureResult {
    std::uintptr_t address;
    std::uintptr_t baseAddress;
    std::uint32_t imageSize;
    std::string moduleName;
    std::string modulePath;
    std::vector<PatternByte> pattern;
    std::size_t matchCount;
};

class MemoryReader;
struct MemoryAccessDiagnostics;

class SignatureGenerator {
public:
    SignatureGenerator(const MemoryReader& memoryReader, const PatternScanner& patternScanner, const Disassembler& disassembler);

    [[nodiscard]] bool Generate(
        std::uintptr_t address,
        std::size_t maxBytes,
        GeneratedSignatureResult& result,
        std::string& error,
        MemoryAccessDiagnostics* diagnostics = nullptr) const;

private:
    [[nodiscard]] bool IsUniqueCandidate(
        const std::vector<PatternByte>& pattern,
        std::uintptr_t expectedMatch,
        const ReadableMemoryRegions& regions) const;
    void BuildExactPattern(const PatternByte* bytes, std::size_t size, std::vector<PatternByte>& pattern) const;

    const MemoryReader& memoryReader_;
    const PatternScanner& patternScanner_;
    const Disassembler& disassembler_;
};

}  // namespace idmcp