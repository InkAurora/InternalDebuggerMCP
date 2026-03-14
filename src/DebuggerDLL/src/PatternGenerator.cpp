#include "PatternGenerator.h"

#include <Windows.h>

#include <algorithm>
#include <format>

#include "DebuggerProtocol.h"
#include "MemoryReader.h"

namespace idmcp {

namespace {

[[nodiscard]] bool IsExecutableProtection(const DWORD protect) {
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) {
        return false;
    }

    const DWORD baseProtect = protect & 0xFFU;
    return baseProtect == PAGE_EXECUTE ||
           baseProtect == PAGE_EXECUTE_READ ||
           baseProtect == PAGE_EXECUTE_READWRITE ||
           baseProtect == PAGE_EXECUTE_WRITECOPY;
}

}  // namespace

PatternGenerator::PatternGenerator(
    const MemoryReader& memoryReader,
    const PatternScanner& patternScanner,
    const Disassembler& disassembler)
    : memoryReader_(memoryReader), patternScanner_(patternScanner), disassembler_(disassembler) {}

bool PatternGenerator::Generate(
    const std::uintptr_t address,
    const std::size_t maxBytes,
    GeneratedPatternResult& result,
    std::string& error) const {
    error.clear();
    if (address == 0) {
        error = "address_required";
        return false;
    }
    if (maxBytes == 0 || maxBytes > kMaxGeneratedPatternBytes) {
        error = "invalid_max_bytes";
        return false;
    }
    if (!memoryReader_.IsReadable(address, 1)) {
        error = "memory_read_failed";
        return false;
    }

    const bool executable = IsExecutableAddress(address);
    const auto readableRegions = memoryReader_.EnumerateReadableRegions(std::nullopt, std::nullopt);
    for (std::size_t length = 1; length <= maxBytes; ++length) {
        for (std::size_t targetOffset = 0; targetOffset < length; ++targetOffset) {
            if (address < targetOffset) {
                continue;
            }

            const auto start = address - targetOffset;
            std::vector<std::uint8_t> bytes;
            if (!memoryReader_.ReadBytes(start, length, bytes)) {
                continue;
            }

            auto exact = BuildExactPattern(bytes);
            std::vector<PatternByte> codeAware;
            if (executable) {
                codeAware = BuildCodeAwarePattern(start, bytes);
            }

            std::fill(bytes.begin(), bytes.end(), static_cast<std::uint8_t>(0));

            if (executable && CountWildcards(codeAware) > 0) {
                if (IsUniqueCandidate(codeAware, start, readableRegions)) {
                    result = GeneratedPatternResult{
                        .address = address,
                        .patternStart = start,
                        .targetOffset = targetOffset,
                        .pattern = codeAware,
                        .matchCount = 1,
                    };
                    return true;
                }
            }

            if (!IsUniqueCandidate(exact, start, readableRegions)) {
                continue;
            }

            result = GeneratedPatternResult{
                .address = address,
                .patternStart = start,
                .targetOffset = targetOffset,
                .pattern = exact,
                .matchCount = 1,
            };
            return true;
        }
    }

    error = "pattern_generation_failed";
    return false;
}

std::string PatternGenerator::FormatPattern(const std::vector<PatternByte>& pattern) {
    std::string formatted;
    formatted.reserve(pattern.size() * 3);
    for (std::size_t index = 0; index < pattern.size(); ++index) {
        if (index != 0) {
            formatted.push_back(' ');
        }
        if (pattern[index].wildcard) {
            formatted += "??";
            continue;
        }
        formatted += std::format("{:02X}", pattern[index].value);
    }
    return formatted;
}

std::string PatternGenerator::FormatMask(const std::vector<PatternByte>& pattern) {
    std::string mask;
    mask.reserve(pattern.size());
    for (const auto& byte : pattern) {
        mask.push_back(byte.wildcard ? '?' : 'x');
    }
    return mask;
}

std::size_t PatternGenerator::CountWildcards(const std::vector<PatternByte>& pattern) {
    return static_cast<std::size_t>(std::count_if(pattern.begin(), pattern.end(), [](const PatternByte& byte) {
        return byte.wildcard;
    }));
}

bool PatternGenerator::IsUniqueCandidate(
    const std::vector<PatternByte>& pattern,
    const std::uintptr_t expectedMatch,
    const ReadableMemoryRegions& regions) const {
    const auto matches = patternScanner_.ScanPrepared(pattern, regions, 2);
    return matches.size() == 1 && matches.front() == expectedMatch;
}

bool PatternGenerator::IsExecutableAddress(const std::uintptr_t address) const {
    MEMORY_BASIC_INFORMATION mbi{};
    return VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi) &&
           mbi.State == MEM_COMMIT &&
           IsExecutableProtection(mbi.Protect);
}

std::vector<PatternByte> PatternGenerator::BuildExactPattern(const std::vector<std::uint8_t>& bytes) const {
    std::vector<PatternByte> pattern;
    pattern.reserve(bytes.size());
    for (const auto byte : bytes) {
        pattern.push_back(PatternByte{byte, false});
    }
    return pattern;
}

std::vector<PatternByte> PatternGenerator::BuildCodeAwarePattern(
    const std::uintptr_t start,
    const std::vector<std::uint8_t>& bytes) const {
    auto pattern = BuildExactPattern(bytes);
    const auto instructions = disassembler_.Disassemble(start, bytes, bytes.size());
    for (const auto& instruction : instructions) {
        const auto offset = static_cast<std::size_t>(instruction.address - start);
        if (instruction.bytes.empty() || offset >= pattern.size()) {
            continue;
        }

        if ((instruction.mnemonic == "call" || instruction.mnemonic == "jmp") &&
            instruction.bytes.size() == 5 &&
            (instruction.bytes[0] == 0xE8 || instruction.bytes[0] == 0xE9)) {
            for (std::size_t index = 1; index < instruction.bytes.size() && offset + index < pattern.size(); ++index) {
                pattern[offset + index].wildcard = true;
            }
            continue;
        }

        if (instruction.mnemonic == "mov" &&
            instruction.operands.find("[rip") != std::string::npos &&
            instruction.bytes.size() >= 7) {
            const auto wildcardStart = instruction.bytes.size() - 4;
            for (std::size_t index = wildcardStart; index < instruction.bytes.size() && offset + index < pattern.size(); ++index) {
                pattern[offset + index].wildcard = true;
            }
        }
    }

    return pattern;
}

}  // namespace idmcp