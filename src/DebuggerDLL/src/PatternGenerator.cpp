#include "PatternGenerator.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
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

struct CandidateRegionContext {
    std::uintptr_t start = 0;
    std::uintptr_t end = 0;
    bool executable = false;
};

[[nodiscard]] bool TryGetCandidateRegionContext(
    const std::uintptr_t address,
    CandidateRegionContext& context) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT) {
        return false;
    }

    context.start = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
    context.end = context.start + mbi.RegionSize;
    context.executable = IsExecutableProtection(mbi.Protect);
    return true;
}

[[nodiscard]] bool CopyBytesGuarded(
    const std::uintptr_t address,
    const std::size_t size,
    std::uint8_t* output) noexcept {
    __try {
        std::memcpy(output, reinterpret_cast<const void*>(address), size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
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
    std::string& error,
    MemoryAccessDiagnostics* diagnostics) const {
    error.clear();
    if (diagnostics != nullptr) {
        *diagnostics = {};
        diagnostics->address = address;
        diagnostics->size = 1;
    }
    if (address == 0) {
        error = "address_required";
        return false;
    }
    if (maxBytes == 0 || maxBytes > kMaxGeneratedPatternBytes) {
        error = "invalid_max_bytes";
        return false;
    }
    if (!memoryReader_.IsReadable(address, 1, diagnostics)) {
        error = "memory_read_failed";
        return false;
    }

    CandidateRegionContext candidateRegion{};
    if (!TryGetCandidateRegionContext(address, candidateRegion)) {
        error = "memory_read_failed";
        return false;
    }

    const auto readableRegions = memoryReader_.EnumerateReadableRegions(std::nullopt, std::nullopt);
    std::vector<std::uint8_t> bytes;
    bytes.reserve(maxBytes);
    std::vector<PatternByte> exact;
    exact.reserve(maxBytes);
    std::vector<PatternByte> codeAware;
    codeAware.reserve(maxBytes);
    const auto maxOffsetByStart = address - candidateRegion.start;
    const auto bytesAvailableFromAddress = candidateRegion.end - address;
    for (std::size_t length = 1; length <= maxBytes; ++length) {
        const auto minOffsetByEnd = length > bytesAvailableFromAddress ? length - bytesAvailableFromAddress : 0;
        const auto maxTargetOffset = std::min(length - 1, maxOffsetByStart);
        if (minOffsetByEnd > maxTargetOffset) {
            continue;
        }

        for (std::size_t targetOffset = minOffsetByEnd; targetOffset <= maxTargetOffset; ++targetOffset) {
            if (address < targetOffset) {
                break;
            }

            const auto start = address - targetOffset;
            bytes.resize(length);
            if (!CopyBytesGuarded(start, length, bytes.data())) {
                continue;
            }

            BuildExactPattern(bytes, exact);
            bool hasCodeAwareWildcards = false;
            if (candidateRegion.executable) {
                hasCodeAwareWildcards = BuildCodeAwarePattern(start, bytes, codeAware);
            } else {
                codeAware.clear();
            }

            std::fill(bytes.begin(), bytes.end(), static_cast<std::uint8_t>(0));

            if (candidateRegion.executable && hasCodeAwareWildcards) {
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
    const auto compiled = patternScanner_.CompilePattern(pattern);
    const auto matches = patternScanner_.ScanCompiledPrepared(compiled, regions, 2);
    return matches.size() == 1 && matches.front() == expectedMatch;
}

void PatternGenerator::BuildExactPattern(
    const std::vector<std::uint8_t>& bytes,
    std::vector<PatternByte>& pattern) const {
    pattern.clear();
    pattern.reserve(bytes.size());
    for (const auto byte : bytes) {
        pattern.push_back(PatternByte{byte, false});
    }
}

bool PatternGenerator::BuildCodeAwarePattern(
    const std::uintptr_t start,
    const std::vector<std::uint8_t>& bytes,
    std::vector<PatternByte>& pattern) const {
    BuildExactPattern(bytes, pattern);
    bool hasWildcards = false;
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
                if (!pattern[offset + index].wildcard) {
                    pattern[offset + index].wildcard = true;
                    hasWildcards = true;
                }
            }
            continue;
        }

        if (instruction.mnemonic == "mov" &&
            instruction.operands.find("[rip") != std::string::npos &&
            instruction.bytes.size() >= 7) {
            const auto wildcardStart = instruction.bytes.size() - 4;
            for (std::size_t index = wildcardStart; index < instruction.bytes.size() && offset + index < pattern.size(); ++index) {
                if (!pattern[offset + index].wildcard) {
                    pattern[offset + index].wildcard = true;
                    hasWildcards = true;
                }
            }
        }
    }

    return hasWildcards;
}

}  // namespace idmcp