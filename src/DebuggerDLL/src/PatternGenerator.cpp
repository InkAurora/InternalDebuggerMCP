#include "PatternGenerator.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <format>
#include <utility>

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

bool TryBuildCodeAwareWildcardSpans(
    const Disassembler& disassembler,
    const std::uintptr_t start,
    std::span<const std::uint8_t> bytes,
    std::vector<WildcardSpan>& spans) {
    static_cast<void>(start);
    return disassembler.FindCodeAwareWildcardSpans(bytes, spans);
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
    const auto maxOffsetByStart = std::min(maxBytes - 1, address - candidateRegion.start);
    const auto bytesAvailableFromAddress = candidateRegion.end - address;
    const auto maxForwardBytes = std::min(maxBytes, bytesAvailableFromAddress);
    const auto windowStart = address - maxOffsetByStart;
    const auto windowSize = maxOffsetByStart + maxForwardBytes;

    std::vector<std::uint8_t> rawWindow(windowSize);
    if (!CopyBytesGuarded(windowStart, windowSize, rawWindow.data())) {
        error = "memory_read_failed";
        return false;
    }

    std::vector<PatternByte> exactWindow;
    exactWindow.reserve(windowSize);
    for (const auto byte : rawWindow) {
        exactWindow.push_back(PatternByte{byte, false});
    }

    std::vector<std::vector<WildcardSpan>> wildcardSpansByStart;
    if (candidateRegion.executable) {
        wildcardSpansByStart.resize(maxOffsetByStart + 1);
        for (std::size_t startOffset = 0; startOffset <= maxOffsetByStart; ++startOffset) {
            TryBuildCodeAwareWildcardSpans(
                disassembler_,
                windowStart + startOffset,
                std::span<const std::uint8_t>(rawWindow.data() + static_cast<std::ptrdiff_t>(startOffset), rawWindow.size() - startOffset),
                wildcardSpansByStart[startOffset]);
        }
    }

    std::fill(rawWindow.begin(), rawWindow.end(), static_cast<std::uint8_t>(0));
    rawWindow.clear();

    std::vector<PatternByte> exact;
    exact.reserve(maxBytes);
    std::vector<PatternByte> codeAware;
    codeAware.reserve(maxBytes);

    auto applyCodeAwareWildcards = [&codeAware](
                                     const std::vector<WildcardSpan>& spans,
                                     const std::size_t length) -> bool {
        bool hasWildcards = false;
        for (const auto& span : spans) {
            if (span.start >= length) {
                continue;
            }

            const auto wildcardEnd = std::min(span.end, length);
            for (std::size_t index = span.start; index < wildcardEnd; ++index) {
                if (!codeAware[index].wildcard) {
                    codeAware[index].wildcard = true;
                    hasWildcards = true;
                }
            }
        }

        return hasWildcards;
    };

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
            const auto startOffset = static_cast<std::size_t>(start - windowStart);
            BuildExactPattern(exactWindow.data() + startOffset, length, exact);
            bool hasCodeAwareWildcards = false;
            if (candidateRegion.executable) {
                codeAware = exact;
                hasCodeAwareWildcards = applyCodeAwareWildcards(wildcardSpansByStart[startOffset], length);
            } else {
                codeAware.clear();
            }

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
    const PatternByte* bytes,
    const std::size_t size,
    std::vector<PatternByte>& pattern) const {
    pattern.clear();
    pattern.insert(pattern.end(), bytes, bytes + static_cast<std::ptrdiff_t>(size));
}

}  // namespace idmcp