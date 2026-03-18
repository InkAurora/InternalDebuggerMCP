#include "PatternScanner.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <sstream>
#include <span>

#include "DebuggerProtocol.h"

namespace idmcp {

namespace {

[[nodiscard]] std::string StripWhitespace(std::string_view value) {
    std::string normalized;
    normalized.reserve(value.size());
    for (const auto ch : value) {
        if (!std::isspace(static_cast<unsigned char>(ch))) {
            normalized.push_back(ch);
        }
    }
    return normalized;
}

[[nodiscard]] bool MatchesAtGuarded(std::span<const PatternByte> pattern, const std::uint8_t* candidate) noexcept {
    __try {
        for (std::size_t index = 0; index < pattern.size(); ++index) {
            if (pattern[index].wildcard) {
                continue;
            }
            if (candidate[index] != pattern[index].value) {
                return false;
            }
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

[[nodiscard]] bool MatchesCompiledAt(const CompiledPattern& pattern, const std::uint8_t* candidate) noexcept {
    for (const auto& exactByte : pattern.exactBytes) {
        if (candidate[exactByte.offset] != exactByte.value) {
            return false;
        }
    }

    return true;
}

[[nodiscard]] const std::uint8_t* FindAnchorMatch(
    const std::uint8_t* begin,
    const std::uint8_t* end,
    const CompiledPattern& pattern) noexcept {
    if (pattern.anchorLength == 0 || begin >= end) {
        return nullptr;
    }

    const auto anchorFirstByte = pattern.pattern[pattern.anchorOffset].value;
    const auto* cursor = begin;
    const auto* last = end - static_cast<std::ptrdiff_t>(pattern.anchorLength);
    while (cursor <= last) {
        const auto remaining = static_cast<std::size_t>(last - cursor + 1);
        const auto* candidate = static_cast<const std::uint8_t*>(std::memchr(cursor, anchorFirstByte, remaining));
        if (candidate == nullptr) {
            return nullptr;
        }

        bool matches = true;
        for (std::size_t index = 1; index < pattern.anchorLength; ++index) {
            if (candidate[index] != pattern.pattern[pattern.anchorOffset + index].value) {
                matches = false;
                break;
            }
        }
        if (matches) {
            return candidate;
        }
        cursor = candidate + 1;
    }

    return nullptr;
}

}  // namespace

PatternScanner::PatternScanner(const MemoryReader& memoryReader) : memoryReader_(memoryReader) {}

bool PatternScanner::ParsePattern(
    const std::string& patternText,
    const std::optional<std::string>& maskText,
    std::vector<PatternByte>& pattern,
    std::string& error) const {
    pattern.clear();
    error.clear();

    std::istringstream stream(patternText);
    std::string token;
    std::vector<bool> tokenWildcards;
    while (stream >> token) {
        if (token == "??" || token == "?") {
            pattern.push_back(PatternByte{0, true});
            tokenWildcards.push_back(true);
            continue;
        }

        unsigned int value = 0;
        std::istringstream converter(token);
        converter >> std::hex >> value;
        if (converter.fail() || value > 0xFFU) {
            pattern.clear();
            error = "pattern must be space-separated hex bytes or ?? wildcards";
            return false;
        }
        pattern.push_back(PatternByte{static_cast<std::uint8_t>(value), false});
        tokenWildcards.push_back(false);
    }

    if (pattern.empty()) {
        error = "pattern must be space-separated hex bytes or ?? wildcards";
        return false;
    }

    if (!maskText.has_value()) {
        return true;
    }

    const auto mask = StripWhitespace(*maskText);
    if (mask.size() != pattern.size()) {
        pattern.clear();
        error = "mask length must match the pattern byte count";
        return false;
    }

    for (std::size_t index = 0; index < mask.size(); ++index) {
        const auto marker = static_cast<char>(std::tolower(static_cast<unsigned char>(mask[index])));
        if (marker == 'x') {
            if (tokenWildcards[index]) {
                pattern.clear();
                error = "mask marks an exact byte where the pattern uses ??";
                return false;
            }
            pattern[index].wildcard = false;
            continue;
        }
        if (marker == '?') {
            pattern[index].wildcard = true;
            continue;
        }

        pattern.clear();
        error = "mask must contain only x and ? characters";
        return false;
    }

    return true;
}

CompiledPattern PatternScanner::CompilePattern(const std::vector<PatternByte>& pattern) const {
    CompiledPattern compiled;
    compiled.pattern = pattern;
    compiled.exactBytes.reserve(pattern.size());

    std::size_t bestAnchorStart = 0;
    std::size_t bestAnchorLength = 0;
    std::size_t currentAnchorStart = 0;
    std::size_t currentAnchorLength = 0;

    for (std::size_t index = 0; index < pattern.size(); ++index) {
        if (pattern[index].wildcard) {
            if (currentAnchorLength > bestAnchorLength) {
                bestAnchorStart = currentAnchorStart;
                bestAnchorLength = currentAnchorLength;
            }
            currentAnchorLength = 0;
            continue;
        }

        compiled.exactBytes.push_back(ExactPatternByte{index, pattern[index].value});
        if (currentAnchorLength == 0) {
            currentAnchorStart = index;
        }
        ++currentAnchorLength;
    }

    if (currentAnchorLength > bestAnchorLength) {
        bestAnchorStart = currentAnchorStart;
        bestAnchorLength = currentAnchorLength;
    }

    compiled.anchorOffset = bestAnchorStart;
    compiled.anchorLength = bestAnchorLength;

    return compiled;
}

std::vector<std::uintptr_t> PatternScanner::Scan(
    const std::vector<PatternByte>& pattern,
    const std::optional<std::uintptr_t> start,
    const std::optional<std::size_t> length,
    const std::size_t limit) const {
    const auto compiled = CompilePattern(pattern);
    return ScanCompiled(compiled, start, length, limit);
}

std::vector<std::uintptr_t> PatternScanner::ScanCompiled(
    const CompiledPattern& pattern,
    const std::optional<std::uintptr_t> start,
    const std::optional<std::size_t> length,
    const std::size_t limit) const {
    const auto regions = memoryReader_.EnumerateReadableRegions(start, length);
    return ScanCompiledPrepared(pattern, regions, limit);
}

std::vector<std::uintptr_t> PatternScanner::ScanPrepared(
    const std::vector<PatternByte>& pattern,
    const ReadableMemoryRegions& regions,
    const std::size_t limit) const {
    const auto compiled = CompilePattern(pattern);
    return ScanCompiledPrepared(compiled, regions, limit);
}

std::vector<std::uintptr_t> PatternScanner::ScanCompiledPrepared(
    const CompiledPattern& pattern,
    const ReadableMemoryRegions& regions,
    const std::size_t limit) const {
    std::vector<std::uintptr_t> matches;
    if (pattern.pattern.empty() || limit == 0) {
        return matches;
    }

    for (const auto& region : regions) {
        const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
        if (region.RegionSize < pattern.pattern.size()) {
            continue;
        }

        const auto* bytes = reinterpret_cast<const std::uint8_t*>(base);
        const auto last = region.RegionSize - pattern.pattern.size();
        if (pattern.anchorLength == pattern.pattern.size()) {
            const auto* cursor = bytes;
            const auto* end = bytes + region.RegionSize;
            while (const auto* match = FindAnchorMatch(cursor, end, pattern)) {
                matches.push_back(base + static_cast<std::uintptr_t>(match - bytes));
                if (matches.size() >= limit) {
                    return matches;
                }
                cursor = match + 1;
            }
            continue;
        }

        if (pattern.anchorLength != 0) {
            const auto searchStart = bytes + pattern.anchorOffset;
            const auto searchLength = region.RegionSize - pattern.anchorOffset;
            const auto* cursor = searchStart;
            const auto* end = searchStart + searchLength;
            while (const auto* match = FindAnchorMatch(cursor, end, pattern)) {
                const auto matchOffset = static_cast<std::size_t>(match - bytes);
                if (matchOffset >= pattern.anchorOffset) {
                    const auto candidateOffset = matchOffset - pattern.anchorOffset;
                    if (candidateOffset <= last && MatchesCompiledAt(pattern, bytes + candidateOffset)) {
                        matches.push_back(base + candidateOffset);
                        if (matches.size() >= limit) {
                            return matches;
                        }
                    }
                }
                cursor = match + 1;
            }
            continue;
        }

        for (std::size_t offset = 0; offset <= last; ++offset) {
            if (!MatchesAtGuarded(pattern.pattern, bytes + offset)) {
                continue;
            }

            matches.push_back(base + offset);
            if (matches.size() >= limit) {
                return matches;
            }
        }
    }

    return matches;
}

}  // namespace idmcp
