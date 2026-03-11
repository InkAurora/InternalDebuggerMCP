#include "PatternScanner.h"

#include <Windows.h>

#include <algorithm>
#include <sstream>

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

std::vector<std::uintptr_t> PatternScanner::Scan(
    const std::vector<PatternByte>& pattern,
    const std::optional<std::uintptr_t> start,
    const std::optional<std::size_t> length,
    const std::size_t limit) const {
    std::vector<std::uintptr_t> matches;
    if (pattern.empty() || limit == 0) {
        return matches;
    }

    const auto regions = memoryReader_.EnumerateReadableRegions(start, length);
    for (const auto& region : regions) {
        const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
        if (region.RegionSize < pattern.size()) {
            continue;
        }

        const auto* bytes = reinterpret_cast<const std::uint8_t*>(base);
        const auto last = region.RegionSize - pattern.size();
        for (std::size_t offset = 0; offset <= last; ++offset) {
            if (!MatchesAtGuarded(pattern, bytes + offset)) {
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

bool PatternScanner::MatchesAt(const std::vector<PatternByte>& pattern, const std::uint8_t* candidate) const {
    for (std::size_t index = 0; index < pattern.size(); ++index) {
        if (pattern[index].wildcard) {
            continue;
        }
        if (candidate[index] != pattern[index].value) {
            return false;
        }
    }
    return true;
}

}  // namespace idmcp
