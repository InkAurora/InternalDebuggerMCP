#include "PatternScanner.h"

#include <Windows.h>

#include <algorithm>
#include <sstream>

#include "DebuggerProtocol.h"

namespace idmcp {

namespace {

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

bool PatternScanner::ParsePattern(const std::string& patternText, std::vector<PatternByte>& pattern) const {
    pattern.clear();
    std::istringstream stream(patternText);
    std::string token;
    while (stream >> token) {
        if (token == "??" || token == "?") {
            pattern.push_back(PatternByte{0, true});
            continue;
        }

        unsigned int value = 0;
        std::istringstream converter(token);
        converter >> std::hex >> value;
        if (converter.fail() || value > 0xFFU) {
            pattern.clear();
            return false;
        }
        pattern.push_back(PatternByte{static_cast<std::uint8_t>(value), false});
    }

    return !pattern.empty();
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
