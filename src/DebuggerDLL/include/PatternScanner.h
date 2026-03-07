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

class PatternScanner {
public:
    explicit PatternScanner(const MemoryReader& memoryReader);

    [[nodiscard]] bool ParsePattern(const std::string& patternText, std::vector<PatternByte>& pattern) const;
    [[nodiscard]] std::vector<std::uintptr_t> Scan(
        const std::vector<PatternByte>& pattern,
        std::optional<std::uintptr_t> start,
        std::optional<std::size_t> length,
        std::size_t limit) const;

private:
    [[nodiscard]] bool MatchesAt(const std::vector<PatternByte>& pattern, const std::uint8_t* candidate) const;

    const MemoryReader& memoryReader_;
};

}  // namespace idmcp
