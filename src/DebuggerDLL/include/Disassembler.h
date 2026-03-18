#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace idmcp {

struct Instruction {
    std::uintptr_t address;
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
};

struct WildcardSpan {
    std::size_t start;
    std::size_t end;
};

class Disassembler {
public:
    [[nodiscard]] bool FindCodeAwareWildcardSpans(
        std::span<const std::uint8_t> bytes,
        std::vector<WildcardSpan>& spans) const;
    [[nodiscard]] std::vector<Instruction> Disassemble(
        std::uintptr_t address,
        std::span<const std::uint8_t> bytes,
        std::size_t maxInstructions) const;
    [[nodiscard]] std::vector<Instruction> Disassemble(
        std::uintptr_t address,
        const std::vector<std::uint8_t>& bytes,
        std::size_t maxInstructions) const;
};

}  // namespace idmcp
