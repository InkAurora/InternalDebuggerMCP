#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace idmcp {

struct Instruction {
    std::uintptr_t address;
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
};

class Disassembler {
public:
    [[nodiscard]] std::vector<Instruction> Disassemble(
        std::uintptr_t address,
        const std::vector<std::uint8_t>& bytes,
        std::size_t maxInstructions) const;
};

}  // namespace idmcp
