#include "Disassembler.h"

#include <algorithm>
#include <format>

namespace idmcp {

namespace {

Instruction MakeInstruction(
    const std::uintptr_t address,
    std::initializer_list<std::uint8_t> bytes,
    std::string mnemonic,
    std::string operands) {
    return Instruction{
        .address = address,
        .bytes = std::vector<std::uint8_t>(bytes),
        .mnemonic = std::move(mnemonic),
        .operands = std::move(operands),
    };
}

Instruction MakeDbInstruction(const std::uintptr_t address, const std::uint8_t byte) {
    return MakeInstruction(address, {byte}, "db", std::format("0x{:02X}", byte));
}

}  // namespace

std::vector<Instruction> Disassembler::Disassemble(
    const std::uintptr_t address,
    const std::vector<std::uint8_t>& bytes,
    const std::size_t maxInstructions) const {
    std::vector<Instruction> instructions;
    instructions.reserve(std::min<std::size_t>(maxInstructions, bytes.size()));

    std::size_t offset = 0;
    while (offset < bytes.size() && instructions.size() < maxInstructions) {
        const auto currentAddress = address + offset;
        const auto remaining = bytes.size() - offset;

        if (remaining >= 1 && bytes[offset] == 0x55) {
            instructions.push_back(MakeInstruction(currentAddress, {0x55}, "push", "rbp"));
            offset += 1;
            continue;
        }
        if (remaining >= 1 && bytes[offset] == 0xC3) {
            instructions.push_back(MakeInstruction(currentAddress, {0xC3}, "ret", ""));
            offset += 1;
            continue;
        }
        if (remaining >= 1 && bytes[offset] == 0x90) {
            instructions.push_back(MakeInstruction(currentAddress, {0x90}, "nop", ""));
            offset += 1;
            continue;
        }
        if (remaining >= 1 && bytes[offset] == 0xCC) {
            instructions.push_back(MakeInstruction(currentAddress, {0xCC}, "int3", ""));
            offset += 1;
            continue;
        }
        if (remaining >= 3 && bytes[offset] == 0x48 && bytes[offset + 1] == 0x89 && bytes[offset + 2] == 0xE5) {
            instructions.push_back(MakeInstruction(currentAddress, {0x48, 0x89, 0xE5}, "mov", "rbp, rsp"));
            offset += 3;
            continue;
        }
        if (remaining >= 4 && bytes[offset] == 0x48 && bytes[offset + 1] == 0x83 && bytes[offset + 2] == 0xEC) {
            instructions.push_back(MakeInstruction(
                currentAddress,
                {0x48, 0x83, 0xEC, bytes[offset + 3]},
                "sub",
                std::format("rsp, 0x{:02X}", bytes[offset + 3])));
            offset += 4;
            continue;
        }
        if (remaining >= 5 && bytes[offset] == 0xE8) {
            const auto rel = *reinterpret_cast<const std::int32_t*>(&bytes[offset + 1]);
            const auto target = static_cast<std::uintptr_t>(currentAddress + 5 + rel);
            instructions.push_back(MakeInstruction(
                currentAddress,
                {bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3], bytes[offset + 4]},
                "call",
                std::format("{}", target)));
            offset += 5;
            continue;
        }
        if (remaining >= 5 && bytes[offset] == 0xE9) {
            const auto rel = *reinterpret_cast<const std::int32_t*>(&bytes[offset + 1]);
            const auto target = static_cast<std::uintptr_t>(currentAddress + 5 + rel);
            instructions.push_back(MakeInstruction(
                currentAddress,
                {bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3], bytes[offset + 4]},
                "jmp",
                std::format("{}", target)));
            offset += 5;
            continue;
        }

        instructions.push_back(MakeDbInstruction(currentAddress, bytes[offset]));
        offset += 1;
    }

    return instructions;
}

}  // namespace idmcp
