#include "Disassembler.h"

#include <algorithm>
#include <array>
#include <format>

namespace idmcp {

namespace {

[[nodiscard]] std::string FormatDisplacement(const std::int32_t displacement) {
    if (displacement < 0) {
        return std::format("-0x{:X}", static_cast<std::uint32_t>(-displacement));
    }
    return std::format("+0x{:X}", static_cast<std::uint32_t>(displacement));
}

[[nodiscard]] std::string FormatMemoryOperand(
    const std::uint8_t modrm,
    const std::vector<std::uint8_t>& bytes,
    const std::size_t offset,
    const std::uint8_t rex) {
    constexpr std::array<const char*, 16> registerNames{
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    };

    const auto mod = (modrm >> 6U) & 0x03U;
    const auto rm = (modrm & 0x07U) | (((rex >> 0U) & 0x01U) << 3U);
    if (mod == 0b11U) {
        return registerNames[rm];
    }
    if ((modrm & 0x07U) == 0b100U) {
        return "[sib]";
    }

    if (mod == 0b00U && (modrm & 0x07U) == 0b101U) {
        const auto displacement = *reinterpret_cast<const std::int32_t*>(&bytes[offset]);
        return std::format("[rip{}]", FormatDisplacement(displacement));
    }
    if (mod == 0b00U) {
        return std::format("[{}]", registerNames[rm]);
    }
    if (mod == 0b01U) {
        const auto displacement = static_cast<std::int8_t>(bytes[offset]);
        return std::format("[{}{}]", registerNames[rm], FormatDisplacement(displacement));
    }

    const auto displacement = *reinterpret_cast<const std::int32_t*>(&bytes[offset]);
    return std::format("[{}{}]", registerNames[rm], FormatDisplacement(displacement));
}

[[nodiscard]] std::size_t MemoryOperandLength(const std::uint8_t modrm) {
    const auto mod = (modrm >> 6U) & 0x03U;
    const auto rm = modrm & 0x07U;
    if (mod == 0b11U) {
        return 0;
    }
    if (rm == 0b100U) {
        return 0;
    }
    if (mod == 0b00U && rm == 0b101U) {
        return 4;
    }
    if (mod == 0b01U) {
        return 1;
    }
    if (mod == 0b10U) {
        return 4;
    }
    return 0;
}

[[nodiscard]] std::string RegisterOperand(const std::uint8_t modrm, const std::uint8_t rex) {
    constexpr std::array<const char*, 16> registerNames{
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    };
    const auto reg = ((modrm >> 3U) & 0x07U) | (((rex >> 2U) & 0x01U) << 3U);
    return registerNames[reg];
}

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

        if (remaining >= 3 && bytes[offset] == 0x48 && (bytes[offset + 1] == 0x89 || bytes[offset + 1] == 0x8B)) {
            const auto modrm = bytes[offset + 2];
            const auto displacementLength = MemoryOperandLength(modrm);
            if (displacementLength > 0 || ((modrm >> 6U) & 0x03U) != 0b11U) {
                const auto instructionLength = 3 + displacementLength;
                if (remaining >= instructionLength) {
                    std::vector<std::uint8_t> instructionBytes(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.begin() + static_cast<std::ptrdiff_t>(offset + instructionLength));
                    const auto memoryOperand = FormatMemoryOperand(modrm, bytes, offset + 3, 0x48);
                    const auto registerOperand = RegisterOperand(modrm, 0x48);
                    if (bytes[offset + 1] == 0x89) {
                        instructions.push_back(Instruction{
                            .address = currentAddress,
                            .bytes = std::move(instructionBytes),
                            .mnemonic = "mov",
                            .operands = std::format("{}, {}", memoryOperand, registerOperand),
                        });
                    } else {
                        instructions.push_back(Instruction{
                            .address = currentAddress,
                            .bytes = std::move(instructionBytes),
                            .mnemonic = "mov",
                            .operands = std::format("{}, {}", registerOperand, memoryOperand),
                        });
                    }
                    offset += instructionLength;
                    continue;
                }
            }
        }

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
