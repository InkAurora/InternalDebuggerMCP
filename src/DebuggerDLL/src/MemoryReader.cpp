#include "MemoryReader.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>

namespace idmcp {

namespace {

[[nodiscard]] bool IsReadableProtection(DWORD protect) {
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) {
        return false;
    }

    const DWORD baseProtect = protect & 0xFFU;
    return baseProtect == PAGE_READONLY ||
           baseProtect == PAGE_READWRITE ||
           baseProtect == PAGE_WRITECOPY ||
           baseProtect == PAGE_EXECUTE_READ ||
           baseProtect == PAGE_EXECUTE_READWRITE ||
           baseProtect == PAGE_EXECUTE_WRITECOPY ||
           baseProtect == PAGE_EXECUTE;
}

[[nodiscard]] bool IsWritableProtection(DWORD protect) {
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) {
        return false;
    }

    const DWORD baseProtect = protect & 0xFFU;
    return baseProtect == PAGE_READWRITE ||
           baseProtect == PAGE_WRITECOPY ||
           baseProtect == PAGE_EXECUTE_READWRITE ||
           baseProtect == PAGE_EXECUTE_WRITECOPY;
}

[[nodiscard]] bool IsWithinCommittedRegion(
    const std::uintptr_t address,
    const std::size_t size,
    const DWORD requiredProtect) {
    if (address == 0 || size == 0) {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }

    if (mbi.State != MEM_COMMIT) {
        return false;
    }

    const bool protectOk = requiredProtect == PAGE_READONLY
        ? IsReadableProtection(mbi.Protect)
        : IsWritableProtection(mbi.Protect);
    if (!protectOk) {
        return false;
    }

    const auto regionStart = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
    const auto regionEnd = regionStart + mbi.RegionSize;
    return address >= regionStart && address + size <= regionEnd;
}

}  // namespace

bool MemoryReader::IsReadable(const std::uintptr_t address, const std::size_t size) const {
    return IsWithinCommittedRegion(address, size, PAGE_READONLY);
}

bool MemoryReader::IsWritable(const std::uintptr_t address, const std::size_t size) const {
    return IsWithinCommittedRegion(address, size, PAGE_READWRITE);
}

bool MemoryReader::ReadBytes(
    const std::uintptr_t address,
    const std::size_t size,
    std::vector<std::uint8_t>& output) const {
    output.clear();
    if (!IsReadable(address, size)) {
        return false;
    }

    output.resize(size);
    __try {
        std::memcpy(output.data(), reinterpret_cast<const void*>(address), size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        output.clear();
        return false;
    }
    return true;
}

bool MemoryReader::ReadPointer(
    const std::uintptr_t address,
    const std::size_t pointerSize,
    std::uintptr_t& value) const {
    value = 0;
    if (pointerSize != 4 && pointerSize != 8) {
        return false;
    }

    std::vector<std::uint8_t> bytes;
    if (!ReadBytes(address, pointerSize, bytes)) {
        return false;
    }

    if (pointerSize == 4) {
        value = *reinterpret_cast<const std::uint32_t*>(bytes.data());
    } else {
        value = static_cast<std::uintptr_t>(*reinterpret_cast<const std::uint64_t*>(bytes.data()));
    }
    return true;
}

bool MemoryReader::WriteBytes(const std::uintptr_t address, const std::vector<std::uint8_t>& bytes) const {
    if (bytes.empty() || !IsWritable(address, bytes.size())) {
        return false;
    }

    __try {
        std::memcpy(reinterpret_cast<void*>(address), bytes.data(), bytes.size());
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

std::vector<DereferenceStep> MemoryReader::DereferenceChain(
    const std::uintptr_t address,
    const std::size_t depth,
    const std::size_t pointerSize) const {
    std::vector<DereferenceStep> steps;
    steps.reserve(depth);

    std::uintptr_t current = address;
    for (std::size_t index = 0; index < depth; ++index) {
        std::uintptr_t next = 0;
        const bool success = ReadPointer(current, pointerSize, next);
        steps.push_back(DereferenceStep{current, next, success});
        if (!success || next == 0) {
            break;
        }
        current = next;
    }

    return steps;
}

std::vector<MEMORY_BASIC_INFORMATION> MemoryReader::EnumerateReadableRegions(
    const std::optional<std::uintptr_t> start,
    const std::optional<std::size_t> length) const {
    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);

    std::uintptr_t cursor = start.value_or(reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress));
    const auto globalEnd = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);
    const std::uintptr_t requestedEnd = length.has_value()
        ? std::min(globalEnd, cursor + length.value())
        : globalEnd;

    std::vector<MEMORY_BASIC_INFORMATION> regions;
    while (cursor < requestedEnd) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi)) {
            cursor += 0x1000;
            continue;
        }

        const auto regionStart = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect)) {
            regions.push_back(mbi);
        }

        const auto nextCursor = regionStart + mbi.RegionSize;
        if (nextCursor <= cursor) {
            break;
        }
        cursor = nextCursor;
    }

    return regions;
}

}  // namespace idmcp
