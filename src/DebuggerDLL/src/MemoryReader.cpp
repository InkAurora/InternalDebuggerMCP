#include "MemoryReader.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>

namespace idmcp {

namespace {

void ResetDiagnostics(
    MemoryAccessDiagnostics* diagnostics,
    const std::uintptr_t address,
    const std::size_t size) {
    if (diagnostics == nullptr) {
        return;
    }

    *diagnostics = {};
    diagnostics->address = address;
    diagnostics->size = size;
}

void SetRegionDiagnostics(MemoryAccessDiagnostics* diagnostics, const MEMORY_BASIC_INFORMATION& mbi) {
    if (diagnostics == nullptr) {
        return;
    }

    diagnostics->hasRegion = true;
    diagnostics->regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
    diagnostics->regionSize = mbi.RegionSize;
    diagnostics->state = mbi.State;
    diagnostics->protect = mbi.Protect;
}

[[nodiscard]] bool RangeFitsRegion(
    const std::uintptr_t address,
    const std::size_t size,
    const std::uintptr_t regionStart,
    const std::size_t regionSize) {
    if (address < regionStart) {
        return false;
    }

    const auto offset = address - regionStart;
    if (offset > regionSize) {
        return false;
    }

    return size <= regionSize - offset;
}

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
    const DWORD requiredProtect,
    MemoryAccessDiagnostics* diagnostics) {
    ResetDiagnostics(diagnostics, address, size);

    if (address == 0) {
        if (diagnostics != nullptr) {
            diagnostics->reason = "invalid_address";
        }
        return false;
    }
    if (size == 0) {
        if (diagnostics != nullptr) {
            diagnostics->reason = "invalid_size";
        }
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    SetLastError(ERROR_SUCCESS);
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != sizeof(mbi)) {
        if (diagnostics != nullptr) {
            diagnostics->reason = "virtual_query_failed";
            diagnostics->queryError = GetLastError();
        }
        return false;
    }

    SetRegionDiagnostics(diagnostics, mbi);

    if (mbi.State != MEM_COMMIT) {
        if (diagnostics != nullptr) {
            diagnostics->reason = "region_not_committed";
        }
        return false;
    }

    const bool protectOk = requiredProtect == PAGE_READONLY
        ? IsReadableProtection(mbi.Protect)
        : IsWritableProtection(mbi.Protect);
    if (!protectOk) {
        if (diagnostics != nullptr) {
            if ((mbi.Protect & PAGE_GUARD) != 0) {
                diagnostics->reason = "guarded_page";
            } else if ((mbi.Protect & PAGE_NOACCESS) != 0) {
                diagnostics->reason = "no_access";
            } else {
                diagnostics->reason = requiredProtect == PAGE_READONLY
                    ? "protection_not_readable"
                    : "protection_not_writable";
            }
        }
        return false;
    }

    const auto regionStart = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
    if (!RangeFitsRegion(address, size, regionStart, mbi.RegionSize)) {
        if (diagnostics != nullptr) {
            diagnostics->reason = "range_outside_region";
        }
        return false;
    }

    return true;
}

}  // namespace

bool MemoryReader::IsReadable(
    const std::uintptr_t address,
    const std::size_t size,
    MemoryAccessDiagnostics* diagnostics) const {
    return IsWithinCommittedRegion(address, size, PAGE_READONLY, diagnostics);
}

bool MemoryReader::IsWritable(
    const std::uintptr_t address,
    const std::size_t size,
    MemoryAccessDiagnostics* diagnostics) const {
    return IsWithinCommittedRegion(address, size, PAGE_READWRITE, diagnostics);
}

bool MemoryReader::ReadBytes(
    const std::uintptr_t address,
    const std::size_t size,
    std::vector<std::uint8_t>& output,
    MemoryAccessDiagnostics* diagnostics) const {
    output.clear();
    if (!IsReadable(address, size, diagnostics)) {
        return false;
    }

    output.resize(size);
    DWORD exceptionCode = ERROR_SUCCESS;
    __try {
        std::memcpy(output.data(), reinterpret_cast<const void*>(address), size);
    } __except ((exceptionCode = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
        output.clear();
        if (diagnostics != nullptr) {
            diagnostics->reason = "copy_exception";
            diagnostics->copyExceptionCode = exceptionCode;
        }
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

bool MemoryReader::WriteBytes(
    const std::uintptr_t address,
    const std::vector<std::uint8_t>& bytes,
    MemoryAccessDiagnostics* diagnostics) const {
    if (bytes.empty()) {
        ResetDiagnostics(diagnostics, address, bytes.size());
        if (diagnostics != nullptr) {
            diagnostics->reason = "invalid_size";
        }
        return false;
    }
    if (!IsWritable(address, bytes.size(), diagnostics)) {
        return false;
    }

    DWORD exceptionCode = ERROR_SUCCESS;
    __try {
        std::memcpy(reinterpret_cast<void*>(address), bytes.data(), bytes.size());
    } __except ((exceptionCode = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
        if (diagnostics != nullptr) {
            diagnostics->reason = "copy_exception";
            diagnostics->copyExceptionCode = exceptionCode;
        }
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
