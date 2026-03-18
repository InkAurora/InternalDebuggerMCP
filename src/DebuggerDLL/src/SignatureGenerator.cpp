#include "SignatureGenerator.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>

#include "DebuggerProtocol.h"
#include "MemoryReader.h"

namespace idmcp {

namespace {

struct ModuleRecord {
    std::string name;
    std::uintptr_t baseAddress;
    std::uint32_t imageSize;
    std::string path;
};

[[nodiscard]] bool IsExecutableProtection(const DWORD protect) {
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) {
        return false;
    }

    const DWORD baseProtect = protect & 0xFFU;
    return baseProtect == PAGE_EXECUTE ||
           baseProtect == PAGE_EXECUTE_READ ||
           baseProtect == PAGE_EXECUTE_READWRITE ||
           baseProtect == PAGE_EXECUTE_WRITECOPY;
}

[[nodiscard]] std::wstring_view BoundedWideView(const wchar_t* text, const std::size_t capacity) {
    if (text == nullptr || capacity == 0 || *text == L'\0') {
        return {};
    }

    std::size_t length = 0;
    while (length < capacity && text[length] != L'\0') {
        ++length;
    }
    return std::wstring_view(text, length);
}

[[nodiscard]] std::string WideToUtf8(const std::wstring_view text) {
    if (text.empty()) {
        return {};
    }

    const int sourceLength = static_cast<int>(text.size());
    const int required = WideCharToMultiByte(CP_UTF8, 0, text.data(), sourceLength, nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }

    std::string converted(static_cast<std::size_t>(required), '\0');
    const int written = WideCharToMultiByte(CP_UTF8, 0, text.data(), sourceLength, converted.data(), required, nullptr, nullptr);
    if (written <= 0) {
        return {};
    }

    converted.resize(static_cast<std::size_t>(written));
    return converted;
}

[[nodiscard]] std::vector<ModuleRecord> SnapshotModules() {
    std::vector<ModuleRecord> modules;

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        return modules;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return modules;
    }

    do {
        modules.push_back(ModuleRecord{
            .name = WideToUtf8(BoundedWideView(entry.szModule, std::size(entry.szModule))),
            .baseAddress = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr),
            .imageSize = entry.modBaseSize,
            .path = WideToUtf8(BoundedWideView(entry.szExePath, std::size(entry.szExePath))),
        });
    } while (Module32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return modules;
}

[[nodiscard]] std::optional<ModuleRecord> FindContainingModule(const std::uintptr_t address) {
    const auto modules = SnapshotModules();
    for (const auto& module : modules) {
        const auto moduleEnd = module.baseAddress + static_cast<std::uintptr_t>(module.imageSize);
        if (address >= module.baseAddress && address < moduleEnd) {
            return module;
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool CopyBytesGuarded(
    const std::uintptr_t address,
    const std::size_t size,
    std::uint8_t* output,
    DWORD& exceptionCode) noexcept {
    exceptionCode = ERROR_SUCCESS;
    __try {
        std::memcpy(output, reinterpret_cast<const void*>(address), size);
        return true;
    } __except ((exceptionCode = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

[[nodiscard]] ReadableMemoryRegions BoundReadableRegions(
    const ReadableMemoryRegions& regions,
    const std::uintptr_t scopeStart,
    const std::size_t scopeSize) {
    const auto scopeEnd = scopeStart + static_cast<std::uintptr_t>(scopeSize);
    ReadableMemoryRegions bounded;
    bounded.reserve(regions.size());

    for (const auto& region : regions) {
        const auto regionStart = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
        const auto regionEnd = regionStart + region.RegionSize;
        const auto boundedStart = std::max(regionStart, scopeStart);
        const auto boundedEnd = std::min(regionEnd, scopeEnd);
        if (boundedStart >= boundedEnd) {
            continue;
        }

        auto boundedRegion = region;
        boundedRegion.BaseAddress = reinterpret_cast<PVOID>(boundedStart);
        boundedRegion.RegionSize = static_cast<SIZE_T>(boundedEnd - boundedStart);
        bounded.push_back(boundedRegion);
    }

    return bounded;
}

[[nodiscard]] bool CollectForwardBytes(
    const std::uintptr_t address,
    const std::size_t maxBytes,
    const ReadableMemoryRegions& regions,
    std::vector<std::uint8_t>& output,
    MemoryAccessDiagnostics* diagnostics) {
    output.clear();
    if (maxBytes == 0) {
        return false;
    }

    std::size_t startIndex = regions.size();
    for (std::size_t index = 0; index < regions.size(); ++index) {
        const auto regionStart = reinterpret_cast<std::uintptr_t>(regions[index].BaseAddress);
        const auto regionEnd = regionStart + regions[index].RegionSize;
        if (address >= regionStart && address < regionEnd) {
            startIndex = index;
            break;
        }
    }

    if (startIndex == regions.size()) {
        return false;
    }

    output.reserve(maxBytes);
    std::uintptr_t cursor = address;
    std::size_t remaining = maxBytes;

    for (std::size_t index = startIndex; index < regions.size() && remaining > 0; ++index) {
        const auto regionStart = reinterpret_cast<std::uintptr_t>(regions[index].BaseAddress);
        const auto regionEnd = regionStart + regions[index].RegionSize;
        if (cursor < regionStart) {
            if (cursor != regionStart) {
                break;
            }
        }
        if (cursor >= regionEnd) {
            continue;
        }

        const auto chunkSize = static_cast<std::size_t>(std::min<std::uintptr_t>(remaining, regionEnd - cursor));
        const auto offset = output.size();
        output.resize(offset + chunkSize);

        DWORD exceptionCode = ERROR_SUCCESS;
        if (!CopyBytesGuarded(cursor, chunkSize, output.data() + offset, exceptionCode)) {
            output.clear();
            if (diagnostics != nullptr) {
                diagnostics->reason = "copy_exception";
                diagnostics->copyExceptionCode = exceptionCode;
            }
            return false;
        }

        remaining -= chunkSize;
        cursor += chunkSize;
        if (remaining == 0) {
            break;
        }
        if (cursor != regionEnd) {
            break;
        }
    }

    return !output.empty();
}

}  // namespace

SignatureGenerator::SignatureGenerator(
    const MemoryReader& memoryReader,
    const PatternScanner& patternScanner,
    const Disassembler& disassembler)
    : memoryReader_(memoryReader), patternScanner_(patternScanner), disassembler_(disassembler) {}

bool SignatureGenerator::Generate(
    const std::uintptr_t address,
    const std::size_t maxBytes,
    GeneratedSignatureResult& result,
    std::string& error,
    MemoryAccessDiagnostics* diagnostics) const {
    error.clear();
    if (diagnostics != nullptr) {
        *diagnostics = {};
        diagnostics->address = address;
        diagnostics->size = 1;
    }

    if (address == 0) {
        error = "address_required";
        return false;
    }
    if (maxBytes == 0 || maxBytes > kMaxGeneratedPatternBytes) {
        error = "invalid_max_bytes";
        return false;
    }
    if (!memoryReader_.IsReadable(address, 1, diagnostics)) {
        error = "memory_read_failed";
        return false;
    }

    const auto module = FindContainingModule(address);
    if (!module.has_value()) {
        error = "address_not_in_module";
        return false;
    }

    const auto moduleRegions = BoundReadableRegions(
        memoryReader_.EnumerateReadableRegions(module->baseAddress, module->imageSize),
        module->baseAddress,
        module->imageSize);
    if (moduleRegions.empty()) {
        error = "signature_generation_failed";
        return false;
    }

    std::vector<std::uint8_t> rawWindow;
    if (!CollectForwardBytes(address, maxBytes, moduleRegions, rawWindow, diagnostics)) {
        error = "memory_read_failed";
        return false;
    }

    std::vector<PatternByte> exactWindow;
    exactWindow.reserve(rawWindow.size());
    for (const auto byte : rawWindow) {
        exactWindow.push_back(PatternByte{byte, false});
    }

    std::vector<WildcardSpan> wildcardSpans;
    bool executable = false;
    for (const auto& region : moduleRegions) {
        const auto regionStart = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
        const auto regionEnd = regionStart + region.RegionSize;
        if (address >= regionStart && address < regionEnd) {
            executable = IsExecutableProtection(region.Protect);
            break;
        }
    }
    if (executable) {
        const bool spansBuilt = disassembler_.FindCodeAwareWildcardSpans(
            std::span<const std::uint8_t>(rawWindow.data(), rawWindow.size()),
            wildcardSpans);
        if (!spansBuilt) {
            wildcardSpans.clear();
        }
    }

    std::fill(rawWindow.begin(), rawWindow.end(), static_cast<std::uint8_t>(0));
    rawWindow.clear();

    std::vector<PatternByte> exact;
    exact.reserve(exactWindow.size());
    std::vector<PatternByte> codeAware;
    codeAware.reserve(exactWindow.size());

    auto applyCodeAwareWildcards = [&codeAware](const std::vector<WildcardSpan>& spans, const std::size_t length) -> bool {
        bool hasWildcards = false;
        for (const auto& span : spans) {
            if (span.start >= length) {
                continue;
            }

            const auto wildcardEnd = std::min(span.end, length);
            for (std::size_t index = span.start; index < wildcardEnd; ++index) {
                if (!codeAware[index].wildcard) {
                    codeAware[index].wildcard = true;
                    hasWildcards = true;
                }
            }
        }

        return hasWildcards;
    };

    for (std::size_t length = 1; length <= exactWindow.size(); ++length) {
        BuildExactPattern(exactWindow.data(), length, exact);

        if (executable) {
            codeAware = exact;
            if (applyCodeAwareWildcards(wildcardSpans, length) && IsUniqueCandidate(codeAware, address, moduleRegions)) {
                result = GeneratedSignatureResult{
                    .address = address,
                    .baseAddress = module->baseAddress,
                    .imageSize = module->imageSize,
                    .moduleName = module->name,
                    .modulePath = module->path,
                    .pattern = codeAware,
                    .matchCount = 1,
                };
                return true;
            }
        }

        if (!IsUniqueCandidate(exact, address, moduleRegions)) {
            continue;
        }

        result = GeneratedSignatureResult{
            .address = address,
            .baseAddress = module->baseAddress,
            .imageSize = module->imageSize,
            .moduleName = module->name,
            .modulePath = module->path,
            .pattern = exact,
            .matchCount = 1,
        };
        return true;
    }

    error = "signature_generation_failed";
    return false;
}

bool SignatureGenerator::IsUniqueCandidate(
    const std::vector<PatternByte>& pattern,
    const std::uintptr_t expectedMatch,
    const ReadableMemoryRegions& regions) const {
    const auto compiled = patternScanner_.CompilePattern(pattern);
    const auto summary = patternScanner_.CountCompiledPrepared(compiled, regions, 2, expectedMatch);
    return summary.matchCount == 1 && summary.expectedMatchSeen;
}

void SignatureGenerator::BuildExactPattern(
    const PatternByte* bytes,
    const std::size_t size,
    std::vector<PatternByte>& pattern) const {
    pattern.clear();
    pattern.insert(pattern.end(), bytes, bytes + static_cast<std::ptrdiff_t>(size));
}

}  // namespace idmcp