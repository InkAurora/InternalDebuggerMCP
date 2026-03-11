#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace idmcp {

inline constexpr std::size_t kMaxReadSize = 64 * 1024;
inline constexpr std::size_t kMaxWriteSize = 64 * 1024;
inline constexpr std::size_t kMaxPatternResults = 256;
inline constexpr std::size_t kMaxWatchCount = 64;
inline constexpr std::size_t kDefaultPollLimit = 16;
inline constexpr std::size_t kMaxAccessWatchCount = 4;
inline constexpr std::uint64_t kAccessWatchIdleTimeoutMs = 60'000;
inline constexpr std::size_t kAccessWatchInstructionBytes = 16;
inline constexpr std::size_t kMaxInvokeArguments = 6;
inline constexpr std::size_t kMaxInvokeBufferSize = 64 * 1024;
inline constexpr char kFrameDelimiter[] = "\n\n";
inline constexpr char kPipePrefix[] = "\\\\.\\pipe\\InternalDebuggerMCP_";

using MessageField = std::pair<std::string, std::string>;

struct ParsedMessage {
    std::vector<MessageField> fields;

    [[nodiscard]] std::optional<std::string> GetFirst(std::string_view key) const {
        for (const auto& [candidate, value] : fields) {
            if (candidate == key) {
                return value;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<std::string> GetAll(std::string_view key) const {
        std::vector<std::string> values;
        for (const auto& [candidate, value] : fields) {
            if (candidate == key) {
                values.push_back(value);
            }
        }
        return values;
    }
};

inline std::string Trim(std::string value) {
    auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

inline ParsedMessage ParseMessage(std::string_view frame) {
    ParsedMessage parsed;
    std::istringstream stream{std::string(frame)};
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }
        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            continue;
        }
        const auto key = Trim(line.substr(0, separator));
        const auto value = Trim(line.substr(separator + 1));
        parsed.fields.emplace_back(key, value);
    }
    return parsed;
}

inline std::string BuildMessage(const std::vector<MessageField>& fields) {
    std::ostringstream builder;
    for (const auto& [key, value] : fields) {
        builder << key << '=' << value << '\n';
    }
    builder << '\n';
    return builder.str();
}

inline std::string HexEncode(std::span<const std::uint8_t> bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string encoded;
    encoded.reserve((bytes.size() * 3) ? bytes.size() * 3 - 1 : 0);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const auto byte = bytes[index];
        encoded.push_back(digits[(byte >> 4U) & 0x0FU]);
        encoded.push_back(digits[byte & 0x0FU]);
        if (index + 1 < bytes.size()) {
            encoded.push_back(' ');
        }
    }
    return encoded;
}

inline std::string ToHex(std::uintptr_t value) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << value;
    return stream.str();
}

inline std::optional<std::uintptr_t> ParseAddress(std::string_view text) {
    std::string value(text);
    value = Trim(value);
    if (value.starts_with("0x") || value.starts_with("0X")) {
        value = value.substr(2);
    }
    if (value.empty()) {
        return std::nullopt;
    }

    std::uintptr_t parsed = 0;
    std::istringstream stream(value);
    stream >> std::hex >> parsed;
    if (stream.fail()) {
        return std::nullopt;
    }
    return parsed;
}

inline std::optional<std::uint64_t> ParseUnsigned(std::string_view text) {
    const auto value = Trim(std::string(text));
    if (value.empty()) {
        return std::nullopt;
    }
    std::uint64_t parsed = 0;
    std::istringstream stream(value);
    stream >> parsed;
    if (stream.fail()) {
        return std::nullopt;
    }
    return parsed;
}

inline std::optional<bool> ParseBool(std::string_view text) {
    const auto value = Trim(std::string(text));
    if (value.empty()) {
        return std::nullopt;
    }

    if (value == "1" || value == "true" || value == "TRUE" || value == "yes" || value == "YES") {
        return true;
    }
    if (value == "0" || value == "false" || value == "FALSE" || value == "no" || value == "NO") {
        return false;
    }
    return std::nullopt;
}

inline bool ParseHexBytes(std::string_view text, std::vector<std::uint8_t>& output) {
    output.clear();

    std::istringstream stream{std::string(text)};
    std::string token;
    while (stream >> token) {
        if (token.size() != 2) {
            output.clear();
            return false;
        }

        unsigned int value = 0;
        std::istringstream tokenStream{token};
        tokenStream >> std::hex >> value;
        if (tokenStream.fail() || value > 0xFFU) {
            output.clear();
            return false;
        }

        output.push_back(static_cast<std::uint8_t>(value));
    }

    return !output.empty();
}

}  // namespace idmcp
