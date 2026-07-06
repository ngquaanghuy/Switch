#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace switch_encode {

// Supported encoding types.
// - Base16: hex encoding, each byte → 2 chars [0-9a-f]. Simplest, 2x expansion.
// - Base32: RFC 4648, 5 bytes → 8 chars [A-Z2-7], pad with '='. ~1.6x expansion.
// - Base58: Bitcoin-style, no 0/O/I/l. Big-integer div-by-58. Variable length.
// - Base62: 0-9a-zA-Z, no padding. Big-integer div-by-62. URL-safe alphanumeric.
// - Base64: RFC 4648, 3 bytes → 4 chars [A-Za-z0-9+/], pad with '='. ~1.33x.
enum class EncodeType {
    Base16,
    Base32,
    Base58,
    Base62,
    Base64,
};

// Parse an encode type name case-insensitively.
// "base32", "BASE32", "Base32" → EncodeType::Base32
// Unknown name → std::nullopt
std::optional<EncodeType> parse_encode_type(std::string_view name);

// Get canonical lowercase name for an encode type.
std::string_view encode_type_name(EncodeType type);

// Comma-separated list of all valid encode names, for error messages.
std::string all_encode_names();

// Encode raw bytes into the specified encoding's string representation.
std::string encode(EncodeType type, const std::vector<uint8_t>& data);

// Wrap encoded payload into a self-decodable Python script.
// The returned string is valid Python that, when run, decodes and exec()s
// the original code. Uses Python's built-in `base64` module for base16/32/64;
// embeds a pure-Python decoder for base58/62.
std::string make_python_wrapper(EncodeType type, const std::string& encoded);

// Read input_path, encode with the given type, write to output_path.
// Returns false on error; error_msg is populated with a human-readable message.
// Checks: input file exists & readable, output path writable (by attempting open).
bool encode_file(EncodeType type,
                 const std::string& input_path,
                 const std::string& output_path,
                 std::string& error_msg);

} // namespace switch_encode