#include "switch/encode.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <system_error>

namespace switch_encode {

// ---------------------------------------------------------------------------
// Name lookup (case-insensitive)
// ---------------------------------------------------------------------------

namespace {

struct EncodeEntry {
    std::string_view name;
    EncodeType type;
};

constexpr EncodeEntry ENCODE_TABLE[] = {
    {"base16", EncodeType::Base16},
    {"base32", EncodeType::Base32},
    {"base58", EncodeType::Base58},
    {"base62", EncodeType::Base62},
    {"base64", EncodeType::Base64},
};

// Case-insensitive ASCII compare
bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i]))
            != std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

} // anonymous namespace

std::optional<EncodeType> parse_encode_type(std::string_view name) {
    for (const auto& entry : ENCODE_TABLE) {
        if (iequals(name, entry.name)) {
            return entry.type;
        }
    }
    return std::nullopt;
}

std::string_view encode_type_name(EncodeType type) {
    for (const auto& entry : ENCODE_TABLE) {
        if (entry.type == type) return entry.name;
    }
    return "unknown";
}

std::string all_encode_names() {
    std::string result;
    for (size_t i = 0; i < std::size(ENCODE_TABLE); ++i) {
        if (i > 0) result += ", ";
        result += ENCODE_TABLE[i].name;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Encoding alphabets
// ---------------------------------------------------------------------------

namespace {

// Base16: standard hex lowercase
constexpr char B16_ALPHABET[] = "0123456789abcdef";

// Base32: RFC 4648 §6 — A-Z, 2-7
constexpr char B32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
// Padding schema for partial groups:
// bytes_in: 0  1  2  3  4  5
// chars_out: 0  2  4  5  7  8
// pad_count: 0  6  4  3  1  0
constexpr int B32_CHARS_OUT[] = {0, 2, 4, 5, 7, 8};
constexpr int B32_PAD_COUNT[] = {0, 6, 4, 3, 1, 0};

// Base58: Bitcoin — no 0, O, I, l
constexpr char B58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr uint8_t B58_BASE = 58;

// Base62: 0-9, A-Z, a-z
constexpr char B62_ALPHABET[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
constexpr uint8_t B62_BASE = 62;

// Base64: RFC 4648 §4
constexpr char B64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ---------------------------------------------------------------------------
// Big-integer helper for base58 and base62
// ---------------------------------------------------------------------------

// Divide big-endian byte vector (dividend) by `divisor` in-place;
// returns the remainder. Strips leading zeros from quotient after each step.
uint8_t bigint_divmod(std::vector<uint8_t>& number, uint8_t divisor) {
    uint32_t remainder = 0;
    std::vector<uint8_t> quotient;
    quotient.reserve(number.size());

    for (uint8_t byte : number) {
        uint32_t value = (remainder << 8) | byte;
        uint8_t q = static_cast<uint8_t>(value / divisor);
        remainder = value % divisor;
        // Skip leading zeros in quotient
        if (!quotient.empty() || q != 0) {
            quotient.push_back(q);
        }
    }

    number = std::move(quotient);
    return static_cast<uint8_t>(remainder);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Base16 (hex) — each byte → 2 hex chars
// ---------------------------------------------------------------------------

namespace {

std::string encode_base16(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        result.push_back(B16_ALPHABET[byte >> 4]);
        result.push_back(B16_ALPHABET[byte & 0x0F]);
    }
    return result;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Base32 (RFC 4648) — 5 bytes → 8 chars, pad with '='
// ---------------------------------------------------------------------------

namespace {

std::string encode_base32(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(((data.size() + 4) / 5) * 8);

    size_t i = 0;
    while (i < data.size()) {
        int remaining = static_cast<int>(data.size() - i);
        int bytes_in = (remaining >= 5) ? 5 : remaining;

        // Gather 5 bytes into a 40-bit buffer (left-aligned)
        uint64_t buffer = 0;
        for (int j = 0; j < bytes_in; ++j) {
            buffer = (buffer << 8) | data[i + j];
        }
        buffer <<= (8 * (5 - bytes_in));

        // Output chars according to partial-group table
        int chars_out = B32_CHARS_OUT[bytes_in];
        for (int j = 0; j < chars_out; ++j) {
            int shift = 35 - 5 * j;
            result.push_back(B32_ALPHABET[(buffer >> shift) & 0x1F]);
        }
        // Pad
        result.append(B32_PAD_COUNT[bytes_in], '=');

        i += bytes_in;
    }
    return result;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Base58 (Bitcoin-style) — big-integer division by 58
// ---------------------------------------------------------------------------

namespace {

std::string encode_base58(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};

    // Count leading zeros — each becomes a '1' (alphabet[0])
    size_t leading_zeros = 0;
    while (leading_zeros < data.size() && data[leading_zeros] == 0) {
        ++leading_zeros;
    }

    // Copy non-zero-prefixed bytes for division
    std::vector<uint8_t> number(data.begin() + leading_zeros, data.end());

    // Collect remainders
    std::string remainders;
    remainders.reserve(number.size() * 2); // ~138% expansion
    while (!number.empty()) {
        uint8_t rem = bigint_divmod(number, B58_BASE);
        remainders.push_back(B58_ALPHABET[rem]);
    }

    // Reverse remainders → encoded body
    std::string result(leading_zeros, B58_ALPHABET[0]);
    for (auto it = remainders.rbegin(); it != remainders.rend(); ++it) {
        result.push_back(*it);
    }
    return result;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Base62 — big-integer division by 62
// ---------------------------------------------------------------------------

namespace {

std::string encode_base62(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};

    // Count leading zeros — each becomes alphabet[0] = '0'
    size_t leading_zeros = 0;
    while (leading_zeros < data.size() && data[leading_zeros] == 0) {
        ++leading_zeros;
    }

    std::vector<uint8_t> number(data.begin() + leading_zeros, data.end());

    std::string remainders;
    remainders.reserve(number.size() * 2);
    while (!number.empty()) {
        uint8_t rem = bigint_divmod(number, B62_BASE);
        remainders.push_back(B62_ALPHABET[rem]);
    }

    std::string result(leading_zeros, B62_ALPHABET[0]);
    for (auto it = remainders.rbegin(); it != remainders.rend(); ++it) {
        result.push_back(*it);
    }
    return result;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Base64 — 3 bytes → 4 chars, pad with '='
// ---------------------------------------------------------------------------

namespace {

std::string encode_base64(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i < data.size()) {
        int remaining = static_cast<int>(data.size() - i);

        // Gather 3 bytes (pad missing ones with 0)
        uint32_t buffer = 0;
        int bytes_in = (remaining >= 3) ? 3 : remaining;
        for (int j = 0; j < bytes_in; ++j) {
            buffer = (buffer << 8) | data[i + j];
        }
        buffer <<= (8 * (3 - bytes_in)); // left-align the bits we have

        // Output 4 chars per full group; fewer + padding for partial
        int chars_out = (bytes_in == 3) ? 4 : bytes_in + 1;
        for (int j = 0; j < chars_out; ++j) {
            int shift = 18 - 6 * j;
            result.push_back(B64_ALPHABET[(buffer >> shift) & 0x3F]);
        }
        // Pad
        result.append((bytes_in == 3) ? 0 : (4 - chars_out), '=');

        i += bytes_in;
    }
    return result;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Public encode dispatch
// ---------------------------------------------------------------------------

std::string encode(EncodeType type, const std::vector<uint8_t>& data) {
    switch (type) {
    case EncodeType::Base16: return encode_base16(data);
    case EncodeType::Base32: return encode_base32(data);
    case EncodeType::Base58: return encode_base58(data);
    case EncodeType::Base62: return encode_base62(data);
    case EncodeType::Base64: return encode_base64(data);
    }
    return {}; // unreachable
}

// ---------------------------------------------------------------------------
// Python wrapper generator — self-decodable output scripts
// ---------------------------------------------------------------------------

std::string make_python_wrapper(EncodeType type, const std::string& encoded) {
    std::string w;
    w += "# Encoded by Switch — run with: python this_file.py\n";

    switch (type) {
    case EncodeType::Base16:
        w += "import base64\n";
        w += "_sw = \"" + encoded + "\"\n";
        w += "exec(base64.b16decode(_sw.upper()))\n";
        break;

    case EncodeType::Base32:
        w += "import base64\n";
        w += "_sw = \"" + encoded + "\"\n";
        w += "exec(base64.b32decode(_sw))\n";
        break;

    case EncodeType::Base64:
        w += "import base64\n";
        w += "_sw = \"" + encoded + "\"\n";
        w += "exec(base64.b64decode(_sw))\n";
        break;

    case EncodeType::Base58:
        w += "_sw = \"" + encoded + "\"\n";
        w += "_alphabet = \"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz\"\n";
        w += "_n = 0\n";
        w += "_zeros = 0\n";
        w += "for _c in _sw:\n";
        w += "    if _c == '1' and _n == 0:\n";
        w += "        _zeros += 1\n";
        w += "        continue\n";
        w += "    _n = _n * 58 + _alphabet.index(_c)\n";
        w += "if _n or _zeros:\n";
        w += "    exec(b'\\x00' * _zeros + _n.to_bytes(max(1, (_n.bit_length() + 7) // 8), 'big'))\n";
        break;

    case EncodeType::Base62:
        w += "_sw = \"" + encoded + "\"\n";
        w += "_alphabet = \"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\"\n";
        w += "_n = 0\n";
        w += "_zeros = 0\n";
        w += "for _c in _sw:\n";
        w += "    if _c == '0' and _n == 0:\n";
        w += "        _zeros += 1\n";
        w += "        continue\n";
        w += "    _n = _n * 62 + _alphabet.index(_c)\n";
        w += "if _n or _zeros:\n";
        w += "    exec(b'\\x00' * _zeros + _n.to_bytes(max(1, (_n.bit_length() + 7) // 8), 'big'))\n";
        break;
    }
    return w;
}

// ---------------------------------------------------------------------------
// File-to-file encode with validation
// ---------------------------------------------------------------------------

bool encode_file(EncodeType type,
                 const std::string& input_path,
                 const std::string& output_path,
                 std::string& error_msg) {
    // 1. Open and read input file
    std::ifstream in(input_path, std::ios::binary | std::ios::ate);
    if (!in) {
        error_msg = "cannot open input file '" + input_path
                    + "': " + std::generic_category().message(errno);
        return false;
    }

    std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(static_cast<size_t>(size));
    if (!in.read(reinterpret_cast<char*>(data.data()), size)) {
        error_msg = "failed to read input file '" + input_path + "'";
        return false;
    }
    in.close();

    // 2. Encode, then wrap in self-decodable Python script
    std::string encoded = encode(type, data);
    std::string output  = make_python_wrapper(type, encoded);

    // 3. Write output
    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error_msg = "cannot write to output file '" + output_path
                    + "': " + std::generic_category().message(errno);
        return false;
    }
    out.write(output.data(), static_cast<std::streamsize>(output.size()));
    if (!out) {
        error_msg = "failed to write output file '" + output_path + "'";
        return false;
    }
    out.close();

    return true;
}

} // namespace switch_encode