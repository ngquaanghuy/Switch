#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "switch/encode.hpp"

#include <cstring>
#include <string>
#include <vector>

using namespace switch_encode;

// Helper: string → byte vector
static std::vector<uint8_t> bytes(const std::string& s) {
    return {s.begin(), s.end()};
}

// =========================================================================
// parse_encode_type — case-insensitive name resolution
// =========================================================================

TEST_CASE("parse_encode_type: valid names") {
    CHECK(parse_encode_type("base16") == EncodeType::Base16);
    CHECK(parse_encode_type("base32") == EncodeType::Base32);
    CHECK(parse_encode_type("base58") == EncodeType::Base58);
    CHECK(parse_encode_type("base62") == EncodeType::Base62);
    CHECK(parse_encode_type("base64") == EncodeType::Base64);
}

TEST_CASE("parse_encode_type: case-insensitive") {
    CHECK(parse_encode_type("BASE16") == EncodeType::Base16);
    CHECK(parse_encode_type("Base32") == EncodeType::Base32);
    CHECK(parse_encode_type("bAsE58") == EncodeType::Base58);
    CHECK(parse_encode_type("BASE62") == EncodeType::Base62);
    CHECK(parse_encode_type("Base64") == EncodeType::Base64);
}

TEST_CASE("parse_encode_type: unknown name returns nullopt") {
    CHECK(parse_encode_type("base128") == std::nullopt);
    CHECK(parse_encode_type("hex") == std::nullopt);
    CHECK(parse_encode_type("") == std::nullopt);
    CHECK(parse_encode_type("base") == std::nullopt);
}

// =========================================================================
// encode_type_name
// =========================================================================

TEST_CASE("encode_type_name: returns canonical lowercase name") {
    CHECK(encode_type_name(EncodeType::Base16) == "base16");
    CHECK(encode_type_name(EncodeType::Base32) == "base32");
    CHECK(encode_type_name(EncodeType::Base58) == "base58");
    CHECK(encode_type_name(EncodeType::Base62) == "base62");
    CHECK(encode_type_name(EncodeType::Base64) == "base64");
}

// =========================================================================
// all_encode_names
// =========================================================================

TEST_CASE("all_encode_names: contains all five names") {
    std::string names = all_encode_names();
    CHECK(names.find("base16") != std::string::npos);
    CHECK(names.find("base32") != std::string::npos);
    CHECK(names.find("base58") != std::string::npos);
    CHECK(names.find("base62") != std::string::npos);
    CHECK(names.find("base64") != std::string::npos);
}

// =========================================================================
// Base16 (Hex) encoding
// =========================================================================

TEST_CASE("encode base16: empty input") {
    CHECK(encode(EncodeType::Base16, {}) == "");
}

TEST_CASE("encode base16: known values") {
    CHECK(encode(EncodeType::Base16, bytes("hello")) == "68656c6c6f");
    CHECK(encode(EncodeType::Base16, bytes("test")) == "74657374");
    CHECK(encode(EncodeType::Base16, {0x00}) == "00");
    CHECK(encode(EncodeType::Base16, {0xFF}) == "ff");
    CHECK(encode(EncodeType::Base16, {0x0A}) == "0a");
    CHECK(encode(EncodeType::Base16, {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF})
          == "0123456789abcdef");
}

// =========================================================================
// Base32 encoding (RFC 4648)
// =========================================================================

TEST_CASE("encode base32: empty input") {
    CHECK(encode(EncodeType::Base32, {}) == "");
}

TEST_CASE("encode base32: RFC 4648 test vectors") {
    CHECK(encode(EncodeType::Base32, bytes("")) == "");
    CHECK(encode(EncodeType::Base32, bytes("f")) == "MY======");
    CHECK(encode(EncodeType::Base32, bytes("fo")) == "MZXQ====");
    CHECK(encode(EncodeType::Base32, bytes("foo")) == "MZXW6===");
    CHECK(encode(EncodeType::Base32, bytes("foob")) == "MZXW6YQ=");
    CHECK(encode(EncodeType::Base32, bytes("fooba")) == "MZXW6YTB");
    CHECK(encode(EncodeType::Base32, bytes("foobar")) == "MZXW6YTBOI======");
}

TEST_CASE("encode base32: 'hello'") {
    CHECK(encode(EncodeType::Base32, bytes("hello")) == "NBSWY3DP");
}

// =========================================================================
// Base58 encoding (Bitcoin-style)
// =========================================================================

TEST_CASE("encode base58: empty input") {
    CHECK(encode(EncodeType::Base58, {}) == "");
}

TEST_CASE("encode base58: leading zeros") {
    CHECK(encode(EncodeType::Base58, {0x00}) == "1");
    CHECK(encode(EncodeType::Base58, {0x00, 0x00}) == "11");
    CHECK(encode(EncodeType::Base58, {0x00, 0x00, 0x01}) == "112");
}

TEST_CASE("encode base58: known values") {
    // "hello" → verified via Python base58 reference
    CHECK(encode(EncodeType::Base58, bytes("hello")) == "Cn8eVZg");
}

TEST_CASE("encode base58: Bitcoin address-like data") {
    std::vector<uint8_t> data(20, 0x00);
    data.push_back(0x01);
    std::string result = encode(EncodeType::Base58, data);
    CHECK(result.size() >= 20);
    CHECK(result.substr(0, 20) == std::string(20, '1'));
}

// =========================================================================
// Base62 encoding
// =========================================================================

TEST_CASE("encode base62: empty input") {
    CHECK(encode(EncodeType::Base62, {}) == "");
}

TEST_CASE("encode base62: leading zeros") {
    CHECK(encode(EncodeType::Base62, {0x00}) == "0");
    CHECK(encode(EncodeType::Base62, {0x00, 0x00}) == "00");
}

TEST_CASE("encode base62: known values") {
    std::string result = encode(EncodeType::Base62, bytes("hello"));
    // All chars should be in [0-9A-Za-z]
    for (char c : result) {
        bool valid = (c >= '0' && c <= '9')
                  || (c >= 'A' && c <= 'Z')
                  || (c >= 'a' && c <= 'z');
        CHECK(valid);
    }
    CHECK(!result.empty());
}

// =========================================================================
// Base64 encoding (RFC 4648)
// =========================================================================

TEST_CASE("encode base64: empty input") {
    CHECK(encode(EncodeType::Base64, {}) == "");
}

TEST_CASE("encode base64: RFC 4648 test vectors") {
    CHECK(encode(EncodeType::Base64, bytes("")) == "");
    CHECK(encode(EncodeType::Base64, bytes("f")) == "Zg==");
    CHECK(encode(EncodeType::Base64, bytes("fo")) == "Zm8=");
    CHECK(encode(EncodeType::Base64, bytes("foo")) == "Zm9v");
    CHECK(encode(EncodeType::Base64, bytes("foob")) == "Zm9vYg==");
    CHECK(encode(EncodeType::Base64, bytes("fooba")) == "Zm9vYmE=");
    CHECK(encode(EncodeType::Base64, bytes("foobar")) == "Zm9vYmFy");
}

TEST_CASE("encode base64: binary data") {
    CHECK(encode(EncodeType::Base64, {0x00, 0x00, 0x00}) == "AAAA");
    CHECK(encode(EncodeType::Base64, {0xFF, 0xFF, 0xFF}) == "////");
    CHECK(encode(EncodeType::Base64, {0xFB}) == "+w==");
}

// =========================================================================
// Roundtrip correctness via decoding verification
// =========================================================================

static std::vector<uint8_t> decode_base16(const std::string& encoded) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i + 1 < encoded.size(); i += 2) {
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        result.push_back((nibble(encoded[i]) << 4) | nibble(encoded[i+1]));
    }
    return result;
}

TEST_CASE("roundtrip: base16 encode → decode matches original") {
    std::vector<uint8_t> original = {0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF};
    std::string enc = encode(EncodeType::Base16, original);
    std::vector<uint8_t> dec = decode_base16(enc);
    CHECK(dec == original);
}

// =========================================================================
// encode_file error handling
// =========================================================================

TEST_CASE("encode_file: nonexistent input file") {
    std::string error;
    bool ok = encode_file(EncodeType::Base16,
                          "/nonexistent/path/foo.bin",
                          "/tmp/switch_test_output.txt",
                          error);
    CHECK(ok == false);
    CHECK(!error.empty());
}

TEST_CASE("encode_file: unwritable output path") {
    // Skip this test when running as root since root can write anywhere
    #ifdef SWITCH_PLATFORM_LINUX
    if (geteuid() == 0) {
        // Running as root - skip unwritable path test
        MESSAGE("Skipping unwritable path test when running as root");
        return;
    }
    #endif
    
    std::string error;
    bool ok = encode_file(EncodeType::Base16,
                          "/dev/null",
                          "/tmp/switch_test_readonly/output.py",
                          error);
    CHECK(ok == false);
    CHECK(!error.empty());
}