#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "switch/encrypt.hpp"

#include <cstring>
#include <string>
#include <vector>

using namespace switch_encrypt;

// Helper: string → byte vector
static std::vector<uint8_t> bytes(const std::string& s) {
    return {s.begin(), s.end()};
}

// Helper: hex string (convenience wrapper)
static std::vector<uint8_t> from_hex(std::string_view hex) {
    return *hex_to_bytes(hex);
}

// =========================================================================
// hex_to_bytes
// =========================================================================

TEST_CASE("hex_to_bytes: valid hex strings") {
    auto result = hex_to_bytes("deadbeef");
    REQUIRE(result.has_value());
    CHECK(result->size() == 4);
    CHECK((*result)[0] == 0xDE);
    CHECK((*result)[1] == 0xAD);
    CHECK((*result)[2] == 0xBE);
    CHECK((*result)[3] == 0xEF);
}

TEST_CASE("hex_to_bytes: empty string returns nullopt") {
    auto result = hex_to_bytes("");
    CHECK(result == std::nullopt);
}

TEST_CASE("hex_to_bytes: uppercase hex") {
    auto result = hex_to_bytes("ABCD");
    REQUIRE(result.has_value());
    CHECK((*result)[0] == 0xAB);
    CHECK((*result)[1] == 0xCD);
}

TEST_CASE("hex_to_bytes: odd length returns nullopt") {
    CHECK(hex_to_bytes("abc") == std::nullopt);
    CHECK(hex_to_bytes("1") == std::nullopt);
}

TEST_CASE("hex_to_bytes: invalid chars returns nullopt") {
    CHECK(hex_to_bytes("xyz") == std::nullopt);
    CHECK(hex_to_bytes("0g") == std::nullopt);
}

// =========================================================================
// encrypt_type_name
// =========================================================================

TEST_CASE("encrypt_type_name: returns correct names") {
    CHECK(encrypt_type_name(EncryptType::Aes128) == "aes-128");
    CHECK(encrypt_type_name(EncryptType::Aes192) == "aes-192");
    CHECK(encrypt_type_name(EncryptType::Aes256) == "aes-256");
}

// =========================================================================
// AES-128 encrypt / decrypt
// =========================================================================

TEST_CASE("aes-128: encrypt produces non-empty ciphertext") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv  = from_hex("00000000000000000000000000000000");
    auto ct = encrypt(EncryptType::Aes128, bytes("hello world"), key, iv);
    CHECK(!ct.empty());
    CHECK(ct.size() % 16 == 0);
}

TEST_CASE("aes-128: encrypt same data same key/iv → deterministic") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv  = from_hex("00000000000000000000000000000000");
    auto ct1 = encrypt(EncryptType::Aes128, bytes("test"), key, iv);
    auto ct2 = encrypt(EncryptType::Aes128, bytes("test"), key, iv);
    CHECK(ct1 == ct2);
}

TEST_CASE("aes-128: encrypt same data different key → different ciphertext") {
    auto iv = from_hex("00000000000000000000000000000000");
    auto key1 = from_hex("000102030405060708090a0b0c0d0e0f");
    auto key2 = from_hex("1112131415161718191a1b1c1d1e1f20");
    auto ct1 = encrypt(EncryptType::Aes128, bytes("test"), key1, iv);
    auto ct2 = encrypt(EncryptType::Aes128, bytes("test"), key2, iv);
    CHECK(ct1 != ct2);
}

TEST_CASE("aes-128: encrypt same data different iv → different ciphertext") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv1 = from_hex("00000000000000000000000000000000");
    auto iv2 = from_hex("11111111111111111111111111111111");
    auto ct1 = encrypt(EncryptType::Aes128, bytes("test"), key, iv1);
    auto ct2 = encrypt(EncryptType::Aes128, bytes("test"), key, iv2);
    CHECK(ct1 != ct2);
}

TEST_CASE("aes-128: encrypt then decrypt roundtrip") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv  = from_hex("00000000000000000000000000000000");
    std::string original = "Hello, Switch AES encryption!";
    auto ct = encrypt(EncryptType::Aes128, bytes(original), key, iv);
    auto pt = decrypt(EncryptType::Aes128, ct, key, iv);
    REQUIRE(!pt.empty());
    CHECK(std::string(pt.begin(), pt.end()) == original);
}

TEST_CASE("aes-128: roundtrip with empty input") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv  = from_hex("00000000000000000000000000000000");
    auto ct = encrypt(EncryptType::Aes128, {}, key, iv);
    // PKCS7 always adds at least 1 byte of padding, so ciphertext is 16 bytes
    CHECK(ct.size() == 16);
    auto pt = decrypt(EncryptType::Aes128, ct, key, iv);
    CHECK(pt.empty());
}

TEST_CASE("aes-128: roundtrip with binary data") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv  = from_hex("00000000000000000000000000000000");
    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF};
    auto ct = encrypt(EncryptType::Aes128, data, key, iv);
    auto pt = decrypt(EncryptType::Aes128, ct, key, iv);
    CHECK(pt == data);
}

TEST_CASE("aes-128: roundtrip with large data (1KB)") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv  = from_hex("00000000000000000000000000000000");
    std::vector<uint8_t> data(1024);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i & 0xFF);
    auto ct = encrypt(EncryptType::Aes128, data, key, iv);
    auto pt = decrypt(EncryptType::Aes128, ct, key, iv);
    CHECK(pt == data);
}

// =========================================================================
// AES-192 encrypt / decrypt
// =========================================================================

TEST_CASE("aes-192: encrypt produces non-empty ciphertext") {
    // 24-byte key
    auto key = from_hex("000102030405060708090a0b0c0d0e0f1011121314151617");
    auto iv  = from_hex("00000000000000000000000000000000");
    auto ct = encrypt(EncryptType::Aes192, bytes("hello world"), key, iv);
    CHECK(!ct.empty());
    CHECK(ct.size() % 16 == 0);
}

TEST_CASE("aes-192: roundtrip") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f1011121314151617");
    auto iv  = from_hex("00000000000000000000000000000000");
    std::string original = "AES-192 roundtrip test";
    auto ct = encrypt(EncryptType::Aes192, bytes(original), key, iv);
    auto pt = decrypt(EncryptType::Aes192, ct, key, iv);
    REQUIRE(!pt.empty());
    CHECK(std::string(pt.begin(), pt.end()) == original);
}

// =========================================================================
// AES-256 encrypt / decrypt
// =========================================================================

TEST_CASE("aes-256: encrypt produces non-empty ciphertext") {
    // 32-byte key
    auto key = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto iv  = from_hex("00000000000000000000000000000000");
    auto ct = encrypt(EncryptType::Aes256, bytes("hello world"), key, iv);
    CHECK(!ct.empty());
    CHECK(ct.size() % 16 == 0);
}

TEST_CASE("aes-256: roundtrip") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto iv  = from_hex("00000000000000000000000000000000");
    std::string original = "AES-256 roundtrip test with longer content!";
    auto ct = encrypt(EncryptType::Aes256, bytes(original), key, iv);
    auto pt = decrypt(EncryptType::Aes256, ct, key, iv);
    REQUIRE(!pt.empty());
    CHECK(std::string(pt.begin(), pt.end()) == original);
}

TEST_CASE("aes-256: roundtrip with binary data") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto iv  = from_hex("00000000000000000000000000000000");
    std::vector<uint8_t> data(256);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i);
    auto ct = encrypt(EncryptType::Aes256, data, key, iv);
    auto pt = decrypt(EncryptType::Aes256, ct, key, iv);
    CHECK(pt == data);
}

// =========================================================================
// generate_random_iv
// =========================================================================

TEST_CASE("generate_random_iv: returns 16 bytes") {
    auto iv = generate_random_iv();
    CHECK(iv.size() == 16);
}

TEST_CASE("generate_random_iv: two calls produce different IVs") {
    auto iv1 = generate_random_iv();
    auto iv2 = generate_random_iv();
    CHECK(iv1 != iv2);
}

// =========================================================================
// encrypt_file error handling
// =========================================================================

TEST_CASE("encrypt_file: nonexistent input file") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv  = from_hex("00000000000000000000000000000000");
    std::string error;
    bool ok = encrypt_file(EncryptType::Aes128,
                           "/nonexistent/path/foo.py",
                           "/tmp/switch_test_enc_output.py",
                           key, iv, error);
    CHECK(ok == false);
    CHECK(!error.empty());
}

TEST_CASE("encrypt_file: unwritable output path") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv  = from_hex("00000000000000000000000000000000");
    std::string error;
    bool ok = encrypt_file(EncryptType::Aes128,
                           "/dev/null",
                           "/root/switch_test_should_fail.py",
                           key, iv, error);
    CHECK(ok == false);
    CHECK(!error.empty());
}

TEST_CASE("encrypt_file: encrypt empty file") {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv  = from_hex("00000000000000000000000000000000");

    // Create empty temp file
    std::string input_path = "/tmp/switch_test_enc_empty.tmp";
    std::ofstream out(input_path);
    out.close();

    std::string output_path = "/tmp/switch_test_enc_empty_out.py";
    std::string error;
    bool ok = encrypt_file(EncryptType::Aes128, input_path, output_path, key, iv, error);
    INFO("error: ", error);
    CHECK(ok == true);

    std::remove(input_path.c_str());
    std::remove(output_path.c_str());
}

// =========================================================================
// All three AES types: encrypt file produces valid Python wrapper
// =========================================================================

TEST_CASE("encrypt_file: all three types produce self-decryptable wrapper") {
    auto key128 = from_hex("000102030405060708090a0b0c0d0e0f");
    auto key192 = from_hex("000102030405060708090a0b0c0d0e0f1011121314151617");
    auto key256 = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto iv  = from_hex("00000000000000000000000000000000");

    std::string input_path = "/tmp/switch_test_enc_3types.py";
    std::ofstream inp(input_path);
    inp << "print('hello from switch encrypted')\n";
    inp.close();

    struct TestCase { EncryptType type; std::vector<uint8_t> key; };
    std::vector<TestCase> tests = {
        {EncryptType::Aes128, key128},
        {EncryptType::Aes192, key192},
        {EncryptType::Aes256, key256},
    };

    for (auto& tc : tests) {
        std::string output_path = "/tmp/switch_test_enc_3types_" + encrypt_type_name(tc.type) + ".py";
        std::string error;
        bool ok = encrypt_file(tc.type, input_path, output_path, tc.key, iv, error);
        INFO("error for ", encrypt_type_name(tc.type), ": ", error);
        REQUIRE(ok == true);

        // Read output and verify it's a valid Python wrapper
        std::ifstream in(output_path, std::ios::binary | std::ios::ate);
        std::streamsize size = in.tellg();
        in.seekg(0);
        std::string content(static_cast<size_t>(size), '\0');
        in.read(content.data(), size);
        in.close();

        CHECK(content.find("# Encrypted by Switch") != std::string::npos);
        CHECK(content.find("from cryptography") != std::string::npos);
        CHECK(content.find("exec(") != std::string::npos);

        std::remove(output_path.c_str());
    }

    std::remove(input_path.c_str());
}
