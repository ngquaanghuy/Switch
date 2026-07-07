#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace switch_encrypt {

// Supported AES key sizes — determined by key length.
enum class EncryptType {
    Aes128,
    Aes192,
    Aes256,
};

// Determine AES type from hex-encoded key length.
// 32 hex chars (16 bytes) → Aes128
// 48 hex chars (24 bytes) → Aes192
// 64 hex chars (32 bytes) → Aes256
// Other → std::nullopt
std::optional<EncryptType> parse_encrypt_type_from_key(std::string_view hex_key);

// Convert hex string to byte vector.
// Returns std::nullopt if string contains non-hex chars or odd length.
std::optional<std::vector<uint8_t>> hex_to_bytes(std::string_view hex);

// Get human-readable name for an encryption type.
std::string encrypt_type_name(EncryptType type);

// Encrypt plaintext with AES-CBC + PKCS7 padding.
// key must be 16/24/32 bytes. iv must be 16 bytes.
// Returns ciphertext (encrypted bytes, including PKCS7 padding).
std::vector<uint8_t> encrypt(EncryptType type,
                              const std::vector<uint8_t>& plaintext,
                              const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& iv);

// Decrypt ciphertext with AES-CBC + PKCS7 unpadding.
// Returns plaintext bytes. Empty on error.
std::vector<uint8_t> decrypt(EncryptType type,
                              const std::vector<uint8_t>& ciphertext,
                              const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& iv);

// Generate 16 random bytes for IV using OpenSSL RAND.
std::vector<uint8_t> generate_random_iv();

// Wrap encrypted payload into a self-decryptable Python script.
// The returned string is valid Python that, when run with `python3`,
// decrypts and exec()s the original code.
// Requires: pip install cryptography
std::string make_python_decrypt_wrapper(EncryptType type,
                                         const std::string& b64_ciphertext,
                                         const std::string& b64_key,
                                         const std::string& b64_iv);

// Read input_path, encrypt with given type/key/iv, write self-decrypting
// Python wrapper to output_path.
// Returns false on error; error_msg is populated with a human-readable message.
bool encrypt_file(EncryptType type,
                  const std::string& input_path,
                  const std::string& output_path,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::string& error_msg);

} // namespace switch_encrypt
