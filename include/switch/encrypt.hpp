#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace switch_encrypt {

// Supported encryption types.
enum class EncryptType {
    Aes128,
    Aes192,
    Aes256,
    ChaCha20,   // ChaCha20-Poly1305 AEAD (IETF, 12-byte nonce)
};

// Convert hex string to byte vector.
// Returns std::nullopt if string is empty, contains non-hex chars, or odd length.
std::optional<std::vector<uint8_t>> hex_to_bytes(std::string_view hex);

// Get human-readable name for an encryption type.
std::string encrypt_type_name(EncryptType type);

// Get comma-separated list of all supported encryption type names.
std::string all_encrypt_names();

// Get expected key byte count for each encryption type.
size_t expected_key_len(EncryptType type);

// Get expected nonce/IV byte count for each encryption type.
// Returns 16 for AES (IV), 12 for ChaCha20 (IETF nonce).
size_t expected_nonce_len(EncryptType type);

// Check if type is a stream cipher (ChaCha20/XChaCha20).
bool is_stream_cipher(EncryptType type);

// Encrypt plaintext.
// AES: AES-CBC + PKCS7 padding. key=16/24/32 bytes, iv=16 bytes.
// ChaCha20: ChaCha20-Poly1305 AEAD (IETF). key=32 bytes, nonce=12 bytes. Ciphertext = plaintext + 16-byte MAC.
// Returns ciphertext. Empty on error.
std::vector<uint8_t> encrypt(EncryptType type,
                              const std::vector<uint8_t>& plaintext,
                              const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& iv_or_nonce);

// Decrypt ciphertext.
// AES: AES-CBC + PKCS7 unpadding.
// ChaCha20: ChaCha20-Poly1305 AEAD decrypt with MAC verification.
// Returns plaintext bytes. Empty on error.
std::vector<uint8_t> decrypt(EncryptType type,
                              const std::vector<uint8_t>& ciphertext,
                              const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& iv_or_nonce);

// Generate random IV (16 bytes for AES) or nonce (12 bytes for ChaCha20).
std::vector<uint8_t> generate_random_iv();
std::vector<uint8_t> generate_random_nonce(size_t len);

// Generate a random key for the given encryption type.
// Returns hex string. Empty string on error.
std::string generate_key(EncryptType type);

// Wrap encrypted payload into a self-decryptable Python script.
// The returned string is valid Python that, when run with `python3`,
// decrypts and exec()s the original code.
// Requires: pip install cryptography
std::string make_python_decrypt_wrapper(EncryptType type,
                                         const std::string& b64_ciphertext,
                                         const std::string& b64_key,
                                         const std::string& b64_iv_or_nonce);

// Read input_path, encrypt with given type/key/iv_or_nonce, write self-decrypting
// Python wrapper to output_path.
// Returns false on error; error_msg is populated with a human-readable message.
bool encrypt_file(EncryptType type,
                  const std::string& input_path,
                  const std::string& output_path,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv_or_nonce,
                  std::string& error_msg);

} // namespace switch_encrypt
