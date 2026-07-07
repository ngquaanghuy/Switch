#include "switch/encrypt.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace switch_encrypt {

// ---------------------------------------------------------------------------
// Hex conversion
// ---------------------------------------------------------------------------

namespace {

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

char to_hex_digit(uint8_t nibble) {
    return "0123456789abcdef"[nibble & 0x0F];
}

} // anonymous namespace

std::optional<std::vector<uint8_t>> hex_to_bytes(std::string_view hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    if (hex.empty()) return std::vector<uint8_t>();

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_digit(hex[i]);
        int lo = hex_digit(hex[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return bytes;
}

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        result.push_back(to_hex_digit(b >> 4));
        result.push_back(to_hex_digit(b & 0x0F));
    }
    return result;
}

// ---------------------------------------------------------------------------
// EncryptType resolution
// ---------------------------------------------------------------------------

std::optional<EncryptType> parse_encrypt_type_from_key(std::string_view hex_key) {
    // key length in hex chars: 32 → 16 bytes (AES-128), 48 → 24 (AES-192), 64 → 32 (AES-256)
    switch (hex_key.size()) {
    case 32: return EncryptType::Aes128;
    case 48: return EncryptType::Aes192;
    case 64: return EncryptType::Aes256;
    default: return std::nullopt;
    }
}

std::string encrypt_type_name(EncryptType type) {
    switch (type) {
    case EncryptType::Aes128: return "aes-128";
    case EncryptType::Aes192: return "aes-192";
    case EncryptType::Aes256: return "aes-256";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// PKCS7 Padding
// ---------------------------------------------------------------------------

namespace {

// PKCS7 pad: always adds at least 1 byte, at most 16 bytes.
// Output size is always a multiple of 16.
std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t>& data) {
    constexpr size_t BLOCK_SIZE = 16;
    size_t pad_len = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
    std::vector<uint8_t> padded(data);
    padded.insert(padded.end(), pad_len, static_cast<uint8_t>(pad_len));
    return padded;
}

// PKCS7 unpad: removes padding bytes, returns original data.
// Returns empty vector on invalid padding.
std::vector<uint8_t> pkcs7_unpad(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};

    uint8_t pad_len = data.back();
    if (pad_len == 0 || pad_len > 16 || pad_len > data.size()) {
        return {};
    }

    // Verify all padding bytes are correct
    for (size_t i = data.size() - pad_len; i < data.size(); ++i) {
        if (data[i] != pad_len) return {};
    }

    return std::vector<uint8_t>(data.begin(), data.end() - pad_len);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// AES-CBC encrypt / decrypt via OpenSSL EVP
// ---------------------------------------------------------------------------

std::vector<uint8_t> encrypt(EncryptType type,
                              const std::vector<uint8_t>& plaintext,
                              const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& iv) {
    // Select cipher based on key size
    const EVP_CIPHER* cipher = nullptr;
    switch (type) {
    case EncryptType::Aes128: cipher = EVP_aes_128_cbc(); break;
    case EncryptType::Aes192: cipher = EVP_aes_192_cbc(); break;
    case EncryptType::Aes256: cipher = EVP_aes_256_cbc(); break;
    }
    if (!cipher) return {};

    // PKCS7 pad plaintext
    std::vector<uint8_t> padded = pkcs7_pad(plaintext);

    // Allocate output buffer (padded size is sufficient)
    std::vector<uint8_t> ciphertext(padded.size());
    int out_len = 0;
    int final_len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    bool ok = true;
    ok = ok && (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) == 1);
    // Disable OpenSSL's automatic PKCS7 padding — we do our own in pkcs7_pad()
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    ok = ok && (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                                   padded.data(), static_cast<int>(padded.size())) == 1);
    ok = ok && (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return {};
    ciphertext.resize(out_len + final_len);
    return ciphertext;
}

std::vector<uint8_t> decrypt(EncryptType type,
                              const std::vector<uint8_t>& ciphertext,
                              const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& iv) {
    const EVP_CIPHER* cipher = nullptr;
    switch (type) {
    case EncryptType::Aes128: cipher = EVP_aes_128_cbc(); break;
    case EncryptType::Aes192: cipher = EVP_aes_192_cbc(); break;
    case EncryptType::Aes256: cipher = EVP_aes_256_cbc(); break;
    }
    if (!cipher) return {};

    std::vector<uint8_t> plaintext(ciphertext.size());
    int out_len = 0;
    int final_len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    bool ok = true;
    ok = ok && (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) == 1);
    // Disable OpenSSL's automatic PKCS7 padding — we do our own in pkcs7_unpad()
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    ok = ok && (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                                   ciphertext.data(), static_cast<int>(ciphertext.size())) == 1);
    ok = ok && (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return {};
    plaintext.resize(out_len + final_len);

    // Remove PKCS7 padding
    return pkcs7_unpad(plaintext);
}

// ---------------------------------------------------------------------------
// Random IV generation
// ---------------------------------------------------------------------------

std::vector<uint8_t> generate_random_iv() {
    std::vector<uint8_t> iv(16);
    if (RAND_bytes(iv.data(), 16) != 1) {
        return {}; // fallback — caller should check
    }
    return iv;
}

// ---------------------------------------------------------------------------
// Base64 encode (minimal, for Python wrapper)
// ---------------------------------------------------------------------------

namespace {

const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i < data.size()) {
        uint32_t buf = 0;
        int bytes_in = 0;
        for (int j = 0; j < 3 && i < data.size(); ++j) {
            buf = (buf << 8) | data[i++];
            ++bytes_in;
        }
        buf <<= (8 * (3 - bytes_in));

        result.push_back(B64_TABLE[(buf >> 18) & 0x3F]);
        result.push_back(B64_TABLE[(buf >> 12) & 0x3F]);
        result.push_back(bytes_in >= 2 ? B64_TABLE[(buf >> 6) & 0x3F] : '=');
        result.push_back(bytes_in >= 3 ? B64_TABLE[buf & 0x3F] : '=');
    }
    return result;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Python wrapper generator — self-decryptable output scripts
// ---------------------------------------------------------------------------

std::string make_python_decrypt_wrapper(EncryptType type,
                                         const std::string& b64_ciphertext,
                                         const std::string& b64_key,
                                         const std::string& b64_iv) {
    std::string w;
    w += "# Encrypted by Switch (" + encrypt_type_name(type) + ") — run with: python3 this_file.py\n";
    w += "# Requires: pip install cryptography\n";
    w += "import base64\n";
    w += "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n";
    w += "from cryptography.hazmat.primitives import padding as sym_padding\n";
    w += "from cryptography.hazmat.backends import default_backend\n";
    w += "\n";
    w += "_ct = base64.b64decode(\"" + b64_ciphertext + "\")\n";
    w += "_key = base64.b64decode(\"" + b64_key + "\")\n";
    w += "_iv  = base64.b64decode(\"" + b64_iv + "\")\n";
    w += "\n";
    w += "_cipher = Cipher(algorithms.AES(_key), modes.CBC(_iv), backend=default_backend())\n";
    w += "_dec = _cipher.decryptor()\n";
    w += "_pt = _dec.update(_ct) + _dec.finalize()\n";
    w += "\n";
    w += "_unpad = sym_padding.PKCS7(128).unpadder()\n";
    w += "_pt = _unpad.update(_pt) + _unpad.finalize()\n";
    w += "\n";
    w += "exec(_pt.decode('utf-8'))\n";
    return w;
}

// ---------------------------------------------------------------------------
// File-to-file encrypt with validation
// ---------------------------------------------------------------------------

bool encrypt_file(EncryptType type,
                  const std::string& input_path,
                  const std::string& output_path,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
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
    if (size > 0 && !in.read(reinterpret_cast<char*>(data.data()), size)) {
        error_msg = "failed to read input file '" + input_path + "'";
        return false;
    }
    in.close();

    // 2. Encrypt
    std::vector<uint8_t> ciphertext = encrypt(type, data, key, iv);
    if (ciphertext.empty() && !data.empty()) {
        error_msg = "encryption failed";
        return false;
    }

    // 3. Base64-encode ciphertext, key, and IV for embedding
    // Only embed the exact number of key bytes needed for the AES variant
    // (Python's algorithms.AES() auto-detects key size → wrong variant if too long)
    size_t key_len = 0;
    switch (type) {
    case EncryptType::Aes128: key_len = 16; break;
    case EncryptType::Aes192: key_len = 24; break;
    case EncryptType::Aes256: key_len = 32; break;
    }
    std::vector<uint8_t> key_trimmed(key.begin(), key.begin() + key_len);

    std::string b64_ct   = base64_encode(ciphertext);
    std::string b64_key  = base64_encode(key_trimmed);
    std::string b64_iv   = base64_encode(iv);

    // 4. Generate self-decryptable Python wrapper
    std::string output = make_python_decrypt_wrapper(type, b64_ct, b64_key, b64_iv);

    // 5. Write output
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

} // namespace switch_encrypt
