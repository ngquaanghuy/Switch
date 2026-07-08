#include "switch/encrypt.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <sodium.h>

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

} // anonymous namespace

std::optional<std::vector<uint8_t>> hex_to_bytes(std::string_view hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    if (hex.empty()) return std::nullopt;

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

// ---------------------------------------------------------------------------
// EncryptType resolution
// ---------------------------------------------------------------------------

std::string encrypt_type_name(EncryptType type) {
    switch (type) {
    case EncryptType::Aes128:    return "aes-128";
    case EncryptType::Aes192:    return "aes-192";
    case EncryptType::Aes256:    return "aes-256";
    case EncryptType::ChaCha20:  return "chacha20";
    }
    return "unknown";
}

std::string all_encrypt_names() {
    return "aes-128, aes-192, aes-256, chacha20";
}

size_t expected_key_len(EncryptType type) {
    switch (type) {
    case EncryptType::Aes128:    return 16;
    case EncryptType::Aes192:    return 24;
    case EncryptType::Aes256:    return 32;
    case EncryptType::ChaCha20:  return 32;
    }
    return 0;
}

size_t expected_nonce_len(EncryptType type) {
    switch (type) {
    case EncryptType::Aes128:    return 16; // IV
    case EncryptType::Aes192:    return 16; // IV
    case EncryptType::Aes256:    return 16; // IV
    case EncryptType::ChaCha20:  return 12; // IETF nonce
    }
    return 0;
}

bool is_stream_cipher(EncryptType type) {
    return type == EncryptType::ChaCha20;
}

// ---------------------------------------------------------------------------
// AES cipher selection (OpenSSL)
// ---------------------------------------------------------------------------

namespace {

const EVP_CIPHER* get_evp_cipher(EncryptType type) {
    switch (type) {
    case EncryptType::Aes128: return EVP_aes_128_cbc();
    case EncryptType::Aes192: return EVP_aes_192_cbc();
    case EncryptType::Aes256: return EVP_aes_256_cbc();
    default: return nullptr;
    }
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// PKCS7 Padding (AES only)
// ---------------------------------------------------------------------------

namespace {

std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t>& data) {
    constexpr size_t BLOCK_SIZE = 16;
    size_t pad_len = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
    std::vector<uint8_t> padded(data);
    padded.insert(padded.end(), pad_len, static_cast<uint8_t>(pad_len));
    return padded;
}

std::vector<uint8_t> pkcs7_unpad(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};

    uint8_t pad_len = data.back();
    if (pad_len == 0 || pad_len > 16 || pad_len > data.size()) {
        return {};
    }

    for (size_t i = data.size() - pad_len; i < data.size(); ++i) {
        if (data[i] != pad_len) return {};
    }

    return std::vector<uint8_t>(data.begin(), data.end() - pad_len);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// AES-CBC encrypt / decrypt via OpenSSL EVP
// ---------------------------------------------------------------------------

namespace {

std::vector<uint8_t> aes_encrypt(const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& iv,
                                  EncryptType type) {
    const EVP_CIPHER* cipher = get_evp_cipher(type);
    if (!cipher) return {};

    std::vector<uint8_t> padded = pkcs7_pad(plaintext);
    std::vector<uint8_t> ciphertext(padded.size());
    int out_len = 0;
    int final_len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    bool ok = true;
    ok = ok && (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) == 1);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    ok = ok && (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                                   padded.data(), static_cast<int>(padded.size())) == 1);
    ok = ok && (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return {};
    ciphertext.resize(out_len + final_len);
    return ciphertext;
}

std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t>& ciphertext,
                                  const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& iv,
                                  EncryptType type) {
    const EVP_CIPHER* cipher = get_evp_cipher(type);
    if (!cipher) return {};

    std::vector<uint8_t> plaintext(ciphertext.size());
    int out_len = 0;
    int final_len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    bool ok = true;
    ok = ok && (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) == 1);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    ok = ok && (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                                   ciphertext.data(), static_cast<int>(ciphertext.size())) == 1);
    ok = ok && (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return {};
    plaintext.resize(out_len + final_len);
    return pkcs7_unpad(plaintext);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD encrypt / decrypt via libsodium (IETF variant)
// ---------------------------------------------------------------------------

namespace {

// libsodium appends 16-byte Poly1305 MAC to ciphertext.
// Ciphertext = encrypted_data + 16_byte_mac.

std::vector<uint8_t> chacha20_encrypt(const std::vector<uint8_t>& plaintext,
                                       const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& nonce) {
    // ciphertext = plaintext + 16-byte MAC
    std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len = 0;

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0,  // no additional data
            nullptr,     // no nonce copy
            nonce.data(),
            key.data()) != 0) {
        return {};
    }
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::vector<uint8_t> chacha20_decrypt(const std::vector<uint8_t>& ciphertext,
                                       const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& nonce) {
    if (ciphertext.size() < crypto_aead_chacha20poly1305_ietf_ABYTES) {
        return {}; // too short for MAC
    }

    std::vector<uint8_t> plaintext(ciphertext.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_len = 0;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,  // no additional data
            ciphertext.data(), ciphertext.size(),
            nullptr, 0, // no additional data
            nonce.data(),
            key.data()) != 0) {
        return {}; // MAC verification failed
    }
    plaintext.resize(plaintext_len);
    return plaintext;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Unified encrypt / decrypt dispatch
// ---------------------------------------------------------------------------

std::vector<uint8_t> encrypt(EncryptType type,
                              const std::vector<uint8_t>& plaintext,
                              const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& iv_or_nonce) {
    // Validate key length
    if (key.size() != expected_key_len(type)) return {};
    // Validate IV/nonce length
    if (iv_or_nonce.size() != expected_nonce_len(type)) return {};

    switch (type) {
    case EncryptType::Aes128:
    case EncryptType::Aes192:
    case EncryptType::Aes256:
        return aes_encrypt(plaintext, key, iv_or_nonce, type);
    case EncryptType::ChaCha20:
        return chacha20_encrypt(plaintext, key, iv_or_nonce);
    }
    return {};
}

std::vector<uint8_t> decrypt(EncryptType type,
                              const std::vector<uint8_t>& ciphertext,
                              const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& iv_or_nonce) {
    // Validate key length
    if (key.size() != expected_key_len(type)) return {};
    // Validate IV/nonce length
    if (iv_or_nonce.size() != expected_nonce_len(type)) return {};

    switch (type) {
    case EncryptType::Aes128:
    case EncryptType::Aes192:
    case EncryptType::Aes256:
        return aes_decrypt(ciphertext, key, iv_or_nonce, type);
    case EncryptType::ChaCha20:
        return chacha20_decrypt(ciphertext, key, iv_or_nonce);
    }
    return {};
}

// ---------------------------------------------------------------------------
// Random IV / nonce generation
// ---------------------------------------------------------------------------

std::vector<uint8_t> generate_random_iv() {
    std::vector<uint8_t> iv(16);
    if (RAND_bytes(iv.data(), 16) != 1) {
        return {};
    }
    return iv;
}

std::vector<uint8_t> generate_random_nonce(size_t len) {
    std::vector<uint8_t> nonce(len);
    randombytes_buf(nonce.data(), len);
    return nonce;
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

std::string generate_key(EncryptType type) {
    size_t len = expected_key_len(type);
    if (len == 0) return {};

    std::vector<uint8_t> key(len);

    if (is_stream_cipher(type)) {
        randombytes_buf(key.data(), len);
    } else {
        if (RAND_bytes(key.data(), static_cast<int>(len)) != 1) return {};
    }

    // Convert to hex
    static const char HEX[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(len * 2);
    for (uint8_t b : key) {
        hex.push_back(HEX[b >> 4]);
        hex.push_back(HEX[b & 0x0F]);
    }
    return hex;
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
                                         const std::string& b64_iv_or_nonce) {
    std::string w;
    w += "# Encrypted by Switch (" + encrypt_type_name(type) + ") — run with: python3 this_file.py\n";
    w += "# Requires: pip install cryptography\n";
    w += "import sys\n";
    w += "\n";
    w += "try:\n";
    w += "    import base64\n";

    if (type == EncryptType::ChaCha20) {
        w += "    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n";
    } else {
        w += "    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n";
        w += "    from cryptography.hazmat.primitives import padding as sym_padding\n";
    }

    w += "except ImportError:\n";
    w += "    print('Error: \"cryptography\" package not found.', file=sys.stderr)\n";
    w += "    print('Install it with: pip install cryptography', file=sys.stderr)\n";
    w += "    sys.exit(1)\n";
    w += "\n";

    w += "_ct = base64.b64decode(\"" + b64_ciphertext + "\")\n";
    w += "_key = base64.b64decode(\"" + b64_key + "\")\n";

    if (is_stream_cipher(type)) {
        w += "_nonce = base64.b64decode(\"" + b64_iv_or_nonce + "\")\n";
    } else {
        w += "_iv  = base64.b64decode(\"" + b64_iv_or_nonce + "\")\n";
    }

    w += "\n";
    w += "try:\n";

    if (type == EncryptType::ChaCha20) {
        w += "    _box = ChaCha20Poly1305(_key)\n";
        w += "    _pt = _box.decrypt(_nonce, _ct, None)\n";
    } else {
        w += "    _cipher = Cipher(algorithms.AES(_key), modes.CBC(_iv))\n";
        w += "    _dec = _cipher.decryptor()\n";
        w += "    _pt = _dec.update(_ct) + _dec.finalize()\n";
        w += "    _unpad = sym_padding.PKCS7(128).unpadder()\n";
        w += "    _pt = _unpad.update(_pt) + _unpad.finalize()\n";
    }

    w += "    exec(_pt.decode('utf-8'))\n";

    if (type == EncryptType::ChaCha20) {
        w += "except (ValueError, Exception) as e:\n";
        w += "    print(f'Error: decryption failed — {e}', file=sys.stderr)\n";
        w += "    print('The file may have been encrypted with a different key.', file=sys.stderr)\n";
        w += "    sys.exit(1)\n";
    } else {
        w += "except ValueError as e:\n";
        w += "    print(f'Error: decryption failed — {e}', file=sys.stderr)\n";
        w += "    print('The file may have been encrypted with a different key.', file=sys.stderr)\n";
        w += "    sys.exit(1)\n";
    }

    return w;
}

// ---------------------------------------------------------------------------
// File-to-file encrypt with validation
// ---------------------------------------------------------------------------

bool encrypt_file(EncryptType type,
                  const std::string& input_path,
                  const std::string& output_path,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv_or_nonce,
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

    // 2. Safe key trim — validate key length before encryption
    size_t key_len = expected_key_len(type);
    if (key.size() < key_len) {
        error_msg = "key too short for " + encrypt_type_name(type);
        return false;
    }
    std::vector<uint8_t> key_trimmed(key.begin(), key.begin() + key_len);

    // 3. Encrypt
    std::vector<uint8_t> ciphertext = encrypt(type, data, key, iv_or_nonce);
    if (ciphertext.empty()) {
        error_msg = "encryption failed";
        return false;
    }

    // 4. Base64-encode ciphertext, key, and IV/nonce for embedding
    std::string b64_ct   = base64_encode(ciphertext);
    std::string b64_key  = base64_encode(key_trimmed);
    std::string b64_iv   = base64_encode(iv_or_nonce);

    // 5. Generate self-decryptable Python wrapper
    std::string output = make_python_decrypt_wrapper(type, b64_ct, b64_key, b64_iv);

    // 6. Write output
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
