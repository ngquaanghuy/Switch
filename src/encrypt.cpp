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
    case EncryptType::XChaCha20: return "xchacha20";
    case EncryptType::Aes128Gcm: return "aes-128-gcm";
    case EncryptType::Aes192Gcm: return "aes-192-gcm";
    case EncryptType::Aes256Gcm: return "aes-256-gcm";
    case EncryptType::Aes128Ccm: return "aes-128-ccm";
    case EncryptType::Aes192Ccm: return "aes-192-ccm";
    case EncryptType::Aes256Ccm: return "aes-256-ccm";
    case EncryptType::Aes128Siv: return "aes-128-siv";
    case EncryptType::Aes256Siv: return "aes-256-siv";
    case EncryptType::Aes128Ocb: return "aes-128-ocb";
    case EncryptType::Aes192Ocb: return "aes-192-ocb";
    case EncryptType::Aes256Ocb: return "aes-256-ocb";
    }
    return "unknown";
}

std::string all_encrypt_names() {
    // Build from encrypt_type_name() to stay in sync with the enum.
    static const EncryptType types[] = {
        EncryptType::Aes128, EncryptType::Aes192, EncryptType::Aes256,
        EncryptType::ChaCha20, EncryptType::XChaCha20,
        EncryptType::Aes128Gcm, EncryptType::Aes192Gcm, EncryptType::Aes256Gcm,
        EncryptType::Aes128Ccm, EncryptType::Aes192Ccm, EncryptType::Aes256Ccm,
        EncryptType::Aes128Siv, EncryptType::Aes256Siv,
        EncryptType::Aes128Ocb, EncryptType::Aes192Ocb, EncryptType::Aes256Ocb,
    };
    std::string result;
    for (size_t i = 0; i < std::size(types); ++i) {
        if (i > 0) result += ", ";
        result += encrypt_type_name(types[i]);
    }
    return result;
}

size_t expected_key_len(EncryptType type) {
    switch (type) {
    case EncryptType::Aes128:    return 16;
    case EncryptType::Aes192:    return 24;
    case EncryptType::Aes256:    return 32;
    case EncryptType::ChaCha20:  return 32;
    case EncryptType::XChaCha20: return 32;
    case EncryptType::Aes128Gcm: return 16;
    case EncryptType::Aes192Gcm: return 24;
    case EncryptType::Aes256Gcm: return 32;
    case EncryptType::Aes128Ccm: return 16;
    case EncryptType::Aes192Ccm: return 24;
    case EncryptType::Aes256Ccm: return 32;
    case EncryptType::Aes128Siv: return 32;  // 16 CMAC + 16 CTR
    case EncryptType::Aes256Siv: return 32;  // 16 CMAC + 16 CTR
    case EncryptType::Aes128Ocb: return 16;
    case EncryptType::Aes192Ocb: return 24;
    case EncryptType::Aes256Ocb: return 32;
    }
    return 0;
}

size_t expected_nonce_len(EncryptType type) {
    switch (type) {
    case EncryptType::Aes128:    return 16; // IV
    case EncryptType::Aes192:    return 16; // IV
    case EncryptType::Aes256:    return 16; // IV
    case EncryptType::ChaCha20:  return 12; // IETF nonce
    case EncryptType::XChaCha20: return 24; // XChaCha20 IETF nonce
    case EncryptType::Aes128Gcm: return 12; // GCM standard IV
    case EncryptType::Aes192Gcm: return 12; // GCM standard IV
    case EncryptType::Aes256Gcm: return 12; // GCM standard IV
    case EncryptType::Aes128Ccm: return 12; // CCM standard nonce
    case EncryptType::Aes192Ccm: return 12; // CCM standard nonce
    case EncryptType::Aes256Ccm: return 12; // CCM standard nonce
    case EncryptType::Aes128Siv: return 0;  // SIV nonce optional
    case EncryptType::Aes256Siv: return 0;  // SIV nonce optional
    case EncryptType::Aes128Ocb: return 12; // OCB standard nonce
    case EncryptType::Aes192Ocb: return 12; // OCB standard nonce
    case EncryptType::Aes256Ocb: return 12; // OCB standard nonce
    }
    return 0;
}

bool is_stream_cipher(EncryptType type) {
    return type == EncryptType::ChaCha20 || type == EncryptType::XChaCha20;
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

const EVP_CIPHER* get_evp_gcm_cipher(EncryptType type) {
    switch (type) {
    case EncryptType::Aes128Gcm: return EVP_aes_128_gcm();
    case EncryptType::Aes192Gcm: return EVP_aes_192_gcm();
    case EncryptType::Aes256Gcm: return EVP_aes_256_gcm();
    default: return nullptr;
    }
}

const EVP_CIPHER* get_evp_ocb_cipher(EncryptType type) {
    switch (type) {
    case EncryptType::Aes128Ocb: return EVP_aes_128_ocb();
    case EncryptType::Aes192Ocb: return EVP_aes_192_ocb();
    case EncryptType::Aes256Ocb: return EVP_aes_256_ocb();
    default: return nullptr;
    }
}

const EVP_CIPHER* get_evp_ccm_cipher(EncryptType type) {
    switch (type) {
    case EncryptType::Aes128Ccm: return EVP_aes_128_ccm();
    case EncryptType::Aes192Ccm: return EVP_aes_192_ccm();
    case EncryptType::Aes256Ccm: return EVP_aes_256_ccm();
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
// AES-256-GCM AEAD encrypt / decrypt via OpenSSL EVP
// ---------------------------------------------------------------------------

namespace {

// GCM appends 16-byte auth tag to ciphertext.
// Ciphertext = encrypted_data + 16_byte_tag. No padding needed.

std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t>& plaintext,
                                     const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& iv,
                                     EncryptType type) {
    const EVP_CIPHER* cipher = get_evp_gcm_cipher(type);
    if (!cipher) return {};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> ciphertext(plaintext.size());
    int out_len = 0;
    int final_len = 0;
    uint8_t tag[16] = {};

    bool ok = true;
    ok = ok && (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_set_key_length(ctx, static_cast<int>(key.size())) == 1);
    ok = ok && (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);
    ok = ok && (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                                  plaintext.data(), static_cast<int>(plaintext.size())) == 1);
    ok = ok && (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return {};
    ciphertext.resize(out_len + final_len);
    ciphertext.insert(ciphertext.end(), tag, tag + 16);
    return ciphertext;
}

std::vector<uint8_t> aes_gcm_decrypt(const std::vector<uint8_t>& ciphertext,
                                     const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& iv,
                                     EncryptType type) {
    const EVP_CIPHER* cipher = get_evp_gcm_cipher(type);
    if (!cipher) return {};

    constexpr size_t TAG_LEN = 16;
    if (ciphertext.size() < TAG_LEN) return {};

    size_t enc_len = ciphertext.size() - TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> plaintext(enc_len);
    int out_len = 0;
    int final_len = 0;

    bool ok = true;
    ok = ok && (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_set_key_length(ctx, static_cast<int>(key.size())) == 1);
    ok = ok && (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);
    ok = ok && (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                                  ciphertext.data(), static_cast<int>(enc_len)) == 1);
    // Set expected tag
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                    const_cast<uint8_t*>(ciphertext.data() + enc_len)) == 1);
    // Verify tag on finalize — returns 0 if tag mismatch
    ok = ok && (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return {}; // tag verification failed
    plaintext.resize(out_len + final_len);
    return plaintext;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// AES-OCB AEAD encrypt / decrypt via OpenSSL EVP (RFC 7253)
// ---------------------------------------------------------------------------

namespace {

// OCB appends 16-byte auth tag to ciphertext.
// Same pattern as GCM — no padding, stream mode.

std::vector<uint8_t> aes_ocb_encrypt(const std::vector<uint8_t>& plaintext,
                                     const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& iv,
                                     EncryptType type) {
    const EVP_CIPHER* cipher = get_evp_ocb_cipher(type);
    if (!cipher) return {};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> ciphertext(plaintext.size());
    int out_len = 0;
    int final_len = 0;
    uint8_t tag[16] = {};

    bool ok = true;
    ok = ok && (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_set_key_length(ctx, static_cast<int>(key.size())) == 1);
    ok = ok && (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);
    ok = ok && (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                                  plaintext.data(), static_cast<int>(plaintext.size())) == 1);
    ok = ok && (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return {};
    ciphertext.resize(out_len + final_len);
    ciphertext.insert(ciphertext.end(), tag, tag + 16);
    return ciphertext;
}

std::vector<uint8_t> aes_ocb_decrypt(const std::vector<uint8_t>& ciphertext,
                                     const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& iv,
                                     EncryptType type) {
    const EVP_CIPHER* cipher = get_evp_ocb_cipher(type);
    if (!cipher) return {};

    constexpr size_t TAG_LEN = 16;
    if (ciphertext.size() < TAG_LEN) return {};

    size_t enc_len = ciphertext.size() - TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> plaintext(enc_len);
    int out_len = 0;
    int final_len = 0;

    bool ok = true;
    ok = ok && (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_set_key_length(ctx, static_cast<int>(key.size())) == 1);
    ok = ok && (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);
    ok = ok && (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                                  ciphertext.data(), static_cast<int>(enc_len)) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                    const_cast<uint8_t*>(ciphertext.data() + enc_len)) == 1);
    ok = ok && (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return {};
    plaintext.resize(out_len + final_len);
    return plaintext;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// AES-CCM AEAD encrypt / decrypt via OpenSSL EVP (NIST SP 800-38C)
// ---------------------------------------------------------------------------

namespace {

// CCM appends 16-byte auth tag to ciphertext.
// Unlike GCM, CCM requires message length set BEFORE encryption.

constexpr size_t CCM_TAG_LEN = 16;
constexpr int CCM_L = 3; // nonce_len = 15 - L → 15 - 3 = 12 bytes

std::vector<uint8_t> aes_ccm_encrypt(const std::vector<uint8_t>& plaintext,
                                     const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& nonce,
                                     EncryptType type) {
    const EVP_CIPHER* cipher = get_evp_ccm_cipher(type);
    if (!cipher) return {};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> ciphertext(plaintext.size());
    int out_len = 0;
    int final_len = 0;
    uint8_t tag[CCM_TAG_LEN] = {};

    bool ok = true;
    ok = ok && (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, CCM_TAG_LEN, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, CCM_L, nullptr) == 1);
    // Note: SET_MSGLEN returns 0 (not 1) in OpenSSL 3.x — not an error, value is set internally.
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_MSGLEN, static_cast<int>(plaintext.size()), nullptr);
    ok = ok && (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1);
    ok = ok && (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                                  plaintext.data(), static_cast<int>(plaintext.size())) == 1);
    ok = ok && (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, CCM_TAG_LEN, tag) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return {};
    ciphertext.resize(out_len + final_len);
    ciphertext.insert(ciphertext.end(), tag, tag + CCM_TAG_LEN);
    return ciphertext;
}

std::vector<uint8_t> aes_ccm_decrypt(const std::vector<uint8_t>& ciphertext,
                                     const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& nonce,
                                     EncryptType type) {
    const EVP_CIPHER* cipher = get_evp_ccm_cipher(type);
    if (!cipher) return {};

    if (ciphertext.size() < CCM_TAG_LEN) return {};
    size_t enc_len = ciphertext.size() - CCM_TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> plaintext(enc_len);
    int out_len = 0;
    int final_len = 0;

    bool ok = true;
    ok = ok && (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, CCM_L, nullptr) == 1);
    // Note: SET_MSGLEN returns 0 (not 1) in OpenSSL 3.x — not an error, value is set internally.
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_MSGLEN, static_cast<int>(enc_len), nullptr);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, CCM_TAG_LEN,
                                    const_cast<uint8_t*>(ciphertext.data() + enc_len)) == 1);
    ok = ok && (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1);
    ok = ok && (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                                  ciphertext.data(), static_cast<int>(enc_len)) == 1);
    ok = ok && (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return {}; // tag verification failed
    plaintext.resize(out_len + final_len);
    return plaintext;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// AES-SIV (RFC 5297) encrypt / decrypt via OpenSSL CMAC + AES-CTR
// ---------------------------------------------------------------------------

namespace {

// GF(2^128) doubling: shift left by 1 bit, XOR 0x87 if MSB was set.
// Byte-order convention: block[0] holds the MSB (big-endian byte order),
// consistent with AES-CMAC output per RFC 5297 S2V. The carry propagates
// from block[0] → block[15], and the reduction polynomial 0x87 is applied
// to the LSB (block[15]) when the MSB was set before the shift.
static void gf128_double(uint8_t block[16]) {
    uint8_t msb = block[0] & 0x80;
    // Shift left by 1 bit
    for (int i = 0; i < 15; ++i) {
        block[i] = (block[i] << 1) | (block[i + 1] >> 7);
    }
    block[15] <<= 1;
    if (msb) block[15] ^= 0x87;
}

// AES-128-CMAC via OpenSSL EVP_MAC (OpenSSL 3.x API).
static std::vector<uint8_t> cmac_aes128(const uint8_t key[16],
                                        const uint8_t* data, size_t len) {
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
    if (!mac) return {};

    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) { EVP_MAC_free(mac); return {}; }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("cipher", const_cast<char*>("AES-128-CBC"), 0),
        OSSL_PARAM_construct_end()
    };

    bool ok = true;
    ok = ok && (EVP_MAC_init(ctx, key, 16, params) == 1);
    ok = ok && (EVP_MAC_update(ctx, data, len) == 1);

    size_t tag_len = 0;
    ok = ok && (EVP_MAC_final(ctx, nullptr, &tag_len, 0) == 1);
    std::vector<uint8_t> tag(tag_len);
    ok = ok && (EVP_MAC_final(ctx, tag.data(), &tag_len, tag_len) == 1);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok ? tag : std::vector<uint8_t>{};
}

// S2V: derive 16-byte synthetic IV per RFC 5297.
// ad_list is a vector of associated data chunks.
static std::vector<uint8_t> siv_s2v(const uint8_t* cmac_key,
                                    const std::vector<std::vector<uint8_t>>& ad_list,
                                    const uint8_t* plaintext, size_t pt_len) {
    // Step 1: D = CMAC(K1, "") — start with CMAC of empty string
    std::vector<uint8_t> d = cmac_aes128(cmac_key, nullptr, 0);

    // Step 2: For each AD[i], D = CMAC(K1, D XOR CMAC(K1, AD[i]))
    for (const auto& ad : ad_list) {
        auto cmac_ad = cmac_aes128(cmac_key, ad.data(), ad.size());
        for (int i = 0; i < 16; ++i) d[i] ^= cmac_ad[i];
        gf128_double(d.data());
        auto cmac_d = cmac_aes128(cmac_key, d.data(), 16);
        d = cmac_d;
    }

    // Step 3: Double D
    gf128_double(d.data());

    // Step 4: D ^= pad(plaintext) per RFC 5297 Section 2.3
    // For len >= 16 bytes: XOR with last block XOR 0xFF...FF
    // For len < 16 bytes: CMAC(K1, plaintext || 1 || 0^pad)
    if (pt_len >= 16) {
        const uint8_t* last_block = plaintext + pt_len - 16;
        uint8_t ones[16];
        std::memset(ones, 0xFF, 16);
        for (int i = 0; i < 16; ++i) d[i] ^= (last_block[i] ^ ones[i]);
    } else {
        // Pad: plaintext || 0x80 || zeros to 16 bytes
        uint8_t padded[16] = {};
        std::memcpy(padded, plaintext, pt_len);
        padded[pt_len] = 0x80;
        auto cmac_padded = cmac_aes128(cmac_key, padded, 16);
        for (int i = 0; i < 16; ++i) d[i] ^= cmac_padded[i];
    }

    // Step 5: SIV = CMAC(K1, D)
    return cmac_aes128(cmac_key, d.data(), 16);
}

// AES-CTR with 128-bit IV (big-endian counter = IV + 1).
// Note: OpenSSL EVP_aes_256_cbc() with padding disabled is NOT CTR.
// We use EVP_EncryptInit_ex with the actual CTR cipher.
static std::vector<uint8_t> aes_ctr(const uint8_t* key, size_t key_len,
                                    const uint8_t iv[16],
                                    const uint8_t* data, size_t len) {
    const EVP_CIPHER* cipher = (key_len == 32) ? EVP_aes_256_ctr() : EVP_aes_128_ctr();
    if (!cipher) return {};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> out(len);
    int out_len = 0, final_len = 0;

    bool ok = true;
    ok = ok && (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv) == 1);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    ok = ok && (EVP_EncryptUpdate(ctx, out.data(), &out_len, data, static_cast<int>(len)) == 1);
    ok = ok && (EVP_EncryptFinal_ex(ctx, out.data() + out_len, &final_len) == 1);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return {};
    out.resize(out_len + final_len);
    return out;
}

// SIV encrypt: returns SIV(16 bytes) || CTR_ciphertext.
static std::vector<uint8_t> aes_siv_encrypt(const uint8_t* key, size_t key_len,
                                            const uint8_t* /*nonce*/, size_t /*nonce_len*/,
                                            const uint8_t* plaintext, size_t pt_len) {
    // Key split: CMAC=key[:16], CTR=key[16:32] (first32 bytes used for both sizes)
    const uint8_t* cmac_key = key;       // first 16 bytes
    const uint8_t* ctr_key = key + 16;   // bytes 16-31

    // Compute SIV
    std::vector<std::vector<uint8_t>> ad_list;
    auto siv = siv_s2v(cmac_key, ad_list, plaintext, pt_len);

    // Derive CTR IV: clear MSB of SIV
    uint8_t iv[16];
    std::copy(siv.begin(), siv.end(), iv);
    iv[0] &= 0x7F; // clear MSB

    // CTR encrypt
    auto ct = aes_ctr(ctr_key, 16, iv, plaintext, pt_len);

    // Output: SIV || ciphertext
    std::vector<uint8_t> result;
    result.reserve(16 + ct.size());
    result.insert(result.end(), siv.begin(), siv.end());
    result.insert(result.end(), ct.begin(), ct.end());
    return result;
}

// SIV decrypt: split SIV, CTR decrypt, verify SIV.
static std::vector<uint8_t> aes_siv_decrypt(const uint8_t* key, size_t key_len,
                                            const uint8_t* /*nonce*/, size_t /*nonce_len*/,
                                            const uint8_t* ciphertext, size_t ct_len) {
    if (ct_len < 16) return {};

    // Key split: CMAC=key[:16], CTR=key[16:32]
    const uint8_t* cmac_key = key;
    const uint8_t* ctr_key = key + 16;

    // Extract SIV
    const uint8_t* siv = ciphertext;
    const uint8_t* enc_data = ciphertext + 16;
    size_t enc_len = ct_len - 16;

    // Derive CTR IV
    uint8_t iv[16];
    std::copy(siv, siv + 16, iv);
    iv[0] &= 0x7F;

    // CTR decrypt
    auto pt = aes_ctr(ctr_key, 16, iv, enc_data, enc_len);
    if (pt.empty() && enc_len > 0) return {};

    // Verify: recompute SIV and compare
    std::vector<std::vector<uint8_t>> ad_list;
    auto expected_siv = siv_s2v(cmac_key, ad_list, pt.data(), pt.size());

    if (std::memcmp(siv, expected_siv.data(), 16) != 0) return {};
    return pt;
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
// XChaCha20-Poly1305 AEAD encrypt / decrypt via libsodium (IETF variant)
// ---------------------------------------------------------------------------

namespace {

// XChaCha20 extends ChaCha20 with 24-byte nonce (HChaCha20 key derivation).
// libsodium appends 16-byte Poly1305 MAC to ciphertext.

std::vector<uint8_t> xchacha20_encrypt(const std::vector<uint8_t>& plaintext,
                                       const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& nonce) {
    std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
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

std::vector<uint8_t> xchacha20_decrypt(const std::vector<uint8_t>& ciphertext,
                                       const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& nonce) {
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return {}; // too short for MAC
    }

    std::vector<uint8_t> plaintext(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
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
    case EncryptType::XChaCha20:
        return xchacha20_encrypt(plaintext, key, iv_or_nonce);
    case EncryptType::Aes128Gcm:
    case EncryptType::Aes192Gcm:
    case EncryptType::Aes256Gcm:
        return aes_gcm_encrypt(plaintext, key, iv_or_nonce, type);
    case EncryptType::Aes128Ccm:
    case EncryptType::Aes192Ccm:
    case EncryptType::Aes256Ccm:
        return aes_ccm_encrypt(plaintext, key, iv_or_nonce, type);
    case EncryptType::Aes128Siv:
    case EncryptType::Aes256Siv:
        return aes_siv_encrypt(key.data(), key.size(),
                               iv_or_nonce.data(), iv_or_nonce.size(),
                               plaintext.data(), plaintext.size());
    case EncryptType::Aes128Ocb:
    case EncryptType::Aes192Ocb:
    case EncryptType::Aes256Ocb:
        return aes_ocb_encrypt(plaintext, key, iv_or_nonce, type);
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
    case EncryptType::XChaCha20:
        return xchacha20_decrypt(ciphertext, key, iv_or_nonce);
    case EncryptType::Aes128Gcm:
    case EncryptType::Aes192Gcm:
    case EncryptType::Aes256Gcm:
        return aes_gcm_decrypt(ciphertext, key, iv_or_nonce, type);
    case EncryptType::Aes128Ccm:
    case EncryptType::Aes192Ccm:
    case EncryptType::Aes256Ccm:
        return aes_ccm_decrypt(ciphertext, key, iv_or_nonce, type);
    case EncryptType::Aes128Siv:
    case EncryptType::Aes256Siv:
        return aes_siv_decrypt(key.data(), key.size(),
                               iv_or_nonce.data(), iv_or_nonce.size(),
                               ciphertext.data(), ciphertext.size());
    case EncryptType::Aes128Ocb:
    case EncryptType::Aes192Ocb:
    case EncryptType::Aes256Ocb:
        return aes_ocb_decrypt(ciphertext, key, iv_or_nonce, type);
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
    if (type == EncryptType::XChaCha20) {
        w += "# Requires: pip install pynacl\n";
    } else {
        w += "# Requires: pip install cryptography\n";
    }
    w += "import sys\n";
    w += "\n";
    w += "try:\n";
    w += "    import base64\n";

    if (type == EncryptType::ChaCha20) {
        w += "    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n";
    } else if (type == EncryptType::XChaCha20) {
        w += "    from nacl._sodium import ffi, lib\n";
    } else if (type == EncryptType::Aes128Gcm || type == EncryptType::Aes192Gcm || type == EncryptType::Aes256Gcm) {
        w += "    from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n";
    } else if (type == EncryptType::Aes128Ccm || type == EncryptType::Aes192Ccm || type == EncryptType::Aes256Ccm) {
        w += "    from cryptography.hazmat.primitives.ciphers.aead import AESCCM\n";
    } else if (type == EncryptType::Aes128Ocb || type == EncryptType::Aes192Ocb || type == EncryptType::Aes256Ocb) {
        w += "    from cryptography.hazmat.primitives.ciphers.aead import AESOCB3\n";
    } else if (type == EncryptType::Aes128Siv || type == EncryptType::Aes256Siv) {
        w += "    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n";
        w += "    from cryptography.hazmat.primitives.cmac import CMAC as _CMAC\n";
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
    } else if (type == EncryptType::XChaCha20) {
        w += "    _pt_buf = ffi.new('unsigned char[]', len(_ct) - 16)\n";
        w += "    _pt_len = ffi.new('unsigned long long *')\n";
        w += "    if lib.crypto_aead_xchacha20poly1305_ietf_decrypt(\n";
        w += "            _pt_buf, _pt_len, ffi.NULL,\n";
        w += "            _ct, len(_ct), ffi.NULL, 0, _nonce, _key) != 0:\n";
        w += "        raise ValueError('XChaCha20-Poly1305 decryption failed (bad key or nonce)')\n";
        w += "    _pt = bytes(_pt_buf)[:_pt_len[0]]\n";
    } else if (type == EncryptType::Aes128Gcm || type == EncryptType::Aes192Gcm || type == EncryptType::Aes256Gcm) {
        w += "    _box = AESGCM(_key)\n";
        w += "    _pt = _box.decrypt(_iv, _ct, None)\n";
    } else if (type == EncryptType::Aes128Ccm || type == EncryptType::Aes192Ccm || type == EncryptType::Aes256Ccm) {
        w += "    _box = AESCCM(_key, tag_length=16)\n";
        w += "    _pt = _box.decrypt(_iv, _ct, None)\n";
    } else if (type == EncryptType::Aes128Ocb || type == EncryptType::Aes192Ocb || type == EncryptType::Aes256Ocb) {
        w += "    _box = AESOCB3(_key)\n";
        w += "    _pt = _box.decrypt(_iv, _ct, None)\n";
    } else if (type == EncryptType::Aes128Siv || type == EncryptType::Aes256Siv) {
        w += "    def _cmac128(k, d):\n";
        w += "        c = _CMAC(algorithms.AES(k[:16])); c.update(d); return c.finalize()\n";
        w += "    def _gf128dbl(b):\n";
        w += "        b = bytearray(b); m = b[0] & 0x80\n";
        w += "        for i in range(15): b[i] = ((b[i] << 1) | (b[i+1] >> 7)) & 0xFF\n";
        w += "        b[15] = (b[15] << 1) & 0xFF\n";
        w += "        if m: b[15] ^= 0x87\n";
        w += "        return bytes(b)\n";
        w += "    def _s2v(k, pt):\n";
        w += "        d = _cmac128(k, b'')\n";
        w += "        d = _gf128dbl(d)\n";
        w += "        if len(pt) >= 16:\n";
        w += "            d = bytes(a ^ b ^ 0xFF for a, b in zip(d, pt[-16:]))\n";
        w += "        else:\n";
        w += "            padded = pt + b'\\x80' + b'\\x00' * (15 - len(pt))\n";
        w += "            d = bytes(a ^ b for a, b in zip(d, _cmac128(k, padded)))\n";
        w += "        return _cmac128(k, d)\n";
        w += "    _siv = bytes(_ct[:16])\n";
        w += "    _iv = bytearray(_siv); _iv[0] &= 0x7F\n";
        w += "    _cmac_key = _key[:16]\n";
        w += "    _ctr_key = _key[16:32]\n";
        w += "    _dec = Cipher(algorithms.AES(_ctr_key), modes.CTR(bytes(_iv))).decryptor()\n";
        w += "    _pt = _dec.update(_ct[16:]) + _dec.finalize()\n";
        w += "    _expected_siv = _s2v(_cmac_key, _pt)\n";
        w += "    if _siv != _expected_siv:\n";
        w += "        raise ValueError('AES-SIV verification failed (bad key)')\n";
    } else {
        w += "    _cipher = Cipher(algorithms.AES(_key), modes.CBC(_iv))\n";
        w += "    _dec = _cipher.decryptor()\n";
        w += "    _pt = _dec.update(_ct) + _dec.finalize()\n";
        w += "    _unpad = sym_padding.PKCS7(128).unpadder()\n";
        w += "    _pt = _unpad.update(_pt) + _unpad.finalize()\n";
    }

    w += "    exec(_pt.decode('utf-8'))\n";

    if (type == EncryptType::ChaCha20 || type == EncryptType::XChaCha20) {
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

    // 2. Validate key length
    size_t key_len = expected_key_len(type);
    if (key.size() < key_len) {
        error_msg = "key too short for " + encrypt_type_name(type);
        return false;
    }

    // 3. Encrypt
    std::vector<uint8_t> ciphertext = encrypt(type, data, key, iv_or_nonce);
    if (ciphertext.empty()) {
        error_msg = "encryption failed";
        return false;
    }

    // 4. Base64-encode ciphertext, key, and IV/nonce for embedding
    std::string b64_ct   = base64_encode(ciphertext);
    std::string b64_key  = base64_encode(key);
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
