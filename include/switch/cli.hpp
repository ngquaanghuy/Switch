#pragma once

#include "switch/encode.hpp"
#include "switch/encrypt.hpp"
#include "switch/obfuscate.hpp"

#include <string>
#include <vector>
#include <optional>
#include <string_view>

namespace switch_cli {

enum class Command {
    Help,
    Version,
    Protect,
    Build,
    Encode,
    EncodeList,
    Encrypt,
    EncryptList,
    KeyGenerator,
    Obfuscate,      // standalone --obf (no --encode/--encrypt)
    Unknown,
};

struct Args {
    Command cmd = Command::Unknown;
    std::vector<std::string> positional;     // input files
    bool show_help    = false;
    bool show_version = false;
    bool encode_list  = false;               // --encode-list flag
    bool encrypt_list = false;               // --encrypt-list flag
    std::optional<switch_encode::EncodeType> encode_type; // --encode <type>
    std::optional<switch_encrypt::EncryptType> encrypt_type; // --encrypt <type>
    std::optional<std::string> encrypt_key;  // --key <hex>
    std::optional<std::string> encrypt_key_file; // --key-file <path>
    std::optional<std::string> encrypt_key_env;  // --key-env <ENV_VAR>
    std::optional<std::string> encrypt_iv;   // --iv <hex> (AES)
    std::optional<std::string> encrypt_nonce; // --nonce <hex> (ChaCha20/XChaCha20)
    std::optional<std::string> output_file;   // -o <output>
    std::optional<switch_encrypt::EncryptType> key_gen_type; // --key-generator <type>
    std::vector<switch_obf::ObfType> obf_types;  // --obf <type> (repeatable)
    bool obf_list = false;                         // --obf-list flag
};

// Parse CLI arguments into structured Args.
// Returns std::nullopt on fatal parse error (message already printed).
std::optional<Args> parse(int argc, const char* argv[]);

// Print help text to stdout.
void print_help();

// Print version banner to stdout.
void print_version();

} // namespace switch_cli