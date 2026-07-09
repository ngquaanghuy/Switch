#include "switch/cli.hpp"
#include "switch/encode.hpp"
#include "switch/encrypt.hpp"

#include <iostream>
#include <cstdlib>
#include <fstream>
#include <algorithm>

#include <openssl/crypto.h>
#include <sodium.h>

// F03: Cleanup OpenSSL thread-local state on exit.
// Using std::atexit ensures it runs after ALL return paths, not just fallthrough.
namespace {
struct OpenSSLCleanup {
    ~OpenSSLCleanup() { OPENSSL_thread_stop(); }
};
OpenSSLCleanup openssl_cleanup_instance;
} // anonymous namespace

int main(int argc, const char* argv[]) {
    // Initialize libsodium (required for ChaCha20/XChaCha20)
    if (sodium_init() < 0) {
        std::cerr << "switch: failed to initialize libsodium\n";
        return 1;
    }

    auto args = switch_cli::parse(argc, argv);
    if (!args) {
        return 1; // parse error, message already printed
    }

    switch (args->cmd) {
    case switch_cli::Command::Help:
        switch_cli::print_help();
        return 0;

    case switch_cli::Command::Version:
        switch_cli::print_version();
        return 0;

    case switch_cli::Command::EncodeList:
        std::cout << "Supported encoding types:\n"
                  << "  " << switch_encode::all_encode_names() << "\n";
        return 0;

    case switch_cli::Command::EncryptList:
        std::cout << "Supported encryption types:\n"
                  << "  " << switch_encrypt::all_encrypt_names() << "\n";
        return 0;

    case switch_cli::Command::KeyGenerator: {
        if (!args->key_gen_type) {
            std::cerr << "switch: --key-generator requires an encryption type\n"
                      << "Usage: switch --key-generator <type>\n";
            return 1;
        }
        std::string key_hex = switch_encrypt::generate_key(*args->key_gen_type);
        if (key_hex.empty()) {
            std::cerr << "switch: failed to generate key for "
                      << switch_encrypt::encrypt_type_name(*args->key_gen_type) << "\n";
            return 1;
        }
        std::cout << key_hex << "\n";
        return 0;
    }

    case switch_cli::Command::Encode: {
        // Validate we have input file
        if (args->positional.empty()) {
            std::cerr << "switch: --encode requires an input file\n"
                      << "Usage: switch --encode <type> <input> [-o <output>]\n";
            return 1;
        }

        const auto& input_path  = args->positional[0];
        const auto& encode_type = *args->encode_type;

        // Derive output path: use -o if given, else <input>.<encname>
        std::string output_path;
        if (args->output_file) {
            output_path = *args->output_file;
        } else {
            output_path = input_path + "." + std::string(switch_encode::encode_type_name(encode_type));
        }

        std::string error_msg;
        if (!switch_encode::encode_file(encode_type, input_path, output_path, error_msg)) {
            std::cerr << "switch: encode failed: " << error_msg << "\n";
            return 1;
        }

        std::cout << "Encoded " << input_path
                  << " → " << output_path
                  << " (" << switch_encode::encode_type_name(encode_type) << ")\n";
        return 0;
    }

    case switch_cli::Command::Encrypt: {
        // Validate we have input file
        if (args->positional.empty()) {
            std::cerr << "switch: --encrypt requires an input file\n"
                      << "Usage: switch --encrypt <type> <input> --key <hex> [-o <output>]\n";
            return 1;
        }

        // Validate key source: --key, --key-file, or --key-env (mutually exclusive)
        int key_sources = (args->encrypt_key ? 1 : 0)
                        + (args->encrypt_key_file ? 1 : 0)
                        + (args->encrypt_key_env ? 1 : 0);
        if (key_sources == 0) {
            std::cerr << "switch: --encrypt requires --key, --key-file, or --key-env\n"
                      << "Usage: switch --encrypt <type> <input> --key <hex> [-o <output>]\n";
            return 1;
        }
        if (key_sources > 1) {
            std::cerr << "switch: --key, --key-file, and --key-env are mutually exclusive\n";
            return 1;
        }

        // Resolve key hex string from the chosen source
        std::string key_hex;
        if (args->encrypt_key) {
            key_hex = *args->encrypt_key;
        } else if (args->encrypt_key_file) {
            std::ifstream kf(*args->encrypt_key_file, std::ios::binary);
            if (!kf) {
                std::cerr << "switch: cannot open key file '" << *args->encrypt_key_file
                          << "': " << std::generic_category().message(errno) << "\n";
                return 1;
            }
            std::string contents((std::istreambuf_iterator<char>(kf)),
                                  std::istreambuf_iterator<char>());
            kf.close();
            // Strip whitespace and newlines
            contents.erase(std::remove_if(contents.begin(), contents.end(),
                           [](unsigned char c) { return std::isspace(c); }),
                           contents.end());
            key_hex = contents;
            if (key_hex.empty()) {
                std::cerr << "switch: key file '" << *args->encrypt_key_file << "' is empty\n";
                return 1;
            }
        } else if (args->encrypt_key_env) {
            const char* val = std::getenv(args->encrypt_key_env->c_str());
            if (!val) {
                std::cerr << "switch: environment variable '" << *args->encrypt_key_env << "' is not set\n";
                return 1;
            }
            key_hex = val;
            // Strip whitespace
            key_hex.erase(std::remove_if(key_hex.begin(), key_hex.end(),
                           [](unsigned char c) { return std::isspace(c); }),
                           key_hex.end());
            if (key_hex.empty()) {
                std::cerr << "switch: environment variable '" << *args->encrypt_key_env << "' is empty\n";
                return 1;
            }
        }

        // Parse key from hex
        auto key = switch_encrypt::hex_to_bytes(key_hex);
        if (!key) {
            std::cerr << "switch: invalid hex key\n";
            return 1;
        }

        // Validate key length matches encryption type
        const auto& encrypt_type = *args->encrypt_type;
        size_t expected_key = switch_encrypt::expected_key_len(encrypt_type);
        if (key->size() != expected_key) {
            std::cerr << "switch: key must be " << (expected_key * 2)
                      << " hex characters (" << expected_key << " bytes) for "
                      << switch_encrypt::encrypt_type_name(encrypt_type)
                      << ", got " << key->size() * 2 << " hex characters\n";
            return 1;
        }

        // Parse or generate IV/nonce based on cipher type
        std::vector<uint8_t> iv_or_nonce;
        size_t expected_nonce = switch_encrypt::expected_nonce_len(encrypt_type);

        if (expected_nonce == 0) {
            // SIV: no nonce needed, leave iv_or_nonce empty
        } else if (switch_encrypt::is_stream_cipher(encrypt_type)) {
            // ChaCha20/XChaCha20: use --nonce or generate random
            if (args->encrypt_nonce) {
                auto parsed = switch_encrypt::hex_to_bytes(*args->encrypt_nonce);
                if (!parsed || parsed->size() != expected_nonce) {
                    std::cerr << "switch: nonce must be " << (expected_nonce * 2)
                              << " hex characters (" << expected_nonce << " bytes) for "
                              << switch_encrypt::encrypt_type_name(encrypt_type) << "\n";
                    return 1;
                }
                iv_or_nonce = *parsed;
            } else {
                iv_or_nonce = switch_encrypt::generate_random_nonce(expected_nonce);
            }
        } else {
            // AES: use --iv or generate random IV
            if (args->encrypt_iv) {
                auto parsed = switch_encrypt::hex_to_bytes(*args->encrypt_iv);
                if (!parsed || parsed->size() != expected_nonce) {
                    std::cerr << "switch: IV must be " << (expected_nonce * 2)
                              << " hex characters (" << expected_nonce << " bytes) for "
                              << switch_encrypt::encrypt_type_name(encrypt_type) << "\n";
                    return 1;
                }
                iv_or_nonce = *parsed;
            } else {
                iv_or_nonce = switch_encrypt::generate_random_nonce(expected_nonce);
                if (iv_or_nonce.empty()) {
                    std::cerr << "switch: failed to generate random IV\n";
                    return 1;
                }
            }
        }

        const auto& input_path  = args->positional[0];

        // Derive output path: use -o if given, else <input>.<encname>.py
        std::string output_path;
        if (args->output_file) {
            output_path = *args->output_file;
        } else {
            output_path = input_path + "." + switch_encrypt::encrypt_type_name(encrypt_type) + ".py";
        }

        std::string error_msg;
        if (!switch_encrypt::encrypt_file(encrypt_type, input_path, output_path,
                                           *key, iv_or_nonce, error_msg)) {
            std::cerr << "switch: encrypt failed: " << error_msg << "\n";
            return 1;
        }

        std::cout << "Encrypted " << input_path
                  << " → " << output_path
                  << " (" << switch_encrypt::encrypt_type_name(encrypt_type) << ")\n";
        return 0;
    }

    case switch_cli::Command::Protect:
        std::cerr << "switch: 'protect' command not yet implemented.\n"
                  << "Coming in a future release.\n";
        return 1;

    case switch_cli::Command::Build:
        std::cerr << "switch: 'build' command not yet implemented.\n"
                  << "Coming in a future release.\n";
        return 1;

    case switch_cli::Command::Unknown:
        switch_cli::print_help();
        return 1;
    }

    return 0;
}
