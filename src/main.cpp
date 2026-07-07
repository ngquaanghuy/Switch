#include "switch/cli.hpp"
#include "switch/encode.hpp"
#include "switch/encrypt.hpp"

#include <iostream>
#include <cstdlib>

#include <openssl/crypto.h>

int main(int argc, const char* argv[]) {
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

        // Validate we have a key
        if (!args->encrypt_key) {
            std::cerr << "switch: --encrypt requires --key <hex>\n"
                      << "Usage: switch --encrypt <type> <input> --key <hex> [-o <output>]\n";
            return 1;
        }

        // Parse key from hex
        auto key = switch_encrypt::hex_to_bytes(*args->encrypt_key);
        if (!key) {
            std::cerr << "switch: invalid hex key\n";
            return 1;
        }

        // Parse or generate IV
        std::vector<uint8_t> iv;
        if (args->encrypt_iv) {
            auto parsed_iv = switch_encrypt::hex_to_bytes(*args->encrypt_iv);
            if (!parsed_iv || parsed_iv->size() != 16) {
                std::cerr << "switch: IV must be exactly 16 bytes (32 hex characters)\n";
                return 1;
            }
            iv = *parsed_iv;
        } else {
            iv = switch_encrypt::generate_random_iv();
            if (iv.empty()) {
                std::cerr << "switch: failed to generate random IV\n";
                return 1;
            }
        }

        const auto& input_path  = args->positional[0];
        const auto& encrypt_type = *args->encrypt_type;

        // Derive output path: use -o if given, else <input>.<encname>.py
        std::string output_path;
        if (args->output_file) {
            output_path = *args->output_file;
        } else {
            output_path = input_path + "." + switch_encrypt::encrypt_type_name(encrypt_type) + ".py";
        }

        std::string error_msg;
        if (!switch_encrypt::encrypt_file(encrypt_type, input_path, output_path,
                                           *key, iv, error_msg)) {
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

    // Clean up OpenSSL thread-local state before exit to prevent
    // double-free in atexit handler (known OpenSSL 3.x issue on Linux)
    OPENSSL_thread_stop();
    return 0;
}