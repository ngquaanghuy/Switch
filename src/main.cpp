#include "switch/cli.hpp"
#include "switch/encode.hpp"
#include "switch/encrypt.hpp"
#include "switch/obfuscate.hpp"

#include <iostream>
#include <cstdlib>
#include <fstream>
#include <algorithm>
#include <unistd.h>

#include <openssl/crypto.h>
#include <sodium.h>

// F03: Cleanup OpenSSL thread-local state on exit.
// Using std::atexit ensures it runs after ALL return paths, not just fallthrough.
namespace {
struct OpenSSLCleanup {
    ~OpenSSLCleanup() { OPENSSL_thread_stop(); }
};
OpenSSLCleanup openssl_cleanup_instance;

// Safe write that handles partial writes and errors.
// Returns false on failure (error printed to stderr).
bool safe_write(int fd, const char* data, size_t len) {
    const char* ptr = data;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t written = ::write(fd, ptr, remaining);
        if (written <= 0) {
            std::cerr << "switch: failed to write temp file: "
                      << std::generic_category().message(errno) << "\n";
            return false;
        }
        ptr += written;
        remaining -= static_cast<size_t>(written);
    }
    return true;
}

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

    // Auto-sort obfuscation techniques in the correct order.
    // scramble MUST run before xorencoding and importrewrite (those generate
    // code with identifiers that scramble would corrupt).
    // importrewrite MUST run last among import-related techniques.
    if (!args->obf_types.empty()) {
        auto& v = args->obf_types;
        std::stable_sort(v.begin(), v.end(), [](switch_obf::ObfType a, switch_obf::ObfType b) {
            return switch_obf::obf_type_priority(a) < switch_obf::obf_type_priority(b);
        });
    }

    // Handle --obf-list (independent of command)
    if (args->obf_list) {
        std::cout << "Supported obfuscation techniques:\n"
                  << "  " << switch_obf::all_obf_names() << "\n";
        return 0;
    }

    // If --obf is given without --encode/--encrypt, treat as standalone obfuscation
    if (!args->obf_types.empty() && args->cmd == switch_cli::Command::Unknown) {
        args->cmd = switch_cli::Command::Obfuscate;
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

        // If obfuscation requested, apply it first (write to temp file)
        std::string effective_input = input_path;
        std::string obf_tmp;
        if (!args->obf_types.empty()) {
            // Read source
            std::ifstream in(input_path, std::ios::binary | std::ios::ate);
            if (!in) {
                std::cerr << "switch: cannot open input file '" << input_path
                          << "': " << std::generic_category().message(errno) << "\n";
                return 1;
            }
            std::streamsize sz = in.tellg();
            in.seekg(0, std::ios::beg);
            std::string src(static_cast<size_t>(sz), '\0');
            if (sz > 0 && !in.read(src.data(), sz)) {
                std::cerr << "switch: failed to read input file\n";
                return 1;
            }
            in.close();

            for (auto obf_type : args->obf_types) {
                auto result = switch_obf::obfuscate(obf_type, src);
                if (!result) {
                    std::cerr << "switch: obfuscation failed for "
                              << switch_obf::obf_type_name(obf_type) << "\n";
                    return 1;
                }
                src = *result;
            }

            // Write obfuscated source to temp file
            obf_tmp = "/tmp/switch_obf_enc_XXXXXX";
            int fd = mkstemp(obf_tmp.data());
            if (fd < 0) {
                std::cerr << "switch: failed to create temp file\n";
                return 1;
            }
            if (!safe_write(fd, src.data(), src.size())) {
                close(fd);
                unlink(obf_tmp.c_str());
                return 1;
            }
            close(fd);
            effective_input = obf_tmp;
        }

        std::string error_msg;
        bool ok = switch_encode::encode_file(encode_type, effective_input, output_path, error_msg);

        // Cleanup temp file
        if (!obf_tmp.empty()) unlink(obf_tmp.c_str());

        if (!ok) {
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
        if (key_sources > 1) {
            std::cerr << "switch: --key, --key-file, and --key-env are mutually exclusive\n";
            return 1;
        }

        // Resolve key hex string from the chosen source, or auto-generate
        std::string key_hex;
        if (key_sources == 0) {
            // Auto-generate key
            key_hex = switch_encrypt::generate_key(*args->encrypt_type);
            if (key_hex.empty()) {
                std::cerr << "switch: failed to generate key for "
                          << switch_encrypt::encrypt_type_name(*args->encrypt_type) << "\n";
                return 1;
            }
            std::cerr << "switch: auto-generated key: " << key_hex << "\n";

            // Save key to file if --key-save specified
            if (args->key_save_file) {
                std::ofstream kf_out(*args->key_save_file, std::ios::binary | std::ios::trunc);
                if (!kf_out) {
                    std::cerr << "switch: cannot write key file '" << *args->key_save_file
                              << "': " << std::generic_category().message(errno) << "\n";
                    return 1;
                }
                kf_out.write(key_hex.data(), static_cast<std::streamsize>(key_hex.size()));
                kf_out.close();
                std::cerr << "switch: key saved to " << *args->key_save_file << "\n";
            }
        } else if (args->encrypt_key) {
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

        // If obfuscation requested, apply it first (write to temp file)
        std::string effective_input = input_path;
        std::string obf_tmp;
        if (!args->obf_types.empty()) {
            std::ifstream in(input_path, std::ios::binary | std::ios::ate);
            if (!in) {
                std::cerr << "switch: cannot open input file '" << input_path
                          << "': " << std::generic_category().message(errno) << "\n";
                return 1;
            }
            std::streamsize sz = in.tellg();
            in.seekg(0, std::ios::beg);
            std::string src(static_cast<size_t>(sz), '\0');
            if (sz > 0 && !in.read(src.data(), sz)) {
                std::cerr << "switch: failed to read input file\n";
                return 1;
            }
            in.close();

            for (auto obf_type : args->obf_types) {
                auto result = switch_obf::obfuscate(obf_type, src);
                if (!result) {
                    std::cerr << "switch: obfuscation failed for "
                              << switch_obf::obf_type_name(obf_type) << "\n";
                    return 1;
                }
                src = *result;
            }

            obf_tmp = "/tmp/switch_obf_enc_XXXXXX";
            int fd = mkstemp(obf_tmp.data());
            if (fd < 0) {
                std::cerr << "switch: failed to create temp file\n";
                return 1;
            }
            if (!safe_write(fd, src.data(), src.size())) {
                close(fd);
                unlink(obf_tmp.c_str());
                return 1;
            }
            close(fd);
            effective_input = obf_tmp;
        }

        std::string error_msg;
        bool ok = switch_encrypt::encrypt_file(encrypt_type, effective_input, output_path,
                                               *key, iv_or_nonce, error_msg);

        if (!obf_tmp.empty()) unlink(obf_tmp.c_str());

        if (!ok) {
            std::cerr << "switch: encrypt failed: " << error_msg << "\n";
            return 1;
        }

        std::cout << "Encrypted " << input_path
                  << " → " << output_path
                  << " (" << switch_encrypt::encrypt_type_name(encrypt_type) << ")\n";
        return 0;
    }

    case switch_cli::Command::Obfuscate: {
        // Standalone obfuscation: read → obfuscate → write .py
        if (args->positional.empty()) {
            std::cerr << "switch: --obf requires an input file\n"
                      << "Usage: switch --obf <type> <input> [-o <output>]\n";
            return 1;
        }

        const auto& input_path = args->positional[0];

        // Read input file
        std::ifstream in(input_path, std::ios::binary | std::ios::ate);
        if (!in) {
            std::cerr << "switch: cannot open input file '" << input_path
                      << "': " << std::generic_category().message(errno) << "\n";
            return 1;
        }
        std::streamsize size = in.tellg();
        in.seekg(0, std::ios::beg);
        std::string source(static_cast<size_t>(size), '\0');
        if (size > 0 && !in.read(source.data(), size)) {
            std::cerr << "switch: failed to read input file '" << input_path << "'\n";
            return 1;
        }
        in.close();

        // Apply obfuscation techniques in sequence
        std::string current = source;
        for (auto obf_type : args->obf_types) {
            auto result = switch_obf::obfuscate(obf_type, current);
            if (!result) {
                std::cerr << "switch: obfuscation failed for "
                          << switch_obf::obf_type_name(obf_type) << "\n";
                return 1;
            }
            current = *result;
        }

        // Derive output path
        std::string output_path;
        if (args->output_file) {
            output_path = *args->output_file;
        } else {
            output_path = input_path + ".obf.py";
        }

        // Write output
        std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "switch: cannot write to output file '" << output_path
                      << "': " << std::generic_category().message(errno) << "\n";
            return 1;
        }
        out.write(current.data(), static_cast<std::streamsize>(current.size()));
        out.close();

        std::cout << "Obfuscated " << input_path
                  << " → " << output_path << "\n";
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
