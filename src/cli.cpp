#include "switch/cli.hpp"
#include "switch/version.hpp"

#include <iostream>
#include <string_view>

namespace switch_cli {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

namespace {

bool is_flag(std::string_view arg, std::string_view short_name, std::string_view long_name) {
    return arg == short_name || arg == long_name;
}

void print_banner() {
    std::cout << "Switch " << SWITCH_VERSION_STRING << " — Python Code Protector\n";
    std::cout << "Built with C++17 | Python 3.14+ | Cross-platform\n\n";
}

// Centralized type string → EncryptType mapping.
// Case-insensitive: checks lowercase, CamelCase, and UPPER variants.
std::optional<switch_encrypt::EncryptType> parse_encrypt_type_name(std::string_view s) {
    if (s == "aes-128" || s == "aes128" || s == "AES-128" || s == "AES128")
        return switch_encrypt::EncryptType::Aes128;
    if (s == "aes-192" || s == "aes192" || s == "AES-192" || s == "AES192")
        return switch_encrypt::EncryptType::Aes192;
    if (s == "aes-256" || s == "aes256" || s == "AES-256" || s == "AES256")
        return switch_encrypt::EncryptType::Aes256;
    if (s == "chacha20" || s == "ChaCha20" || s == "CHACHA20")
        return switch_encrypt::EncryptType::ChaCha20;
    if (s == "xchacha20" || s == "XChaCha20" || s == "XCHACHA20")
        return switch_encrypt::EncryptType::XChaCha20;
    if (s == "aes-128-gcm" || s == "aes128gcm" || s == "AES-128-GCM" || s == "AES128GCM")
        return switch_encrypt::EncryptType::Aes128Gcm;
    if (s == "aes-192-gcm" || s == "aes192gcm" || s == "AES-192-GCM" || s == "AES192GCM")
        return switch_encrypt::EncryptType::Aes192Gcm;
    if (s == "aes-256-gcm" || s == "aes256gcm" || s == "AES-256-GCM" || s == "AES256GCM")
        return switch_encrypt::EncryptType::Aes256Gcm;
    if (s == "aes-128-ccm" || s == "aes128ccm" || s == "AES-128-CCM" || s == "AES128CCM")
        return switch_encrypt::EncryptType::Aes128Ccm;
    if (s == "aes-192-ccm" || s == "aes192ccm" || s == "AES-192-CCM" || s == "AES192CCM")
        return switch_encrypt::EncryptType::Aes192Ccm;
    if (s == "aes-256-ccm" || s == "aes256ccm" || s == "AES-256-CCM" || s == "AES256CCM")
        return switch_encrypt::EncryptType::Aes256Ccm;
    if (s == "aes-128-siv" || s == "aes128siv" || s == "AES-128-SIV" || s == "AES128SIV")
        return switch_encrypt::EncryptType::Aes128Siv;
    if (s == "aes-256-siv" || s == "aes256siv" || s == "AES-256-SIV" || s == "AES256SIV")
        return switch_encrypt::EncryptType::Aes256Siv;
    if (s == "aes-128-ocb" || s == "aes128ocb" || s == "AES-128-OCB" || s == "AES128OCB")
        return switch_encrypt::EncryptType::Aes128Ocb;
    if (s == "aes-192-ocb" || s == "aes192ocb" || s == "AES-192-OCB" || s == "AES192OCB")
        return switch_encrypt::EncryptType::Aes192Ocb;
    if (s == "aes-256-ocb" || s == "aes256ocb" || s == "AES-256-OCB" || s == "AES256OCB")
        return switch_encrypt::EncryptType::Aes256Ocb;
    return std::nullopt;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

std::optional<Args> parse(int argc, const char* argv[]) {
    Args args;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};

        // Help flags
        if (is_flag(arg, "-h", "--help")) {
            args.show_help = true;
            args.cmd = Command::Help;
            continue;
        }

        // Version flags
        if (is_flag(arg, "-v", "--version")) {
            args.show_version = true;
            args.cmd = Command::Version;
            continue;
        }

        // --encode-list
        if (is_flag(arg, "", "--encode-list")) {
            args.encode_list = true;
            args.cmd = Command::EncodeList;
            continue;
        }

        // --encrypt-list
        if (is_flag(arg, "", "--encrypt-list")) {
            args.encrypt_list = true;
            args.cmd = Command::EncryptList;
            continue;
        }

        // --encode <type>
        if (arg == "--encode") {
            if (i + 1 >= argc) {
                std::cerr << "switch: --encode requires an encoding type\n"
                          << "Valid types: " << switch_encode::all_encode_names() << "\n"
                          << "Try 'switch --encode-list' to see all options.\n";
                return std::nullopt;
            }
            std::string_view enc_name{argv[++i]};
            auto parsed = switch_encode::parse_encode_type(enc_name);
            if (!parsed) {
                std::cerr << "switch: unknown encoding type '" << enc_name << "'\n"
                          << "Valid types: " << switch_encode::all_encode_names() << "\n"
                          << "Try 'switch --encode-list' to see all options.\n";
                return std::nullopt;
            }
            args.encode_type = *parsed;
            args.cmd = Command::Encode;

            // Consume positional input file
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                args.positional.emplace_back(argv[++i]);
            }
            continue;
        }

        // -o <output>
        if (arg == "-o") {
            if (i + 1 >= argc) {
                std::cerr << "switch: -o requires an output file path\n";
                return std::nullopt;
            }
            args.output_file = argv[++i];
            continue;
        }

        // --encrypt <type>
        if (arg == "--encrypt") {
            if (i + 1 >= argc) {
                std::cerr << "switch: --encrypt requires an encryption type\n";
                return std::nullopt;
            }
            std::string_view type_str{argv[++i]};
            auto parsed = parse_encrypt_type_name(type_str);
            if (!parsed) {
                std::cerr << "switch: unknown encryption type '" << type_str << "'\n"
                          << "Valid types: " << switch_encrypt::all_encrypt_names() << "\n";
                return std::nullopt;
            }
            args.encrypt_type = *parsed;
            args.cmd = Command::Encrypt;
            // F15: Consume positional input file (consistent with --encode)
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                args.positional.emplace_back(argv[++i]);
            }
            continue;
        }

        // --key <hex>
        if (arg == "--key") {
            if (i + 1 >= argc) {
                std::cerr << "switch: --key requires a hex-encoded key string\n";
                return std::nullopt;
            }
            args.encrypt_key = argv[++i];
            continue;
        }

        // --key-file <path>
        if (arg == "--key-file") {
            if (i + 1 >= argc) {
                std::cerr << "switch: --key-file requires a file path\n";
                return std::nullopt;
            }
            args.encrypt_key_file = argv[++i];
            continue;
        }

        // --key-env <ENV_VAR>
        if (arg == "--key-env") {
            if (i + 1 >= argc) {
                std::cerr << "switch: --key-env requires an environment variable name\n";
                return std::nullopt;
            }
            args.encrypt_key_env = argv[++i];
            continue;
        }

        // --key-generator <type>
        if (arg == "--key-generator") {
            if (i + 1 >= argc) {
                std::cerr << "switch: --key-generator requires an encryption type\n"
                          << "Valid types: " << switch_encrypt::all_encrypt_names() << "\n";
                return std::nullopt;
            }
            std::string_view kg_name{argv[++i]};
            auto kg_parsed = parse_encrypt_type_name(kg_name);
            if (!kg_parsed) {
                std::cerr << "switch: unknown encryption type '" << kg_name << "'\n"
                          << "Valid types: " << switch_encrypt::all_encrypt_names() << "\n";
                return std::nullopt;
            }
            args.key_gen_type = *kg_parsed;
            args.cmd = Command::KeyGenerator;
            continue;
        }

        // --iv <hex> (AES only)
        if (arg == "--iv") {
            if (i + 1 >= argc) {
                std::cerr << "switch: --iv requires a hex-encoded IV string\n";
                return std::nullopt;
            }
            if (args.encrypt_type && switch_encrypt::is_stream_cipher(*args.encrypt_type)) {
                std::cerr << "switch: --iv is not valid for stream ciphers (use --nonce instead)\n";
                return std::nullopt;
            }
            args.encrypt_iv = argv[++i];
            continue;
        }

        // --nonce <hex> (ChaCha20 only)
        if (arg == "--nonce") {
            if (i + 1 >= argc) {
                std::cerr << "switch: --nonce requires a hex-encoded nonce string\n";
                return std::nullopt;
            }
            if (args.encrypt_type && !switch_encrypt::is_stream_cipher(*args.encrypt_type)) {
                std::cerr << "switch: --nonce is only valid for ChaCha20/XChaCha20 (use --iv for AES)\n";
                return std::nullopt;
            }
            args.encrypt_nonce = argv[++i];
            continue;
        }

        // Future subcommands — parsed but not yet functional
        if (arg == "protect") {
            args.cmd = Command::Protect;
            // Consume remaining positional args for protect command
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                args.positional.emplace_back(argv[++i]);
            }
            continue;
        }

        if (arg == "build") {
            args.cmd = Command::Build;
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                args.positional.emplace_back(argv[++i]);
            }
            continue;
        }

        // Unknown flag
        if (!arg.empty() && arg[0] == '-') {
            std::cerr << "switch: unknown option '" << arg << "'\n"
                      << "Try 'switch --help' for usage.\n";
            return std::nullopt;
        }

        // Bare positional before any subcommand → treat as input for default action
        args.positional.emplace_back(arg);
    }

    // Default command: if nothing specified, show help
    if (args.cmd == Command::Unknown && !args.show_help && !args.show_version) {
        if (!args.positional.empty()) {
            // Bare file → hint at future protect behavior
            args.cmd = Command::Protect;
        } else {
            args.cmd = Command::Help;
            args.show_help = true;
        }
    }

    return args;
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

void print_help() {
    print_banner();

    std::cout << "USAGE\n"
              << "  switch [OPTIONS] [COMMAND] [ARGS...]\n"
              << "\n"
              << "OPTIONS\n"
              << "  -h, --help         Show this help text\n"
              << "  -v, --version      Show version information\n"
              << "  --encode <type>    Encode input .py into runnable encoded .py\n"
              << "                     Types: " << switch_encode::all_encode_names() << "\n"
              << "                     Output runs with: python output.py\n"
              << "  --encrypt <type>   Encrypt input .py into runnable encrypted .py\n"
              << "                     Types: aes-128, aes-192, aes-256, chacha20, xchacha20,\n"
              << "                             aes-{128,192,256}-gcm, aes-{128,192,256}-ccm,\n"
              << "                             aes-{128,256}-siv, aes-{128,192,256}-ocb\n"
              << "                     Requires: --key <hex>\n"
              << "                     AES: --iv <hex> (optional, auto-generated)\n"
              << "                     ChaCha20/XChaCha20: --nonce <hex> (optional, auto-generated)\n"
              << "                     Output runs with: python output.py\n"
              << "  --key <hex>        Hex-encoded encryption key (required with --encrypt)\n"
              << "  --key-file <path>  Read hex key from file (whitespace stripped)\n"
              << "  --key-env <VAR>    Read hex key from environment variable\n"
              << "  --iv <hex>         Hex-encoded IV, 16 bytes (AES-CBC) / 12 bytes (AES-GCM), optional\n"
              << "  --nonce <hex>      Hex-encoded nonce, 12 bytes (ChaCha20) / 24 bytes (XChaCha20), optional\n"
              << "  -o <file>          Output file path\n"
              << "  --encode-list      List all supported encoding types\n"
              << "  --encrypt-list     List all supported encryption types\n"
              << "  --key-generator <type>\n"
              << "                     Generate a random key for the given encryption type\n"
              << "                     Types: " << switch_encrypt::all_encrypt_names() << "\n"
              << "\n"
              << "COMMANDS (planned)\n"
              << "  protect <file>     Encrypt and protect Python source\n"
              << "  build <file>       Build protected executable bundle\n"
              << "\n"
              << "EXAMPLES\n"
              << "  switch --help\n"
              << "  switch --version\n"
              << "  switch --encode-list\n"
              << "  switch --encrypt-list\n"
              << "  switch --encode base32 input.py -o output.py\n"
              << "  switch --encrypt aes-256 input.py --key <64-hex-chars> -o output.py\n"
              << "  switch --encrypt chacha20 input.py --key <64-hex-chars> -o output.py\n"
              << "  python output.py                 # runs original code\n"
              << "\n"
              << "Python 3.14+ required for runtime features.\n"
              << "Python 'cryptography' package required for --encrypt output.\n";
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

void print_version() {
    std::cout << "Switch " << SWITCH_VERSION_STRING << "\n"
              << "  Target Python: " << SWITCH_PYTHON_MIN_MAJOR << "."
              << SWITCH_PYTHON_MIN_MINOR << "+\n"
              << "  Platform: "
#if defined(SWITCH_PLATFORM_WINDOWS)
              << "Windows"
#elif defined(SWITCH_PLATFORM_MACOS)
              << "macOS"
#elif defined(SWITCH_PLATFORM_LINUX)
              << "Linux"
#else
              << "Unknown"
#endif
              << "\n"
              << "  Compiler: "
#if defined(__clang__)
              << "Clang " << __clang_major__ << "." << __clang_minor__
#elif defined(__GNUC__)
              << "GCC " << __GNUC__ << "." << __GNUC_MINOR__
#elif defined(_MSC_VER)
              << "MSVC " << _MSC_VER
#else
              << "Unknown"
#endif
              << "\n";
}

} // namespace switch_cli