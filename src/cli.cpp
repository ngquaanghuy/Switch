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
              << "  -o <file>          Output file path (used with --encode)\n"
              << "  --encode-list      List all supported encoding types\n"
              << "\n"
              << "COMMANDS (planned)\n"
              << "  protect <file>     Encrypt and protect Python source\n"
              << "  build <file>       Build protected executable bundle\n"
              << "\n"
              << "EXAMPLES\n"
              << "  switch --help\n"
              << "  switch --version\n"
              << "  switch --encode-list\n"
              << "  switch --encode base32 input.py -o output.py\n"
              << "  python output.py                 # runs original code\n"
              << "\n"
              << "Python 3.14+ required for runtime features.\n";
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