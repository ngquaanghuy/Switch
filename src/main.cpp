#include "switch/cli.hpp"
#include "switch/encode.hpp"

#include <iostream>
#include <cstdlib>

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