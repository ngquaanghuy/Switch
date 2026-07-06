#pragma once

#include "switch/encode.hpp"

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
    Unknown,
};

struct Args {
    Command cmd = Command::Unknown;
    std::vector<std::string> positional;     // input files
    bool show_help    = false;
    bool show_version = false;
    bool encode_list  = false;               // --encode-list flag
    std::optional<switch_encode::EncodeType> encode_type; // --encode <type>
    std::optional<std::string> output_file;   // -o <output>
};

// Parse CLI arguments into structured Args.
// Returns std::nullopt on fatal parse error (message already printed).
std::optional<Args> parse(int argc, const char* argv[]);

// Print help text to stdout.
void print_help();

// Print version banner to stdout.
void print_version();

} // namespace switch_cli