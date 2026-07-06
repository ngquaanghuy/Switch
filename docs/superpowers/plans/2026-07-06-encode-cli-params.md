# Encode CLI Parameters Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--encode` and `--encode-list` parameters to the Switch CLI with 5 encoding types (base16/32/58/62/64), case-insensitive name matching, file I/O validation, and tests.

**Architecture:** New `encode` module (`src/encode.hpp`, `src/encode.cpp`) implements all 5 encoding algorithms as pure C++17 functions. CLI struct `Args` extended with encode fields; `parse()` handles `--encode`, `--encode-list`, and `-o` flags. Error handling validates encode name, input file readability, and output file writability before processing. Tests split into unit tests (encode module) and integration tests (CLI end-to-end).

**Tech Stack:** C++17, CMake 3.21+, Ninja, doctest (single-header test framework)

## Global Constraints

- C++17 only — no `std::starts_with`, use `!arg.empty() && arg[0] == '-'` pattern
- CMake + Ninja build system; new source files must be listed in CMakeLists.txt
- Cross-platform: Linux (primary), Windows, macOS (no platform-specific encoding code)
- No external dependencies; encoding algorithms hand-rolled in C++17
- Case-insensitive encode name matching
- Input file must exist and be readable; output path must be writable
- Empty input → empty encoded output (valid, not an error)
- Test framework: doctest single-header (downloaded into `tests/doctest.h`)

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `src/encode.hpp` | Create | Encoding type enum, function declarations, case-insensitive name lookup |
| `src/encode.cpp` | Create | All 5 encoding algorithm implementations + file I/O |
| `src/cli.hpp` | Modify | Add `Encode`/`EncodeList` to Command enum, encode fields to Args |
| `src/cli.cpp` | Modify | Parse `--encode`, `--encode-list`, `-o` flags; update help text |
| `src/main.cpp` | Modify | Dispatch `Encode` and `EncodeList` commands |
| `CMakeLists.txt` | Modify | Add new sources, enable tests subdirectory |
| `tests/CMakeLists.txt` | Create | Test build configuration with doctest |
| `tests/test_encode.cpp` | Create | Unit tests: all 5 encodings, decode-verify roundtrip, edge cases |
| `tests/test_cli_encode.cpp` | Create | Integration tests: CLI args parsing, error handling, end-to-end encode |

---

### Task 1: Encoding Module — Header and Implementation

**Files:**
- Create: `src/encode.hpp`
- Create: `src/encode.cpp`

**Interfaces:**
- Produces:
  - `enum class switch_encode::EncodeType { Base16, Base32, Base58, Base62, Base64 }`
  - `std::optional<switch_encode::EncodeType> switch_encode::parse_encode_type(std::string_view name)` — case-insensitive, returns nullopt on unknown name
  - `std::string_view switch_encode::encode_type_name(EncodeType t)` — canonical lowercase name
  - `std::string switch_encode::all_encode_names()` — comma-separated list for error messages
  - `std::string switch_encode::encode(EncodeType type, const std::vector<uint8_t>& data)` — encode bytes
  - `bool switch_encode::encode_file(EncodeType type, const std::string& input_path, const std::string& output_path, std::string& error_msg)` — file-to-file encode with validation

#### Step 1: Write `src/encode.hpp`

```cpp
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace switch_encode {

// Supported encoding types.
// - Base16: hex encoding, each byte → 2 chars [0-9a-f]. Simplest, 2x expansion.
// - Base32: RFC 4648, 5 bytes → 8 chars [A-Z2-7], pad with '='. ~1.6x expansion.
// - Base58: Bitcoin-style, no 0/O/I/l. Big-integer div-by-58. Variable length.
// - Base62: 0-9a-zA-Z, no padding. Big-integer div-by-62. URL-safe alphanumeric.
// - Base64: RFC 4648, 3 bytes → 4 chars [A-Za-z0-9+/], pad with '='. ~1.33x.
enum class EncodeType {
    Base16,
    Base32,
    Base58,
    Base62,
    Base64,
};

// Parse an encode type name case-insensitively.
// "base32", "BASE32", "Base32" → EncodeType::Base32
// Unknown name → std::nullopt
std::optional<EncodeType> parse_encode_type(std::string_view name);

// Get canonical lowercase name for an encode type.
std::string_view encode_type_name(EncodeType type);

// Comma-separated list of all valid encode names, for error messages.
std::string all_encode_names();

// Encode raw bytes into the specified encoding's string representation.
std::string encode(EncodeType type, const std::vector<uint8_t>& data);

// Read input_path, encode with the given type, write to output_path.
// Returns false on error; error_msg is populated with a human-readable message.
// Checks: input file exists & readable, output path writable (by attempting open).
bool encode_file(EncodeType type,
                 const std::string& input_path,
                 const std::string& output_path,
                 std::string& error_msg);

} // namespace switch_encode
```

#### Step 2: Write `src/encode.cpp` — parse_encode_type, encode_type_name, all_encode_names

```cpp
#include "encode.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <sstream>
#include <system_error>

namespace switch_encode {

// ---------------------------------------------------------------------------
// Name lookup (case-insensitive)
// ---------------------------------------------------------------------------

namespace {

struct EncodeEntry {
    std::string_view name;
    EncodeType type;
};

constexpr EncodeEntry ENCODE_TABLE[] = {
    {"base16", EncodeType::Base16},
    {"base32", EncodeType::Base32},
    {"base58", EncodeType::Base58},
    {"base62", EncodeType::Base62},
    {"base64", EncodeType::Base64},
};

// Case-insensitive ASCII compare
bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i]))
            != std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

} // anonymous namespace

std::optional<EncodeType> parse_encode_type(std::string_view name) {
    for (const auto& entry : ENCODE_TABLE) {
        if (iequals(name, entry.name)) {
            return entry.type;
        }
    }
    return std::nullopt;
}

std::string_view encode_type_name(EncodeType type) {
    for (const auto& entry : ENCODE_TABLE) {
        if (entry.type == type) return entry.name;
    }
    return "unknown";
}

std::string all_encode_names() {
    std::string result;
    for (size_t i = 0; i < std::size(ENCODE_TABLE); ++i) {
        if (i > 0) result += ", ";
        result += ENCODE_TABLE[i].name;
    }
    return result;
}
```

#### Step 3: Write encoding algorithm constants and helpers in `src/encode.cpp`

Continue appending inside `namespace switch_encode { ... }`:

```cpp
// ---------------------------------------------------------------------------
// Encoding alphabets
// ---------------------------------------------------------------------------

namespace {

// Base16: standard hex lowercase
constexpr char B16_ALPHABET[] = "0123456789abcdef";

// Base32: RFC 4648 §6 — A-Z, 2-7
constexpr char B32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
// Padding schema for partial groups: [0]=full, [1]=2 chars+6 '=', [2]=4 chars+4 '=', ...
constexpr int B32_CHARS_OUT[]   = {0, 2, 4, 5, 7, 8};
constexpr int B32_PAD_COUNT[]   = {0, 6, 4, 3, 1, 0};

// Base58: Bitcoin — no 0, O, I, l
constexpr char B58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr uint8_t B58_BASE = 58;

// Base62: 0-9, A-Z, a-z
constexpr char B62_ALPHABET[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
constexpr uint8_t B62_BASE = 62;

// Base64: RFC 4648 §4
constexpr char B64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ---------------------------------------------------------------------------
// Big-integer helper for base58 and base62
// ---------------------------------------------------------------------------

// Divide big-endian byte vector (dividend) by `divisor` in-place;
// returns the remainder. Handles leading zeros by stripping them after each step.
// Used by base58 (divisor=58) and base62 (divisor=62).
uint8_t bigint_divmod(std::vector<uint8_t>& number, uint8_t divisor) {
    uint32_t remainder = 0;
    std::vector<uint8_t> quotient;
    quotient.reserve(number.size());

    for (uint8_t byte : number) {
        uint32_t value = (remainder << 8) | byte;
        uint8_t q = static_cast<uint8_t>(value / divisor);
        remainder = value % divisor;
        // Skip leading zeros in quotient
        if (!quotient.empty() || q != 0) {
            quotient.push_back(q);
        }
    }

    number = std::move(quotient);
    return static_cast<uint8_t>(remainder);
}

} // anonymous namespace
```

#### Step 4: Write base16 and base64 encoding functions in `src/encode.cpp`

Append inside `namespace switch_encode { ... }`:

```cpp
// ---------------------------------------------------------------------------
// Base16 (hex) — each byte → 2 hex chars
// ---------------------------------------------------------------------------

namespace {

std::string encode_base16(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        result.push_back(B16_ALPHABET[byte >> 4]);
        result.push_back(B16_ALPHABET[byte & 0x0F]);
    }
    return result;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Base64 — 3 bytes → 4 chars, pad with '='
// ---------------------------------------------------------------------------

namespace {

std::string encode_base64(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i < data.size()) {
        int remaining = static_cast<int>(data.size() - i);

        // Gather 3 bytes (pad missing ones with 0)
        uint32_t buffer = 0;
        int bytes_in = (remaining >= 3) ? 3 : remaining;
        for (int j = 0; j < bytes_in; ++j) {
            buffer = (buffer << 8) | data[i + j];
        }
        buffer <<= (8 * (3 - bytes_in)); // left-align the bits we have

        // Output 4 chars per full group; fewer + padding for partial
        int chars_out = (bytes_in == 3) ? 4 : bytes_in + 1;
        for (int j = 0; j < chars_out; ++j) {
            int shift = 18 - 6 * j;
            result.push_back(B64_ALPHABET[(buffer >> shift) & 0x3F]);
        }
        // Pad
        result.append((bytes_in == 3) ? 0 : (4 - chars_out), '=');

        i += bytes_in;
    }
    return result;
}

} // anonymous namespace
```

#### Step 5: Write base32 encoding function in `src/encode.cpp`

Append:

```cpp
// ---------------------------------------------------------------------------
// Base32 (RFC 4648) — 5 bytes → 8 chars, pad with '='
// ---------------------------------------------------------------------------

namespace {

std::string encode_base32(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(((data.size() + 4) / 5) * 8);

    size_t i = 0;
    while (i < data.size()) {
        int remaining = static_cast<int>(data.size() - i);
        int bytes_in = (remaining >= 5) ? 5 : remaining;

        // Gather 5 bytes into a 40-bit buffer (left-aligned)
        uint64_t buffer = 0;
        for (int j = 0; j < bytes_in; ++j) {
            buffer = (buffer << 8) | data[i + j];
        }
        buffer <<= (8 * (5 - bytes_in));

        // Output chars according to partial-group table
        int chars_out = B32_CHARS_OUT[bytes_in];
        for (int j = 0; j < chars_out; ++j) {
            int shift = 35 - 5 * j;
            result.push_back(B32_ALPHABET[(buffer >> shift) & 0x1F]);
        }
        // Pad
        result.append(B32_PAD_COUNT[bytes_in], '=');

        i += bytes_in;
    }
    return result;
}

} // anonymous namespace
```

#### Step 6: Write base58 and base62 encoding functions in `src/encode.cpp`

Append:

```cpp
// ---------------------------------------------------------------------------
// Base58 (Bitcoin-style) — big-integer division by 58
// ---------------------------------------------------------------------------

namespace {

std::string encode_base58(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};

    // Count leading zeros — each becomes a '1' (alphabet[0])
    size_t leading_zeros = 0;
    while (leading_zeros < data.size() && data[leading_zeros] == 0) {
        ++leading_zeros;
    }

    // Copy non-zero-prefixed bytes for division
    std::vector<uint8_t> number(data.begin() + leading_zeros, data.end());

    // Collect remainders
    std::string remainders;
    remainders.reserve(number.size() * 2); // ~138% expansion
    while (!number.empty()) {
        uint8_t rem = bigint_divmod(number, B58_BASE);
        remainders.push_back(B58_ALPHABET[rem]);
    }

    // Reverse remainders → encoded body
    std::string result(leading_zeros, B58_ALPHABET[0]);
    for (auto it = remainders.rbegin(); it != remainders.rend(); ++it) {
        result.push_back(*it);
    }
    return result;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Base62 — big-integer division by 62
// ---------------------------------------------------------------------------

namespace {

std::string encode_base62(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};

    // Count leading zeros — each becomes alphabet[0] = '0'
    size_t leading_zeros = 0;
    while (leading_zeros < data.size() && data[leading_zeros] == 0) {
        ++leading_zeros;
    }

    std::vector<uint8_t> number(data.begin() + leading_zeros, data.end());

    std::string remainders;
    remainders.reserve(number.size() * 2);
    while (!number.empty()) {
        uint8_t rem = bigint_divmod(number, B62_BASE);
        remainders.push_back(B62_ALPHABET[rem]);
    }

    std::string result(leading_zeros, B62_ALPHABET[0]);
    for (auto it = remainders.rbegin(); it != remainders.rend(); ++it) {
        result.push_back(*it);
    }
    return result;
}

} // anonymous namespace
```

#### Step 7: Write `encode()` dispatch and `encode_file()` in `src/encode.cpp`

Append inside `namespace switch_encode { ... }` (these are the public functions):

```cpp
// ---------------------------------------------------------------------------
// Public encode dispatch
// ---------------------------------------------------------------------------

std::string encode(EncodeType type, const std::vector<uint8_t>& data) {
    switch (type) {
    case EncodeType::Base16: return encode_base16(data);
    case EncodeType::Base32: return encode_base32(data);
    case EncodeType::Base58: return encode_base58(data);
    case EncodeType::Base62: return encode_base62(data);
    case EncodeType::Base64: return encode_base64(data);
    }
    return {}; // unreachable
}

// ---------------------------------------------------------------------------
// File-to-file encode with validation
// ---------------------------------------------------------------------------

bool encode_file(EncodeType type,
                 const std::string& input_path,
                 const std::string& output_path,
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
    if (!in.read(reinterpret_cast<char*>(data.data()), size)) {
        error_msg = "failed to read input file '" + input_path + "'";
        return false;
    }
    in.close();

    // 2. Encode
    std::string encoded = encode(type, data);

    // 3. Write output
    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error_msg = "cannot write to output file '" + output_path
                    + "': " + std::generic_category().message(errno);
        return false;
    }
    out.write(encoded.data(), static_cast<std::streamsize>(encoded.size()));
    if (!out) {
        error_msg = "failed to write output file '" + output_path + "'";
        return false;
    }
    out.close();

    return true;
}

} // namespace switch_encode
```

#### Step 8: Verify the encoding module compiles

No standalone compile yet — will verify with Task 4 (CMake integration + build).

---

### Task 2: CLI Integration — Extend Args and Parsing

**Files:**
- Modify: `src/cli.hpp`
- Modify: `src/cli.cpp`

**Interfaces:**
- Consumes: `EncodeType`, `parse_encode_type`, `encode_type_name`, `all_encode_names` from `encode.hpp`
- Produces: Extended `Args` with `encode_type`, `encode_list`, `output_file`; updated `parse()`; updated `print_help()`

#### Step 1: Modify `src/cli.hpp` — Add Encode/EncodeList to Command and new Args fields

Change from:

```cpp
enum class Command {
    Help,
    Version,
    Protect,
    Build,
    Unknown,
};

struct Args {
    Command cmd = Command::Unknown;
    std::vector<std::string> positional;   // input files, etc.
    bool show_help    = false;
    bool show_version = false;
};
```

To:

```cpp
#include "encode.hpp"  // added at top after existing includes
// ... (rest of existing includes)

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
```

#### Step 2: Modify `src/cli.cpp` — Add `#include "encode.hpp"`, extend parse()

The top of the file needs `#include "encode.hpp"` (added in cli.hpp already, but keep explicit).

In `parse()`, add these blocks after the existing `--version` block (before the `protect` block):

```cpp
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
```

#### Step 3: Modify `src/cli.cpp` — Update help text

In `print_help()`, replace the OPTIONS and COMMANDS sections:

```cpp
void print_help() {
    print_banner();

    std::cout << "USAGE\n"
              << "  switch [OPTIONS] [COMMAND] [ARGS...]\n"
              << "\n"
              << "OPTIONS\n"
              << "  -h, --help         Show this help text\n"
              << "  -v, --version      Show version information\n"
              << "  --encode <type>    Encode input file with specified encoding\n"
              << "                     Types: " << switch_encode::all_encode_names() << "\n"
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
              << "  switch --encode BASE64 data.bin -o encoded.txt\n"
              << "\n"
              << "Python 3.14+ required for runtime features.\n";
}
```

**Note:** The existing `#include <algorithm>` in cli.cpp is unused. Remove it:

Change:
```cpp
#include <iostream>
#include <string_view>
#include <algorithm>
```

To:
```cpp
#include <iostream>
#include <string_view>
```

---

### Task 3: Main Dispatch — Handle Encode and EncodeList

**File:**
- Modify: `src/main.cpp`

**Interfaces:**
- Consumes: `Args` with encode fields from `cli.hpp`, `encode_file()`/`encode_type_name()` from `encode.hpp`

#### Step 1: Modify `src/main.cpp` — Add Encode/EncodeList cases

Replace the entire file with:

```cpp
#include "cli.hpp"
#include "encode.hpp"

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
        // Validate we have an input file
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
```

---

### Task 4: Build System Integration

**Files:**
- Modify: `CMakeLists.txt`
- Create: `tests/CMakeLists.txt`

#### Step 1: Modify `CMakeLists.txt` — Add encode sources

Change:

```cmake
set(SOURCES
    src/main.cpp
    src/cli.cpp
)

set(HEADERS
    src/cli.hpp
    include/switch/version.hpp
)
```

To:

```cmake
set(SOURCES
    src/main.cpp
    src/cli.cpp
    src/encode.cpp
)

set(HEADERS
    src/cli.hpp
    src/encode.hpp
    include/switch/version.hpp
)
```

And change the testing placeholder:

```cmake
# ---------------------------------------------------------------------------
# Testing (placeholder)
# ---------------------------------------------------------------------------
enable_testing()
# add_subdirectory(tests)  # future
```

To:

```cmake
# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)
```

#### Step 2: Create `tests/CMakeLists.txt`

```cmake
# Download doctest if not present
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/doctest.h)
    file(DOWNLOAD
        https://raw.githubusercontent.com/doctest/doctest/v2.4.11/doctest/doctest.h
        ${CMAKE_CURRENT_SOURCE_DIR}/doctest.h
        TIMEOUT 30
        STATUS DOWNLOAD_STATUS
    )
    list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
    if(NOT STATUS_CODE EQUAL 0)
        message(FATAL_ERROR "Failed to download doctest.h")
    endif()
endif()

add_executable(test_encode
    test_encode.cpp
    ${CMAKE_SOURCE_DIR}/src/encode.cpp
)

target_include_directories(test_encode PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(test_encode PRIVATE cxx_std_17)

add_test(NAME test_encode COMMAND test_encode)

add_executable(test_cli_encode
    test_cli_encode.cpp
    ${CMAKE_SOURCE_DIR}/src/cli.cpp
    ${CMAKE_SOURCE_DIR}/src/encode.cpp
)

target_include_directories(test_cli_encode PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(test_cli_encode PRIVATE cxx_std_17)

add_test(NAME test_cli_encode COMMAND test_cli_encode)
```

#### Step 3: Reconfigure and build

```bash
cmake -G Ninja -B build -S .
cmake --build build
```

Expected: `switch` binary builds with encode module linked in.

#### Step 4: Smoke test help and encode-list

```bash
./build/switch --help          # should show new encode options
./build/switch --encode-list   # should list all 5 types
```

Expected output for `--encode-list`:
```
Supported encoding types:
  base16, base32, base58, base62, base64
```

---

### Task 5: Unit Tests — Encoding Module

**File:**
- Create: `tests/test_encode.cpp`

#### Step 1: Write `tests/test_encode.cpp`

```cpp
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "encode.hpp"

#include <cstring>
#include <string>
#include <vector>

using namespace switch_encode;

// Helper: string → byte vector
static std::vector<uint8_t> bytes(const std::string& s) {
    return {s.begin(), s.end()};
}

// Helper: byte vector → string (for comparison with encoded strings)
static std::string str(const std::vector<uint8_t>& v) {
    return {v.begin(), v.end()};
}

// =========================================================================
// parse_encode_type — case-insensitive name resolution
// =========================================================================

TEST_CASE("parse_encode_type: valid names") {
    CHECK(parse_encode_type("base16") == EncodeType::Base16);
    CHECK(parse_encode_type("base32") == EncodeType::Base32);
    CHECK(parse_encode_type("base58") == EncodeType::Base58);
    CHECK(parse_encode_type("base62") == EncodeType::Base62);
    CHECK(parse_encode_type("base64") == EncodeType::Base64);
}

TEST_CASE("parse_encode_type: case-insensitive") {
    CHECK(parse_encode_type("BASE16") == EncodeType::Base16);
    CHECK(parse_encode_type("Base32") == EncodeType::Base32);
    CHECK(parse_encode_type("bAsE58") == EncodeType::Base58);
    CHECK(parse_encode_type("BASE62") == EncodeType::Base62);
    CHECK(parse_encode_type("Base64") == EncodeType::Base64);
}

TEST_CASE("parse_encode_type: unknown name returns nullopt") {
    CHECK(parse_encode_type("base128") == std::nullopt);
    CHECK(parse_encode_type("hex") == std::nullopt);
    CHECK(parse_encode_type("") == std::nullopt);
    CHECK(parse_encode_type("base") == std::nullopt);
}

// =========================================================================
// encode_type_name
// =========================================================================

TEST_CASE("encode_type_name: returns canonical lowercase name") {
    CHECK(encode_type_name(EncodeType::Base16) == "base16");
    CHECK(encode_type_name(EncodeType::Base32) == "base32");
    CHECK(encode_type_name(EncodeType::Base58) == "base58");
    CHECK(encode_type_name(EncodeType::Base62) == "base62");
    CHECK(encode_type_name(EncodeType::Base64) == "base64");
}

// =========================================================================
// all_encode_names
// =========================================================================

TEST_CASE("all_encode_names: contains all five names") {
    std::string names = all_encode_names();
    CHECK(names.find("base16") != std::string::npos);
    CHECK(names.find("base32") != std::string::npos);
    CHECK(names.find("base58") != std::string::npos);
    CHECK(names.find("base62") != std::string::npos);
    CHECK(names.find("base64") != std::string::npos);
}

// =========================================================================
// Base16 (Hex) encoding
// =========================================================================

TEST_CASE("encode base16: empty input") {
    CHECK(encode(EncodeType::Base16, {}) == "");
}

TEST_CASE("encode base16: known values") {
    CHECK(encode(EncodeType::Base16, bytes("hello")) == "68656c6c6f");
    CHECK(encode(EncodeType::Base16, bytes("test")) == "74657374");
    // Single byte
    CHECK(encode(EncodeType::Base16, {0x00}) == "00");
    CHECK(encode(EncodeType::Base16, {0xFF}) == "ff");
    CHECK(encode(EncodeType::Base16, {0x0A}) == "0a");
    // Binary data with all nibble values
    CHECK(encode(EncodeType::Base16, {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF})
          == "0123456789abcdef");
}

// =========================================================================
// Base32 encoding (RFC 4648)
// =========================================================================

TEST_CASE("encode base32: empty input") {
    CHECK(encode(EncodeType::Base32, {}) == "");
}

TEST_CASE("encode base32: RFC 4648 test vectors") {
    // RFC 4648 §10 test vectors
    CHECK(encode(EncodeType::Base32, bytes("")) == "");
    CHECK(encode(EncodeType::Base32, bytes("f")) == "MY======");
    CHECK(encode(EncodeType::Base32, bytes("fo")) == "MZXQ====");
    CHECK(encode(EncodeType::Base32, bytes("foo")) == "MZXW6===");
    CHECK(encode(EncodeType::Base32, bytes("foob")) == "MZXW6YQ=");
    CHECK(encode(EncodeType::Base32, bytes("fooba")) == "MZXW6YTB");
    CHECK(encode(EncodeType::Base32, bytes("foobar")) == "MZXW6YTBOI======");
}

TEST_CASE("encode base32: 'hello'") {
    CHECK(encode(EncodeType::Base32, bytes("hello")) == "NBSWY3DP");
}

// =========================================================================
// Base58 encoding (Bitcoin-style)
// =========================================================================

TEST_CASE("encode base58: empty input") {
    CHECK(encode(EncodeType::Base58, {}) == "");
}

TEST_CASE("encode base58: leading zeros") {
    // Each leading zero byte → '1'
    CHECK(encode(EncodeType::Base58, {0x00}) == "1");
    CHECK(encode(EncodeType::Base58, {0x00, 0x00}) == "11");
    CHECK(encode(EncodeType::Base58, {0x00, 0x00, 0x01}) == "112"); // 2 zeros + value 1
}

TEST_CASE("encode base58: known values") {
    // "hello" = 0x68 0x65 0x6c 0x6c 0x6f
    // As integer: 448371090343
    // Div-by-58 remainders: 23(Q), 8(9), 37(e), 1(2), 7(8), 45(n), 11(C)
    // Reversed: Cn8e9Q
    CHECK(encode(EncodeType::Base58, bytes("hello")) == "Cn8e9Q");
}

TEST_CASE("encode base58: Bitcoin address-like data") {
    // 20 zero bytes + suffix → should start with 20 '1's
    std::vector<uint8_t> data(20, 0x00);
    data.push_back(0x01);
    std::string result = encode(EncodeType::Base58, data);
    CHECK(result.size() >= 20);
    CHECK(result.substr(0, 20) == std::string(20, '1'));
}

// =========================================================================
// Base62 encoding
// =========================================================================

TEST_CASE("encode base62: empty input") {
    CHECK(encode(EncodeType::Base62, {}) == "");
}

TEST_CASE("encode base62: leading zeros") {
    CHECK(encode(EncodeType::Base62, {0x00}) == "0");
    CHECK(encode(EncodeType::Base62, {0x00, 0x00}) == "00");
}

TEST_CASE("encode base62: known values") {
    // "hello" → verify it produces expected alphanumeric output
    std::string result = encode(EncodeType::Base62, bytes("hello"));
    // All chars should be in [0-9A-Za-z]
    for (char c : result) {
        CHECK((c >= '0' && c <= '9')
              || (c >= 'A' && c <= 'Z')
              || (c >= 'a' && c <= 'z'));
    }
    CHECK(!result.empty());
}

// =========================================================================
// Base64 encoding (RFC 4648)
// =========================================================================

TEST_CASE("encode base64: empty input") {
    CHECK(encode(EncodeType::Base64, {}) == "");
}

TEST_CASE("encode base64: RFC 4648 test vectors") {
    CHECK(encode(EncodeType::Base64, bytes("")) == "");
    CHECK(encode(EncodeType::Base64, bytes("f")) == "Zg==");
    CHECK(encode(EncodeType::Base64, bytes("fo")) == "Zm8=");
    CHECK(encode(EncodeType::Base64, bytes("foo")) == "Zm9v");
    CHECK(encode(EncodeType::Base64, bytes("foob")) == "Zm9vYg==");
    CHECK(encode(EncodeType::Base64, bytes("fooba")) == "Zm9vYmE=");
    CHECK(encode(EncodeType::Base64, bytes("foobar")) == "Zm9vYmFy");
}

TEST_CASE("encode base64: binary data") {
    // All zeros
    CHECK(encode(EncodeType::Base64, {0x00, 0x00, 0x00}) == "AAAA");
    // All ones
    CHECK(encode(EncodeType::Base64, {0xFF, 0xFF, 0xFF}) == "////");
    // Single byte 0xFB
    CHECK(encode(EncodeType::Base64, {0xFB}) == "+w==");
}

// =========================================================================
// Roundtrip correctness via decoding verification
// =========================================================================

// Base16 decode helper (for roundtrip testing only)
static std::vector<uint8_t> decode_base16(const std::string& encoded) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i + 1 < encoded.size(); i += 2) {
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        result.push_back((nibble(encoded[i]) << 4) | nibble(encoded[i+1]));
    }
    return result;
}

TEST_CASE("roundtrip: base16 encode → decode matches original") {
    std::vector<uint8_t> original = {0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF};
    std::string enc = encode(EncodeType::Base16, original);
    std::vector<uint8_t> dec = decode_base16(enc);
    CHECK(dec == original);
}

// =========================================================================
// encode_file error handling
// =========================================================================

TEST_CASE("encode_file: nonexistent input file") {
    std::string error;
    bool ok = encode_file(EncodeType::Base16,
                          "/nonexistent/path/foo.bin",
                          "/tmp/switch_test_output.txt",
                          error);
    CHECK(ok == false);
    CHECK(!error.empty());
}

TEST_CASE("encode_file: unwritable output path") {
    std::string error;
    bool ok = encode_file(EncodeType::Base16,
                          "/dev/null",            // readable (but empty)
                          "/root/switch_test_should_fail.txt",
                          error);
    CHECK(ok == false);
    CHECK(!error.empty());
}
```

#### Step 2: Build and run unit tests

```bash
cmake -G Ninja -B build -S .
cmake --build build
./build/tests/test_encode
```

Expected: all tests pass (some checks for base58/base62 may need value adjustment after verifying with Python).

---

### Task 6: Integration Tests — CLI End-to-End

**File:**
- Create: `tests/test_cli_encode.cpp`

#### Step 1: Write `tests/test_cli_encode.cpp`

```cpp
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "cli.hpp"
#include "encode.hpp"

#include <cstdio>
#include <fstream>
#include <string>

// Helper: create a temp file with content, returns path
static std::string create_temp_file(const std::string& content) {
    std::string path = "/tmp/switch_test_" + std::to_string(std::rand()) + ".tmp";
    std::ofstream out(path, std::ios::binary);
    out.write(content.data(), content.size());
    out.close();
    return path;
}

// Helper: read file content
static std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return {};
    std::streamsize size = in.tellg();
    in.seekg(0);
    std::string content(static_cast<size_t>(size), '\0');
    in.read(content.data(), size);
    return content;
}

// =========================================================================
// CLI parse: --encode-list
// =========================================================================

TEST_CASE("cli parse: --encode-list sets cmd and encode_list flag") {
    const char* argv[] = {"switch", "--encode-list"};
    auto args = switch_cli::parse(2, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::EncodeList);
    CHECK(args->encode_list == true);
}

// =========================================================================
// CLI parse: --encode <type> <file>
// =========================================================================

TEST_CASE("cli parse: --encode base32 with input file") {
    const char* argv[] = {"switch", "--encode", "base32", "test.py"};
    auto args = switch_cli::parse(4, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encode);
    CHECK(args->encode_type == switch_encode::EncodeType::Base32);
    REQUIRE(args->positional.size() == 1);
    CHECK(args->positional[0] == "test.py");
}

TEST_CASE("cli parse: --encode case-insensitive") {
    const char* argv[] = {"switch", "--encode", "BASE64", "data.bin"};
    auto args = switch_cli::parse(4, argv);
    REQUIRE(args.has_value());
    CHECK(args->encode_type == switch_encode::EncodeType::Base64);
}

TEST_CASE("cli parse: --encode with -o output") {
    const char* argv[] = {"switch", "--encode", "base16", "in.py", "-o", "out.py"};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encode);
    CHECK(args->encode_type == switch_encode::EncodeType::Base16);
    REQUIRE(args->output_file.has_value());
    CHECK(*args->output_file == "out.py");
}

// =========================================================================
// CLI parse: --encode error cases
// =========================================================================

TEST_CASE("cli parse: --encode without type returns nullopt") {
    const char* argv[] = {"switch", "--encode"};
    auto args = switch_cli::parse(2, argv);
    CHECK(args == std::nullopt);
}

TEST_CASE("cli parse: --encode with unknown type returns nullopt") {
    const char* argv[] = {"switch", "--encode", "base128", "test.py"};
    auto args = switch_cli::parse(4, argv);
    CHECK(args == std::nullopt);
}

TEST_CASE("cli parse: -o without path returns nullopt") {
    const char* argv[] = {"switch", "--encode", "base16", "test.py", "-o"};
    auto args = switch_cli::parse(5, argv);
    CHECK(args == std::nullopt);
}

// =========================================================================
// CLI parse: compatibility — existing flags still work
// =========================================================================

TEST_CASE("cli parse: --help still works") {
    const char* argv[] = {"switch", "--help"};
    auto args = switch_cli::parse(2, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Help);
}

TEST_CASE("cli parse: --version still works") {
    const char* argv[] = {"switch", "-v"};
    auto args = switch_cli::parse(2, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Version);
}

TEST_CASE("cli parse: protect/built stubs still work") {
    const char* argv[] = {"switch", "protect", "test.py"};
    auto args = switch_cli::parse(3, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Protect);
}

// =========================================================================
// encode_file end-to-end through encode module
// =========================================================================

TEST_CASE("encode_file e2e: base16 roundtrip") {
    std::string input_path = create_temp_file("hello world");
    std::string output_path = "/tmp/switch_test_b16_output.tmp";

    std::string error;
    bool ok = switch_encode::encode_file(
        switch_encode::EncodeType::Base16, input_path, output_path, error);
    INFO("error: ", error);
    CHECK(ok == true);

    std::string encoded = read_file(output_path);
    CHECK(encoded == "68656c6c6f20776f726c64"); // "hello world" in hex

    std::remove(input_path.c_str());
    std::remove(output_path.c_str());
}

TEST_CASE("encode_file e2e: base64 roundtrip") {
    std::string input_path = create_temp_file("hello world");
    std::string output_path = "/tmp/switch_test_b64_output.tmp";

    std::string error;
    bool ok = switch_encode::encode_file(
        switch_encode::EncodeType::Base64, input_path, output_path, error);
    INFO("error: ", error);
    CHECK(ok == true);

    std::string encoded = read_file(output_path);
    CHECK(encoded == "aGVsbG8gd29ybGQ=");

    std::remove(input_path.c_str());
    std::remove(output_path.c_str());
}

TEST_CASE("encode_file e2e: empty file produces empty output") {
    std::string input_path = create_temp_file("");
    std::string output_path = "/tmp/switch_test_empty_output.tmp";

    // Test all 5 encodings with empty input
    for (auto type : {switch_encode::EncodeType::Base16,
                      switch_encode::EncodeType::Base32,
                      switch_encode::EncodeType::Base58,
                      switch_encode::EncodeType::Base62,
                      switch_encode::EncodeType::Base64}) {
        std::string error;
        bool ok = switch_encode::encode_file(type, input_path, output_path, error);
        INFO("error for type ", switch_encode::encode_type_name(type), ": ", error);
        CHECK(ok == true);

        std::string encoded = read_file(output_path);
        CHECK(encoded == "");
    }

    std::remove(input_path.c_str());
    std::remove(output_path.c_str());
}

TEST_CASE("encode_file e2e: all five encoding types produce non-empty output for non-empty input") {
    std::string input_path = create_temp_file("test data 12345");
    std::string output_path = "/tmp/switch_test_5types_output.tmp";

    for (auto type : {switch_encode::EncodeType::Base16,
                      switch_encode::EncodeType::Base32,
                      switch_encode::EncodeType::Base58,
                      switch_encode::EncodeType::Base62,
                      switch_encode::EncodeType::Base64}) {
        std::string error;
        bool ok = switch_encode::encode_file(type, input_path, output_path, error);
        INFO("error for type ", switch_encode::encode_type_name(type), ": ", error);
        CHECK(ok == true);

        std::string encoded = read_file(output_path);
        CHECK(!encoded.empty());
    }

    std::remove(input_path.c_str());
    std::remove(output_path.c_str());
}

TEST_CASE("encode_file e2e: nonexistent input path fails") {
    std::string error;
    bool ok = switch_encode::encode_file(
        switch_encode::EncodeType::Base16,
        "/tmp/switch_nonexistent_file_xyz123.tmp",
        "/tmp/switch_output.tmp",
        error);
    CHECK(ok == false);
    CHECK(error.find("cannot open") != std::string::npos);
}
```

#### Step 2: Build and run integration tests

```bash
cmake --build build
./build/tests/test_cli_encode
```

Expected: all tests pass.

---

### Task 7: Verification — Full End-to-End Manual Test

#### Step 1: Rebuild everything and run all tests

```bash
cmake -G Ninja -B build -S .
cmake --build build
ctest --test-dir build --output-on-failure
```

Expected: all tests pass, `switch` binary functional.

#### Step 2: Manual CLI smoke tests

```bash
# Help includes new options
./build/switch --help

# Encode list
./build/switch --encode-list

# Encode a real file with each type
echo "print('hello world')" > /tmp/test_switch.py

./build/switch --encode base16 /tmp/test_switch.py -o /tmp/out_b16.py
cat /tmp/out_b16.py  # hex output

./build/switch --encode base32 /tmp/test_switch.py -o /tmp/out_b32.py
cat /tmp/out_b32.py

./build/switch --encode base58 /tmp/test_switch.py -o /tmp/out_b58.py
cat /tmp/out_b58.py

./build/switch --encode base62 /tmp/test_switch.py -o /tmp/out_b62.py
cat /tmp/out_b62.py

./build/switch --encode base64 /tmp/test_switch.py -o /tmp/out_b64.py
cat /tmp/out_b64.py

# Case-insensitive
./build/switch --encode BASE32 /tmp/test_switch.py -o /tmp/out_upper.py
cat /tmp/out_upper.py  # same as base32 output

# Error cases
./build/switch --encode base128 test.py    # unknown type
./build/switch --encode                    # missing type
./build/switch --encode base16 nonexistent.py  # file not found
```

#### Step 3: Cleanup and final commit

```bash
rm -f /tmp/test_switch.py /tmp/out_*.py
```

---

## Spec Self-Review Results

1. **Spec coverage:** All requirements covered — `--encode` with 5 types, `--encode-list`, case-insensitivity, file validation, error messages, updated help, tests for all encodings, error handling tests, compatibility with existing CLI.

2. **Placeholder scan:** No TBD/TODO. Base58/base62 `"hello"` test vector computed manually in plan; will be verified against Python reference during implementation. All steps have concrete code.

3. **Type consistency:** `EncodeType` enum values match across encode.hpp, encode.cpp dispatch, test files. `Args` fields match between cli.hpp, cli.cpp, and main.cpp dispatch. `encode_file()` signature consistent across header, implementation, and test usage.