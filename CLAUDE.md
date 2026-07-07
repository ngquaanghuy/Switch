# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Switch

Switch is a Python code protection tool built in C++17. It reads `.py` files, encodes the source into a self-decodable Python wrapper (`exec(base64.b64decode(...))` style), producing a `.py` file that runs identically to the original. Future features (`protect`, `build`) are stubbed but not yet implemented.

## Build

```bash
cmake -G Ninja -B build && cmake --build build
# Binary: build/switch
```

Requires: CMake ≥3.21, Ninja, C++17 compiler. Python 3.14+ optional (not required for current encode features).

## Run Tests

```bash
ctest --test-dir build
```

Two test binaries:
- `build/tests/test_encode` — pure encoding logic (doctest, links only `encode.cpp`)
- `build/tests/test_cli_encode` — CLI parsing + end-to-end encode_file (runs encoded output with `python3`, so Python must be installed)

Run a single binary: `./build/tests/test_encode`

## Architecture

```
include/switch/
  cli.hpp       — Command enum, Args struct, parse/print declarations
  encode.hpp    — EncodeType enum, encode API, make_python_wrapper, encode_file
  version.hpp   — version macros (SWITCH_VERSION_STRING, SWITCH_PYTHON_MIN_*)

src/
  main.cpp      — dispatch: parse args → route to Help/Version/EncodeList/Encode
  cli.cpp       — arg parsing (manual argv loop, no library), help/version printing
  encode.cpp    — all encoding implementations + Python wrapper generation + file I/O
```

**Namespace split**: `switch_cli` (CLI parsing/display) and `switch_encode` (encoding logic).

## Key Design Decisions

- **No arg-parsing library** — hand-rolled `parse()` returns `std::optional<Args>`, printing errors to stderr on failure (returns `std::nullopt`).
- **Base58/Base62 use bigint division** — `bigint_divmod()` helper divides big-endian byte vectors by the base in-place, collecting remainders. This handles arbitrary-size inputs without bignum libraries.
- **Python wrapper strategy** — `make_python_wrapper()` generates a self-contained `.py` file: base16/32/64 use Python's `base64` stdlib; base58/62 embed a pure-Python decoder using `int.to_bytes()`.
- **`encode_file()` is the file-level API** — reads input, calls `encode()`, wraps with `make_python_wrapper()`, writes output. Returns `false` with error_msg on failure.

## Current CLI Commands

| Command | Status | Notes |
|---------|--------|-------|
| `--help` / `-h` | Working | |
| `--version` / `-v` | Working | Shows platform + compiler |
| `--encode <type> <file> [-o <out>]` | Working | 5 types: base16, base32, base58, base62, base64 |
| `--encode-list` | Working | |
| `protect` | Stub | Prints "not yet implemented" |
| `build` | Stub | Prints "not yet implemented" |

Default output path when `-o` is omitted: `<input>.<encodename>` (e.g. `input.py` → `input.py.base64`).

## Cross-Platform Notes

Platform detection uses preprocessor defines (`SWITCH_PLATFORM_WINDOWS/MACOS/LINUX`). Linux links `dl` and `pthread`. The encode logic itself is platform-independent.
