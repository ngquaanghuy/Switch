# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Switch

Switch is a Python code protection tool built in C++17. It reads `.py` files and produces self-executing Python wrappers — either encoded (base16/32/58/62/64) or encrypted (AES-128/192/256-CBC, ChaCha20-Poly1305). Future features (`protect`, `build`) are stubbed but not yet implemented.

## Build

```bash
cmake -G Ninja -B build && cmake --build build
# Binary: build/switch
```

Requires: CMake ≥3.21, Ninja, C++17 compiler, **OpenSSL dev** (`libssl-dev` / `openssl-devel`), **libsodium dev** (`libsodium-dev` / `libsodium-devel`).
Python 3.14+ optional (not required for current features). Encrypted output requires `pip install cryptography`.

## Run Tests

```bash
ctest --test-dir build
```

Six test binaries:
- `build/tests/test_encode` — encoding logic unit tests (doctest, links `encode.cpp`)
- `build/tests/test_cli_encode` — CLI parsing + encoding e2e (runs output with `python3`)
- `build/tests/test_encrypt` — encryption unit tests (links `encrypt.cpp`, OpenSSL + libsodium)
- `build/tests/test_cli_encrypt` — CLI parsing + encryption e2e (runs output with `python3`)
- `build/tests/test_scramble` — scramble identifier unit tests (pure C++, no crypto deps)
- `build/tests/test_obf` — obfuscation pipeline stacking e2e (requires `python3`)

Run a single binary: `./build/tests/test_encrypt`

## Architecture

```
include/switch/
  cli.hpp       — Command enum, Args struct, parse/print declarations
  encode.hpp    — EncodeType enum, encode API, make_python_wrapper, encode_file
  encrypt.hpp   — EncryptType enum, AES+ChaCha20 encrypt/decrypt API, encrypt_file, make_python_decrypt_wrapper
  obfuscate.hpp — ObfType enum, parse_obf_type, obfuscate API
  scramble.hpp  — scramble_identifiers API (C++ inline, no Python subprocess)
  version.hpp   — version macros (SWITCH_VERSION_STRING, SWITCH_PYTHON_MIN_*)

src/
  main.cpp      — dispatch: parse args → route to Help/Version/EncodeList/EncryptList/KeyGenerator/Encode/Encrypt/Obfuscate
  cli.cpp       — arg parsing (manual argv loop, no library), help/version printing
  encode.cpp    — all encoding implementations + Python wrapper generation + file I/O
  encrypt.cpp   — AES-CBC (OpenSSL EVP) + ChaCha20/XChaCha20-Poly1305 (libsodium) encrypt/decrypt, Python decrypt wrapper
  obfuscate.cpp — subprocess calls to Python scripts for obfuscation (name mangling, string encoding, doc strip, literal)
  scramble.cpp  — C++ inline identifier scrambling (confusable chars, scope-aware)

scripts/
  obf_namemangling.py — AST-based identifier renaming
  obf_stringencode.py — string literal encoding (chr, bytes, base64)
  obf_docstrip.py     — docstring/comment removal
  obf_literal.py      — numeric/boolean/None literal obfuscation
  obf_xor.py          — XOR-encode strings with random multi-byte keys
  obf_importrewrite.py — rewrite imports as obfuscated dynamic imports
  obf_deadcode.py     — inject dense dead code (functions, classes, opaque predicates)
  obf_varsplit.py     — variable splitting (bool/int/float → sub-variables)
  obf_opaque.py       — opaque predicates (inject known-True/False branches)
```

**Namespace split**: `switch_cli` (CLI parsing/display), `switch_encode` (encoding logic), `switch_encrypt` (encryption — AES via OpenSSL, ChaCha20/XChaCha20 via libsodium), `switch_obf` (obfuscation — Python subprocess scripts), `switch_scramble` (C++ inline identifier scrambling).

## Key Design Decisions

- **No arg-parsing library** — hand-rolled `parse()` returns `std::optional<Args>`, printing errors to stderr on failure (returns `std::nullopt`).
- **Base58/Base62 use bigint division** — `bigint_divmod()` helper divides big-endian byte vectors by the base in-place, collecting remainders.
- **OpenSSL for AES** — uses EVP API (`EVP_aes_{128,192,256}_cbc()`), with `EVP_CIPHER_CTX_set_padding(ctx, 0)` to disable auto-padding (we do our own PKCS7).
- **libsodium for ChaCha20/XChaCha20** — ChaCha20 uses `crypto_aead_chacha20poly1305_ietf` (12-byte nonce); XChaCha20 uses `crypto_aead_xchacha20poly1305_ietf` (24-byte nonce). Both IETF variant, authenticated encryption with Poly1305 MAC. Ciphertext = plaintext + 16-byte MAC.
- **Python wrapper strategy** — encode wrappers use Python's `base64` stdlib; AES encrypt wrappers use `cryptography` library; ChaCha20/XChaCha20 wrappers both use `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305` (Python's ChaCha20Poly1305 auto-selects XChaCha20 based on nonce length: 12 = ChaCha20, 24 = XChaCha20). All have error handling (import check, UTF-8 decode guard).
- **Key length validation** — CLI validates key hex length matches AES variant before calling `encrypt_file()`. `encrypt()`/`decrypt()` also validate internally.
- **`encode_file()` / `encrypt_file()` are file-level APIs** — read input, transform, wrap in Python, write output. Return `false` with error_msg on failure.

## Current CLI Commands

| Command | Status | Notes |
|---------|--------|-------|
| `--help` / `-h` | Working | |
| `--version` / `-v` | Working | Shows platform + compiler |
| `--encode <type> <file> [-o <out>]` | Working | 5 types: base16, base32, base58, base62, base64 |
| `--encrypt <type> <file> [--key/--key-file/--key-env <hex>] [--iv/--nonce <hex>] [--key-save <file>] [-o <out>]` | Working | 16 types: aes-128, aes-192, aes-256, chacha20, xchacha20, aes-{128,192,256}-gcm, aes-{128,192,256}-ccm, aes-{128,256}-siv, aes-{128,192,256}-ocb. Key auto-generated if omitted. IV/nonce auto-generated if omitted. |
| `--encode-list` | Working | |
| `--encrypt-list` | Working | |
| `--obf <type>` | Working | Obfuscate Python source (repeatable). Types: namemangling, stringencoding, docstrip, literal, xorencoding, importrewrite, deadcode, scramble, variablesplitting, opaquepredicates. Can work standalone or with --encode/--encrypt |
| `--obf-list` | Working | List all obfuscation techniques |
| `protect` | Stub | Prints "not yet implemented" |
| `build` | Stub | Prints "not yet implemented" |

Default output path: `<input>.<encodename>` for encode, `<input>.<encname>.py` for encrypt.

## Cross-Platform Notes

Platform detection uses preprocessor defines (`SWITCH_PLATFORM_WINDOWS/MACOS/LINUX`). Linux links `dl` and `pthread`. OpenSSL and libsodium are required on all platforms. The encode/encrypt logic itself is platform-independent.
