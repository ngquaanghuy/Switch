# Switch Project — Session Context & TODO

> **Last updated:** 2026-07-10  
> **Current branch:** `main` (PR #8 merged — Scramble Identifiers)

---

## 1. Project Overview

**Switch** — Python code protection tool built in C++17.  
Reads `.py` files → produces self-executing Python wrappers (encoded or encrypted).

- **Language:** C++17 (core), Python 3.8+ (obfuscation scripts)
- **Build:** CMake ≥3.21 + Ninja → `build/switch`
- **Dependencies:** OpenSSL (AES), libsodium (ChaCha20), Python 3.8+ (obf scripts)
- **Tests:** 4 test binaries via `ctest --test-dir build`

---

## 2. Git History (Feature Branches → Main)

| # | PR | Feature | Contributors |
|---|-----|---------|--------------|
| 1 | — | Base project (encode/encrypt) | User (70%) + Claude (20%) + Codex (10%) |
| 2 | #1 | Fix 14 code review findings (F1-F14) | User 70% / Claude 20% / Codex 10% |
| 3 | #2 | XOR string encoding (`xorencoding`) | Same split |
| 4 | #3 | Import Rewriting (`importrewrite`) — 7 security layers | Same split |
| 5 | #4 | Dead Code Injection (`deadcode`) — >17 per function | Same split |
| 6 | #5 | Remove `--key-generator`, integrate into `--encrypt` | Same split |
| 7 | #6 | Add `--key-save <file>` parameter | Same split |
| 8 | #7 | Key auto-generation in encrypt flow | Same split |
| 9 | #8 | **Scramble Identifiers** (`scramble`) — C++ inline | Same split |

**Contributors convention:** User 70%, Claude 20%, Codex (OpenAI) 10%  
*(applied to commit messages as Co-Authored-By lines)*

---

## 3. Architecture — Namespaces

| Namespace | Responsibility |
|-----------|---------------|
| `switch_cli` | CLI arg parsing, help/version printing |
| `switch_encode` | Encoding logic (base16/32/58/62/64) + Python wrapper gen |
| `switch_encrypt` | AES-CBC (OpenSSL EVP) + ChaCha20/XChaCha20 (libsodium) |
| `switch_obf` | Obfuscation — dispatches to Python scripts or C++ inline |
| `switch_scramble` | C++ inline identifier scrambling (no subprocess) |

---

## 4. Obfuscation Techniques (8 total)

| Type | File/Engine | Description |
|------|-------------|-------------|
| `namemangling` | `scripts/obf_namemangling.py` | AST-based identifier renaming |
| `stringencoding` | `scripts/obf_stringencode.py` | String literal encoding (chr, bytes, base64) |
| `docstrip` | `scripts/obf_docstrip.py` | Docstring/comment removal |
| `literal` | `scripts/obf_literal.py` | Numeric/boolean/None literal obfuscation |
| `xorencoding` | `scripts/obf_xor.py` | XOR-encode strings with random multi-byte keys |
| `importrewrite` | `scripts/obf_importrewrite.py` | Rewrite imports as obfuscated dynamic imports (7 security layers) |
| `deadcode` | `scripts/obf_deadcode.py` | Inject dense dead code (>17 per function, opaque predicates) |
| `scramble` | `src/scramble.cpp` | **C++ inline** — confusable chars (l/I/1/o/O/0), scope-aware |

**Pipeline:** Python scripts = subprocess via `obfuscate.cpp`. Scramble = direct C++ call (faster, no Python dependency).

---

## 5. CLI Commands

| Command | Status | Notes |
|---------|--------|-------|
| `--help` / `-h` | ✅ Working | |
| `--version` / `-v` | ✅ Working | Shows platform + compiler |
| `--encode <type> <file> [-o]` | ✅ Working | 5 types: base16, base32, base58, base62, base64 |
| `--encrypt <type> <file> [--key/--key-file/--key-env] [--iv/--nonce] [--key-save] [-o]` | ✅ Working | 16 types. Key auto-gen if omitted. `--key-save` saves to file. |
| `--encode-list` | ✅ Working | |
| `--encrypt-list` | ✅ Working | |
| `--obf <type>` | ✅ Working | Repeatable. 8 types. Works standalone or with `--encode`/`--encrypt` |
| `--obf-list` | ✅ Working | Lists all obfuscation techniques |
| `protect` | 🔲 Stub | "not yet implemented" |
| `build` | 🔲 Stub | "not yet implemented" |

---

## 6. Key Files Reference

### Headers (`include/switch/`)
| File | Content |
|------|---------|
| `cli.hpp` | Command enum, Args struct, parse/print declarations |
| `encode.hpp` | EncodeType enum, encode API, make_python_wrapper, encode_file |
| `encrypt.hpp` | EncryptType enum, AES+ChaCha20 API, encrypt_file, make_python_decrypt_wrapper |
| `obfuscate.hpp` | ObfType enum (8 types), parse_obf_type, obfuscate API → `std::optional<std::string>` |
| `scramble.hpp` | scramble_identifiers API (C++ inline) |
| `version.hpp` | SWITCH_VERSION_STRING, SWITCH_PYTHON_MIN_* macros |

### Sources (`src/`)
| File | Lines | Content |
|------|-------|---------|
| `main.cpp` | ~200 | Dispatch: parse → route to command handlers |
| `cli.cpp` | ~400 | Arg parsing (manual argv loop, no library), help/version |
| `encode.cpp` | ~500 | All encoding implementations + Python wrapper gen |
| `encrypt.cpp` | ~600 | AES-CBC (OpenSSL EVP) + ChaCha20/XChaCha20 (libsodium) |
| `obfuscate.cpp` | ~230 | Subprocess calls to Python scripts, stderr capture |
| `scramble.cpp` | 502 | C++ inline identifier scrambling (8-state machine) |

### Scripts (`scripts/`)
| File | Lines | Content |
|------|-------|---------|
| `obf_namemangling.py` | ~150 | AST-based identifier renaming |
| `obf_stringencode.py` | ~200 | String encoding (chr, bytes, base64) |
| `obf_docstrip.py` | ~100 | Docstring/comment removal |
| `obf_literal.py` | ~200 | Numeric/boolean/None obfuscation |
| `obf_xor.py` | ~250 | XOR string encoding with multi-byte keys |
| `obf_importrewrite.py` | ~300 | Import rewriting (7 layers: __import__, base64, chr, dead imports) |
| `obf_deadcode.py` | ~350 | Dead code injection (8 types, opaque predicates) |

### Tests (`tests/`)
| File | Content |
|------|---------|
| `test_encode.cpp` | Encoding logic unit tests (doctest) |
| `test_cli_encode.cpp` | CLI parsing + encoding e2e |
| `test_encrypt.cpp` | Encryption unit tests (links OpenSSL + libsodium) |
| `test_cli_encrypt.cpp` | CLI parsing + encryption e2e |
| `CMakeLists.txt` | Test targets — all 4 binaries linked correctly |

---

## 7. Scramble Identifiers — Deep Dive

**Engine:** `src/scramble.cpp` (502 lines), namespace `switch_scramble`

### Two-pass approach:
1. **Pass 1 (collect):** Python-aware state machine scans source → identifies all user-defined identifiers → builds `map_` (original → scrambled)
2. **Pass 2 (replace):** Walks source again → replaces mapped identifiers with scrambled names

### State machine (8 states):
```
NORMAL → SINGLE_QUOTE / DOUBLE_QUOTE / TRIPLE_SINGLE / TRIPLE_DOUBLE
       → FSTRING_S / FSTRING_D (f-string expressions)
       → COMMENT
```

### Confusable naming scheme:
- **Character set:** `l`, `I`, `1`, `o`, `O`, `0` (visually indistinguishable)
- **First char:** must be letter (l/I/o/O) — Python identifier rule
- **Name length:** 3-6 chars (4+ at module level)
- **Example names:** `lOO0`, `O1O1l`, `I0IlO`

### Key design decisions:
- **Scope-aware:** tracks `scope_level_` — module-level names get longer names
- **Import handling:** module names (`os`, `json`) stored in `import_names_` set, NOT scrambled
- **Keyword/builtin protection:** Python keywords, builtins, dunders (`__init__`) preserved
- **Decorator preservation:** `@property`, `@staticmethod` passed through
- **f-string support:** tracks `brace_depth` for expressions inside f-strings
- **Direct C++ call** — no Python subprocess, faster execution

### Bugs found & fixed during implementation:
1. **Off-by-one:** `collect_id` advanced `i` past identifier, loop's `++i` skipped next char → spaces lost between tokens → **Fix:** `break` → `continue` after `collect_id`
2. **Import handler overreach:** consumed tokens past newline into next line (`def foo()` was swallowed) → **Fix:** Added `src[i] != '\n'` check in import handler
3. **Digit-first names:** `os` mapped to `0OIO` (invalid Python ID) → **Fix:** First char forced to letter from `CONFUSABLE_LETTERS` only

---

## 8. Import Rewriting — Security Layers

`scripts/obf_importrewrite.py` — 7 layers of obfuscation:

1. `__import__()` dynamic import instead of `import X`
2. Module name base64-encoded → `__import__(base64.b64decode("bW9kdWxl").decode())`
3. Module name chr() encoded → `__import__("".join([chr(109),chr(111)...]))`
4. Dead imports in `try/except` blocks (noise)
5. `importlib` wrapper function for additional indirection
6. Multi-level encoding (b64 of chr sequences)
7. Double `__import__()` wrapping

4 strategies: b64 decode, chr sequence, b64(chr()), double __import__

---

## 9. Dead Code Injection — Features

`scripts/obf_deadcode.py` — >17 dead statements per function:

**8 types of dead code:**
1. Dead variables (unused assignments)
2. Dead functions (called but return value discarded)
3. Dead classes (instantiated but never used)
4. Opaque predicates (always True/False: `x*x >= 0`, `2*3 == 6`)
5. Dead loops (`for _ in range(1): pass`)
6. Dead list comprehensions
7. Dead try/except blocks
8. Dead imports (wrapped in try/except)

**Interleaving:** dead code injected throughout function body, not just at start/end

---

## 10. Code Review Fixes (F1-F14) — Previously Applied

| ID | File | Issue | Fix |
|----|------|-------|-----|
| F1 | `obf_docstrip.py` | Triple-quote opening only appended 1 char | Append all 3 chars, advance i by 3 |
| F2 | `obf_literal.py` | Negative integers: `_obfuscate_int()` checked `n>1` | Use `abs(n)` for strategy, negate with `ast.UnaryOp(op=ast.USub())` |
| F3-F6 | `obfuscate.cpp` | write/fread unchecked, empty vs error indistinguishable | `std::optional<std::string>` return, check all I/O, capture stderr |
| F7 | `cli.cpp` | `--obf` comma-separated values not trimmed | Added `find_first_not_of`/`find_last_not_of` whitespace trim |
| F8 | `obf_xor.py` | `ast.Xor()` → Module has no attribute | Changed to `ast.BitXor()` |
| F9 | `obf_xor.py` | `cycle()` used in AST without import | Added `from itertools import cycle` to generated module AST |
| F10 | `obf_importrewrite.py` | Dead imports tried importing nonexistent modules | Wrapped in `try/except` |
| F11-F14 | Various | Minor edge cases | Fixed during implementation |

---

## 11. Known Limitations & Future TODOs

### Immediate (known bugs):
- [x] **Module attribute access tracking in scramble:** FIXED — added `module_names_` set + `mod_seen_` flag to track dot-attribute access. `os.listdir()`, `os.path.join()` etc. now preserved. Chain-break reset handles `(`, `)`, operators.
- [ ] **Scramble + deadcode stacking order matters:** deadcode should run BEFORE scramble (dead code generates valid Python, scramble renames its identifiers). Both orders now produce valid Python output.

### Feature stubs:
- [ ] `protect` command — not yet implemented
- [ ] `build` command — not yet implemented

### Potential enhancements:
- [ ] **AST-based scramble** (Python or C++ libclang): more accurate than state machine, handles edge cases like string concatenation across lines
- [ ] **Type annotation preservation:** scramble could optionally preserve type hints for debugging
- [ ] **Incremental obfuscation:** pass multiple `--obf` flags in sequence with correct ordering
- [ ] **Obfuscation strength levels:** `--obf-level light|medium|heavy` to control dead code density, string encoding strategy
- [ ] **Self-contained output:** encrypted/encoded wrappers could bundle everything (no `cryptography` pip dependency)
- [ ] **Batch processing:** process entire directories of `.py` files
- [ ] **Progress indicators:** show obfuscation progress for large files

### Testing:
- [ ] Add scramble-specific unit tests (test_scramble.cpp)
- [ ] Add obfuscation end-to-end tests (test_obf.cpp)
- [ ] Test stacking: all 8 techniques combined in various orders
- [ ] Test edge cases: empty files, syntax errors, non-Python files

### Documentation:
- [ ] User-facing README with examples
- [ ] Man page or `--help` for each command
- [ ] Security whitepaper explaining obfuscation layers

---

## 12. Build & Test Commands

```bash
# Build
cmake -G Ninja -B build && cmake --build build

# Run all tests
ctest --test-dir build

# Run single test
./build/tests/test_encode
./build/tests/test_cli_encode
./build/tests/test_encrypt
./build/tests/test_cli_encrypt

# Run switch
./build/switch --help
./build/switch --obf scramble input.py -o output.py
./build/switch --obf deadcode --obf scramble input.py -o output.py
./build/switch --encrypt aes-256 input.py --key-save key.txt
```

---

## 13. Session Decisions & Preferences

- **Response language:** Vietnamese (user preference)
- **Commit format:** 3 contributors — User 70% / Claude 20% / Codex 10%
- **Code style:** No external libraries for arg parsing, hand-rolled solutions preferred
- **Error handling:** `std::optional` for nullable returns, stderr for diagnostics
- **No Python dependency for core:** scramble runs C++ inline (no subprocess)
- **Test framework:** doctest (header-only)
- **Build system:** CMake + Ninja

---

## 14. Context for Next Session

**When resuming work:**
1. Read `src/scramble.cpp` for scramble implementation details
2. Read `scripts/obf_*.py` for Python obfuscation scripts
3. Read `src/obfuscate.cpp` for dispatch logic
4. Run `ctest --test-dir build` to verify current state
5. Check `git -C /home/ngquanghuy/Switch log --oneline` for latest commits

**Most impactful next tasks:**
1. Fix module attribute access tracking in scramble (known limitation)
2. Add scramble-specific unit tests
3. Test all 8 techniques stacked together
4. Implement `protect` or `build` commands
