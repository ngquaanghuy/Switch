# Code Review Findings — Switch

**Date**: 2026-07-13
**Reviewer**: Claude (Fable 5)
**Files reviewed**: 22 files, ~10,500 lines (6 `.cpp`, 6 `.hpp`, 9 `.py`, test infrastructure)
**Test status**: 6/6 passed (4.16s)
**Overall assessment**: **REQUEST_CHANGES**

---

## P0 — Critical

*(none)*

---

## P1 — High

### 1. `src/main.cpp:150` and `src/main.cpp:354` — Unchecked `write()` to temp files

```cpp
write(fd, src.data(), src.size());  // return value ignored
close(fd);
```

Both occurrences (in the `Encode` and `Encrypt` command paths) ignore the return value of `write()`. If the write is partial (disk full, I/O error) or fails entirely (`returns -1`), the temp file will be truncated or empty. The subsequent `encode_file()` or `encrypt_file()` call will silently operate on corrupt data, producing broken output with no error message.

**Impact**: Silent data corruption — user thinks their code is protected but the output is garbage.

**Fix**: Check the return value, similar to the safe write pattern already used in `obfuscate.cpp:166-178`:

```cpp
const char* src_ptr = src.data();
size_t remaining = src.size();
while (remaining > 0) {
    ssize_t written = write(fd, src_ptr, remaining);
    if (written <= 0) {
        close(fd); unlink(obf_tmp.c_str());
        std::cerr << "switch: failed to write temp file\n";
        return 1;
    }
    src_ptr += written;
    remaining -= static_cast<size_t>(written);
}
```

---

### 2. `src/encrypt.cpp:1117-1130` — `key_trimmed` computed but never used for encryption

```cpp
// Line 1117-1119: key_trimmed is computed
std::vector<uint8_t> key_trimmed(key.begin(),
    (type == EncryptType::Aes128Siv || type == EncryptType::Aes256Siv)
        ? key.end() : key.begin() + key_len);

// Line 1122: but encrypt() receives the FULL key, not key_trimmed
std::vector<uint8_t> ciphertext = encrypt(type, data, key, iv_or_nonce);

// Line 1130: key_trimmed only used for b64 wrapper
std::string b64_key = base64_encode(key_trimmed);
```

The variable name `key_trimmed` and the surrounding comments suggest the key was meant to be trimmed *before* encryption. The `encrypt()` function validates key length internally (line 803), so if the CLI passes the correct-length key, this works. But:

- For non-SIV types: `key_trimmed` is `key[0..key_len]` — identical to the full key (CLI already validated length). Dead code.
- For SIV types: `key_trimmed` = full key (32 bytes), used for wrapper. Correct.
- The misleading variable name could cause a future maintainer to "fix" the code by passing `key_trimmed` to `encrypt()`, which would break SIV (needs full 32-byte key).

**Fix**: Remove `key_trimmed` entirely. The `encrypt()` function already handles key validation. For the wrapper, use `key` directly since the CLI guarantees correct length:

```cpp
std::string b64_key = base64_encode(key);
```

---

### 3. `src/scramble.cpp:43-113` — 42 duplicate entries in `python_builtins()` set

The `python_builtins()` static set contains **42 exact duplicate string literals** (e.g., `"encode"` ×2, `"split"` ×2, `"append"` ×2, `"read"` ×2, `"write"` ×2, `"remove"` ×3, etc.). This is a `std::unordered_set`, so duplicates don't cause bugs, but:

- Makes the list ~30% larger than necessary
- Masks copy-paste errors — duplicated entries suggest the list was assembled by concatenating blocks without deduplication
- Future additions may accidentally create more duplicates

**Fix**: Deduplicate the list. A simple approach: sort and unique, or just manually remove the 42 duplicates.

---

## P2 — Medium

### 4. `src/obfuscate.cpp:184` — `system()` for subprocess execution

```cpp
std::string run_cmd = "python3 \"" + script_path + "\" < \"" + tmp_in
                    + "\" > \"" + tmp_out + "\" 2>\"" + tmp_err + "\"";
int rc = system(run_cmd.c_str());
```

While the current inputs are controlled (script names are hardcoded, tmp files use `mkstemp`), `system()` invokes a shell which expands glob patterns, interprets quotes, and is susceptible to injection if `find_script_path()` ever returns a path containing shell metacharacters.

**Recommendation**: Replace with `fork()/execvp()` or `posix_spawn()` to avoid shell interpretation. This is the pattern used in production security tools. Not urgent since inputs are currently safe, but becomes important if script paths become configurable.

---

### 5. `scripts/obf_cff.py` — No Python version check for 3.10+ output requirement

The CFF script uses `ast.unparse()` to generate `match/case` syntax (Python 3.10+). While the script itself runs on any Python 3.8+, the *output* is only valid on 3.10+. The header comment documents this, but there's no runtime check or warning.

If a user runs `switch --obf controlflowflattening input.py` and then tries `python3 output.py` on Python 3.9, they get a `SyntaxError` with no explanation.

**Fix**: Add a version check in `main()` or a comment in the generated wrapper:

```python
# WARNING: This output requires Python 3.10+ (uses match/case syntax)
```

---

### 6. `src/main.cpp:40-61` — Obfuscation pipeline order hardcoded in lambda

The auto-sort lambda in `main()` duplicates the ordering knowledge that should live in `obfuscate.hpp` or a shared constant. If a new technique is added, the developer must update both `obf_type_name()` in `obfuscate.cpp` AND the ordering lambda in `main.cpp`.

**Recommendation**: Move the ordering to `obfuscate.hpp`/`obfuscate.cpp` as a public function:

```cpp
// In obfuscate.hpp
int obf_type_priority(ObfType type);
```

Then `main.cpp` just calls `std::stable_sort(..., obf_type_priority)`.

---

### 7. `src/encrypt.cpp:519-527` — AES-SIV: `gf128_double` potential endianness concern

```cpp
static void gf128_double(uint8_t block[16]) {
    uint8_t msb = block[0] & 0x80;
    for (int i = 0; i < 15; ++i) {
        block[i] = (block[i] << 1) | (block[i + 1] >> 7);
    }
    block[15] <<= 1;
    if (msb) block[15] ^= 0x87;
}
```

This implements GF(2^128) doubling in **little-endian** byte order (MSB at `block[0]`, carry propagates to `block[15]`). RFC 5297 S2V uses AES-CMAC which operates on big-endian blocks. The correctness depends on whether the CMAC output is interpreted consistently. The tests pass (roundtrip verified), but this is a subtle crypto implementation that warrants a comment explaining the byte-order convention.

---

### 8. `scripts/obf_varsplit.py` — Float precision loss after reconstruction

The `split_float()` function splits `3.14` into two random floats and reconstructs via `round(a + b, 6)`. Due to IEEE 754 representation, the reconstructed value may differ from the original in later decimal places. For example:

- Original: `3.14`
- Split: `_p0 = -458.123456`, `_q0 = 461.263456`
- Reconstructed: `round(-458.123456 + 461.263456, 6)` = `3.140000` (correct)

This works for 6 decimal places, but values with more precision or extreme magnitudes may drift. The `round()` mitigates but doesn't eliminate the issue.

**Impact**: Low — most float literals in Python code have ≤6 significant digits.

---

## P3 — Low

### 9. `.gitignore` missing entries

The `.gitignore` doesn't include `.agents/`, `.claude/`, or `__pycache__/`. These show up as untracked in `git status`:

```
?? .agents/
?? .claude/
?? scripts/__pycache__/
```

**Fix**: Add to `.gitignore`:

```
.claude/
.agents/
__pycache__/
```

---

### 10. `src/encode.cpp:60-67` — `all_encode_names()` returns hardcoded string

```cpp
std::string all_encode_names() {
    return "base16, base32, base58, base62, base64";
}
```

Same pattern in `encrypt.cpp:75-77` and `obfuscate.cpp:75-77`. If a new type is added, the hardcoded string must be updated manually alongside the enum and lookup table.

**Fix**: Build the string from the lookup table at compile time or runtime, similar to how `encode_type_name()` already iterates the table.

---

### 11. `src/obfuscate.cpp:84-117` — `find_script_path()` uses `/proc/self/exe` (Linux-only)

The function reads `/proc/self/exe` to find the binary's directory, then looks for scripts relative to it. On macOS/Windows, this would fall through to the cwd-relative fallback. The code works cross-platform but the comment could be clearer about the platform-specific behavior.

---

### 12. `src/scramble.cpp` — O(n²) collision check in `map_id()`

```cpp
std::string map_id(const std::string& id) {
    if (map_.count(id)) return map_[id];
    std::string name = gen_name();
    while (std::any_of(map_.begin(), map_.end(),
                       [&name](const auto& p) { return p.second == name; })) {
        name = gen_name();
    }
    map_[id] = name;
    return name;
}
```

For every new identifier, the entire map is scanned to check for name collisions. With confusable characters (`lI1oO0`) and 3-6 char names, the namespace is small (~6^6 = ~46K possibilities). For codebases with hundreds of identifiers, this could slow down, but it's unlikely to be a practical issue.

---

## Summary

| Severity | Count | Details |
|----------|-------|---------|
| P0 Critical | 0 | — |
| P1 High | 3 | Unchecked write(), dead key_trimmed, 42 duplicate builtins |
| P2 Medium | 5 | system() subprocess, no CFF version check, hardcoded pipeline order, SIV endianness comment, float precision |
| P3 Low | 4 | .gitignore, hardcoded name strings, /proc/self/exe comment, O(n²) collision check |
| **Total** | **12** | |

## Removal/Iteration Plan

**Safe to remove now:**
- 42 duplicate entries in `python_builtins()` (`scramble.cpp`)
- Dead `key_trimmed` variable (`encrypt.cpp:1117-1119`)

**Follow-up with plan:**
- Replace `system()` with `posix_spawn()` in `obfuscate.cpp` (improves security posture)
- Extract obf pipeline ordering to a shared constant
- Build `all_*_names()` strings from lookup tables
- Add `.gitignore` entries for IDE/tool directories
