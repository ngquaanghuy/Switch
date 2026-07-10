#include "switch/obfuscate.hpp"

#include <cstdio>
#include <cstring>
#include <array>
#include <unistd.h>
#include <fcntl.h>

namespace switch_obf {

// ---------------------------------------------------------------------------
// Python availability check (cached)
// ---------------------------------------------------------------------------

static bool python3_available() {
    static int cached = -1; // -1 = unchecked, 0 = unavailable, 1 = available
    if (cached >= 0) return cached == 1;
    cached = (system("python3 -c '' >/dev/null 2>&1") == 0) ? 1 : 0;
    if (!cached) {
        fprintf(stderr, "switch: python3 is not installed or not in PATH\n"
                        "switch: obfuscation requires Python 3.8+\n");
    }
    return cached == 1;
}

// ---------------------------------------------------------------------------
// Type resolution
// ---------------------------------------------------------------------------

std::optional<ObfType> parse_obf_type(std::string_view name) {
    // Case-insensitive comparison
    auto ieq = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            char ca = a[i], cb = b[i];
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cb >= 'A' && cb <= 'Z') cb += 32;
            if (ca != cb) return false;
        }
        return true;
    };

    if (ieq(name, "namemangling")) return ObfType::NameMangling;
    if (ieq(name, "stringencoding")) return ObfType::StringEncoding;
    if (ieq(name, "docstrip")) return ObfType::DocStrip;
    if (ieq(name, "literal")) return ObfType::Literal;
    if (ieq(name, "xorencoding")) return ObfType::XorEncoding;
    if (ieq(name, "importrewrite")) return ObfType::ImportRewrite;
    if (ieq(name, "deadcode")) return ObfType::DeadCode;
    return std::nullopt;
}

std::string_view obf_type_name(ObfType type) {
    switch (type) {
    case ObfType::NameMangling: return "namemangling";
    case ObfType::StringEncoding: return "stringencoding";
    case ObfType::DocStrip: return "docstrip";
    case ObfType::Literal: return "literal";
    case ObfType::XorEncoding: return "xorencoding";
    case ObfType::ImportRewrite: return "importrewrite";
    case ObfType::DeadCode: return "deadcode";
    }
    return "unknown";
}

std::string all_obf_names() {
    return "namemangling, stringencoding, docstrip, literal, xorencoding, importrewrite, deadcode";
}

// ---------------------------------------------------------------------------
// Python subprocess obfuscation
// ---------------------------------------------------------------------------

// Find the obfuscation script path.
static std::string find_script_path(const std::string& script_name) {
    // In development: script is at ../scripts/ relative to binary
    // Binary is at build/switch, script at scripts/obf_namemangling.py
    // We try relative to /proc/self/exe on Linux, or fallback to cwd-relative

    // Try to get binary directory from /proc/self/exe (Linux)
    char exe_path[4096] = {};
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        // Strip binary name to get directory
        char* last_slash = strrchr(exe_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            std::string bin_dir = exe_path;
            // Try <bin_dir>/../scripts/<script_name>
            std::string candidate = bin_dir + "/../scripts/" + script_name;
            FILE* f = fopen(candidate.c_str(), "r");
            if (f) {
                fclose(f);
                return candidate;
            }
        }
    }

    // Fallback: try from working directory
    FILE* f = fopen(("scripts/" + script_name).c_str(), "r");
    if (f) {
        fclose(f);
        return "scripts/" + script_name;
    }

    return "";
}

std::optional<std::string> obfuscate(ObfType type, const std::string& source) {
    if (source.empty()) return source;

    if (!python3_available()) return std::nullopt;

    // Select script based on technique
    std::string script_name;
    switch (type) {
    case ObfType::NameMangling:  script_name = "obf_namemangling.py"; break;
    case ObfType::StringEncoding: script_name = "obf_stringencode.py"; break;
    case ObfType::DocStrip: script_name = "obf_docstrip.py"; break;
    case ObfType::Literal: script_name = "obf_literal.py"; break;
    case ObfType::XorEncoding: script_name = "obf_xor.py"; break;
    case ObfType::ImportRewrite: script_name = "obf_importrewrite.py"; break;
    case ObfType::DeadCode: script_name = "obf_deadcode.py"; break;
    }

    std::string script_path = find_script_path(script_name);
    if (script_path.empty()) {
        return std::nullopt; // script not found
    }

    // Write source to temp input file, capture output + stderr
    char tmp_in[] = "/tmp/switch_obf_in_XXXXXX";
    char tmp_out[] = "/tmp/switch_obf_out_XXXXXX";
    char tmp_err[] = "/tmp/switch_obf_err_XXXXXX";
    int fd_in = mkstemp(tmp_in);
    int fd_out = mkstemp(tmp_out);
    int fd_err = mkstemp(tmp_err);

    if (fd_in < 0 || fd_out < 0 || fd_err < 0) {
        if (fd_in >= 0) { close(fd_in); unlink(tmp_in); }
        if (fd_out >= 0) { close(fd_out); unlink(tmp_out); }
        if (fd_err >= 0) { close(fd_err); unlink(tmp_err); }
        return std::nullopt;
    }

    // F3: Check write() return value for partial writes
    const char* src_ptr = source.data();
    size_t remaining = source.size();
    while (remaining > 0) {
        ssize_t written = write(fd_in, src_ptr, remaining);
        if (written <= 0) {
            close(fd_in); unlink(tmp_in);
            close(fd_out); unlink(tmp_out);
            close(fd_err); unlink(tmp_err);
            return std::nullopt;
        }
        src_ptr += written;
        remaining -= static_cast<size_t>(written);
    }
    close(fd_in);

    // Run Python script — capture stderr separately for diagnostics
    std::string run_cmd = "python3 \"" + script_path + "\" < \"" + tmp_in
                        + "\" > \"" + tmp_out + "\" 2>\"" + tmp_err + "\"";
    int rc = system(run_cmd.c_str());

    // Read stderr for error diagnostics (F6)
    std::string stderr_output;
    {
        FILE* f = fopen(tmp_err, "r");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (sz > 0) {
                stderr_output.resize(static_cast<size_t>(sz));
                size_t nread = fread(stderr_output.data(), 1, static_cast<size_t>(sz), f);
                stderr_output.resize(nread);
            }
            fclose(f);
        }
    }

    // Cleanup input and stderr temp files
    unlink(tmp_in);
    unlink(tmp_err);

    if (rc != 0) {
        unlink(tmp_out);
        // F6: Surface Python error output instead of silently discarding
        if (!stderr_output.empty()) {
            fprintf(stderr, "switch: python obfuscation error:\n%s\n", stderr_output.c_str());
        }
        return std::nullopt;
    }

    // F4: Check fread() return value and resize result to actual bytes read
    std::string result;
    {
        FILE* f = fopen(tmp_out, "r");
        if (!f) {
            unlink(tmp_out);
            return std::nullopt;
        }
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (fsize > 0) {
            result.resize(static_cast<size_t>(fsize));
            size_t nread = fread(result.data(), 1, static_cast<size_t>(fsize), f);
            result.resize(nread); // Trim to actual bytes read
        }
        fclose(f);
    }

    unlink(tmp_out);
    return result;
}

} // namespace switch_obf
