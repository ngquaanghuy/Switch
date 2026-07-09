#include "switch/obfuscate.hpp"

#include <cstdio>
#include <cstring>
#include <array>
#include <unistd.h>
#include <fcntl.h>

namespace switch_obf {

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
    return std::nullopt;
}

std::string_view obf_type_name(ObfType type) {
    switch (type) {
    case ObfType::NameMangling: return "namemangling";
    case ObfType::StringEncoding: return "stringencoding";
    }
    return "unknown";
}

std::string all_obf_names() {
    return "namemangling, stringencoding";
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

std::string obfuscate(ObfType type, const std::string& source) {
    if (source.empty()) return source;

    // Select script based on technique
    std::string script_name;
    switch (type) {
    case ObfType::NameMangling:  script_name = "obf_namemangling.py"; break;
    case ObfType::StringEncoding: script_name = "obf_stringencode.py"; break;
    }

    std::string script_path = find_script_path(script_name);
    if (script_path.empty()) {
        return ""; // script not found
    }

    // Build command: python3 <script> < /dev/stdin
    // We pipe source via popen with "w" mode, then read output
    std::string cmd = "python3 \"" + script_path + "\" 2>/dev/null";

    // Write source to script stdin, read obfuscated output
    // Use popen in "r+" mode doesn't work well. Instead:
    // Write to temp file, run script reading from it, capture output

    // Simple approach: use popen with a pipe
    // We'll write source to a temp file, run script, read output
    char tmp_in[] = "/tmp/switch_obf_in_XXXXXX";
    char tmp_out[] = "/tmp/switch_obf_out_XXXXXX";
    int fd_in = mkstemp(tmp_in);
    int fd_out = mkstemp(tmp_out);

    if (fd_in < 0 || fd_out < 0) {
        if (fd_in >= 0) { close(fd_in); unlink(tmp_in); }
        if (fd_out >= 0) { close(fd_out); unlink(tmp_out); }
        return "";
    }

    // Write source to temp input file
    write(fd_in, source.data(), source.size());
    close(fd_in);

    // Run Python script
    std::string run_cmd = "python3 \"" + script_path + "\" < \"" + tmp_in
                        + "\" > \"" + tmp_out + "\" 2>/dev/null";
    int rc = system(run_cmd.c_str());

    // Read output
    std::string result;
    if (rc == 0) {
        FILE* f = fopen(tmp_out, "r");
        if (f) {
            fseek(f, 0, SEEK_END);
            long fsize = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (fsize > 0) {
                result.resize(static_cast<size_t>(fsize));
                fread(result.data(), 1, static_cast<size_t>(fsize), f);
            }
            fclose(f);
        }
    }

    // Cleanup temp files
    unlink(tmp_in);
    unlink(tmp_out);

    return result;
}

} // namespace switch_obf
