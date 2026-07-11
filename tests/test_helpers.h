#pragma once

// Shared test helpers for all test binaries.
// Eliminates duplication of create_temp_file, read_file, run_python, is_valid_python.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#ifdef _WIN32
// On Windows, _pclose() returns the exit code directly (no wait-status encoding).
#define WEXITSTATUS(s) (s)
#else
#include <sys/wait.h>
#endif

// ---------------------------------------------------------------------------
// RNG seeding
// ---------------------------------------------------------------------------

inline void seed_rng() {
    static bool seeded = [] { std::srand(static_cast<unsigned>(std::time(nullptr))); return true; }();
    (void)seeded;
}

// ---------------------------------------------------------------------------
// python3 availability (cached — only spawns subprocess once)
// ---------------------------------------------------------------------------

inline bool python3_available() {
    static bool available = system("python3 -c '' >/dev/null 2>&1") == 0;
    return available;
}

// ---------------------------------------------------------------------------
// Temp file helpers
// ---------------------------------------------------------------------------

inline std::string create_temp_file(const std::string& content,
                                    const std::string& prefix = "switch_test") {
    seed_rng();
    std::string path = "/tmp/" + prefix + "_" + std::to_string(std::rand()) + ".tmp";
    std::ofstream out(path, std::ios::binary);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    out.close();
    return path;
}

inline std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return {};
    std::streamsize size = in.tellg();
    in.seekg(0);
    std::string content(static_cast<size_t>(size), '\0');
    in.read(content.data(), size);
    return content;
}

// ---------------------------------------------------------------------------
// Python execution helpers
// ---------------------------------------------------------------------------

inline bool is_valid_python(const std::string& code) {
    std::string path = create_temp_file(code, "switch_valid");
    std::string cmd = "python3 -c \"compile(open('" + path + "').read(), '" + path + "', 'exec')\" 2>&1";
    int rc = system(cmd.c_str());
    std::remove(path.c_str());
    return rc == 0;
}

inline int run_python(const std::string& code, std::string& output,
                      const std::string& prefix = "switch_run") {
    std::string path = create_temp_file(code, prefix);
    std::string cmd = "python3 " + path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) { std::remove(path.c_str()); return -1; }
    char buf[4096];
    output.clear();
    while (fgets(buf, sizeof(buf), pipe)) output += buf;
    int rc = pclose(pipe);
    std::remove(path.c_str());
#ifdef _WIN32
    return rc;
#else
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;  // killed by signal
#endif
}

// ---------------------------------------------------------------------------
// RAII temp file guard (use for tests that create multiple temp files)
// ---------------------------------------------------------------------------

struct TempFileGuard {
    std::vector<std::string> paths;
    ~TempFileGuard() { for (auto& p : paths) std::remove(p.c_str()); }
};
