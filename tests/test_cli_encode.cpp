#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "switch/cli.hpp"
#include "switch/encode.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <sys/wait.h>

// Helper: create a temp file with content, returns path
static std::string create_temp_file(const std::string& content) {
    std::string path = "/tmp/switch_test_" + std::to_string(std::rand()) + ".tmp";
    std::ofstream out(path, std::ios::binary);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
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

TEST_CASE("cli parse: protect stub still works") {
    const char* argv[] = {"switch", "protect", "test.py"};
    auto args = switch_cli::parse(3, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Protect);
}

// =========================================================================
// encode_file end-to-end — output must be runnable Python
// =========================================================================

TEST_CASE("encode_file e2e: output is self-decodable Python wrapper") {
    std::string input_path = create_temp_file("print('hello from switch')\n");
    std::string output_path = "/tmp/switch_test_wrapper.py";

    std::string error;
    bool ok = switch_encode::encode_file(
        switch_encode::EncodeType::Base16, input_path, output_path, error);
    INFO("error: ", error);
    REQUIRE(ok == true);

    std::string output = read_file(output_path);
    CHECK(output.find("# Encoded by Switch") != std::string::npos);
    CHECK(output.find("import base64") != std::string::npos);
    CHECK(output.find("_sw") != std::string::npos);
    CHECK(output.find("exec(") != std::string::npos);

    // Verify runnable: python output.py should print "hello from switch"
    std::string cmd = "python3 " + output_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    char buf[256] = {};
    std::string py_output;
    while (fgets(buf, sizeof(buf), pipe)) py_output += buf;
    int rc = pclose(pipe);
    INFO("python output: ", py_output);
    CHECK(WEXITSTATUS(rc) == 0);
    CHECK(py_output.find("hello from switch") != std::string::npos);

    std::remove(input_path.c_str());
    std::remove(output_path.c_str());
}

TEST_CASE("encode_file e2e: base64 output runnable with python") {
    std::string input_path = create_temp_file("x = 42; print('answer:', x)\n");
    std::string output_path = "/tmp/switch_test_b64.py";

    std::string error;
    bool ok = switch_encode::encode_file(
        switch_encode::EncodeType::Base64, input_path, output_path, error);
    INFO("error: ", error);
    REQUIRE(ok == true);

    std::string cmd = "python3 " + output_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    char buf[256] = {};
    std::string py_output;
    while (fgets(buf, sizeof(buf), pipe)) py_output += buf;
    int rc = pclose(pipe);
    INFO("python output: ", py_output);
    CHECK(WEXITSTATUS(rc) == 0);
    CHECK(py_output.find("answer: 42") != std::string::npos);

    std::remove(input_path.c_str());
    std::remove(output_path.c_str());
}

TEST_CASE("encode_file e2e: all five types produce runnable Python") {
    std::string input_path = create_temp_file("print('ok')\n");
    std::string output_path = "/tmp/switch_test_5types.py";

    for (auto type : {switch_encode::EncodeType::Base16,
                      switch_encode::EncodeType::Base32,
                      switch_encode::EncodeType::Base58,
                      switch_encode::EncodeType::Base62,
                      switch_encode::EncodeType::Base64}) {
        std::string error;
        bool ok = switch_encode::encode_file(type, input_path, output_path, error);
        INFO("error for type ", switch_encode::encode_type_name(type), ": ", error);
        REQUIRE(ok == true);

        // Run it with python
        std::string cmd = "python3 " + output_path + " 2>&1";
        FILE* pipe = popen(cmd.c_str(), "r");
        REQUIRE(pipe != nullptr);
        char buf[128] = {};
        std::string py_output;
        while (fgets(buf, sizeof(buf), pipe)) py_output += buf;
        int rc = pclose(pipe);
        INFO("python output for ", switch_encode::encode_type_name(type), ": ", py_output);
        CHECK(WEXITSTATUS(rc) == 0);
        CHECK(py_output.find("ok") != std::string::npos);
    }

    std::remove(input_path.c_str());
    std::remove(output_path.c_str());
}

TEST_CASE("encode_file e2e: empty input produces runnable Python (no-op exec)") {
    std::string input_path = create_temp_file("");
    std::string output_path = "/tmp/switch_test_empty.py";

    // Test all 5 encodings with empty input — each must run without error
    for (auto type : {switch_encode::EncodeType::Base16,
                      switch_encode::EncodeType::Base32,
                      switch_encode::EncodeType::Base58,
                      switch_encode::EncodeType::Base62,
                      switch_encode::EncodeType::Base64}) {
        std::string error;
        bool ok = switch_encode::encode_file(type, input_path, output_path, error);
        INFO("error for type ", switch_encode::encode_type_name(type), ": ", error);
        REQUIRE(ok == true);

        std::string output = read_file(output_path);
        CHECK(!output.empty()); // wrapper is never empty
        CHECK(output.find("# Encoded by Switch") != std::string::npos);

        // Run — should exit 0 with no output
        std::string cmd = "python3 " + output_path + " 2>&1";
        int rc = std::system(cmd.c_str());
        CHECK(WEXITSTATUS(rc) == 0);
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