#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "switch/cli.hpp"
#include "switch/encrypt.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#ifdef _WIN32
// On Windows, _pclose() returns the exit code directly (no wait-status encoding).
#define WEXITSTATUS(s) (s)
#else
#include <sys/wait.h>
#endif

// Helper: create a temp file with content, returns path
static std::string create_temp_file(const std::string& content) {
    std::string path = "/tmp/switch_test_enc_" + std::to_string(std::rand()) + ".tmp";
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

// F08: RAII guard — removes file(s) on scope exit, even on test failure
struct TempFileGuard {
    std::vector<std::string> paths;
    ~TempFileGuard() { for (auto& p : paths) std::remove(p.c_str()); }
};

static const char* AES256_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

// =========================================================================
// CLI parse: --encrypt with valid args
// =========================================================================

TEST_CASE("cli parse: --encrypt aes-256 with key and input file") {
    const char* argv[] = {"switch", "--encrypt", "aes-256", "test.py",
                          "--key", AES256_KEY};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes256);
    REQUIRE(args->encrypt_key.has_value());
    CHECK(*args->encrypt_key == AES256_KEY);
    REQUIRE(args->positional.size() == 1);
    CHECK(args->positional[0] == "test.py");
}

TEST_CASE("cli parse: --encrypt aes-128") {
    const char* key = "000102030405060708090a0b0c0d0e0f";
    const char* argv[] = {"switch", "--encrypt", "aes-128", "in.py",
                          "--key", key};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes128);
}

TEST_CASE("cli parse: --encrypt aes-192") {
    const char* key = "000102030405060708090a0b0c0d0e0f1011121314151617";
    const char* argv[] = {"switch", "--encrypt", "aes-192", "in.py",
                          "--key", key};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes192);
}

TEST_CASE("cli parse: --encrypt chacha20") {
    const char* argv[] = {"switch", "--encrypt", "chacha20", "in.py",
                          "--key", AES256_KEY};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::ChaCha20);
}

TEST_CASE("cli parse: --encrypt ChaCha20 (mixed case)") {
    const char* argv[] = {"switch", "--encrypt", "ChaCha20", "in.py",
                          "--key", AES256_KEY};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::ChaCha20);
}

TEST_CASE("cli parse: --encrypt xchacha20") {
    const char* argv[] = {"switch", "--encrypt", "xchacha20", "in.py",
                          "--key", AES256_KEY};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::XChaCha20);
}

TEST_CASE("cli parse: --encrypt XChaCha20 (mixed case)") {
    const char* argv[] = {"switch", "--encrypt", "XChaCha20", "in.py",
                          "--key", AES256_KEY};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::XChaCha20);
}

TEST_CASE("cli parse: --encrypt xchacha20 with --nonce") {
    const char* nonce = "000000000000000000000000000000000000000000000000";
    const char* argv[] = {"switch", "--encrypt", "xchacha20", "in.py",
                          "--key", AES256_KEY, "--nonce", nonce};
    auto args = switch_cli::parse(8, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::XChaCha20);
    REQUIRE(args->encrypt_nonce.has_value());
    CHECK(*args->encrypt_nonce == nonce);
}

TEST_CASE("cli parse: --encrypt aes-256-gcm") {
    const char* argv[] = {"switch", "--encrypt", "aes-256-gcm", "in.py",
                          "--key", AES256_KEY};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes256Gcm);
}

TEST_CASE("cli parse: --encrypt AES-256-GCM (mixed case)") {
    const char* argv[] = {"switch", "--encrypt", "AES-256-GCM", "in.py",
                          "--key", AES256_KEY};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes256Gcm);
}

TEST_CASE("cli parse: --encrypt aes-128-gcm") {
    const char* key = "000102030405060708090a0b0c0d0e0f";
    const char* argv[] = {"switch", "--encrypt", "aes-128-gcm", "in.py",
                          "--key", key};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes128Gcm);
}

TEST_CASE("cli parse: --encrypt aes-192-gcm") {
    const char* key = "000102030405060708090a0b0c0d0e0f1011121314151617";
    const char* argv[] = {"switch", "--encrypt", "aes-192-gcm", "in.py",
                          "--key", key};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes192Gcm);
}

TEST_CASE("cli parse: --encrypt aes-128-ccm") {
    const char* key = "000102030405060708090a0b0c0d0e0f";
    const char* argv[] = {"switch", "--encrypt", "aes-128-ccm", "in.py",
                          "--key", key};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes128Ccm);
}

TEST_CASE("cli parse: --encrypt aes-192-ccm") {
    const char* key = "000102030405060708090a0b0c0d0e0f1011121314151617";
    const char* argv[] = {"switch", "--encrypt", "aes-192-ccm", "in.py",
                          "--key", key};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes192Ccm);
}

TEST_CASE("cli parse: --encrypt aes-256-ccm") {
    const char* argv[] = {"switch", "--encrypt", "aes-256-ccm", "in.py",
                          "--key", AES256_KEY};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes256Ccm);
}

TEST_CASE("cli parse: --encrypt aes-128-siv") {
    const char* key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
    const char* argv[] = {"switch", "--encrypt", "aes-128-siv", "in.py",
                          "--key", key};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes128Siv);
}

TEST_CASE("cli parse: --encrypt aes-256-siv") {
    const char* key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f";
    const char* argv[] = {"switch", "--encrypt", "aes-256-siv", "in.py",
                          "--key", key};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes256Siv);
}

TEST_CASE("cli parse: --encrypt aes-128-ocb") {
    const char* key = "000102030405060708090a0b0c0d0e0f";
    const char* argv[] = {"switch", "--encrypt", "aes-128-ocb", "in.py",
                          "--key", key};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes128Ocb);
}

TEST_CASE("cli parse: --encrypt aes-192-ocb") {
    const char* key = "000102030405060708090a0b0c0d0e0f1011121314151617";
    const char* argv[] = {"switch", "--encrypt", "aes-192-ocb", "in.py",
                          "--key", key};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes192Ocb);
}

TEST_CASE("cli parse: --encrypt aes-256-ocb") {
    const char* argv[] = {"switch", "--encrypt", "aes-256-ocb", "in.py",
                          "--key", AES256_KEY};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(args->encrypt_type == switch_encrypt::EncryptType::Aes256Ocb);
}

TEST_CASE("cli parse: --encrypt aes-256-gcm with --iv (12 bytes)") {
    const char* iv = "000000000000000000000000";
    const char* argv[] = {"switch", "--encrypt", "aes-256-gcm", "in.py",
                          "--key", AES256_KEY, "--iv", iv};
    auto args = switch_cli::parse(8, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    REQUIRE(args->encrypt_iv.has_value());
    CHECK(*args->encrypt_iv == iv);
}

TEST_CASE("cli parse: --encrypt chacha20 with --nonce") {
    const char* nonce = "000000000000000000000000";
    const char* argv[] = {"switch", "--encrypt", "chacha20", "in.py",
                          "--key", AES256_KEY, "--nonce", nonce};
    auto args = switch_cli::parse(8, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    REQUIRE(args->encrypt_nonce.has_value());
    CHECK(*args->encrypt_nonce == nonce);
}

TEST_CASE("cli parse: --encrypt case-insensitive (AES-256, AES256)") {
    const char* argv1[] = {"switch", "--encrypt", "AES-256", "f.py",
                           "--key", AES256_KEY};
    auto args1 = switch_cli::parse(6, argv1);
    REQUIRE(args1.has_value());
    CHECK(args1->encrypt_type == switch_encrypt::EncryptType::Aes256);

    const char* argv2[] = {"switch", "--encrypt", "AES256", "f.py",
                           "--key", AES256_KEY};
    auto args2 = switch_cli::parse(6, argv2);
    REQUIRE(args2.has_value());
    CHECK(args2->encrypt_type == switch_encrypt::EncryptType::Aes256);
}

TEST_CASE("cli parse: --encrypt with -o output") {
    const char* argv[] = {"switch", "--encrypt", "aes-256", "in.py",
                          "--key", AES256_KEY, "-o", "out.py"};
    auto args = switch_cli::parse(8, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    REQUIRE(args->output_file.has_value());
    CHECK(*args->output_file == "out.py");
}

TEST_CASE("cli parse: --encrypt with --iv") {
    const char* iv = "00000000000000000000000000000000";
    const char* argv[] = {"switch", "--encrypt", "aes-256", "in.py",
                          "--key", AES256_KEY, "--iv", iv};
    auto args = switch_cli::parse(8, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    REQUIRE(args->encrypt_iv.has_value());
    CHECK(*args->encrypt_iv == iv);
}

// =========================================================================
// CLI parse: --encrypt error cases
// =========================================================================

TEST_CASE("cli parse: --encrypt without type returns nullopt") {
    const char* argv[] = {"switch", "--encrypt"};
    auto args = switch_cli::parse(2, argv);
    CHECK(args == std::nullopt);
}

TEST_CASE("cli parse: --encrypt with unknown type returns nullopt") {
    const char* argv[] = {"switch", "--encrypt", "aes-512", "test.py",
                          "--key", AES256_KEY};
    auto args = switch_cli::parse(6, argv);
    CHECK(args == std::nullopt);
}

TEST_CASE("cli parse: --encrypt without --key still parses (key checked in main)") {
    const char* argv[] = {"switch", "--encrypt", "aes-256", "test.py"};
    auto args = switch_cli::parse(4, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    CHECK(!args->encrypt_key.has_value());
}

TEST_CASE("cli parse: --key without value returns nullopt") {
    const char* argv[] = {"switch", "--encrypt", "aes-256", "test.py", "--key"};
    auto args = switch_cli::parse(5, argv);
    CHECK(args == std::nullopt);
}

TEST_CASE("cli parse: --iv without value returns nullopt") {
    const char* argv[] = {"switch", "--encrypt", "aes-256", "test.py",
                          "--key", AES256_KEY, "--iv"};
    auto args = switch_cli::parse(7, argv);
    CHECK(args == std::nullopt);
}

TEST_CASE("cli parse: --key-file sets encrypt_key_file") {
    const char* argv[] = {"switch", "--encrypt", "aes-256", "test.py",
                          "--key-file", "/path/to/key.hex"};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    REQUIRE(args->encrypt_key_file.has_value());
    CHECK(*args->encrypt_key_file == "/path/to/key.hex");
    CHECK(!args->encrypt_key.has_value());
}

TEST_CASE("cli parse: --key-env sets encrypt_key_env") {
    const char* argv[] = {"switch", "--encrypt", "aes-256", "test.py",
                          "--key-env", "MY_SECRET_KEY"};
    auto args = switch_cli::parse(6, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encrypt);
    REQUIRE(args->encrypt_key_env.has_value());
    CHECK(*args->encrypt_key_env == "MY_SECRET_KEY");
}

TEST_CASE("cli parse: --key-file without value returns nullopt") {
    const char* argv[] = {"switch", "--encrypt", "aes-256", "test.py",
                          "--key-file"};
    auto args = switch_cli::parse(5, argv);
    CHECK(args == std::nullopt);
}

TEST_CASE("cli parse: --key-env without value returns nullopt") {
    const char* argv[] = {"switch", "--encrypt", "aes-256", "test.py",
                          "--key-env"};
    auto args = switch_cli::parse(5, argv);
    CHECK(args == std::nullopt);
}

TEST_CASE("cli parse: --encrypt chacha20 with --iv returns error") {
    const char* iv = "00000000000000000000000000000000";
    const char* argv[] = {"switch", "--encrypt", "chacha20", "in.py",
                          "--key", AES256_KEY, "--iv", iv};
    auto args = switch_cli::parse(8, argv);
    CHECK(args == std::nullopt);
}

TEST_CASE("cli parse: --encrypt aes-256 with --nonce returns error") {
    const char* nonce = "000000000000000000000000";
    const char* argv[] = {"switch", "--encrypt", "aes-256", "in.py",
                          "--key", AES256_KEY, "--nonce", nonce};
    auto args = switch_cli::parse(8, argv);
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

TEST_CASE("cli parse: --encode still works") {
    const char* argv[] = {"switch", "--encode", "base32", "test.py"};
    auto args = switch_cli::parse(4, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::Encode);
}

// =========================================================================
// encrypt_file end-to-end: output is self-decryptable Python
// =========================================================================

TEST_CASE("encrypt_file e2e: AES-256 output is runnable Python") {
    std::string input_path = create_temp_file("print('hello from switch encrypted')\n");
    std::string output_path = "/tmp/switch_test_enc_e2e_aes256.py";
    TempFileGuard guard{{input_path, output_path}};

    auto key = switch_encrypt::hex_to_bytes(AES256_KEY);
    auto iv  = switch_encrypt::hex_to_bytes("00000000000000000000000000000000");

    std::string error;
    bool ok = switch_encrypt::encrypt_file(
        switch_encrypt::EncryptType::Aes256, input_path, output_path,
        *key, *iv, error);
    INFO("error: ", error);
    REQUIRE(ok == true);

    // Verify wrapper structure
    std::string output = read_file(output_path);
    CHECK(output.find("# Encrypted by Switch") != std::string::npos);
    CHECK(output.find("from cryptography") != std::string::npos);
    CHECK(output.find("_ct") != std::string::npos);
    CHECK(output.find("_key") != std::string::npos);
    CHECK(output.find("_iv") != std::string::npos);
    CHECK(output.find("exec(") != std::string::npos);

    // Verify runnable: python output.py should print "hello from switch encrypted"
    std::string cmd = "python3 " + output_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    char buf[256] = {};
    std::string py_output;
    while (fgets(buf, sizeof(buf), pipe)) py_output += buf;
    int rc = pclose(pipe);
    INFO("python output: ", py_output);
    CHECK(WEXITSTATUS(rc) == 0);
    CHECK(py_output.find("hello from switch encrypted") != std::string::npos);
}

TEST_CASE("encrypt_file e2e: AES-128 output runnable with python") {
    std::string input_path = create_temp_file("x = 42; print('answer:', x)\n");
    std::string output_path = "/tmp/switch_test_enc_e2e_aes128.py";
    TempFileGuard guard{{input_path, output_path}};

    auto key = switch_encrypt::hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    auto iv  = switch_encrypt::hex_to_bytes("00000000000000000000000000000000");

    std::string error;
    bool ok = switch_encrypt::encrypt_file(
        switch_encrypt::EncryptType::Aes128, input_path, output_path,
        *key, *iv, error);
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
}

TEST_CASE("encrypt_file e2e: all three AES types produce runnable Python") {
    std::string input_path = create_temp_file("print('aes_ok')\n");
    std::string output_path = "/tmp/switch_test_enc_e2e_3types.py";
    TempFileGuard guard{{input_path, output_path}};

    auto key128 = switch_encrypt::hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    auto key192 = switch_encrypt::hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
    auto key256 = switch_encrypt::hex_to_bytes(AES256_KEY);
    auto iv     = switch_encrypt::hex_to_bytes("00000000000000000000000000000000");

    struct TestCase {
        switch_encrypt::EncryptType type;
        const std::vector<uint8_t>& key;
    };

    std::vector<TestCase> tests = {
        {switch_encrypt::EncryptType::Aes128, *key128},
        {switch_encrypt::EncryptType::Aes192, *key192},
        {switch_encrypt::EncryptType::Aes256, *key256},
    };

    for (auto& tc : tests) {
        std::string error;
        bool ok = switch_encrypt::encrypt_file(tc.type, input_path, output_path,
                                                tc.key, *iv, error);
        INFO("error for ", switch_encrypt::encrypt_type_name(tc.type), ": ", error);
        REQUIRE(ok == true);

        // Run it with python
        std::string cmd = "python3 " + output_path + " 2>&1";
        FILE* pipe = popen(cmd.c_str(), "r");
        REQUIRE(pipe != nullptr);
        char buf[128] = {};
        std::string py_output;
        while (fgets(buf, sizeof(buf), pipe)) py_output += buf;
        int rc = pclose(pipe);
        INFO("python output for ", switch_encrypt::encrypt_type_name(tc.type), ": ", py_output);
        CHECK(WEXITSTATUS(rc) == 0);
        CHECK(py_output.find("aes_ok") != std::string::npos);
    }
}

TEST_CASE("encrypt_file e2e: empty input produces runnable Python") {
    std::string input_path = create_temp_file("");
    std::string output_path = "/tmp/switch_test_enc_e2e_empty.py";
    TempFileGuard guard{{input_path, output_path}};

    // F09: Use correct-length keys for each AES variant
    auto key128 = switch_encrypt::hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    auto key192 = switch_encrypt::hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
    auto key256 = switch_encrypt::hex_to_bytes(AES256_KEY);
    auto iv     = switch_encrypt::hex_to_bytes("00000000000000000000000000000000");

    struct TestCase {
        switch_encrypt::EncryptType type;
        const std::vector<uint8_t>& key;
    };

    std::vector<TestCase> tests = {
        {switch_encrypt::EncryptType::Aes128, *key128},
        {switch_encrypt::EncryptType::Aes192, *key192},
        {switch_encrypt::EncryptType::Aes256, *key256},
    };

    for (auto& tc : tests) {
        std::string error;
        bool ok = switch_encrypt::encrypt_file(tc.type, input_path, output_path,
                                                tc.key, *iv, error);
        INFO("error for ", switch_encrypt::encrypt_type_name(tc.type), ": ", error);
        REQUIRE(ok == true);

        // F09: Run — should exit 0 with no output
        std::string cmd = "python3 " + output_path + " 2>&1";
        FILE* pipe = popen(cmd.c_str(), "r");
        REQUIRE(pipe != nullptr);
        char buf[256] = {};
        std::string py_output;
        while (fgets(buf, sizeof(buf), pipe)) py_output += buf;
        int rc = pclose(pipe);
        INFO("python output for ", switch_encrypt::encrypt_type_name(tc.type), ": ", py_output);
        CHECK(WEXITSTATUS(rc) == 0);
        CHECK(py_output.empty());
    }
}

TEST_CASE("encrypt_file e2e: ChaCha20-Poly1305 output is runnable Python") {
    std::string input_path = create_temp_file("print('hello from chacha20')\n");
    std::string output_path = "/tmp/switch_test_enc_e2e_chacha20.py";
    TempFileGuard guard{{input_path, output_path}};

    auto key = switch_encrypt::hex_to_bytes(AES256_KEY);
    auto nonce = switch_encrypt::hex_to_bytes("000000000000000000000000");

    std::string error;
    bool ok = switch_encrypt::encrypt_file(
        switch_encrypt::EncryptType::ChaCha20, input_path, output_path,
        *key, *nonce, error);
    INFO("error: ", error);
    REQUIRE(ok == true);

    // Verify wrapper structure
    std::string output = read_file(output_path);
    CHECK(output.find("# Encrypted by Switch") != std::string::npos);
    CHECK(output.find("ChaCha20Poly1305") != std::string::npos);
    CHECK(output.find("exec(") != std::string::npos);

    // Verify runnable
    std::string cmd = "python3 " + output_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    char buf[256] = {};
    std::string py_output;
    while (fgets(buf, sizeof(buf), pipe)) py_output += buf;
    int rc = pclose(pipe);
    INFO("python output: ", py_output);
    CHECK(WEXITSTATUS(rc) == 0);
    CHECK(py_output.find("hello from chacha20") != std::string::npos);
}

TEST_CASE("encrypt_file e2e: XChaCha20-Poly1305 output is runnable Python") {
    std::string input_path = create_temp_file("print('hello from xchacha20')\n");
    std::string output_path = "/tmp/switch_test_enc_e2e_xchacha20.py";
    TempFileGuard guard{{input_path, output_path}};

    auto key = switch_encrypt::hex_to_bytes(AES256_KEY);
    auto nonce = switch_encrypt::hex_to_bytes("000000000000000000000000000000000000000000000000");

    std::string error;
    bool ok = switch_encrypt::encrypt_file(
        switch_encrypt::EncryptType::XChaCha20, input_path, output_path,
        *key, *nonce, error);
    INFO("error: ", error);
    REQUIRE(ok == true);

    // Verify wrapper structure
    std::string output = read_file(output_path);
    CHECK(output.find("# Encrypted by Switch") != std::string::npos);
    CHECK(output.find("nacl") != std::string::npos);  // XChaCha20 uses nacl._sodium
    CHECK(output.find("exec(") != std::string::npos);

    // Verify runnable
    std::string cmd = "python3 " + output_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    char buf[256] = {};
    std::string py_output;
    while (fgets(buf, sizeof(buf), pipe)) py_output += buf;
    int rc = pclose(pipe);
    INFO("python output: ", py_output);
    CHECK(WEXITSTATUS(rc) == 0);
    CHECK(py_output.find("hello from xchacha20") != std::string::npos);
}

TEST_CASE("encrypt_file e2e: AES-256-GCM output is runnable Python") {
    std::string input_path = create_temp_file("print('hello from aes-gcm')\n");
    std::string output_path = "/tmp/switch_test_enc_e2e_aesgcm.py";
    TempFileGuard guard{{input_path, output_path}};

    auto key = switch_encrypt::hex_to_bytes(AES256_KEY);
    auto iv  = switch_encrypt::hex_to_bytes("000000000000000000000000");

    std::string error;
    bool ok = switch_encrypt::encrypt_file(
        switch_encrypt::EncryptType::Aes256Gcm, input_path, output_path,
        *key, *iv, error);
    INFO("error: ", error);
    REQUIRE(ok == true);

    // Verify wrapper structure
    std::string output = read_file(output_path);
    CHECK(output.find("# Encrypted by Switch") != std::string::npos);
    CHECK(output.find("AESGCM") != std::string::npos);
    CHECK(output.find("exec(") != std::string::npos);

    // Verify runnable
    std::string cmd = "python3 " + output_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    char buf[256] = {};
    std::string py_output;
    while (fgets(buf, sizeof(buf), pipe)) py_output += buf;
    int rc = pclose(pipe);
    INFO("python output: ", py_output);
    CHECK(WEXITSTATUS(rc) == 0);
    CHECK(py_output.find("hello from aes-gcm") != std::string::npos);
}

TEST_CASE("encrypt_file e2e: AES-256-CCM output is runnable Python") {
    std::string input_path = create_temp_file("print('hello from aes-ccm')\n");
    std::string output_path = "/tmp/switch_test_enc_e2e_aesccm.py";
    TempFileGuard guard{{input_path, output_path}};

    auto key = switch_encrypt::hex_to_bytes(AES256_KEY);
    auto nonce = switch_encrypt::hex_to_bytes("000000000000000000000000");

    std::string error;
    bool ok = switch_encrypt::encrypt_file(
        switch_encrypt::EncryptType::Aes256Ccm, input_path, output_path,
        *key, *nonce, error);
    INFO("error: ", error);
    REQUIRE(ok == true);

    // Verify wrapper structure
    std::string output = read_file(output_path);
    CHECK(output.find("# Encrypted by Switch") != std::string::npos);
    CHECK(output.find("AESCCM") != std::string::npos);
    CHECK(output.find("exec(") != std::string::npos);

    // Verify runnable
    std::string cmd = "python3 " + output_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    char buf[256] = {};
    std::string py_output;
    while (fgets(buf, sizeof(buf), pipe)) py_output += buf;
    int rc = pclose(pipe);
    INFO("python output: ", py_output);
    CHECK(WEXITSTATUS(rc) == 0);
    CHECK(py_output.find("hello from aes-ccm") != std::string::npos);
}

TEST_CASE("encrypt_file e2e: AES-256-SIV output is runnable Python") {
    std::string input_path = create_temp_file("print('hello from aes-siv')\n");
    std::string output_path = "/tmp/switch_test_enc_e2e_aessiv.py";
    TempFileGuard guard{{input_path, output_path}};

    // 32-byte key = 16 CMAC + 16 CTR
    auto key = switch_encrypt::hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    std::string error;
    bool ok = switch_encrypt::encrypt_file(
        switch_encrypt::EncryptType::Aes256Siv, input_path, output_path,
        *key, {}, error);
    INFO("error: ", error);
    REQUIRE(ok == true);

    // Verify wrapper structure
    std::string output = read_file(output_path);
    CHECK(output.find("# Encrypted by Switch") != std::string::npos);
    CHECK(output.find("_s2v") != std::string::npos);  // custom SIV implementation
    CHECK(output.find("exec(") != std::string::npos);

    // Verify runnable
    std::string cmd = "python3 " + output_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    char buf[256] = {};
    std::string py_output;
    while (fgets(buf, sizeof(buf), pipe)) py_output += buf;
    int rc = pclose(pipe);
    INFO("python output: ", py_output);
    CHECK(WEXITSTATUS(rc) == 0);
    CHECK(py_output.find("hello from aes-siv") != std::string::npos);
}

TEST_CASE("encrypt_file e2e: AES-256-OCB output is runnable Python") {
    std::string input_path = create_temp_file("print('hello from aes-ocb')\n");
    std::string output_path = "/tmp/switch_test_enc_e2e_aesocb.py";
    TempFileGuard guard{{input_path, output_path}};

    auto key = switch_encrypt::hex_to_bytes(AES256_KEY);
    auto iv  = switch_encrypt::hex_to_bytes("000000000000000000000000");

    std::string error;
    bool ok = switch_encrypt::encrypt_file(
        switch_encrypt::EncryptType::Aes256Ocb, input_path, output_path,
        *key, *iv, error);
    INFO("error: ", error);
    REQUIRE(ok == true);

    // Verify wrapper structure
    std::string output = read_file(output_path);
    CHECK(output.find("# Encrypted by Switch") != std::string::npos);
    CHECK(output.find("AESOCB3") != std::string::npos);
    CHECK(output.find("exec(") != std::string::npos);

    // Verify runnable
    std::string cmd = "python3 " + output_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    char buf[256] = {};
    std::string py_output;
    while (fgets(buf, sizeof(buf), pipe)) py_output += buf;
    int rc = pclose(pipe);
    INFO("python output: ", py_output);
    CHECK(WEXITSTATUS(rc) == 0);
    CHECK(py_output.find("hello from aes-ocb") != std::string::npos);
}

// =========================================================================
// --key-file and --key-env e2e tests
// =========================================================================

TEST_CASE("e2e: --key-file reads key from file and encrypts") {
    // Create key file
    std::string keyfile = "/tmp/switch_test_keyfile.hex";
    std::ofstream kf(keyfile);
    kf << AES256_KEY;
    kf.close();

    // Create input
    std::string input = create_temp_file("print('hello from keyfile')\n");
    std::string output = "/tmp/switch_test_e2e_keyfile.py";
    TempFileGuard guard{{input, output, keyfile}};

    // Run CLI with --key-file
    std::string cmd = "/home/ngquanghuy/Switch/build/switch --encrypt aes-256 " + input
                    + " --key-file " + keyfile
                    + " -o " + output + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    char buf[256] = {};
    std::string cli_output;
    while (fgets(buf, sizeof(buf), pipe)) cli_output += buf;
    int rc = pclose(pipe);
    CHECK(WEXITSTATUS(rc) == 0);
    CHECK(cli_output.find("Encrypted") != std::string::npos);

    // Verify output runs
    std::string run_cmd = "python3 " + output + " 2>&1";
    FILE* pipe2 = popen(run_cmd.c_str(), "r");
    REQUIRE(pipe2 != nullptr);
    std::string py_output;
    while (fgets(buf, sizeof(buf), pipe2)) py_output += buf;
    int rc2 = pclose(pipe2);
    CHECK(WEXITSTATUS(rc2) == 0);
    CHECK(py_output.find("hello from keyfile") != std::string::npos);
}

TEST_CASE("e2e: --key-file with whitespace-stripped key") {
    // Create key file with spaces and newlines
    std::string keyfile = "/tmp/switch_test_keyfile_ws.hex";
    std::ofstream kf(keyfile);
    kf << "0001 0203 0405 0607 0809 0a0b 0c0d 0e0f\n"
       << "1011 1213 1415 1617 1819 1a1b 1c1d 1e1f\n";
    kf.close();

    std::string input = create_temp_file("print('ws key')\n");
    std::string output = "/tmp/switch_test_e2e_keyfile_ws.py";
    TempFileGuard guard{{input, output, keyfile}};

    std::string cmd = "/home/ngquanghuy/Switch/build/switch --encrypt aes-256 " + input
                    + " --key-file " + keyfile
                    + " -o " + output + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    char buf[256] = {};
    std::string cli_output;
    while (fgets(buf, sizeof(buf), pipe)) cli_output += buf;
    int rc = pclose(pipe);
    CHECK(WEXITSTATUS(rc) == 0);

    // Verify output runs
    std::string run_cmd = "python3 " + output + " 2>&1";
    FILE* pipe2 = popen(run_cmd.c_str(), "r");
    std::string py_output;
    while (fgets(buf, sizeof(buf), pipe2)) py_output += buf;
    pclose(pipe2);
    CHECK(py_output.find("ws key") != std::string::npos);
}

TEST_CASE("e2e: --key-env reads key from environment variable") {
    std::string input = create_temp_file("print('hello from envkey')\n");
    std::string output = "/tmp/switch_test_e2e_keyenv.py";
    TempFileGuard guard{{input, output}};

    std::string cmd = "MY_AES_KEY=" + std::string(AES256_KEY)
                    + " /home/ngquanghuy/Switch/build/switch --encrypt aes-256 " + input
                    + " --key-env MY_AES_KEY"
                    + " -o " + output + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    char buf[256] = {};
    std::string cli_output;
    while (fgets(buf, sizeof(buf), pipe)) cli_output += buf;
    int rc = pclose(pipe);
    CHECK(WEXITSTATUS(rc) == 0);
    CHECK(cli_output.find("Encrypted") != std::string::npos);

    // Verify output runs
    std::string run_cmd = "python3 " + output + " 2>&1";
    FILE* pipe2 = popen(run_cmd.c_str(), "r");
    std::string py_output;
    while (fgets(buf, sizeof(buf), pipe2)) py_output += buf;
    int rc2 = pclose(pipe2);
    CHECK(WEXITSTATUS(rc2) == 0);
    CHECK(py_output.find("hello from envkey") != std::string::npos);
}

TEST_CASE("e2e: --key-file nonexistent file fails") {
    std::string input = create_temp_file("print('test')\n");
    TempFileGuard guard{{input}};

    std::string cmd = "/home/ngquanghuy/Switch/build/switch --encrypt aes-256 " + input
                    + " --key-file /tmp/nonexistent_key_xxx.hex 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    char buf[256] = {};
    std::string cli_output;
    while (fgets(buf, sizeof(buf), pipe)) cli_output += buf;
    int rc = pclose(pipe);
    CHECK(WEXITSTATUS(rc) != 0);
    CHECK(cli_output.find("cannot open key file") != std::string::npos);
}

TEST_CASE("e2e: --key-env unset variable fails") {
    std::string input = create_temp_file("print('test')\n");
    TempFileGuard guard{{input}};

    std::string cmd = "/home/ngquanghuy/Switch/build/switch --encrypt aes-256 " + input
                    + " --key-env UNSET_VAR_XXXXX 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    char buf[256] = {};
    std::string cli_output;
    while (fgets(buf, sizeof(buf), pipe)) cli_output += buf;
    int rc = pclose(pipe);
    CHECK(WEXITSTATUS(rc) != 0);
    CHECK(cli_output.find("is not set") != std::string::npos);
}

TEST_CASE("e2e: --key-file wrong length key fails") {
    std::string keyfile = "/tmp/switch_test_keyfile_bad.hex";
    std::ofstream kf(keyfile);
    kf << "00010203";  // only 4 bytes, need 32 for aes-256
    kf.close();

    std::string input = create_temp_file("print('test')\n");
    TempFileGuard guard{{input, keyfile}};

    std::string cmd = "/home/ngquanghuy/Switch/build/switch --encrypt aes-256 " + input
                    + " --key-file " + keyfile + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    char buf[256] = {};
    std::string cli_output;
    while (fgets(buf, sizeof(buf), pipe)) cli_output += buf;
    int rc = pclose(pipe);
    CHECK(WEXITSTATUS(rc) != 0);
    CHECK(cli_output.find("key must be") != std::string::npos);
}

TEST_CASE("e2e: --key and --key-file mutually exclusive") {
    std::string input = create_temp_file("print('test')\n");
    TempFileGuard guard{{input}};

    std::string cmd = "/home/ngquanghuy/Switch/build/switch --encrypt aes-256 " + input
                    + " --key " + AES256_KEY
                    + " --key-file /tmp/some.key 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    char buf[256] = {};
    std::string cli_output;
    while (fgets(buf, sizeof(buf), pipe)) cli_output += buf;
    int rc = pclose(pipe);
    CHECK(WEXITSTATUS(rc) != 0);
    CHECK(cli_output.find("mutually exclusive") != std::string::npos);
}

TEST_CASE("encrypt_file e2e: nonexistent input path fails") {
    auto key = switch_encrypt::hex_to_bytes(AES256_KEY);
    auto iv  = switch_encrypt::hex_to_bytes("00000000000000000000000000000000");
    std::string error;
    bool ok = switch_encrypt::encrypt_file(
        switch_encrypt::EncryptType::Aes256,
        "/tmp/switch_nonexistent_file_xyz123.tmp",
        "/tmp/switch_output.tmp",
        *key, *iv, error);
    CHECK(ok == false);
    CHECK(error.find("cannot open") != std::string::npos);
}

// =========================================================================
// --key-generator: generate_key unit tests
// =========================================================================

TEST_CASE("generate_key: returns correct-length hex for each type") {
    // AES-128: 16 bytes → 32 hex chars
    std::string key128 = switch_encrypt::generate_key(switch_encrypt::EncryptType::Aes128);
    CHECK(key128.size() == 32);
    CHECK(switch_encrypt::hex_to_bytes(key128).has_value());

    // AES-192: 24 bytes → 48 hex chars
    std::string key192 = switch_encrypt::generate_key(switch_encrypt::EncryptType::Aes192);
    CHECK(key192.size() == 48);
    CHECK(switch_encrypt::hex_to_bytes(key192).has_value());

    // AES-256: 32 bytes → 64 hex chars
    std::string key256 = switch_encrypt::generate_key(switch_encrypt::EncryptType::Aes256);
    CHECK(key256.size() == 64);
    CHECK(switch_encrypt::hex_to_bytes(key256).has_value());

    // ChaCha20: 32 bytes → 64 hex chars
    std::string keych = switch_encrypt::generate_key(switch_encrypt::EncryptType::ChaCha20);
    CHECK(keych.size() == 64);
    CHECK(switch_encrypt::hex_to_bytes(keych).has_value());
}

TEST_CASE("generate_key: generated key produces valid encrypt/decrypt round-trip") {
    for (auto type : {switch_encrypt::EncryptType::Aes128,
                      switch_encrypt::EncryptType::Aes192,
                      switch_encrypt::EncryptType::Aes256,
                      switch_encrypt::EncryptType::ChaCha20}) {
        std::string key_hex = switch_encrypt::generate_key(type);
        auto key = switch_encrypt::hex_to_bytes(key_hex);
        REQUIRE(key.has_value());

        std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};
        std::vector<uint8_t> iv_or_nonce;
        if (switch_encrypt::is_stream_cipher(type)) {
            iv_or_nonce = switch_encrypt::generate_random_nonce(
                switch_encrypt::expected_nonce_len(type));
        } else {
            iv_or_nonce = switch_encrypt::generate_random_iv();
        }
        REQUIRE(!iv_or_nonce.empty());

        auto ct = switch_encrypt::encrypt(type, plaintext, *key, iv_or_nonce);
        REQUIRE(!ct.empty());

        auto pt = switch_encrypt::decrypt(type, ct, *key, iv_or_nonce);
        REQUIRE(pt == plaintext);
    }
}
