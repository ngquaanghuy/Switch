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
    CHECK(output.find("from nacl") != std::string::npos);
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
// --key-generator: CLI parse
// =========================================================================

TEST_CASE("cli parse: --key-generator aes-256") {
    const char* argv[] = {"switch", "--key-generator", "aes-256"};
    auto args = switch_cli::parse(3, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::KeyGenerator);
    REQUIRE(args->key_gen_type.has_value());
    CHECK(*args->key_gen_type == switch_encrypt::EncryptType::Aes256);
}

TEST_CASE("cli parse: --key-generator chacha20") {
    const char* argv[] = {"switch", "--key-generator", "chacha20"};
    auto args = switch_cli::parse(3, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::KeyGenerator);
    CHECK(*args->key_gen_type == switch_encrypt::EncryptType::ChaCha20);
}

TEST_CASE("cli parse: --key-generator xchacha20") {
    const char* argv[] = {"switch", "--key-generator", "xchacha20"};
    auto args = switch_cli::parse(3, argv);
    REQUIRE(args.has_value());
    CHECK(args->cmd == switch_cli::Command::KeyGenerator);
    CHECK(*args->key_gen_type == switch_encrypt::EncryptType::XChaCha20);
}

TEST_CASE("cli parse: --key-generator case-insensitive") {
    const char* argv[] = {"switch", "--key-generator", "AES-192"};
    auto args = switch_cli::parse(3, argv);
    REQUIRE(args.has_value());
    CHECK(*args->key_gen_type == switch_encrypt::EncryptType::Aes192);
}

TEST_CASE("cli parse: --key-generator without type returns nullopt") {
    const char* argv[] = {"switch", "--key-generator"};
    auto args = switch_cli::parse(2, argv);
    CHECK(args == std::nullopt);
}

TEST_CASE("cli parse: --key-generator unknown type returns nullopt") {
    const char* argv[] = {"switch", "--key-generator", "aes-512"};
    auto args = switch_cli::parse(3, argv);
    CHECK(args == std::nullopt);
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
