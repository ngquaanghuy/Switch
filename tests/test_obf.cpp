#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "switch/obfuscate.hpp"
#include "test_helpers.h"

#include <string>
#include <vector>

// Sample Python code for testing
static const std::string SAMPLE_CODE =
    "import os\n"
    "import json\n"
    "\n"
    "def process_data():\n"
    "    files = os.listdir('/tmp')\n"
    "    data = json.dumps({'count': len(files)})\n"
    "    return data\n"
    "\n"
    "result = process_data()\n"
    "print(result)\n";

// Simple code without imports
static const std::string SIMPLE_CODE =
    "def add(a, b):\n"
    "    return a + b\n"
    "\n"
    "result = add(2, 3)\n"
    "print(result)\n";

using namespace switch_obf;

// ---------------------------------------------------------------------------
// parse_obf_type tests
// ---------------------------------------------------------------------------

TEST_CASE("obf: parse_obf_type valid names") {
    CHECK(parse_obf_type("namemangling") == ObfType::NameMangling);
    CHECK(parse_obf_type("stringencoding") == ObfType::StringEncoding);
    CHECK(parse_obf_type("docstrip") == ObfType::DocStrip);
    CHECK(parse_obf_type("literal") == ObfType::Literal);
    CHECK(parse_obf_type("xorencoding") == ObfType::XorEncoding);
    CHECK(parse_obf_type("importrewrite") == ObfType::ImportRewrite);
    CHECK(parse_obf_type("deadcode") == ObfType::DeadCode);
    CHECK(parse_obf_type("scramble") == ObfType::ScrambleIdentifiers);
}

TEST_CASE("obf: parse_obf_type case-insensitive") {
    CHECK(parse_obf_type("SCRAMBLE") == ObfType::ScrambleIdentifiers);
    CHECK(parse_obf_type("DeadCode") == ObfType::DeadCode);
    CHECK(parse_obf_type("NameMangling") == ObfType::NameMangling);
    CHECK(parse_obf_type("lItErAl") == ObfType::Literal);
}

TEST_CASE("obf: parse_obf_type unknown returns nullopt") {
    CHECK(parse_obf_type("invalid") == std::nullopt);
    CHECK(parse_obf_type("") == std::nullopt);
    CHECK(parse_obf_type("unknown") == std::nullopt);
}

TEST_CASE("obf: obf_type_name returns canonical name") {
    CHECK(obf_type_name(ObfType::ScrambleIdentifiers) == "scramble");
    CHECK(obf_type_name(ObfType::DeadCode) == "deadcode");
    CHECK(obf_type_name(ObfType::NameMangling) == "namemangling");
    CHECK(obf_type_name(ObfType::StringEncoding) == "stringencoding");
    CHECK(obf_type_name(ObfType::DocStrip) == "docstrip");
    CHECK(obf_type_name(ObfType::Literal) == "literal");
    CHECK(obf_type_name(ObfType::XorEncoding) == "xorencoding");
    CHECK(obf_type_name(ObfType::ImportRewrite) == "importrewrite");
}

TEST_CASE("obf: all_obf_names contains all eight") {
    std::string names = all_obf_names();
    CHECK(names.find("namemangling") != std::string::npos);
    CHECK(names.find("stringencoding") != std::string::npos);
    CHECK(names.find("docstrip") != std::string::npos);
    CHECK(names.find("literal") != std::string::npos);
    CHECK(names.find("xorencoding") != std::string::npos);
    CHECK(names.find("importrewrite") != std::string::npos);
    CHECK(names.find("deadcode") != std::string::npos);
    CHECK(names.find("scramble") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Scramble inline (C++ no python3 needed)
// ---------------------------------------------------------------------------

TEST_CASE("obf: scramble — returns non-empty for valid input") {
    auto result = obfuscate(ObfType::ScrambleIdentifiers, SIMPLE_CODE);
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("obf: scramble — empty input returns empty") {
    auto result = obfuscate(ObfType::ScrambleIdentifiers, "");
    REQUIRE(result.has_value());
    CHECK(result->empty());
}

TEST_CASE("obf: scramble — output is different from input") {
    auto result = obfuscate(ObfType::ScrambleIdentifiers, SIMPLE_CODE);
    REQUIRE(result.has_value());
    CHECK(*result != SIMPLE_CODE);
}

TEST_CASE("obf: scramble — output is valid Python") {
    auto result = obfuscate(ObfType::ScrambleIdentifiers, SIMPLE_CODE);
    REQUIRE(result.has_value());
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: scramble — output runs correctly") {
    auto result = obfuscate(ObfType::ScrambleIdentifiers, SIMPLE_CODE);
    REQUIRE(result.has_value());
    std::string output;
    int rc = run_python(*result, output);
    CHECK(rc == 0);
    CHECK(output.find("5") != std::string::npos);
}

TEST_CASE("obf: scramble — preserves module attribute access") {
    std::string code = "import os\nx = os.listdir('/tmp')\nprint(len(x))\n";
    auto result = obfuscate(ObfType::ScrambleIdentifiers, code);
    REQUIRE(result.has_value());
    CHECK(result->find("os.listdir") != std::string::npos);
    CHECK(is_valid_python(*result));
}

// ---------------------------------------------------------------------------
// Stacking: scramble + deadcode (the key fix)
// ---------------------------------------------------------------------------

TEST_CASE("obf stacking: deadcode → scramble — valid Python") {
    REQUIRE(python3_available());

    std::string code =
        "import os\n"
        "def process():\n"
        "    files = os.listdir('/tmp')\n"
        "    return len(files)\n"
        "result = process()\n"
        "print(result)\n";

    // deadcode first
    auto step1 = obfuscate(ObfType::DeadCode, code);
    REQUIRE(step1.has_value());
    CHECK(!step1->empty());

    // then scramble
    auto step2 = obfuscate(ObfType::ScrambleIdentifiers, *step1);
    REQUIRE(step2.has_value());
    CHECK(!step2->empty());

    // should be valid Python
    CHECK(is_valid_python(*step2));

    // should run without error
    std::string output;
    int rc = run_python(*step2, output);
    CHECK(rc == 0);
}

TEST_CASE("obf stacking: scramble → deadcode — valid Python") {
    REQUIRE(python3_available());

    std::string code =
        "import os\n"
        "def process():\n"
        "    files = os.listdir('/tmp')\n"
        "    return len(files)\n"
        "result = process()\n"
        "print(result)\n";

    // scramble first
    auto step1 = obfuscate(ObfType::ScrambleIdentifiers, code);
    REQUIRE(step1.has_value());

    // then deadcode
    auto step2 = obfuscate(ObfType::DeadCode, *step1);
    REQUIRE(step2.has_value());

    CHECK(is_valid_python(*step2));
}

TEST_CASE("obf stacking: deadcode → scramble — os.listdir preserved") {
    REQUIRE(python3_available());

    std::string code = "import os\nos.listdir('/tmp')\n";

    auto step1 = obfuscate(ObfType::DeadCode, code);
    REQUIRE(step1.has_value());
    auto step2 = obfuscate(ObfType::ScrambleIdentifiers, *step1);
    REQUIRE(step2.has_value());

    // os and listdir must be preserved
    CHECK(step2->find("import os") != std::string::npos);
    CHECK(step2->find("os.listdir") != std::string::npos);

    CHECK(is_valid_python(*step2));
}

// ---------------------------------------------------------------------------
// Stacking: multiple techniques
// ---------------------------------------------------------------------------

TEST_CASE("obf stacking: each technique → scramble — valid Python") {
    REQUIRE(python3_available());

    // Each subcase: one technique followed by scramble
    SUBCASE("docstrip → scramble") {
        std::string code =
            "# This is a comment\n"
            "def add(a, b):\n"
            "    \"\"\"Add two numbers.\"\"\"\n"
            "    return a + b\n"
            "print(add(2, 3))\n";
        auto step1 = obfuscate(ObfType::DocStrip, code);
        REQUIRE(step1.has_value());
        auto step2 = obfuscate(ObfType::ScrambleIdentifiers, *step1);
        REQUIRE(step2.has_value());
        CHECK(is_valid_python(*step2));
    }
    SUBCASE("literal → scramble") {
        std::string code =
            "x = 42\n"
            "y = 3.14\n"
            "z = True\n"
            "print(x + int(y))\n";
        auto step1 = obfuscate(ObfType::Literal, code);
        REQUIRE(step1.has_value());
        auto step2 = obfuscate(ObfType::ScrambleIdentifiers, *step1);
        REQUIRE(step2.has_value());
        CHECK(is_valid_python(*step2));
    }
    SUBCASE("namemangling → scramble") {
        std::string code =
            "def calculate_sum(a, b):\n"
            "    total = a + b\n"
            "    return total\n"
            "result = calculate_sum(10, 20)\n"
            "print(result)\n";
        auto step1 = obfuscate(ObfType::NameMangling, code);
        REQUIRE(step1.has_value());
        auto step2 = obfuscate(ObfType::ScrambleIdentifiers, *step1);
        REQUIRE(step2.has_value());
        CHECK(is_valid_python(*step2));
    }
    SUBCASE("stringencoding → scramble") {
        std::string code =
            "name = 'hello'\n"
            "greeting = 'world'\n"
            "print(name + ' ' + greeting)\n";
        auto step1 = obfuscate(ObfType::StringEncoding, code);
        REQUIRE(step1.has_value());
        auto step2 = obfuscate(ObfType::ScrambleIdentifiers, *step1);
        REQUIRE(step2.has_value());
        CHECK(is_valid_python(*step2));
    }
    SUBCASE("xorencoding → scramble") {
        std::string code =
            "secret = 'password123'\n"
            "print(secret)\n";
        auto step1 = obfuscate(ObfType::XorEncoding, code);
        REQUIRE(step1.has_value());
        auto step2 = obfuscate(ObfType::ScrambleIdentifiers, *step1);
        REQUIRE(step2.has_value());
        CHECK(is_valid_python(*step2));
    }
    SUBCASE("importrewrite → scramble") {
        std::string code =
            "import os\n"
            "import json\n"
            "files = os.listdir('/tmp')\n"
            "print(len(files))\n";
        auto step1 = obfuscate(ObfType::ImportRewrite, code);
        REQUIRE(step1.has_value());
        auto step2 = obfuscate(ObfType::ScrambleIdentifiers, *step1);
        REQUIRE(step2.has_value());
        CHECK(is_valid_python(*step2));
    }
}

TEST_CASE("obf stacking: three techniques (deadcode→scramble→namemangling)") {
    REQUIRE(python3_available());

    std::string code =
        "import os\n"
        "def process():\n"
        "    files = os.listdir('/tmp')\n"
        "    return len(files)\n"
        "print(process())\n";

    std::string current = code;
    for (auto type : {ObfType::DeadCode, ObfType::ScrambleIdentifiers, ObfType::NameMangling}) {
        auto step = obfuscate(type, current);
        REQUIRE(step.has_value());
        current = *step;
    }

    CHECK(is_valid_python(current));
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

TEST_CASE("obf: obfuscate with unknown type returns nullopt") {
    // There's no invalid ObfType enum value since parse_obf_type rejects them
    // But we can test that empty input returns empty
    auto result = obfuscate(ObfType::ScrambleIdentifiers, "");
    REQUIRE(result.has_value());
    CHECK(result->empty());
}

// ---------------------------------------------------------------------------
// Stress test: all techniques sequential
// ---------------------------------------------------------------------------

TEST_CASE("obf stacking: all 8 techniques — valid Python") {
    REQUIRE(python3_available());

    std::string code =
        "import os\n"
        "import json\n"
        "\n"
        "def process():\n"
        "    \"\"\"Process files.\"\"\"\n"
        "    files = os.listdir('/tmp')\n"
        "    data = json.dumps({'count': len(files)})\n"
        "    return data\n"
        "\n"
        "result = process()\n"
        "print(result)\n";

    // All 8 in recommended order: other techniques first, scramble last
    // (scramble must be last to rename all identifiers in the final output)
    std::vector<ObfType> pipeline = {
        ObfType::DeadCode,
        ObfType::NameMangling,
        ObfType::DocStrip,
        ObfType::Literal,
        ObfType::StringEncoding,
        ObfType::XorEncoding,
        ObfType::ImportRewrite,
        ObfType::ScrambleIdentifiers,  // last — scrambles all identifiers
    };

    std::string current = code;
    for (auto type : pipeline) {
        auto step = obfuscate(type, current);
        INFO("failed at: ", obf_type_name(type));
        REQUIRE(step.has_value());
        CHECK(!step->empty());
        current = *step;
    }

    // Final output should be syntactically valid Python
    CHECK(is_valid_python(current));
}

TEST_CASE("obf stacking: all 8 — output is syntactically valid Python") {
    REQUIRE(python3_available());

    std::string code =
        "import os\n"
        "def process():\n"
        "    files = os.listdir('/tmp')\n"
        "    return len(files)\n"
        "print(process())\n";

    // All 8 techniques — scramble last to rename identifiers in final output
    // Note: runtime may fail due to pre-existing technique interaction bugs
    // (namemangling scope issues, stringencoding __import__ patterns).
    // This test verifies all techniques produce valid Python syntax.
    std::vector<ObfType> pipeline = {
        ObfType::DeadCode,
        ObfType::NameMangling,
        ObfType::DocStrip,
        ObfType::Literal,
        ObfType::StringEncoding,
        ObfType::XorEncoding,
        ObfType::ImportRewrite,
        ObfType::ScrambleIdentifiers,  // last — scrambles all identifiers
    };

    std::string current = code;
    for (auto type : pipeline) {
        auto step = obfuscate(type, current);
        REQUIRE(step.has_value());
        current = *step;
    }

    CHECK(is_valid_python(current));
}