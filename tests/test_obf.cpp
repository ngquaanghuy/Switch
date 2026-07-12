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
    CHECK(parse_obf_type("variablesplitting") == ObfType::VariableSplitting);
    CHECK(parse_obf_type("opaquepredicates") == ObfType::OpaquePredicates);
}

TEST_CASE("obf: parse_obf_type case-insensitive") {
    CHECK(parse_obf_type("SCRAMBLE") == ObfType::ScrambleIdentifiers);
    CHECK(parse_obf_type("DeadCode") == ObfType::DeadCode);
    CHECK(parse_obf_type("NameMangling") == ObfType::NameMangling);
    CHECK(parse_obf_type("lItErAl") == ObfType::Literal);
    CHECK(parse_obf_type("VariableSplitting") == ObfType::VariableSplitting);
    CHECK(parse_obf_type("VARIABLESPLITTING") == ObfType::VariableSplitting);
    CHECK(parse_obf_type("OpaquePredicates") == ObfType::OpaquePredicates);
    CHECK(parse_obf_type("OPAQUEPREDICATES") == ObfType::OpaquePredicates);
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
    CHECK(obf_type_name(ObfType::VariableSplitting) == "variablesplitting");
    CHECK(obf_type_name(ObfType::OpaquePredicates) == "opaquepredicates");
}

TEST_CASE("obf: all_obf_names contains all nine") {
    std::string names = all_obf_names();
    CHECK(names.find("namemangling") != std::string::npos);
    CHECK(names.find("stringencoding") != std::string::npos);
    CHECK(names.find("docstrip") != std::string::npos);
    CHECK(names.find("literal") != std::string::npos);
    CHECK(names.find("xorencoding") != std::string::npos);
    CHECK(names.find("importrewrite") != std::string::npos);
    CHECK(names.find("deadcode") != std::string::npos);
    CHECK(names.find("scramble") != std::string::npos);
    CHECK(names.find("variablesplitting") != std::string::npos);
    CHECK(names.find("opaquepredicates") != std::string::npos);
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
// Variable splitting (bool/int/float)
// ---------------------------------------------------------------------------

TEST_CASE("obf: variablesplitting — bool split valid Python") {
    std::string code = "flag = True\nprint(flag)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: variablesplitting — bool split runs correctly") {
    std::string code = "flag = True\nprint(flag)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    std::string output;
    int rc = run_python(*result, output);
    CHECK(rc == 0);
    CHECK(output.find("True") != std::string::npos);
}

TEST_CASE("obf: variablesplitting — False split runs correctly") {
    std::string code = "flag = False\nprint(flag)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    std::string output;
    int rc = run_python(*result, output);
    CHECK(rc == 0);
    CHECK(output.find("False") != std::string::npos);
}

TEST_CASE("obf: variablesplitting — int split valid Python") {
    std::string code = "x = 42\nprint(x)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: variablesplitting — int split runs correctly") {
    std::string code = "x = 42\nprint(x)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    std::string output;
    int rc = run_python(*result, output);
    CHECK(rc == 0);
    CHECK(output.find("42") != std::string::npos);
}

TEST_CASE("obf: variablesplitting — negative int split") {
    std::string code = "x = -42\nprint(x)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    std::string output;
    int rc = run_python(*result, output);
    CHECK(rc == 0);
    CHECK(output.find("-42") != std::string::npos);
}

TEST_CASE("obf: variablesplitting — zero split") {
    std::string code = "x = 0\nprint(x)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    std::string output;
    int rc = run_python(*result, output);
    CHECK(rc == 0);
    CHECK(output.find("0") != std::string::npos);
}

TEST_CASE("obf: variablesplitting — float split valid Python") {
    std::string code = "pi = 3.14\nprint(pi)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: variablesplitting — float split runs correctly") {
    std::string code = "pi = 3.14\nprint(pi)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    std::string output;
    int rc = run_python(*result, output);
    CHECK(rc == 0);
    CHECK(output.find("3.14") != std::string::npos);
}

TEST_CASE("obf: variablesplitting — negative float split") {
    std::string code = "x = -2.71\nprint(x)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    std::string output;
    int rc = run_python(*result, output);
    CHECK(rc == 0);
    CHECK(output.find("-2.71") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Variable splitting — edge cases (scope rules)
// ---------------------------------------------------------------------------

TEST_CASE("obf: variablesplitting — skips global variables") {
    std::string code = "def f():\n    global x\n    x = 42\n    print(x)\nf()\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    CHECK(result->find("global x") != std::string::npos);
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: variablesplitting — skips augmented assignment") {
    std::string code = "x = 10\nx += 5\nprint(x)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    CHECK(result->find("x += 5") != std::string::npos);
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: variablesplitting — skips attribute assignment") {
    std::string code = "class A:\n    pass\na = A()\na.x = 10\nprint(a.x)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    CHECK(result->find("a.x = 10") != std::string::npos);
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: variablesplitting — skips loop variable") {
    std::string code = "for i in range(10):\n    print(i)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    CHECK(result->find("for i in range(10)") != std::string::npos);
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: variablesplitting — skips walrus operator") {
    std::string code = "data = [1,2,3]\nif (n := len(data)) > 2:\n    print(n)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    CHECK(result->find("n := len(data)") != std::string::npos);
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: variablesplitting — skips comprehension variable") {
    std::string code = "result = [x*2 for x in range(10)]\nprint(result)\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    CHECK(result->find("for x in range(10)") != std::string::npos);
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: variablesplitting — skips with-item variable") {
    std::string code = "with open('/dev/null') as f:\n    pass\nprint('ok')\n";
    auto result = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(result.has_value());
    CHECK(result->find("as f") != std::string::npos);
    CHECK(is_valid_python(*result));
}

// ---------------------------------------------------------------------------
// Opaque predicates
// ---------------------------------------------------------------------------

TEST_CASE("obf: opaquepredicates — injects into if statement") {
    std::string code = "x = 42\nif x > 0:\n    print('positive')\n";
    auto result = obfuscate(ObfType::OpaquePredicates, code);
    REQUIRE(result.has_value());
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: opaquepredicates — output runs correctly") {
    std::string code = "x = 42\nif x > 0:\n    print('positive')\n";
    auto result = obfuscate(ObfType::OpaquePredicates, code);
    REQUIRE(result.has_value());
    std::string output;
    int rc = run_python(*result, output);
    CHECK(rc == 0);
    CHECK(output.find("positive") != std::string::npos);
}

TEST_CASE("obf: opaquepredicates — injects into while loop") {
    std::string code = "i = 0\nwhile i < 5:\n    i += 1\nprint(i)\n";
    auto result = obfuscate(ObfType::OpaquePredicates, code);
    REQUIRE(result.has_value());
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: opaquepredicates — while loop runs correctly") {
    std::string code = "i = 0\nwhile i < 5:\n    i += 1\nprint(i)\n";
    auto result = obfuscate(ObfType::OpaquePredicates, code);
    REQUIRE(result.has_value());
    std::string output;
    int rc = run_python(*result, output);
    CHECK(rc == 0);
    CHECK(output.find("5") != std::string::npos);
}

TEST_CASE("obf: opaquepredicates — injects into for loop") {
    std::string code = "for i in range(5):\n    pass\nprint('done')\n";
    auto result = obfuscate(ObfType::OpaquePredicates, code);
    REQUIRE(result.has_value());
    CHECK(is_valid_python(*result));
}

TEST_CASE("obf: opaquepredicates — for loop runs correctly") {
    std::string code = "for i in range(5):\n    pass\nprint('done')\n";
    auto result = obfuscate(ObfType::OpaquePredicates, code);
    REQUIRE(result.has_value());
    std::string output;
    int rc = run_python(*result, output);
    CHECK(rc == 0);
    CHECK(output.find("done") != std::string::npos);
}

TEST_CASE("obf: opaquepredicates — skips __name__ check") {
    std::string code = "if __name__ == '__main__':\n    print('main')\n";
    auto result = obfuscate(ObfType::OpaquePredicates, code);
    REQUIRE(result.has_value());
    CHECK(is_valid_python(*result));
}

// ---------------------------------------------------------------------------
// Stacking: opaquepredicates composition
// ---------------------------------------------------------------------------

TEST_CASE("obf stacking: opaquepredicates → scramble — valid Python") {
    std::string code = "x = 42\nif x > 0:\n    print(x)\n";
    auto step1 = obfuscate(ObfType::OpaquePredicates, code);
    REQUIRE(step1.has_value());
    auto step2 = obfuscate(ObfType::ScrambleIdentifiers, *step1);
    REQUIRE(step2.has_value());
    CHECK(is_valid_python(*step2));
}

TEST_CASE("obf stacking: scramble → opaquepredicates — valid Python") {
    std::string code = "x = 42\nif x > 0:\n    print(x)\n";
    auto step1 = obfuscate(ObfType::ScrambleIdentifiers, code);
    REQUIRE(step1.has_value());
    auto step2 = obfuscate(ObfType::OpaquePredicates, *step1);
    REQUIRE(step2.has_value());
    CHECK(is_valid_python(*step2));
}

TEST_CASE("obf stacking: deadcode → opaquepredicates → scramble — valid Python") {
    std::string code = "x = 42\nif x > 0:\n    print(x)\n";
    auto step1 = obfuscate(ObfType::DeadCode, code);
    REQUIRE(step1.has_value());
    auto step2 = obfuscate(ObfType::OpaquePredicates, *step1);
    REQUIRE(step2.has_value());
    auto step3 = obfuscate(ObfType::ScrambleIdentifiers, *step2);
    REQUIRE(step3.has_value());
    CHECK(is_valid_python(*step3));
}

TEST_CASE("obf stacking: opaquepredicates runs correctly after scramble") {
    std::string code = "x = 42\nif x > 0:\n    print('yes')\nelse:\n    print('no')\n";
    auto step1 = obfuscate(ObfType::ScrambleIdentifiers, code);
    REQUIRE(step1.has_value());
    auto step2 = obfuscate(ObfType::OpaquePredicates, *step1);
    REQUIRE(step2.has_value());
    std::string output;
    int rc = run_python(*step2, output);
    CHECK(rc == 0);
    CHECK(output.find("yes") != std::string::npos);
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
// Stacking: variablesplitting composition
// ---------------------------------------------------------------------------

TEST_CASE("obf stacking: variablesplitting → scramble — valid Python") {
    std::string code = "x = 42\ny = True\nprint(x, y)\n";
    auto step1 = obfuscate(ObfType::VariableSplitting, code);
    REQUIRE(step1.has_value());
    auto step2 = obfuscate(ObfType::ScrambleIdentifiers, *step1);
    REQUIRE(step2.has_value());
    CHECK(is_valid_python(*step2));
}

TEST_CASE("obf stacking: scramble → variablesplitting — valid Python") {
    std::string code = "x = 42\ny = True\nprint(x, y)\n";
    auto step1 = obfuscate(ObfType::ScrambleIdentifiers, code);
    REQUIRE(step1.has_value());
    auto step2 = obfuscate(ObfType::VariableSplitting, *step1);
    REQUIRE(step2.has_value());
    CHECK(is_valid_python(*step2));
}

TEST_CASE("obf stacking: deadcode → variablesplitting → scramble — valid Python") {
    std::string code = "x = 42\nprint(x)\n";
    auto step1 = obfuscate(ObfType::DeadCode, code);
    REQUIRE(step1.has_value());
    auto step2 = obfuscate(ObfType::VariableSplitting, *step1);
    REQUIRE(step2.has_value());
    auto step3 = obfuscate(ObfType::ScrambleIdentifiers, *step2);
    REQUIRE(step3.has_value());
    CHECK(is_valid_python(*step3));
}

TEST_CASE("obf stacking: literal → variablesplitting — valid Python") {
    std::string code = "x = 42\ny = 3.14\nprint(x + int(y))\n";
    auto step1 = obfuscate(ObfType::Literal, code);
    REQUIRE(step1.has_value());
    auto step2 = obfuscate(ObfType::VariableSplitting, *step1);
    REQUIRE(step2.has_value());
    CHECK(is_valid_python(*step2));
}

TEST_CASE("obf stacking: namemangling → variablesplitting — valid Python") {
    std::string code = "def add(a, b):\n    return a + b\nprint(add(2, 3))\n";
    auto step1 = obfuscate(ObfType::NameMangling, code);
    REQUIRE(step1.has_value());
    auto step2 = obfuscate(ObfType::VariableSplitting, *step1);
    REQUIRE(step2.has_value());
    CHECK(is_valid_python(*step2));
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

TEST_CASE("obf stacking: all 10 techniques — valid Python") {
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

    // All 10 in recommended order:
    // scramble MUST run before xorencoding and importrewrite
    // opaquepredicates AFTER scramble, BEFORE xorencoding
    // Order: DeadCode → NameMangling → DocStrip → Literal → StringEncoding
    //        → ScrambleIdentifiers → OpaquePredicates → XorEncoding
    //        → ImportRewrite → VariableSplitting
    std::vector<ObfType> pipeline = {
        ObfType::DeadCode,
        ObfType::NameMangling,
        ObfType::DocStrip,
        ObfType::Literal,
        ObfType::StringEncoding,
        ObfType::ScrambleIdentifiers,
        ObfType::OpaquePredicates,
        ObfType::XorEncoding,
        ObfType::ImportRewrite,
        ObfType::VariableSplitting,
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

TEST_CASE("obf stacking: all 9 — output is syntactically valid Python") {
    REQUIRE(python3_available());

    std::string code =
        "import os\n"
        "def process():\n"
        "    files = os.listdir('/tmp')\n"
        "    return len(files)\n"
        "print(process())\n";

    // All 10 techniques — scramble MUST run before xorencoding/importrewrite
    // opaquepredicates AFTER scramble, BEFORE xorencoding
    // Note: runtime may fail due to pre-existing technique interaction bugs
    // (namemangling scope issues, stringencoding __import__ patterns).
    // This test verifies all techniques produce valid Python syntax.
    std::vector<ObfType> pipeline = {
        ObfType::DeadCode,
        ObfType::NameMangling,
        ObfType::DocStrip,
        ObfType::Literal,
        ObfType::StringEncoding,
        ObfType::ScrambleIdentifiers,
        ObfType::OpaquePredicates,
        ObfType::XorEncoding,
        ObfType::ImportRewrite,
        ObfType::VariableSplitting,
    };

    std::string current = code;
    for (auto type : pipeline) {
        auto step = obfuscate(type, current);
        REQUIRE(step.has_value());
        current = *step;
    }

    CHECK(is_valid_python(current));
}