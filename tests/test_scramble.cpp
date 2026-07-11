#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "switch/scramble.hpp"
#include "test_helpers.h"

#include <string>

using namespace switch_scramble;

// =========================================================================
// Edge cases
// =========================================================================

TEST_CASE("scramble: empty string returns empty") {
    CHECK(scramble_identifiers("") == "");
}

TEST_CASE("scramble: no identifiers — unchanged") {
    std::string src = "123 + 456\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("123") != std::string::npos);
    CHECK(result.find("456") != std::string::npos);
}

TEST_CASE("scramble: single identifier gets mapped") {
    std::string src = "my_var = 42\n";
    std::string result = scramble_identifiers(src);
    // my_var should be replaced with something else
    CHECK(result.find("my_var") == std::string::npos);
    CHECK(result.find("42") != std::string::npos);
}

// =========================================================================
// Keyword / builtin / dunder preservation
// =========================================================================

TEST_CASE("scramble: keywords preserved") {
    std::string src = "if True:\n    pass\nfor i in range(10):\n    break\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("if") != std::string::npos);
    CHECK(result.find("True") != std::string::npos);
    CHECK(result.find("pass") != std::string::npos);
    CHECK(result.find("for") != std::string::npos);
    CHECK(result.find("in") != std::string::npos);
    CHECK(result.find("range") != std::string::npos);
    CHECK(result.find("break") != std::string::npos);
}

TEST_CASE("scramble: builtins preserved") {
    std::string src = "x = len([1,2,3])\nprint(int(x))\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("len") != std::string::npos);
    CHECK(result.find("print") != std::string::npos);
    CHECK(result.find("int") != std::string::npos);
    CHECK(result.find("[1,2,3]") != std::string::npos);
}

TEST_CASE("scramble: dunders preserved") {
    std::string src = "class Foo:\n    def __init__(self):\n        self.__name__ = 'test'\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("__init__") != std::string::npos);
    CHECK(result.find("__name__") != std::string::npos);
    CHECK(result.find("class") != std::string::npos);
    CHECK(result.find("def") != std::string::npos);
}

// =========================================================================
// Import module name preservation
// =========================================================================

TEST_CASE("scramble: import module names not scrambled") {
    std::string src = "import os\nimport json\nimport sys\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("import os") != std::string::npos);
    CHECK(result.find("import json") != std::string::npos);
    CHECK(result.find("import sys") != std::string::npos);
}

TEST_CASE("scramble: from import module name not scrambled") {
    std::string src = "from os import path\nfrom json import loads\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("from os") != std::string::npos);
    CHECK(result.find("from json") != std::string::npos);
}

// =========================================================================
// Module attribute access (the fix)
// =========================================================================

TEST_CASE("scramble: os.listdir preserved") {
    std::string src = "import os\nos.listdir(\"/tmp\")\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("os.listdir") != std::string::npos);
}

TEST_CASE("scramble: json.loads preserved") {
    std::string src = "import json\njson.loads('{\"a\": 1}')\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("json.loads") != std::string::npos);
}

TEST_CASE("scramble: os.path.join preserved (chained)") {
    std::string src = "import os\nos.path.join(\"/tmp\", \"test\")\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("os.path.join") != std::string::npos);
}

TEST_CASE("scramble: user-defined variables still scrambled") {
    std::string src = "import os\nmy_var = os.listdir(\"/tmp\")\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("my_var") == std::string::npos);  // scrambled
    CHECK(result.find("os.listdir") != std::string::npos);  // preserved
}

TEST_CASE("scramble: module used without dot — still preserved") {
    std::string src = "import os\nx = os\n";
    std::string result = scramble_identifiers(src);
    // os should be preserved (it's in import_names_)
    CHECK(result.find("import os") != std::string::npos);
}

// =========================================================================
// String / comment preservation
// =========================================================================

TEST_CASE("scramble: single-quoted strings unchanged") {
    std::string src = "x = 'hello world'\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("'hello world'") != std::string::npos);
}

TEST_CASE("scramble: double-quoted strings unchanged") {
    std::string src = "x = \"hello world\"\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("\"hello world\"") != std::string::npos);
}

TEST_CASE("scramble: triple-quoted strings unchanged") {
    std::string src = "x = \"\"\"hello world\"\"\"\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("\"\"\"hello world\"\"\"") != std::string::npos);
}

TEST_CASE("scramble: comments unchanged") {
    std::string src = "# this is a comment\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("# this is a comment") != std::string::npos);
}

TEST_CASE("scramble: docstrings preserved") {
    std::string src = "def foo():\n    \"\"\"This is a docstring\"\"\"\n    pass\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("\"\"\"This is a docstring\"\"\"") != std::string::npos);
}

// =========================================================================
// F-string handling
// =========================================================================

TEST_CASE("scramble: f-string text preserved") {
    std::string src = "name = \"world\"\nx = f\"hello {name}\"\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("f\"hello") != std::string::npos);
    // name inside f-string should be scrambled (it's a user variable)
    // But the f-string syntax should be preserved
    CHECK(result.find("f\"") != std::string::npos);
}

// =========================================================================
// Decorator preservation
// =========================================================================

TEST_CASE("scramble: decorators preserved") {
    std::string src = "@property\ndef foo():\n    pass\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("@property") != std::string::npos);
    CHECK(result.find("def") != std::string::npos);
}

TEST_CASE("scramble: dotted decorators preserved") {
    std::string src = "@app.route(\"/\")\ndef index():\n    pass\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("@app.route") != std::string::npos);
    CHECK(is_valid_python(result));
}

TEST_CASE("scramble: deeply dotted decorators preserved") {
    std::string src = "@framework.web.handler\nasync def handle():\n    pass\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("@framework.web.handler") != std::string::npos);
    CHECK(is_valid_python(result));
}

// =========================================================================
// Python correctness — output runs without error
// =========================================================================

TEST_CASE("scramble: simple function executes correctly") {
    std::string src = "def add(a, b):\n    return a + b\nresult = add(2, 3)\nprint(result)\n";
    std::string result = scramble_identifiers(src);
    REQUIRE(is_valid_python(result));

    std::string output;
    int rc = run_python(result, output);
    CHECK(rc == 0);
    CHECK(output.find("5") != std::string::npos);
}

TEST_CASE("scramble: module attribute access executes correctly") {
    std::string src = "import os\nfiles = os.listdir(\"/tmp\")\nprint(len(files))\n";
    std::string result = scramble_identifiers(src);
    REQUIRE(is_valid_python(result));

    std::string output;
    int rc = run_python(result, output);
    CHECK(rc == 0);
}

TEST_CASE("scramble: chained module attributes execute correctly") {
    std::string src = "import os\npath = os.path.join(\"/tmp\", \"test\")\nprint(path)\n";
    std::string result = scramble_identifiers(src);
    REQUIRE(is_valid_python(result));

    std::string output;
    int rc = run_python(result, output);
    CHECK(rc == 0);
    CHECK(output.find("/tmp/test") != std::string::npos);
}

// =========================================================================
// Complex code
// =========================================================================

TEST_CASE("scramble: class with methods") {
    std::string src = "class MyClass:\n    def __init__(self, name):\n        self.name = name\n    def greet(self):\n        return f\"Hello, {self.name}!\"\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("class") != std::string::npos);
    CHECK(result.find("__init__") != std::string::npos);
    CHECK(result.find("self") != std::string::npos);
    CHECK(is_valid_python(result));
}

TEST_CASE("scramble: nested functions") {
    std::string src = "def outer():\n    def inner():\n        return 42\n    return inner()\nresult = outer()\nprint(result)\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("def") != std::string::npos);
    CHECK(result.find("return") != std::string::npos);
    CHECK(is_valid_python(result));
}

TEST_CASE("scramble: list comprehension") {
    std::string src = "nums = [1, 2, 3, 4, 5]\nsquares = [x*x for x in nums]\nprint(squares)\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("[1, 2, 3, 4, 5]") != std::string::npos);
    CHECK(is_valid_python(result));
}

TEST_CASE("scramble: try/except") {
    std::string src = "try:\n    x = 1 / 0\nexcept ZeroDivisionError:\n    x = 0\nprint(x)\n";
    std::string result = scramble_identifiers(src);
    CHECK(result.find("try") != std::string::npos);
    CHECK(result.find("except") != std::string::npos);
    CHECK(result.find("ZeroDivisionError") != std::string::npos);
    CHECK(is_valid_python(result));
}
