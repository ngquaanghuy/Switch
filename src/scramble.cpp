#include "switch/scramble.hpp"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <random>
#include <cctype>
#include <algorithm>

namespace switch_scramble {

// ---------------------------------------------------------------------------
// State machine states
// ---------------------------------------------------------------------------

enum class State {
    NORMAL,
    SINGLE_QUOTE,
    DOUBLE_QUOTE,
    TRIPLE_SINGLE,
    TRIPLE_DOUBLE,
    FSTRING_S,   // f-string with single-quote delimiter
    FSTRING_D,   // f-string with double-quote delimiter
    COMMENT
};

// ---------------------------------------------------------------------------
// Python reserved words
// ---------------------------------------------------------------------------

static const std::unordered_set<std::string>& python_keywords() {
    static const std::unordered_set<std::string> kws = {
        "False", "None", "True", "and", "as", "assert", "async", "await",
        "break", "class", "continue", "def", "del", "elif", "else", "except",
        "finally", "for", "from", "global", "if", "import", "in", "is",
        "lambda", "nonlocal", "not", "or", "pass", "raise", "return",
        "try", "while", "with", "yield",
    };
    return kws;
}

static const std::unordered_set<std::string>& python_builtins() {
    static const std::unordered_set<std::string> bis = {
        "abs", "all", "any", "bin", "bool", "bytearray", "bytes",
        "callable", "chr", "classmethod", "compile", "complex",
        "delattr", "dict", "dir", "divmod", "enumerate", "eval", "exec",
        "filter", "float", "format", "frozenset", "getattr", "globals",
        "hasattr", "hash", "help", "hex", "id", "input", "int",
        "isinstance", "issubclass", "iter", "len", "list", "locals",
        "map", "max", "memoryview", "min", "next", "object", "oct",
        "open", "ord", "pow", "print", "property", "range", "repr",
        "reversed", "round", "set", "setattr", "slice", "sorted",
        "staticmethod", "str", "sum", "super", "tuple", "type",
        "vars", "zip", "__import__",
        // Common exception types
        "Exception", "ValueError", "TypeError", "KeyError", "IndexError",
        "AttributeError", "ImportError", "FileNotFoundError", "IOError",
        "OSError", "RuntimeError", "StopIteration", "NotImplementedError",
        "ZeroDivisionError", "OverflowError", "MemoryError",
        "RecursionError", "SyntaxError", "IndentationError",
        "TabError", "NameError", "UnboundLocalError",
        // Common conventions
        "self", "cls",
        // Common string/bytes methods (must not be renamed — they're built-in)
        "encode", "decode", "format", "replace", "split", "join",
        "strip", "lstrip", "rstrip", "upper", "lower", "title",
        "capitalize", "startswith", "endswith", "find", "rfind",
        "count", "center", "ljust", "rjust", "zfill", "expandtabs",
        "translate", "maketrans", "isalnum", "isalpha", "isdigit",
        "islower", "isupper", "isspace", "istitle", "isnumeric",
        "isdecimal", "isidentifier", "iskeyword", "isprintable",
        "isascii", "isascii",
        "b64encode", "b64decode", "b32encode", "b32decode",
        "b16encode", "b16decode", "b85encode", "b85decode",
        "encodebytes", "decodebytes", "encode", "decode",
        "hexlify", "unhexlify",
        // Common list/dict/set methods
        "append", "extend", "insert", "remove", "pop", "clear",
        "index", "count", "sort", "reverse", "copy",
        "keys", "values", "items", "get", "update", "setdefault",
        "popitem", "fromkeys",
        "add", "discard", "remove", "pop", "union", "intersection",
        "difference", "symmetric_difference", "issubset", "issuperset",
        // Common file/object methods
        "read", "readline", "readlines", "write", "writelines",
        "seek", "tell", "flush", "close", "fileno",
        "name", "mode", "closed", "readable", "writable", "seekable",
        // Common type check/conversion methods
        "append", "extend", "insert", "remove", "pop", "clear",
        "index", "count", "sort", "reverse", "copy",
        // Common math/io methods
        "sqrt", "log", "sin", "cos", "tan", "pow",
        "getcwd", "listdir", "makedirs", "mkdir", "rmdir", "remove",
        "rename", "stat", "access", "chmod", "chown",
        "pathjoin", "dirname", "basename", "exists", "isfile", "isdir",
        "abspath", "relpath", "realpath", "normpath", "splitext",
        // Common JSON/yaml/xml methods
        "dumps", "loads", "dump", "load",
        "safe_load", "safe_dump",
        // Common datetime methods
        "now", "utcnow", "strftime", "strptime", "timestamp",
        "isoformat", "fromisoformat",
        // Common re/regex methods
        "match", "search", "findall", "finditer", "sub", "subn",
        "split", "compile", "fullmatch",
        // Common os/pathlib methods
        "getcwd", "listdir", "makedirs", "mkdir", "rmdir", "remove",
        "rename", "stat", "access", "chmod", "chown",
        // Common io methods
        "read", "readline", "readlines", "write", "writelines",
        "seek", "tell", "flush", "close",
    };
    return bis;
}

static bool is_keyword(const std::string& s) {
    return python_keywords().count(s) > 0;
}

static bool is_builtin(const std::string& s) {
    return python_builtins().count(s) > 0;
}

// ---------------------------------------------------------------------------
// Confusable character sets for anti-RE naming
// ---------------------------------------------------------------------------

static const char CONFUSABLE_CHARS[] = "lI1oO0";
static const char CONFUSABLE_LETTERS[] = "lIoO";  // letters only for first char

static std::string random_confusable(int len, std::mt19937& rng) {
    std::string result;
    result.reserve(static_cast<size_t>(len));
    // First char: must be letter (not digit) for valid Python identifier
    std::uniform_int_distribution<int> first_dist(0, 3);
    result += CONFUSABLE_LETTERS[first_dist(rng)];
    // Remaining chars: full confusable set
    std::uniform_int_distribution<int> rest_dist(0, 5);
    for (int i = 1; i < len; ++i) {
        result += CONFUSABLE_CHARS[rest_dist(rng)];
    }
    return result;
}

// ---------------------------------------------------------------------------
// Scramble engine
// ---------------------------------------------------------------------------

class ScrambleEngine {
public:
    explicit ScrambleEngine(unsigned seed) : rng_(seed) {}

    std::string run(const std::string& source) {
        collect(source);
        return replace(source);
    }

private:
    std::mt19937 rng_;
    std::unordered_map<std::string, std::string> map_;
    std::unordered_set<std::string> import_names_;  // module names from import statements
    std::unordered_set<std::string> module_names_;   // names that are module objects (for dot-attr)
    // Tracks two related states via one flag:
    // 1. Previous identifier was a module name (for os.path.join preservation)
    // 2. A string literal just ended (for "str".method() preservation)
    // Both suppress scrambling of the next dot-attribute, which is correct behavior
    // for both cases — module attributes and string methods must not be renamed.
    bool mod_seen_ = false;
    int scope_level_ = 0;

    // --- Helpers ---

    static bool is_id_char(char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
    }

    static bool is_id_start(char c) {
        return std::isalpha(static_cast<unsigned char>(c)) || c == '_';
    }

    void push_scope()  { ++scope_level_; }
    void pop_scope()   { scope_level_ = std::max(0, scope_level_ - 1); }

    std::string gen_name() {
        std::uniform_int_distribution<int> len_dist(3, 6);
        int len = len_dist(rng_);
        if (scope_level_ <= 1) len = std::max(4, len);
        return random_confusable(len, rng_);
    }

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

    // Collect a full identifier starting at src[i], advance i past it.
    std::string collect_id(const std::string& src, size_t& i) {
        size_t start = i;
        while (i < src.size() && is_id_char(src[i])) ++i;
        return src.substr(start, i - start);
    }

    // --- String prefix detection ---

    // Detect Python string prefixes: f, b, r, rb, br, rf, fr, u
    // Returns prefix length (0 if not a string prefix, 1 for single-char, 2 for two-char)
    // Requires src[i+prefix_len] to be a quote character.
    static int detect_string_prefix(const std::string& src, size_t i) {
        size_t n = src.size();
        if (i >= n) return 0;
        char c1 = src[i];
        // Two-letter prefixes: rb, br, rf, fr (case-insensitive)
        if (i + 2 < n) {
            char c2 = src[i+1];
            char c3 = src[i+2];
            bool c2_is_quote = (c2 == '\'' || c2 == '"');
            bool c3_is_quote = (c3 == '\'' || c3 == '"');
            // Two-letter prefix only when c2 is NOT a quote (otherwise it's single-letter like r"")
            if (!c2_is_quote) {
                char lo1 = static_cast<char>(std::tolower(static_cast<unsigned char>(c1)));
                char lo2 = static_cast<char>(std::tolower(static_cast<unsigned char>(c2)));
                if ((lo1 == 'r' && (lo2 == 'b' || lo2 == 'f')) ||
                    (lo1 == 'b' && lo2 == 'r') ||
                    (lo1 == 'f' && lo2 == 'r')) {
                    if (c3_is_quote) return 2;
                }
            }
        }
        // Single-letter prefixes: f, b, r, u
        if (i + 1 < n) {
            char lo = static_cast<char>(std::tolower(static_cast<unsigned char>(c1)));
            if ((lo == 'f' || lo == 'b' || lo == 'r' || lo == 'u') &&
                (src[i+1] == '\'' || src[i+1] == '"')) {
                return 1;
            }
        }
        return 0;
    }

    // --- Pass 1: Collect identifiers ---

    void collect(const std::string& src) {
        State state = State::NORMAL;
        int brace_depth = 0;
        size_t i = 0;
        const size_t n = src.size();

        while (i < n) {
            char c = src[i];
            // Reset mod_seen_ when chain breaks (non-dot, non-id char)
            if (state == State::NORMAL && mod_seen_ && c != '.' && !is_id_start(c)) {
                mod_seen_ = false;
            }

            switch (state) {

            case State::NORMAL:
                if (c == '#') {
                    state = State::COMMENT;
                } else if (c == '\'' && i + 2 < n && src[i+1] == '\'' && src[i+2] == '\'') {
                    state = State::TRIPLE_SINGLE; i += 3; continue;
                } else if (c == '"' && i + 2 < n && src[i+1] == '"' && src[i+2] == '"') {
                    state = State::TRIPLE_DOUBLE; i += 3; continue;
                } else if (c == '\'') {
                    state = State::SINGLE_QUOTE;
                } else if (c == '"') {
                    state = State::DOUBLE_QUOTE;
                } else if (int plen = detect_string_prefix(src, i)) {
                    // String prefix: f, b, r, rb, br, rf, fr, u followed by quote
                    char prefix_char = static_cast<char>(std::tolower(static_cast<unsigned char>(src[i])));
                    mod_seen_ = false;
                    char delim = src[i + plen];
                    if (prefix_char == 'f') {
                        // f-string: enter special state for expression handling
                        state = (delim == '\'') ? State::FSTRING_S : State::FSTRING_D;
                        brace_depth = 0;
                    } else {
                        // b, r, rb, br, rf, fr, u — skip prefix, enter string state
                        state = (delim == '\'') ? State::SINGLE_QUOTE : State::DOUBLE_QUOTE;
                    }
                    i += plen + 1; // skip prefix chars + opening quote
                    continue;
                } else if (c == '@') {
                    // Decorator — skip @ and the full decorator name (including dotted: @app.route)
                    ++i;
                    while (i < n && (src[i] == ' ' || src[i] == '\t')) ++i;
                    if (i < n && is_id_start(src[i])) {
                        while (i < n && is_id_char(src[i])) ++i;
                        // Handle dotted decorators: @os.path.join, @app.route
                        while (i < n && src[i] == '.') {
                            ++i;  // skip dot
                            while (i < n && is_id_char(src[i])) ++i;
                        }
                    }
                    continue;
                } else if (c == '.' && mod_seen_) {
                    // Dot after a module name — skip it (part of module.attr access)
                    // Keep mod_seen_ = true for chained access (os.path.join)
                    ++i;
                    continue;
                } else if (is_id_start(c)) {
                    std::string id = collect_id(src, i);

                    if (id == "import" || id == "from") {
                        // Skip module names after import/from — they reference real modules
                        // Stop at newline to avoid consuming next line's code
                        bool is_from = (id == "from");
                        while (i < n && src[i] != '\n') {
                            while (i < n && (src[i] == ' ' || src[i] == '\t' || src[i] == ',')) ++i;
                            if (i >= n || src[i] == '\n' || !is_id_start(src[i])) break;

                            std::string peek_id = collect_id(src, i);
                            if (peek_id == "as") {
                                while (i < n && (src[i] == ' ' || src[i] == '\t')) ++i;
                                if (i < n && is_id_start(src[i])) collect_id(src, i);
                                continue;
                            }
                            // For "import X": X is module name → skip always
                            // For "from X import Y": Y is imported name → skip (must not rename)
                            import_names_.insert(peek_id);
                            // Track module names for dot-attribute access (e.g., os.listdir())
                            module_names_.insert(peek_id);
                        }
                    } else if (mod_seen_) {
                        // This identifier follows a module name — it's an attribute, skip it
                        // Keep mod_seen_ = true for chained access (os.path.join)
                        // Reset only if not a module name itself
                        if (module_names_.count(id) == 0) {
                            mod_seen_ = false;
                        }
                    } else if (!is_keyword(id) && !is_builtin(id) && import_names_.count(id) == 0) {
                        // Skip keywords, builtins, dunders
                        bool is_dunder = id.size() > 4 && id.substr(0, 2) == "__" && id.substr(id.size() - 2) == "__";
                        if (!is_dunder) {
                            map_id(id);
                        }
                    }
                    // Check if this identifier is a module name for dot-attribute tracking
                    if (module_names_.count(id) > 0) {
                        mod_seen_ = true;
                    }
                } else {
                    // Not an identifier start — just advance
                }
                break;

            case State::SINGLE_QUOTE:
                if (c == '\\' && i + 1 < n) { i += 2; continue; }
                if (c == '\'') { state = State::NORMAL; mod_seen_ = true; }
                break;

            case State::DOUBLE_QUOTE:
                if (c == '\\' && i + 1 < n) { i += 2; continue; }
                if (c == '"') { state = State::NORMAL; mod_seen_ = true; }
                break;

            case State::TRIPLE_SINGLE:
                if (c == '\\' && i + 1 < n) { i += 2; continue; }
                if (c == '\'' && i + 2 < n && src[i+1] == '\'' && src[i+2] == '\'') {
                    state = State::NORMAL; mod_seen_ = true; i += 3; continue;
                }
                break;

            case State::TRIPLE_DOUBLE:
                if (c == '\\' && i + 1 < n) { i += 2; continue; }
                if (c == '"' && i + 2 < n && src[i+1] == '"' && src[i+2] == '"') {
                    state = State::NORMAL; mod_seen_ = true; i += 3; continue;
                }
                break;

            case State::FSTRING_S:
            case State::FSTRING_D:
                handle_fstring_collect(src, i, state, brace_depth);
                break;

            case State::COMMENT:
                if (c == '\n') state = State::NORMAL;
                break;
            }
            ++i;
        }
    }

    void handle_fstring_collect(const std::string& src, size_t& i,
                                State& state, int& brace_depth) {
        char c = src[i];
        char delim = (state == State::FSTRING_S) ? '\'' : '"';

        if (brace_depth > 0) {
            // Inside f-string expression { ... }
            // Reset mod_seen_ when chain breaks (non-dot, non-id char)
            if (mod_seen_ && c != '.' && !is_id_start(c)) {
                mod_seen_ = false;
            }
            if (c == '{') {
                ++brace_depth;
            } else if (c == '}') {
                --brace_depth;
            } else if (c == ':' && brace_depth == 1) {
                // Format specifier: {expr:fmt} — skip everything until '}'
                while (i < src.size() && src[i] != '}') {
                    if (src[i] == '{') {
                        // Nested expression in format spec (e.g. {value:{width}})
                        int nested = 1;
                        ++i;
                        while (i < src.size() && nested > 0) {
                            if (src[i] == '{') ++nested;
                            else if (src[i] == '}') --nested;
                            ++i;
                        }
                    } else {
                        ++i;
                    }
                }
                // Don't consume '}' — let the main loop handle it
                // Back up one so main loop's ++i lands on '}'
                if (i > 0) --i;
                return;
            } else if (c == '!' && brace_depth == 1) {
                // Conversion flag: {expr!r} or {expr!r:fmt} — skip !r
                while (i < src.size() && src[i] != ':' && src[i] != '}') ++i;
                return;
            } else if (c == '\\' && i + 1 < src.size()) {
                i += 1; return; // skip escape (main loop ++i advances to next)
            } else if (c == '\'' || c == '"') {
                // Nested string inside expression — skip to matching close
                char nested_delim = c;
                ++i;
                while (i < src.size()) {
                    if (src[i] == '\\') { i += 2; continue; }
                    if (src[i] == nested_delim) { ++i; break; }
                    ++i;
                }
                return; // i past closing quote; main loop ++i advances to next
            } else if (c == '.' && mod_seen_) {
                // Dot after a module name inside f-string expression — skip
                return;
            } else if (is_id_start(c)) {
                std::string id = collect_id(src, i);
                if (mod_seen_) {
                    // Attribute of a module — skip mapping
                    // Keep mod_seen_ = true for chained access (os.path.join)
                } else if (!is_keyword(id) && !is_builtin(id)) {
                    bool is_dunder = id.size() > 4 && id.substr(0, 2) == "__" && id.substr(id.size() - 2) == "__";
                    if (!is_dunder) map_id(id);
                }
                // Check if this identifier is a module name for dot-attribute tracking
                if (module_names_.count(id) > 0) {
                    mod_seen_ = true;
                }
                --i; return; // collect_id advanced i past id; back up so main ++i lands right
            }
        } else {
            // Outside expression in f-string
            if (c == '{') {
                brace_depth = 1;
            } else if (c == delim) {
                // End of f-string
                state = State::NORMAL; mod_seen_ = true;
            } else if (c == '\\' && i + 1 < src.size()) {
                i += 2; return; // skip escape
            }
        }
    }

    // --- Pass 2: Replace identifiers ---

    std::string replace(const std::string& src) {
        std::string out;
        out.reserve(src.size() * 2);

        State state = State::NORMAL;
        int brace_depth = 0;
        size_t i = 0;
        const size_t n = src.size();

        // Reset mod_seen_ from collect() pass — state doesn't carry over
        mod_seen_ = false;

        while (i < n) {
            char c = src[i];
            // Reset mod_seen_ when chain breaks (non-dot, non-id char)
            if (state == State::NORMAL && mod_seen_ && c != '.' && !is_id_start(c)) {
                mod_seen_ = false;
            }
            switch (state) {

            case State::NORMAL:
                if (c == '#') {
                    state = State::COMMENT;
                    out += c;
                } else if (c == '\'' && i + 2 < n && src[i+1] == '\'' && src[i+2] == '\'') {
                    state = State::TRIPLE_SINGLE;
                    out += "'''"; i += 3; continue;
                } else if (c == '"' && i + 2 < n && src[i+1] == '"' && src[i+2] == '"') {
                    state = State::TRIPLE_DOUBLE;
                    out += "\"\"\""; i += 3; continue;
                } else if (c == '\'') {
                    state = State::SINGLE_QUOTE;
                    out += c;
                } else if (c == '"') {
                    state = State::DOUBLE_QUOTE;
                    out += c;
                } else if (int plen = detect_string_prefix(src, i)) {
                    // String prefix: f, b, r, rb, br, rf, fr, u followed by quote
                    char prefix_char = static_cast<char>(std::tolower(static_cast<unsigned char>(src[i])));
                    mod_seen_ = false;
                    // Output entire prefix as-is
                    out += src.substr(i, static_cast<size_t>(plen));
                    char delim = src[i + plen];
                    out += delim;
                    if (prefix_char == 'f') {
                        // f-string: enter special state for expression handling
                        state = (delim == '\'') ? State::FSTRING_S : State::FSTRING_D;
                        brace_depth = 0;
                    } else {
                        state = (delim == '\'') ? State::SINGLE_QUOTE : State::DOUBLE_QUOTE;
                    }
                    i += plen + 1; // skip prefix chars + opening quote
                    continue;
                } else if (c == '@') {
                    // Decorator: output @ and the full decorator name (including dotted: @app.route)
                    out += c;
                    ++i;
                    while (i < n && (src[i] == ' ' || src[i] == '\t')) { out += src[i]; ++i; }
                    if (i < n && is_id_start(src[i])) {
                        size_t start = i;
                        while (i < n && is_id_char(src[i])) ++i;
                        out += src.substr(start, i - start);
                        // Handle dotted decorators: @os.path.join, @app.route
                        while (i < n && src[i] == '.') {
                            size_t dot_start = i;
                            ++i;  // skip dot
                            while (i < n && is_id_char(src[i])) ++i;
                            out += src.substr(dot_start, i - dot_start);
                        }
                    }
                    continue;
                } else if (c == '.' && mod_seen_) {
                    // Dot after a module name — output as-is (part of module.attr access)
                    out += c;
                    ++i;
                    continue;
                } else if (is_id_start(c)) {
                    size_t start = i;
                    std::string id = collect_id(src, i);

                    if (id == "import" || id == "from") {
                        // Output keyword as-is, then pass through module names without mapping
                        out += id;
                        // Consume: import <name> [, <name>] [as <alias>] — stop at newline
                        while (i < n && src[i] != '\n') {
                            // Skip spaces, tabs, commas
                            while (i < n && (src[i] == ' ' || src[i] == '\t' || src[i] == ',')) {
                                out += src[i]; ++i;
                            }
                            if (i >= n || src[i] == '\n' || !is_id_start(src[i])) break;

                            std::string mod_id = collect_id(src, i);
                            if (mod_id == "as") {
                                // Skip alias
                                out += mod_id;
                                while (i < n && (src[i] == ' ' || src[i] == '\t')) { out += src[i]; ++i; }
                                if (i < n && is_id_start(src[i])) {
                                    size_t astart = i;
                                    collect_id(src, i);
                                    out += src.substr(astart, i - astart);
                                }
                            } else {
                                out += mod_id;
                            }
                        }
                        continue;
                    }

                    if (mod_seen_) {
                        // This identifier follows a module name — it's an attribute, output as-is
                        // Keep mod_seen_ = true for chained access (os.path.join)
                        // Reset only when chain breaks (non-dot, non-id char later)
                        out += id;
                    } else {
                        auto it = map_.find(id);
                        if (it != map_.end() && import_names_.count(id) == 0) {
                            out += it->second;
                        } else {
                            out += id;
                        }
                    }
                    // Check if this identifier is a module name for dot-attribute tracking
                    if (module_names_.count(id) > 0) {
                        mod_seen_ = true;
                    }
                    // i now points past the identifier; continue to re-examine current position
                    continue;
                } else {
                    out += c;
                }
                break;

            case State::SINGLE_QUOTE:
                if (c == '\\' && i + 1 < n) { out += c; out += src[i+1]; i += 2; continue; }
                if (c == '\'') { state = State::NORMAL; mod_seen_ = true; }
                out += c;
                break;

            case State::DOUBLE_QUOTE:
                if (c == '\\' && i + 1 < n) { out += c; out += src[i+1]; i += 2; continue; }
                if (c == '"') { state = State::NORMAL; mod_seen_ = true; }
                out += c;
                break;

            case State::TRIPLE_SINGLE:
                if (c == '\\' && i + 1 < n) { out += c; out += src[i+1]; i += 2; continue; }
                if (c == '\'' && i + 2 < n && src[i+1] == '\'' && src[i+2] == '\'') {
                    state = State::NORMAL; mod_seen_ = true; out += "'''"; i += 3; continue;
                }
                out += c;
                break;

            case State::TRIPLE_DOUBLE:
                if (c == '\\' && i + 1 < n) { out += c; out += src[i+1]; i += 2; continue; }
                if (c == '"' && i + 2 < n && src[i+1] == '"' && src[i+2] == '"') {
                    state = State::NORMAL; mod_seen_ = true; out += "\"\"\""; i += 3; continue;
                }
                out += c;
                break;

            case State::FSTRING_S:
            case State::FSTRING_D:
                handle_fstring_replace(src, i, state, brace_depth, out);
                break;

            case State::COMMENT:
                if (c == '\n') state = State::NORMAL;
                out += c;
                break;
            }
            ++i;
        }

        return out;
    }

    void handle_fstring_replace(const std::string& src, size_t& i,
                                State& state, int& brace_depth,
                                std::string& out) {
        char c = src[i];
        char delim = (state == State::FSTRING_S) ? '\'' : '"';

        if (brace_depth > 0) {
            // Reset mod_seen_ when chain breaks (non-dot, non-id char)
            if (mod_seen_ && c != '.' && !is_id_start(c)) {
                mod_seen_ = false;
            }
            if (c == '{') {
                ++brace_depth; out += c;
            } else if (c == '}') {
                --brace_depth; out += c;
            } else if (c == ':' && brace_depth == 1) {
                // Format specifier: {expr:fmt} — copy everything until '}'
                out += c;
                ++i;
                while (i < src.size() && src[i] != '}') {
                    if (src[i] == '{') {
                        // Nested expression in format spec
                        int nested = 1;
                        out += src[i]; ++i;
                        while (i < src.size() && nested > 0) {
                            if (src[i] == '{') ++nested;
                            else if (src[i] == '}') --nested;
                            out += src[i]; ++i;
                        }
                    } else {
                        out += src[i]; ++i;
                    }
                }
                // Don't consume '}' — let the main loop handle it
                // Back up one so main loop's ++i lands on '}'
                if (i > 0) --i;
                return;
            } else if (c == '!' && brace_depth == 1) {
                // Conversion flag: {expr!r} — copy as-is
                out += c;
                while (i + 1 < src.size() && src[i+1] != ':' && src[i+1] != '}') {
                    ++i; out += src[i];
                }
                return;
            } else if (c == '\\' && i + 1 < src.size()) {
                out += c; out += src[i+1]; i += 1; return; // i+1 then main loop ++i
            } else if (c == '\'' || c == '"') {
                char nested_delim = c;
                out += c;
                ++i;
                while (i < src.size()) {
                    if (src[i] == '\\') { out += src[i]; if (i+1<src.size()) out += src[i+1]; i += 2; continue; }
                    if (src[i] == nested_delim) { out += src[i]; ++i; break; }
                    out += src[i]; ++i;
                }
                return; // i past closing quote; main loop ++i advances to next
            } else if (c == '.' && mod_seen_) {
                // Dot after a module name inside f-string expression — output as-is
                out += c;
                return;
            } else if (is_id_start(c)) {
                size_t start = i;
                std::string id = collect_id(src, i);
                if (mod_seen_) {
                    // Attribute of a module — output as-is
                    // Keep mod_seen_ = true for chained access (os.path.join)
                    out += id;
                    if (module_names_.count(id) == 0) {
                        mod_seen_ = false;
                    }
                } else {
                    auto it = map_.find(id);
                    if (it != map_.end()) {
                        out += it->second;
                    } else {
                        out += id;
                    }
                }
                // Check if this identifier is a module name for dot-attribute tracking
                if (module_names_.count(id) > 0) {
                    mod_seen_ = true;
                }
                --i; return; // collect_id advanced i past id; back up so main ++i lands right
            } else {
                out += c;
            }
        } else {
            if (c == '{') {
                brace_depth = 1; out += c;
            } else if (c == delim) {
                state = State::NORMAL; mod_seen_ = true; out += c;
            } else if (c == '\\' && i + 1 < src.size()) {
                out += c; out += src[i+1]; i += 1; return;
            } else {
                out += c;
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::string scramble_identifiers(const std::string& source) {
    if (source.empty()) return source;

    std::random_device rd;
    ScrambleEngine engine(rd());
    return engine.run(source);
}

} // namespace switch_scramble
