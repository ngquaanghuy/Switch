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

    // --- Pass 1: Collect identifiers ---

    void collect(const std::string& src) {
        State state = State::NORMAL;
        int brace_depth = 0;
        size_t i = 0;
        const size_t n = src.size();

        while (i < n) {
            char c = src[i];

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
                } else if ((c == 'f' || c == 'F') && i + 1 < n && (src[i+1] == '\'' || src[i+1] == '"')) {
                    // f-string: f"..." or f'...'
                    state = (src[i+1] == '\'') ? State::FSTRING_S : State::FSTRING_D;
                    brace_depth = 0;
                    i += 2; // skip f and opening quote
                    continue;
                } else if (c == '@') {
                    // Decorator — skip @ and the decorator name
                    ++i;
                    while (i < n && (src[i] == ' ' || src[i] == '\t')) ++i;
                    if (i < n && is_id_start(src[i])) {
                        while (i < n && is_id_char(src[i])) ++i;
                    }
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
                            // For "from X": X is module name → skip, but Y in "from X import Y" is user-mapped
                            if (!is_from) {
                                import_names_.insert(peek_id);
                            }
                            // For "from X import Y": Y names will be handled by normal collection
                            // (they get mapped which is correct — they're user-defined aliases)
                        }
                    } else if (!is_keyword(id) && !is_builtin(id) && import_names_.count(id) == 0) {
                        // Skip keywords, builtins, dunders
                        bool is_dunder = id.size() > 4 && id.substr(0, 2) == "__" && id.substr(id.size() - 2) == "__";
                        if (!is_dunder) {
                            map_id(id);
                        }
                    }
                } else {
                    // Not an identifier start — just advance
                }
                break;

            case State::SINGLE_QUOTE:
                if (c == '\\' && i + 1 < n) { i += 2; continue; }
                if (c == '\'') state = State::NORMAL;
                break;

            case State::DOUBLE_QUOTE:
                if (c == '\\' && i + 1 < n) { i += 2; continue; }
                if (c == '"') state = State::NORMAL;
                break;

            case State::TRIPLE_SINGLE:
                if (c == '\\' && i + 1 < n) { i += 2; continue; }
                if (c == '\'' && i + 2 < n && src[i+1] == '\'' && src[i+2] == '\'') {
                    state = State::NORMAL; i += 3; continue;
                }
                break;

            case State::TRIPLE_DOUBLE:
                if (c == '\\' && i + 1 < n) { i += 2; continue; }
                if (c == '"' && i + 2 < n && src[i+1] == '"' && src[i+2] == '"') {
                    state = State::NORMAL; i += 3; continue;
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
            if (c == '{') {
                ++brace_depth;
            } else if (c == '}') {
                --brace_depth;
            } else if (c == '\\' && i + 1 < src.size()) {
                i += 2; return; // skip escape
            } else if (c == '\'' || c == '"') {
                // Nested string inside expression — skip to matching close
                char nested_delim = c;
                ++i;
                while (i < src.size()) {
                    if (src[i] == '\\') { i += 2; continue; }
                    if (src[i] == nested_delim) break;
                    ++i;
                }
                return; // i already past closing quote
            } else if (is_id_start(c)) {
                std::string id = collect_id(src, i);
                if (!is_keyword(id) && !is_builtin(id)) {
                    bool is_dunder = id.size() > 4 && id.substr(0, 2) == "__" && id.substr(id.size() - 2) == "__";
                    if (!is_dunder) map_id(id);
                }
                return; // collect_id already advanced i
            }
        } else {
            // Outside expression in f-string
            if (c == '{') {
                brace_depth = 1;
            } else if (c == delim) {
                // End of f-string
                state = State::NORMAL;
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

        while (i < n) {
            char c = src[i];
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
                } else if ((c == 'f' || c == 'F') && i + 1 < n && (src[i+1] == '\'' || src[i+1] == '"')) {
                    out += c;
                    out += src[i+1];
                    state = (src[i+1] == '\'') ? State::FSTRING_S : State::FSTRING_D;
                    brace_depth = 0;
                    i += 2;
                    continue;
                } else if (c == '@') {
                    // Decorator: output @ and the decorator name as-is
                    out += c;
                    ++i;
                    while (i < n && (src[i] == ' ' || src[i] == '\t')) { out += src[i]; ++i; }
                    if (i < n && is_id_start(src[i])) {
                        size_t start = i;
                        while (i < n && is_id_char(src[i])) ++i;
                        out += src.substr(start, i - start);
                    }
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

                    auto it = map_.find(id);
                    if (it != map_.end() && import_names_.count(id) == 0) {
                        out += it->second;
                    } else {
                        out += id;
                    }
                    // i now points past the identifier; continue to re-examine current position
                    continue;
                } else {
                    out += c;
                }
                break;

            case State::SINGLE_QUOTE:
                if (c == '\\' && i + 1 < n) { out += c; out += src[i+1]; i += 2; continue; }
                if (c == '\'') state = State::NORMAL;
                out += c;
                break;

            case State::DOUBLE_QUOTE:
                if (c == '\\' && i + 1 < n) { out += c; out += src[i+1]; i += 2; continue; }
                if (c == '"') state = State::NORMAL;
                out += c;
                break;

            case State::TRIPLE_SINGLE:
                if (c == '\\' && i + 1 < n) { out += c; out += src[i+1]; i += 2; continue; }
                if (c == '\'' && i + 2 < n && src[i+1] == '\'' && src[i+2] == '\'') {
                    state = State::NORMAL; out += "'''"; i += 3; continue;
                }
                out += c;
                break;

            case State::TRIPLE_DOUBLE:
                if (c == '\\' && i + 1 < n) { out += c; out += src[i+1]; i += 2; continue; }
                if (c == '"' && i + 2 < n && src[i+1] == '"' && src[i+2] == '"') {
                    state = State::NORMAL; out += "\"\"\""; i += 3; continue;
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
            if (c == '{') {
                ++brace_depth; out += c;
            } else if (c == '}') {
                --brace_depth; out += c;
            } else if (c == '\\' && i + 1 < src.size()) {
                out += c; out += src[i+1]; i += 2; return;
            } else if (c == '\'' || c == '"') {
                char nested_delim = c;
                out += c;
                ++i;
                while (i < src.size()) {
                    if (src[i] == '\\') { out += src[i]; if (i+1<src.size()) out += src[i+1]; i += 2; continue; }
                    if (src[i] == nested_delim) { out += src[i]; break; }
                    out += src[i]; ++i;
                }
                return;
            } else if (is_id_start(c)) {
                size_t start = i;
                std::string id = collect_id(src, i);
                auto it = map_.find(id);
                if (it != map_.end()) {
                    out += it->second;
                } else {
                    out += id;
                }
                return;
            } else {
                out += c;
            }
        } else {
            if (c == '{') {
                brace_depth = 1; out += c;
            } else if (c == delim) {
                state = State::NORMAL; out += c;
            } else if (c == '\\' && i + 1 < src.size()) {
                out += c; out += src[i+1]; i += 2; return;
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
