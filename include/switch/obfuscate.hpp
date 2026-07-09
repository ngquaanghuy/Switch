#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>

namespace switch_obf {

// Supported obfuscation techniques.
enum class ObfType {
    NameMangling,   // Rename variables/functions/classes to short obfuscated names
    StringEncoding, // Encode string literals (chr(), bytes(), base64)
    DocStrip,       // Remove docstrings and comments
    Literal,        // Obfuscate numeric/boolean/None literals
};

// Parse an obfuscation technique name (case-insensitive).
// "namemangling", "NameMangling", "NAMEMANGLING" → ObfType::NameMangling
std::optional<ObfType> parse_obf_type(std::string_view name);

// Get canonical lowercase name for an obfuscation type.
std::string_view obf_type_name(ObfType type);

// Comma-separated list of all valid obfuscation technique names.
std::string all_obf_names();

// Apply obfuscation to Python source code.
// Returns obfuscated source. Empty string on error.
std::string obfuscate(ObfType type, const std::string& source);

} // namespace switch_obf
