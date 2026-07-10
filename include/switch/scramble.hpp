#pragma once

#include <string>

namespace switch_scramble {

// Scramble identifiers in Python source code.
// Replaces user-defined names with meaningless confusable strings.
// Returns obfuscated source. Empty string on error.
std::string scramble_identifiers(const std::string& source);

} // namespace switch_scramble
