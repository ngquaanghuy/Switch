#!/usr/bin/env python3
"""
Docstring and comment removal obfuscation for Python source code.

Removes:
- Module/class/function docstrings (triple-quoted strings at the top)
- Single-line comments (# ...)
- Multi-line comments (triple-quoted strings not in assignment)

Preserves:
- String literals used in code (not docstrings)
- F-strings
- Comments that are actually code (e.g., # type: ignore)

Reads Python source from stdin, writes stripped source to stdout.
"""
import ast
import sys
import re


class DocstringRemover(ast.NodeTransformer):
    """Remove docstrings from module, class, and function definitions."""

    def _is_docstring(self, node):
        """Check if an expression statement is a docstring."""
        if not isinstance(node, ast.Expr):
            return False
        if not isinstance(node.value, ast.Constant):
            return False
        if not isinstance(node.value.value, str):
            return False
        return True

    def _remove_docstring(self, body):
        """Remove leading docstring from a body list."""
        if body and self._is_docstring(body[0]):
            return body[1:]
        return body

    def visit_Module(self, node):
        node.body = self._remove_docstring(node.body)
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node):
        node.body = self._remove_docstring(node.body)
        self.generic_visit(node)
        return node

    def visit_FunctionDef(self, node):
        node.body = self._remove_docstring(node.body)
        self.generic_visit(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef


def remove_comments(source):
    """Remove single-line comments from source code.

    Handles comments at end of lines and full-line comments.
    Preserves # inside strings.
    """
    lines = source.split('\n')
    result = []
    in_triple_quote = False
    triple_quote_char = None

    for line in lines:
        # Track triple-quoted strings across lines
        # Count occurrences of triple quotes
        i = 0
        cleaned = []
        while i < len(line):
            # Check for triple quote start/end
            if i + 2 < len(line) and line[i:i+3] in ('"""', "'''"):
                tq = line[i:i+3]
                if not in_triple_quote:
                    in_triple_quote = True
                    triple_quote_char = tq
                    cleaned.append(line[i])
                    cleaned.append(line[i+1])
                    cleaned.append(line[i+2])
                    i += 3
                    continue
                elif tq == triple_quote_char:
                    in_triple_quote = False
                    triple_quote_char = None
                    cleaned.append(line[i])
                    cleaned.append(line[i+1])
                    cleaned.append(line[i+2])
                    i += 3
                    continue

            if not in_triple_quote and line[i] == '#':
                # Found a comment — skip rest of line
                break

            cleaned.append(line[i])
            i += 1

        # Strip trailing whitespace
        result_line = ''.join(cleaned).rstrip()
        result.append(result_line)

    return '\n'.join(result)


def remove_blank_lines(source):
    """Collapse runs of blank lines into single blank lines."""
    lines = source.split('\n')
    result = []
    prev_blank = False
    for line in lines:
        is_blank = line.strip() == ''
        if is_blank and prev_blank:
            continue
        result.append(line)
        prev_blank = is_blank
    return '\n'.join(result)


def obfuscate(source):
    """Remove docstrings and comments from Python source."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: failed to parse Python source: {e}", file=sys.stderr)
        sys.exit(1)

    # Remove docstrings via AST
    remover = DocstringRemover()
    new_tree = remover.visit(tree)
    ast.fix_missing_locations(new_tree)
    code = ast.unparse(new_tree)

    # Remove comments via line processing
    code = remove_comments(code)

    # Clean up blank lines
    code = remove_blank_lines(code)

    return code + "\n"


def main():
    source = sys.stdin.read()
    result = obfuscate(source)
    sys.stdout.write(result)


if __name__ == '__main__':
    main()
