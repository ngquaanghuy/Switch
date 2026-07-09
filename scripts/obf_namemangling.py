#!/usr/bin/env python3
"""
Name mangling obfuscation for Python source code.

Reads Python source from stdin, renames user-defined identifiers
to short obfuscated names, writes result to stdout.

Usage: echo 'code' | python3 obf_namemangling.py
       python3 obf_namemangling.py < input.py
"""
import ast
import sys
import builtins


# Names that must never be renamed
BUILTIN_NAMES = set(dir(builtins))

# Dunder methods that must be preserved
DUNDER_PATTERN = '__'


def generate_names():
    """Generate short obfuscated names: _a, _b, ..., _z, _aa, _ab, ..."""
    chars = 'abcdefghijklmnopqrstuvwxyz'
    idx = 0
    while True:
        name = '_' + chars[idx % len(chars)]
        if idx >= len(chars):
            name = '_' + chars[idx // len(chars) - 1] + chars[idx % len(chars)]
        idx += 1
        yield name


class NameCollector(ast.NodeVisitor):
    """First pass: collect all user-defined names that should be renamed."""

    def __init__(self):
        self.names = set()
        self.string_refs = set()  # names that appear as string constants

    def visit_FunctionDef(self, node):
        self.names.add(node.name)
        for arg in node.args.args:
            if arg.arg not in ('self', 'cls'):
                self.names.add(arg.arg)
        if node.args.vararg:
            self.names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.names.add(node.args.kwarg.arg)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.names.add(node.name)
        self.generic_visit(node)

    def visit_Name(self, node):
        self.names.add(node.id)
        self.generic_visit(node)

    def visit_Constant(self, node):
        """Collect names that appear as string constants (potential dynamic references)."""
        if isinstance(node.value, str):
            self.string_refs.add(node.value)
        self.generic_visit(node)

    def visit_For(self, node):
        if isinstance(node.target, ast.Name):
            self.names.add(node.target.id)
        elif isinstance(node.target, ast.Tuple):
            for elt in node.target.elts:
                if isinstance(elt, ast.Name):
                    self.names.add(elt.id)
        self.generic_visit(node)

    visit_With = visit_For

    def visit_Import(self, node):
        # Don't rename import targets
        pass

    def visit_ImportFrom(self, node):
        pass


class NameMangler(ast.NodeTransformer):
    """Second pass: rename all collected user-defined names."""

    def __init__(self, mapping):
        self.mapping = mapping

    def _rename(self, name):
        return self.mapping.get(name, name)

    def visit_FunctionDef(self, node):
        node.name = self._rename(node.name)
        # Rename arguments
        for arg in node.args.args:
            if arg.arg not in ('self', 'cls'):
                arg.arg = self._rename(arg.arg)
        if node.args.vararg:
            node.args.vararg.arg = self._rename(node.args.vararg.arg)
        if node.args.kwarg:
            node.args.kwarg.arg = self._rename(node.args.kwarg.arg)
        self.generic_visit(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        node.name = self._rename(node.name)
        self.generic_visit(node)
        return node

    def visit_Name(self, node):
        node.id = self._rename(node.id)
        return node

    def visit_arg(self, node):
        if node.arg not in ('self', 'cls'):
            node.arg = self._rename(node.arg)
        return node

    def visit_For(self, node):
        if isinstance(node.target, ast.Name):
            node.target.id = self._rename(node.target.id)
        elif isinstance(node.target, ast.Tuple):
            for elt in node.target.elts:
                if isinstance(elt, ast.Name):
                    elt.id = self._rename(elt.id)
        self.generic_visit(node)
        return node

    visit_With = visit_For

    def visit_Attribute(self, node):
        # Rename attribute accesses (e.g., obj.add → obj._c)
        node.attr = self._rename(node.attr)
        self.generic_visit(node)
        return node

    def visit_keyword(self, node):
        # Don't rename keyword argument names (they're strings in AST)
        self.generic_visit(node)
        return node

    def visit_Global(self, node):
        node.names = [self._rename(n) for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [self._rename(n) for n in node.names]
        return node

    def visit_ExceptHandler(self, node):
        if node.name:
            node.name = self._rename(node.name)
        self.generic_visit(node)
        return node


def obfuscate(source):
    """Apply name mangling to Python source code."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: failed to parse Python source: {e}", file=sys.stderr)
        sys.exit(1)

    # Collect names
    collector = NameCollector()
    collector.visit(tree)

    # Filter: skip builtins, dunders, and names appearing as string constants
    skip = set()
    skip.update(BUILTIN_NAMES)
    skip.add('self')
    skip.add('cls')
    for name in collector.names:
        if name.startswith(DUNDER_PATTERN) and name.endswith(DUNDER_PATTERN) and len(name) > 2:
            skip.add(name)
        # Don't rename names that appear as string values (potential getattr/dynamic usage)
        if name in collector.string_refs:
            skip.add(name)
        # Don't rename single underscore (Python convention for "don't care")
        if name == '_':
            skip.add(name)

    # Build mapping
    mapper = generate_names()
    mapping = {}
    for name in sorted(collector.names):  # sorted for deterministic output
        if name not in skip:
            new_name = next(mapper)
            while new_name in skip or new_name in mapping.values():
                new_name = next(mapper)
            mapping[name] = new_name

    if not mapping:
        # Nothing to rename
        return source

    # Apply renaming
    mangler = NameMangler(mapping)
    new_tree = mangler.visit(tree)
    ast.fix_missing_locations(new_tree)

    return ast.unparse(new_tree) + "\n"


def main():
    source = sys.stdin.read()
    result = obfuscate(source)
    sys.stdout.write(result)


if __name__ == '__main__':
    main()
