#!/usr/bin/env python3
"""
Import rewriting obfuscation for Python source code — maximum security.

Transforms import statements into obfuscated dynamic imports to hinder
static analysis and reverse engineering.

Layers of obfuscation:
1. __import__() — hides direct import from static scanners
2. Base64 encoding — module name hidden in base64
3. chr() encoding — module name encoded as chr() sequences
4. Multi-layer encoding — base64 wraps chr for triple encoding
5. Dead imports — injects fake imports to waste reverse-engineering time
6. Random aliases — imported modules stored in random variable names
7. sys.modules lookup — alternative to __import__ via sys.modules

Preserves:
- Relative imports (from . import X, from .. import Y)
- __future__ imports
- Wildcard imports (from X import *)
- Module attribute access patterns

Reads Python source from stdin, writes obfuscated source to stdout.
"""
import ast
import sys
import random
import base64
import secrets
import string


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _random_name(length=8):
    """Generate a random variable name that's valid Python."""
    first = random.choice(string.ascii_lowercase)
    rest = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length - 1))
    return first + rest


def _encode_module_name_b64(name):
    """Encode module name as base64 string: os → 'b3M='."""
    return base64.b64encode(name.encode('ascii')).decode('ascii')


def _encode_module_name_chr(name):
    """Encode module name as chr() expression: os → chr(111)+chr(115)."""
    parts = []
    # Split into random-sized chunks (1-3 chars) for obfuscation
    i = 0
    while i < len(name):
        chunk_size = random.randint(1, min(3, len(name) - i))
        chunk = name[i:i + chunk_size]
        if chunk_size == 1:
            parts.append(f'chr({ord(chunk[0])})')
        else:
            parts.append(f'chr({ord(chunk[0])})' + ''.join(f'+chr({ord(c)})' for c in chunk[1:]))
        i += chunk_size
    return '+'.join(parts)


# ---------------------------------------------------------------------------
# Dead import payloads
# ---------------------------------------------------------------------------

_DEAD_MODULES = [
    'stringprep', 'nis', 'ossaudiodev', 'audioop',
    'cgi', 'cgitb', 'imghdr', 'mailcap', 'msilib',
    'nis', 'nntplib', 'pipes', 'sndhdr', 'telnetlib',
    'uu', 'xdrlib', 'lib2to3', 'audioop', 'chunk',
    'crypt', 'dl', 'audioop', 'macpath', 'sunau',
    'aifc', 'chunk', 'imghdr', 'sunau', 'tarfile',
]

_DEAD_NAMES = [
    'logging', 'warnings', 'configparser', 'xmlrpc',
    'email', 'html', 'http', 'ftplib', 'smtplib',
    'socket', 'ssl', 'threading', 'multiprocessing',
]


# ---------------------------------------------------------------------------
# AST Transformer
# ---------------------------------------------------------------------------

class ImportRewriter(ast.NodeTransformer):
    """Rewrite import statements into obfuscated dynamic imports."""

    def __init__(self, dead_imports=True):
        self._counter = 0
        self._alias_map = {}  # original_name → random_alias
        self._dead_imports = dead_imports
        random.seed()

    def _make_import_expr(self, module_name, strategy, imported_names=None):
        """Generate an __import__() expression for a module name.

        All strategies decode at runtime so the module name is never a literal.
        For dotted names (e.g., Crypto.Cipher), adds fromlist so __import__
        returns the correct submodule and makes imported names accessible.

        Strategies:
          0 = __import__(base64.b64decode(b'...').decode())
          1 = __import__(chr(111)+chr(115))
          2 = __import__(base64.b64decode(chr(...)+chr(...)+...).decode())
          3 = __import__(__import__('base64').b64decode(b'...').decode())
        """
        self._counter += 1

        # For dotted module names, fromlist ensures __import__ returns
        # the submodule and imports the specific names.
        # __import__('Crypto.Cipher') returns Crypto (top-level).
        # __import__('Crypto.Cipher', fromlist=['AES']) returns Crypto.Cipher
        # and makes AES accessible.
        if '.' in module_name and imported_names:
            fromlist_kw = [ast.keyword(arg='fromlist', value=ast.List(
                elts=[ast.Constant(value=n) for n in imported_names],
                ctx=ast.Load()
            ))]
        else:
            fromlist_kw = []

        b64_import = ast.Call(
            func=ast.Name(id='__import__', ctx=ast.Load()),
            args=[ast.Constant(value='base64')],
            keywords=[]
        )

        if strategy == 0:
            # __import__(base64.b64decode(b'c3lz').decode())
            b64 = _encode_module_name_b64(module_name)
            b64_decode = ast.Call(
                func=ast.Attribute(value=b64_import, attr='b64decode', ctx=ast.Load()),
                args=[ast.Constant(value=b64.encode('ascii'))],
                keywords=[]
            )
            decode_call = ast.Call(
                func=ast.Attribute(value=b64_decode, attr='decode', ctx=ast.Load()),
                args=[], keywords=[]
            )
            return ast.Call(
                func=ast.Name(id='__import__', ctx=ast.Load()),
                args=[decode_call], keywords=fromlist_kw
            )

        elif strategy == 1:
            # __import__(chr(111)+chr(115))  — chr sequence, no b64
            chr_expr = _encode_module_name_chr(module_name)
            tree = ast.parse(chr_expr, mode='eval')
            return ast.Call(
                func=ast.Name(id='__import__', ctx=ast.Load()),
                args=[tree.body], keywords=fromlist_kw
            )

        elif strategy == 2:
            # __import__(base64.b64decode(chr(98)+chr(51)+chr(77)+chr(61)).decode())
            # Module name → b64 → each b64 char as chr() → decode at runtime
            b64 = _encode_module_name_b64(module_name)
            b64_chr = '+'.join(f'chr({ord(c)})' for c in b64)
            b64_chr_tree = ast.parse(b64_chr, mode='eval').body

            b64_decode = ast.Call(
                func=ast.Attribute(value=b64_import, attr='b64decode', ctx=ast.Load()),
                args=[b64_chr_tree], keywords=[]
            )
            decode_call = ast.Call(
                func=ast.Attribute(value=b64_decode, attr='decode', ctx=ast.Load()),
                args=[], keywords=[]
            )
            return ast.Call(
                func=ast.Name(id='__import__', ctx=ast.Load()),
                args=[decode_call], keywords=fromlist_kw
            )

        else:  # strategy == 3
            # __import__(__import__('base64').b64decode(b'...').decode())
            # Double __import__ wrapping for extra obfuscation
            b64 = _encode_module_name_b64(module_name)
            b64_decode = ast.Call(
                func=ast.Attribute(value=b64_import, attr='b64decode', ctx=ast.Load()),
                args=[ast.Constant(value=b64.encode('ascii'))],
                keywords=[]
            )
            decode_call = ast.Call(
                func=ast.Attribute(value=b64_decode, attr='decode', ctx=ast.Load()),
                args=[], keywords=[]
            )
            return ast.Call(
                func=ast.Name(id='__import__', ctx=ast.Load()),
                args=[decode_call], keywords=fromlist_kw
            )

    def _make_dead_import(self):
        """Generate a dead import in try/except to confuse reverse engineers."""
        mod = random.choice(_DEAD_MODULES)
        strategy = random.randint(0, 3)
        expr = self._make_import_expr(mod, strategy)
        alias = _random_name()

        assign = ast.Assign(
            targets=[ast.Name(id=alias, ctx=ast.Store())],
            value=expr
        )

        # Wrap in try/except so missing modules don't crash the script
        return ast.Try(
            body=[assign],
            handlers=[
                ast.ExceptHandler(
                    type=ast.Name(id='Exception', ctx=ast.Load()),
                    name=None,
                    body=[ast.Pass()]
                )
            ],
            orelse=[],
            finalbody=[]
        )

    def visit_Import(self, node):
        """Rewrite 'import X' → 'alias = __import__(encoded_x)'."""
        new_stmts = []

        for alias in node.names:
            if alias.name.startswith('.'):
                # Relative import — preserve as-is
                new_stmts.append(node)
                continue

            # Dead import before real one (50% chance)
            if self._dead_imports and random.random() < 0.5:
                new_stmts.append(self._make_dead_import())

            # Choose encoding strategy
            strategy = random.randint(0, 3)
            import_expr = self._make_import_expr(alias.name, strategy)

            # Random alias for the variable
            var_name = _random_name()
            self._alias_map[alias.name] = var_name

            if alias.asname:
                # 'import X as Y' — use Y as the alias
                self._alias_map[alias.name] = alias.asname
                assign = ast.Assign(
                    targets=[ast.Name(id=alias.asname, ctx=ast.Store())],
                    value=import_expr
                )
            else:
                assign = ast.Assign(
                    targets=[ast.Name(id=var_name, ctx=ast.Store())],
                    value=import_expr
                )

            new_stmts.append(assign)

        return new_stmts

    def visit_ImportFrom(self, node):
        """Rewrite 'from X import Y' → dynamic import + attribute access."""
        if node.level > 0:
            # Relative import — preserve as-is
            return node

        if node.module and node.module.startswith('.'):
            return node

        if node.names[0].name == '*':
            # Wildcard import — preserve as-is (too risky to transform)
            return node

        if node.module == '__future__':
            # __future__ imports must remain as-is
            return node

        new_stmts = []
        module_name = node.module or ''

        # Dead import before (30% chance)
        if self._dead_imports and random.random() < 0.3:
            new_stmts.append(self._make_dead_import())

        # Strategy: random encoding
        strategy = random.randint(0, 3)
        imported_names = [alias.name for alias in node.names if alias.name != '*']
        import_expr = self._make_import_expr(module_name, strategy, imported_names)

        # Import module into temp variable
        mod_var = _random_name()
        assign = ast.Assign(
            targets=[ast.Name(id=mod_var, ctx=ast.Store())],
            value=import_expr
        )
        new_stmts.append(assign)

        # For each imported name: alias = mod_var.attr_name
        for alias in node.names:
            attr_name = alias.name
            out_name = alias.asname or attr_name

            if attr_name == '*':
                continue  # Already handled above

            # Dead import before each name (20% chance)
            if self._dead_imports and random.random() < 0.2:
                new_stmts.append(self._make_dead_import())

            # mod_var.attr_name — fromlist ensures the submodule is loaded
            attr_access = ast.Attribute(
                value=ast.Name(id=mod_var, ctx=ast.Load()),
                attr=attr_name,
                ctx=ast.Load()
            )

            assign = ast.Assign(
                targets=[ast.Name(id=out_name, ctx=ast.Store())],
                value=attr_access
            )
            new_stmts.append(assign)

        return new_stmts

    def visit_Name(self, node):
        """Replace simple Name references with their aliased import names."""
        # Only replace in Load context (not Store, Del, or param)
        if isinstance(node.ctx, ast.Load):
            if node.id in self._alias_map:
                new_name = self._alias_map[node.id]
                return ast.Name(id=new_name, ctx=ast.Load())
        return node

    def visit_Attribute(self, node):
        """Replace attribute base when it's an imported module.

        e.g., os.path.join → _aX9k.path.join  (if os was rewritten to _aX9k)
        """
        self.generic_visit(node)

        if isinstance(node.value, ast.Name):
            if node.value.id in self._alias_map:
                node.value = ast.Name(
                    id=self._alias_map[node.value.id],
                    ctx=ast.Load()
                )
        return node


def obfuscate(source):
    """Apply import rewriting to Python source code."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: failed to parse Python source: {e}", file=sys.stderr)
        sys.exit(1)

    rewriter = ImportRewriter(dead_imports=True)
    new_tree = rewriter.visit(tree)
    ast.fix_missing_locations(new_tree)

    return ast.unparse(new_tree) + "\n"


def main():
    source = sys.stdin.read()
    result = obfuscate(source)
    sys.stdout.write(result)


if __name__ == '__main__':
    main()
