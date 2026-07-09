#!/usr/bin/env python3
"""
String encoding obfuscation for Python source code.

Encodes string literals into obfuscated forms:
- chr() sequences: "Hello" → "".join([chr(72), chr(101), chr(108), chr(108), chr(111)])
- bytes().decode(): "Hello" → bytes([72,101,108,108,111]).decode()
- b64: "Hello" → __import__('base64').b64decode(b'SGVsbG8=').decode()

Reads Python source from stdin, writes obfuscated source to stdout.

Usage: echo 'code' | python3 obf_stringencode.py
       python3 obf_stringencode.py < input.py
"""
import ast
import sys
import base64
import random


class StringEncoder(ast.NodeTransformer):
    """Replace string constants with encoded representations."""

    def __init__(self, strategy='mixed'):
        self.strategy = strategy
        self._counter = 0
        self._in_fstring = False  # Track if we're inside an f-string

    def _encode_chr(self, s):
        """Encode string as chr() call: "".join([chr(72), chr(101), ...])"""
        if not s:
            return ast.Constant(value='')
        if len(s) == 1:
            return ast.Call(
                func=ast.Name(id='chr', ctx=ast.Load()),
                args=[ast.Constant(value=ord(s[0]))],
                keywords=[]
            )
        elts = [ast.Call(
            func=ast.Name(id='chr', ctx=ast.Load()),
            args=[ast.Constant(value=ord(c))],
            keywords=[]
        ) for c in s]
        join_call = ast.Call(
            func=ast.Constant(value=''),
            args=[],
            keywords=[ast.keyword(arg='sep', value=ast.Constant(value=''))]
        )
        return ast.Call(
            func=ast.Attribute(
                value=ast.Constant(value=''),
                attr='join',
                ctx=ast.Load()
            ),
            args=[
                ast.List(elts=elts, ctx=ast.Load())
            ],
            keywords=[]
        )

    def _encode_bytes(self, s):
        """Encode string as bytes([...]).decode()"""
        byte_vals = [ast.Constant(value=b) for b in s.encode('utf-8')]
        bytes_call = ast.Call(
            func=ast.Name(id='bytes', ctx=ast.Load()),
            args=[ast.List(elts=byte_vals, ctx=ast.Load())],
            keywords=[]
        )
        return ast.Call(
            func=ast.Attribute(
                value=bytes_call,
                attr='decode',
                ctx=ast.Load()
            ),
            args=[],
            keywords=[]
        )

    def _encode_b64(self, s):
        """Encode string as __import__('base64').b64decode(b'...').decode()"""
        b64 = base64.b64encode(s.encode('utf-8')).decode('ascii')
        b64_import = ast.Call(
            func=ast.Name(id='__import__', ctx=ast.Load()),
            args=[ast.Constant(value='base64')],
            keywords=[]
        )
        b64_decode = ast.Call(
            func=ast.Attribute(
                value=b64_import,
                attr='b64decode',
                ctx=ast.Load()
            ),
            args=[ast.Constant(value=b64.encode('ascii'))],
            keywords=[]
        )
        return ast.Call(
            func=ast.Attribute(
                value=b64_decode,
                attr='decode',
                ctx=ast.Load()
            ),
            args=[],
            keywords=[]
        )

    def _choose_encoding(self, s):
        """Choose encoding strategy for a string."""
        if self.strategy == 'chr':
            return self._encode_chr(s)
        elif self.strategy == 'bytes':
            return self._encode_bytes(s)
        elif self.strategy == 'b64':
            return self._encode_b64(s)
        else:  # mixed
            # Use different strategies for variety
            self._counter += 1
            if len(s) == 0:
                return ast.Constant(value='')
            elif len(s) <= 3:
                return self._encode_chr(s)
            elif self._counter % 3 == 0:
                return self._encode_b64(s)
            elif self._counter % 3 == 1:
                return self._encode_bytes(s)
            else:
                return self._encode_chr(s)

    def visit_JoinedStr(self, node):
        """Don't recurse into f-strings — their internal constants can't be replaced."""
        return node

    def visit_Constant(self, node):
        """Replace string constants with encoded forms."""
        if not isinstance(node.value, str):
            return node

        # Don't encode empty strings
        if len(node.value) == 0:
            return node

        # Don't encode strings that are just whitespace
        if node.value.strip() == '' and len(node.value) <= 2:
            return node

        return self._choose_encoding(node.value)


def obfuscate(source, strategy='mixed'):
    """Apply string encoding to Python source code."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: failed to parse Python source: {e}", file=sys.stderr)
        sys.exit(1)

    encoder = StringEncoder(strategy=strategy)
    new_tree = encoder.visit(tree)
    ast.fix_missing_locations(new_tree)

    return ast.unparse(new_tree) + "\n"


def main():
    strategy = sys.argv[1] if len(sys.argv) > 1 else 'mixed'
    source = sys.stdin.read()
    result = obfuscate(source, strategy)
    sys.stdout.write(result)


if __name__ == '__main__':
    main()
