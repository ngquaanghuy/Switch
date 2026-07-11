#!/usr/bin/env python3
"""
XOR string encoding obfuscation for Python source code.

Encodes string literals using multi-byte XOR with random keys.
Each string gets its own random key (2-6 bytes, repeating), making
frequency analysis impossible and each string independently reversible.

Security enhancements over single-byte XOR:
- Multi-byte key (2-6 bytes) eliminates frequency analysis
- Random key length per string prevents pattern matching
- Expression variation (join+chr, bytes+b64, reduce) avoids single regex

Transformations:
- "Hello" → ''.join(chr(c ^ 0x5A) for c in [0x28, 0x3f, 0x2c, 0x2c, 0x21])
- "Hi"   → bytes(a ^ b for a, b in zip([0x48, 0x69], [0x3C, 0x3C])).decode()

Reads Python source from stdin, writes obfuscated source to stdout.
"""
import ast
import sys
import random
import secrets
import base64


class XorEncoder(ast.NodeTransformer):
    """Replace string constants with XOR-encoded representations."""

    def __init__(self):
        self._counter = 0
        random.seed()  # Non-deterministic

    def _xor_bytes(self, s, key):
        """XOR each byte of s with repeating key."""
        encoded = []
        for i, b in enumerate(s.encode('utf-8')):
            encoded.append(b ^ key[i % len(key)])
        return encoded, key

    def _encode_join_chr(self, s, key):
        """Encode as ''.join(chr(c ^ k) for c in [...])

        Most readable to humans, least obvious to automated scanners
        that look for bytes().decode() or base64 patterns.
        """
        encoded, _ = self._xor_bytes(s, key)

        # Build: [encoded[0] ^ key[0], encoded[1] ^ key[1], ...]
        # Actually we store XOR-encoded bytes, runtime XORs back
        byte_list = ast.List(
            elts=[ast.Constant(value=b) for b in encoded],
            ctx=ast.Load()
        )

        # chr(c ^ key_byte) — key cycles via modulo
        if len(key) == 1:
            # Single-byte key: simple chr(c ^ K)
            xor_expr = ast.BinOp(
                left=ast.Name(id='c', ctx=ast.Load()),
                op=ast.BitXor(),
                right=ast.Constant(value=key[0])
            )
        else:
            # Multi-byte key: chr(c ^ key[_xi % len(key)])
            key_index = ast.BinOp(
                left=ast.Name(id='_xi', ctx=ast.Load()),
                op=ast.Mod(),
                right=ast.Constant(value=len(key))
            )
            xor_expr = ast.BinOp(
                left=ast.Name(id='c', ctx=ast.Load()),
                op=ast.BitXor(),
                right=ast.Subscript(
                    value=ast.Constant(value=bytes(key)),
                    slice=key_index,
                    ctx=ast.Load()
                )
            )

        chr_call = ast.Call(
            func=ast.Name(id='chr', ctx=ast.Load()),
            args=[xor_expr],
            keywords=[]
        )

        # Generator: (chr(val ^ key[idx % len(key)]) for idx, val in enumerate(encoded))
        gen = ast.GeneratorExp(
            elt=chr_call,
            generators=[
                ast.comprehension(
                    target=ast.Tuple(
                        elts=[
                            ast.Name(id='_xi', ctx=ast.Store()),
                            ast.Name(id='c', ctx=ast.Store()),
                        ],
                        ctx=ast.Store()
                    ),
                    iter=ast.Call(
                        func=ast.Name(id='enumerate', ctx=ast.Load()),
                        args=[byte_list],
                        keywords=[]
                    ),
                    ifs=[],
                    is_async=0
                )
            ]
        )

        return ast.Call(
            func=ast.Attribute(
                value=ast.Constant(value=''),
                attr='join',
                ctx=ast.Load()
            ),
            args=[gen],
            keywords=[]
        )

    def _encode_bytes_xor(self, s, key):
        """Encode as bytes(a ^ b for a, b in zip([...], cycle([K]))).decode()

        Uses bytes().decode() pattern — different visual from join+chr.
        """
        encoded, _ = self._xor_bytes(s, key)

        byte_list = ast.List(
            elts=[ast.Constant(value=b) for b in encoded],
            ctx=ast.Load()
        )

        key_list = ast.List(
            elts=[ast.Constant(value=k) for k in key],
            ctx=ast.Load()
        )

        # a ^ b where a comes from encoded bytes, b from cycling key
        xor_expr = ast.BinOp(
            left=ast.Name(id='a', ctx=ast.Load()),
            op=ast.BitXor(),
            right=ast.Name(id='b', ctx=ast.Load())
        )

        gen = ast.GeneratorExp(
            elt=xor_expr,
            generators=[
                ast.comprehension(
                    target=ast.Tuple(
                        elts=[
                            ast.Name(id='a', ctx=ast.Store()),
                            ast.Name(id='b', ctx=ast.Store()),
                        ],
                        ctx=ast.Store()
                    ),
                    iter=ast.Call(
                        func=ast.Name(id='zip', ctx=ast.Load()),
                        args=[byte_list, ast.Call(
                            func=ast.Name(id='cycle', ctx=ast.Load()),
                            args=[key_list],
                            keywords=[]
                        )],
                        keywords=[]
                    ),
                    ifs=[],
                    is_async=0
                )
            ]
        )

        # bytes(gen).decode()
        bytes_call = ast.Call(
            func=ast.Name(id='bytes', ctx=ast.Load()),
            args=[gen],
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

    def _encode_base64_xor(self, s, key):
        """Encode as __import__('base64').b64decode(b'...').decode() where
        the base64 payload contains XOR-encoded bytes.

        Triple-layer obfuscation: base64 → XOR → plaintext.
        """
        encoded, _ = self._xor_bytes(s, key)
        b64 = base64.b64encode(bytes(encoded)).decode('ascii')

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

        # bytes(b64decode(...)).decode() — XOR key embedded in the b64 payload
        # Wait, we need to XOR at runtime too. Let me think...
        # Actually the b64 decodes to the XOR-encoded bytes, then we need
        # to XOR with the key at runtime. So:
        # bytes(b ^ k for b, k in zip(b64decode(...), cycle([K]))).decode()

        decoded_var = ast.Name(id='_', ctx=ast.Load())
        xor_expr = ast.BinOp(
            left=ast.Name(id='b', ctx=ast.Load()),
            op=ast.BitXor(),
            right=ast.Name(id='k', ctx=ast.Load())
        )
        gen = ast.GeneratorExp(
            elt=xor_expr,
            generators=[
                ast.comprehension(
                    target=ast.Tuple(
                        elts=[
                            ast.Name(id='b', ctx=ast.Store()),
                            ast.Name(id='k', ctx=ast.Store()),
                        ],
                        ctx=ast.Store()
                    ),
                    iter=ast.Call(
                        func=ast.Name(id='zip', ctx=ast.Load()),
                        args=[
                            b64_decode,
                            ast.Call(
                                func=ast.Name(id='cycle', ctx=ast.Load()),
                                args=[ast.List(
                                    elts=[ast.Constant(value=k) for k in key],
                                    ctx=ast.Load()
                                )],
                                keywords=[]
                            )
                        ],
                        keywords=[]
                    ),
                    ifs=[],
                    is_async=0
                )
            ]
        )

        bytes_call = ast.Call(
            func=ast.Name(id='bytes', ctx=ast.Load()),
            args=[gen],
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

    def _choose_encoding(self, s):
        """Choose encoding strategy with expression variation."""
        # Generate random key (2-6 bytes, no null byte)
        key_len = random.randint(2, 6)
        key = [secrets.randbelow(255) + 1 for _ in range(key_len)]

        self._counter += 1

        if len(s) <= 3:
            # Short strings: always use join+chr (cleanest)
            return self._encode_join_chr(s, key)
        elif self._counter % 3 == 0:
            return self._encode_join_chr(s, key)
        elif self._counter % 3 == 1:
            return self._encode_bytes_xor(s, key)
        else:
            return self._encode_base64_xor(s, key)

    def visit_JoinedStr(self, node):
        """Don't recurse into f-strings — their internal constants can't be replaced."""
        return node

    def visit_Constant(self, node):
        """Replace string constants with XOR-encoded forms."""
        if not isinstance(node.value, str):
            return node

        # Don't encode empty strings
        if len(node.value) == 0:
            return node

        # Don't encode strings that are just whitespace (≤2 chars)
        if node.value.strip() == '' and len(node.value) <= 2:
            return node

        return self._choose_encoding(node.value)


def obfuscate(source):
    """Apply XOR encoding to Python source code."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: failed to parse Python source: {e}", file=sys.stderr)
        sys.exit(1)

    encoder = XorEncoder()
    new_tree = encoder.visit(tree)
    ast.fix_missing_locations(new_tree)

    # Add 'from itertools import cycle' if any strings were XOR-encoded
    if encoder._counter > 0:
        import_node = ast.ImportFrom(
            module='itertools',
            names=[ast.alias(name='cycle', asname=None)],
            level=0
        )
        new_tree.body.insert(0, import_node)

    return ast.unparse(new_tree) + "\n"


def main():
    source = sys.stdin.read()
    result = obfuscate(source)
    sys.stdout.write(result)


if __name__ == '__main__':
    main()
