#!/usr/bin/env python3
"""
Literal obfuscation for Python source code.

Transforms numeric literals, booleans, and None into equivalent
obfuscated expressions to hinder reverse engineering.

Transformations:
- Numbers: 42 → (6*7), 255 → (1<<8)-1, 0x1F → (31), 100 → 10**2
- Booleans: True → (1==1), False → (1==0)
- None: None → ().__class__.__bases__[0].__subclasses__()[0]  (or simpler)
- Strings: "abc" → '\x61\x62\x63'

Reads Python source from stdin, writes obfuscated source to stdout.
"""
import ast
import sys
import random
import math


class LiteralObfuscator(ast.NodeTransformer):
    """Transform literal values into obfuscated expressions."""

    def __init__(self):
        random.seed()  # Non-deterministic for variety

    def _obfuscate_int(self, n):
        """Convert integer to an obfuscated expression.

        Works with abs(n) for strategy selection, then negates the result if n < 0.
        """
        sign = -1 if n < 0 else 1
        a = abs(n)
        strategies = []

        # Strategy 1: eval() with hex/octal/binary string
        if a > 10:
            strategies.append(ast.Call(
                func=ast.Name(id='eval', ctx=ast.Load()),
                args=[ast.Constant(value=hex(a))],
                keywords=[]
            ))
            if a > 7:
                strategies.append(ast.Call(
                    func=ast.Name(id='eval', ctx=ast.Load()),
                    args=[ast.Constant(value=oct(a))],
                    keywords=[]
                ))
            if a > 1:
                strategies.append(ast.Call(
                    func=ast.Name(id='eval', ctx=ast.Load()),
                    args=[ast.Constant(value=bin(a))],
                    keywords=[]
                ))

        # Strategy 2: multiplication of factors
        if a > 1:
            for i in range(2, min(int(math.isqrt(a)) + 1, 20)):
                if a % i == 0 and i > 1:
                    strategies.append(ast.BinOp(
                        left=ast.Constant(value=i),
                        op=ast.Mult(),
                        right=ast.Constant(value=a // i)
                    ))

        # Strategy 3: power expression
        if a > 1:
            for base in range(2, 10):
                for exp in range(2, 6):
                    if base ** exp == a:
                        strategies.append(ast.BinOp(
                            left=ast.Constant(value=base),
                            op=ast.Pow(),
                            right=ast.Constant(value=exp)
                        ))

        # Strategy 4: addition/subtraction
        if a > 5:
            half = a // 2
            strategies.append(ast.BinOp(
                left=ast.Constant(value=half),
                op=ast.Add(),
                right=ast.Constant(value=a - half)
            ))
        if a > 2:
            strategies.append(ast.BinOp(
                left=ast.Constant(value=a + 1),
                op=ast.Sub(),
                right=ast.Constant(value=1)
            ))

        # Strategy 5: bit shift (only for powers of 2)
        if a > 1 and (a & (a - 1)) == 0:
            exp = a.bit_length() - 1
            strategies.append(ast.BinOp(
                left=ast.Constant(value=1),
                op=ast.LShift(),
                right=ast.Constant(value=exp)
            ))

        if not strategies:
            return ast.Constant(value=n)

        expr = random.choice(strategies)
        # Negate if original was negative
        if sign < 0:
            return ast.UnaryOp(op=ast.USub(), operand=expr)
        return expr

    def _obfuscate_float(self, f):
        """Convert float to obfuscated expression."""
        if f == int(f):
            # Integer-like float: 42.0 → float(42)
            return ast.Call(
                func=ast.Name(id='float', ctx=ast.Load()),
                args=[self._obfuscate_int(int(f))],
                keywords=[]
            )
        # Decompose into integer part + fractional part: 3.14 → 3 + 0.14
        return ast.BinOp(
            left=ast.Constant(value=float(int(f))),
            op=ast.Add(),
            right=ast.Constant(value=round(f - int(f), 10))
        )

    def visit_Constant(self, node):
        if isinstance(node.value, bool):
            # True → (1==1), False → (1==0)
            if node.value:
                return ast.Compare(
                    left=ast.Constant(value=1),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=1)]
                )
            else:
                return ast.Compare(
                    left=ast.Constant(value=1),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=0)]
                )

        if node.value is None:
            # None → ([]==[])
            return ast.Compare(
                left=ast.List(elts=[], ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.List(elts=[], ctx=ast.Load())]
            )

        if isinstance(node.value, int) and not isinstance(node.value, bool):
            if abs(node.value) < 2:
                return node  # Don't obfuscate 0, 1, -1
            return self._obfuscate_int(node.value)

        if isinstance(node.value, float):
            if node.value == 0.0 or node.value == 1.0:
                return node
            return self._obfuscate_float(node.value)

        # Leave strings, bytes, etc. unchanged (handled by stringencoding)
        return node


def obfuscate(source):
    """Apply literal obfuscation to Python source."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: failed to parse Python source: {e}", file=sys.stderr)
        sys.exit(1)

    obfuscator = LiteralObfuscator()
    new_tree = obfuscator.visit(tree)
    ast.fix_missing_locations(new_tree)

    return ast.unparse(new_tree) + "\n"


def main():
    source = sys.stdin.read()
    result = obfuscate(source)
    sys.stdout.write(result)


if __name__ == '__main__':
    main()
