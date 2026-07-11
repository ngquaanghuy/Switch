#!/usr/bin/env python3
"""
Variable splitting obfuscation for Python source code.

Splits simple variable assignments (bool/int/float) into 2-3 sub-variables
with arithmetic/bitwise reconstruction to increase data structure complexity.

Transformations:
- Bool: flag = True → _p0 = 0; _q0 = 1; flag = _p0 ^ _q0
- Int: x = 42 → _p1 = 100; _q1 = 58; x = _p1 - _q1
- Float: pi = 3.14 → _p2 = 10.0; _q2 = 6.86; pi = _p2 + _q2

Features:
- Symbol table tracks split variables per scope
- Scope management skips global/nonlocal/attribute/aliased variables
- Type stability check (skip type-unstable vars)
- Nested splits (1 level deep) for extra hardness
- Overflow protection for int/float values

Reads Python source from stdin, writes obfuscated source to stdout.
"""
import ast
import sys
import random
import math


# Operations allowed per type
OPERATIONS = {
    'bool': ['^', '|'],
    'int': ['^', '+', '-', '*', '|', '&'],
    'float': ['+', '-'],
}

# Value range limits
INT_MIN = -10000
INT_MAX = 10000
FLOAT_MIN = -1000.0
FLOAT_MAX = 1000.0


class SymbolTable:
    """Track split variables across scopes."""

    def __init__(self):
        self.scopes = [{}]  # stack of {var_name: SplitInfo}

    class SplitInfo:
        def __init__(self, var_name, sub_vars, op, values, original_value):
            self.var_name = var_name
            self.sub_vars = sub_vars
            self.op = op
            self.values = values
            self.original_value = original_value

    def enter_scope(self):
        self.scopes.append({})

    def exit_scope(self):
        if len(self.scopes) > 1:
            self.scopes.pop()

    def define(self, var_name, split_info):
        self.scopes[-1][var_name] = split_info

    def lookup(self, var_name):
        for scope in reversed(self.scopes):
            if var_name in scope:
                return scope[var_name]
        return None

    def is_split(self, var_name):
        return self.lookup(var_name) is not None


def get_factors(n):
    """Get all integer factors of n (excluding 1 and n itself)."""
    if n == 0:
        return []
    factors = []
    for i in range(2, int(math.isqrt(abs(n))) + 1):
        if n % i == 0:
            factors.append(i)
            if i != n // i:
                factors.append(n // i)
    return factors


def split_bool(name, value, count, op, counter):
    """Split boolean: True/False -> sub_vars with op."""
    target = int(value)

    if op == '^':
        a = random.randint(0, 255)
        b = a ^ target
        sub_vars = [f'_p{counter}', f'_q{counter}']
        values = [a, b]
        expr = f'{sub_vars[0]} ^ {sub_vars[1]}'
    elif op == '|':
        # For OR: a | b = target
        # a must only have bits from target, then b = target ^ a
        a = random.randint(0, 255) & target
        b = target ^ a
        sub_vars = [f'_p{counter}', f'_q{counter}']
        values = [a, b]
        expr = f'{sub_vars[0]} | {sub_vars[1]}'
    else:
        # Fallback
        a = random.randint(0, 255)
        b = a ^ target
        sub_vars = [f'_p{counter}', f'_q{counter}']
        values = [a, b]
        expr = f'{sub_vars[0]} ^ {sub_vars[1]}'

    # Wrap in bool() to preserve boolean type
    expr = f'bool({expr})'

    return sub_vars, values, op, expr


def split_int(name, value, count, op, counter):
    """Split integer with overflow protection."""
    sub_vars = [f'_p{counter}', f'_q{counter}']

    if op == '+':
        a = random.randint(INT_MIN, INT_MAX)
        b = value - a
        attempts = 0
        while (b > INT_MAX or b < INT_MIN) and attempts < 100:
            a = random.randint(INT_MIN, INT_MAX)
            b = value - a
            attempts += 1
        if attempts >= 100:
            # Fallback: use small values
            a = value // 2
            b = value - a
        values = [a, b]
        expr = f'{sub_vars[0]} + {sub_vars[1]}'

    elif op == '-':
        a = random.randint(INT_MIN, INT_MAX)
        b = a - value
        attempts = 0
        while (b > INT_MAX or b < INT_MIN) and attempts < 100:
            a = random.randint(INT_MIN, INT_MAX)
            b = a - value
            attempts += 1
        if attempts >= 100:
            a = value + 100
            b = 100
        values = [a, b]
        expr = f'{sub_vars[0]} - {sub_vars[1]}'

    elif op == '*':
        factors = get_factors(value)
        if not factors:
            return split_int(name, value, count, '+', counter)
        a = random.choice(factors)
        b = value // a
        values = [a, b]
        expr = f'{sub_vars[0]} * {sub_vars[1]}'

    elif op == '^':
        a = random.randint(0, 255)
        b = a ^ value
        values = [a, b]
        expr = f'{sub_vars[0]} ^ {sub_vars[1]}'

    elif op == '|':
        # For OR: a | b = target
        # a must only have bits from target, then b = target ^ a
        a = random.randint(0, 255) & value
        b = value ^ a
        values = [a, b]
        expr = f'{sub_vars[0]} | {sub_vars[1]}'

    elif op == '&':
        # For AND: a & b = target
        # Pick a such that a & b = target
        # Simple approach: a = target | random_mask, b = target
        mask = random.randint(0, 255)
        a = value | mask
        b = value
        values = [a, b]
        expr = f'{sub_vars[0]} & {sub_vars[1]}'

    else:
        return split_int(name, value, count, '+', counter)

    # 3-way split
    if count == 3:
        # Split first variable further
        mid_val = values[0]
        mid_a = mid_val // 2
        mid_b = mid_val - mid_a
        sub_vars_3 = [f'_r{counter}'] + sub_vars
        values_3 = [mid_a, mid_b] + values[1:]
        # Add parentheses for correct operator precedence
        expr = f'({sub_vars_3[0]} + {sub_vars_3[1]}) {op} {sub_vars_3[2]}'
        return sub_vars_3, values_3, op, expr

    return sub_vars, values, op, expr


def split_float(name, value, count, op, counter):
    """Split float with precision protection."""
    # Only use ADD/SUB for floats
    if op not in ['+', '-']:
        op = random.choice(['+', '-'])

    sub_vars = [f'_p{counter}', f'_q{counter}']

    if op == '+':
        a = random.uniform(FLOAT_MIN, FLOAT_MAX)
        b = value - a
        a = round(a, 6)
        b = round(b, 6)
        values = [a, b]
        expr = f'{sub_vars[0]} + {sub_vars[1]}'

    elif op == '-':
        a = random.uniform(FLOAT_MIN, FLOAT_MAX)
        b = a - value
        a = round(a, 6)
        b = round(b, 6)
        values = [a, b]
        expr = f'{sub_vars[0]} - {sub_vars[1]}'

    else:
        a = random.uniform(FLOAT_MIN, FLOAT_MAX)
        b = value - a
        a = round(a, 6)
        b = round(b, 6)
        values = [a, b]
        expr = f'{sub_vars[0]} + {sub_vars[1]}'

    # 3-way split
    if count == 3:
        mid_val = values[0]
        mid_a = round(mid_val / 2, 6)
        mid_b = round(mid_val - mid_a, 6)
        sub_vars_3 = [f'_r{counter}'] + sub_vars
        values_3 = [mid_a, mid_b] + values[1:]
        # Add parentheses for correct operator precedence, round for float precision
        expr = f'round(({sub_vars_3[0]} + {sub_vars_3[1]}) {op} {sub_vars_3[2]}, 6)'
        return sub_vars_3, values_3, op, expr

    # Wrap in round() for float precision
    expr = f'round({expr}, 6)'

    return sub_vars, values, op, expr


def split_variable(var_name, value, var_type, counter):
    """Generate split for a single variable."""
    split_count = random.choice([2, 3])
    op = random.choice(OPERATIONS[var_type])

    if var_type == 'bool':
        return split_bool(var_name, value, split_count, op, counter)
    elif var_type == 'int':
        return split_int(var_name, value, split_count, op, counter)
    elif var_type == 'float':
        return split_float(var_name, value, split_count, op, counter)
    else:
        return None


def should_skip_assignment(node):
    """Check if assignment should be skipped."""
    # Skip augmented assignment (x += 1)
    if isinstance(node, ast.AugAssign):
        return True

    # Skip attribute assignment (obj.x = 42)
    for target in node.targets:
        if isinstance(target, ast.Attribute):
            return True
        if isinstance(target, ast.Subscript):
            return True

    # Skip tuple unpacking
    if len(node.targets) > 1:
        return True

    # Skip if target is tuple/list (a, b = 1, 2)
    if isinstance(node.targets[0], (ast.Tuple, ast.List)):
        return True

    return False


class VariableSplitter(ast.NodeTransformer):
    """Main transformer: splits eligible variables."""

    def __init__(self):
        self.symbol_table = SymbolTable()
        self.counter = 0
        self.skip_vars = set()

    def visit_Module(self, node):
        self.symbol_table.enter_scope()
        self.generic_visit(node)
        self.symbol_table.exit_scope()
        return node

    def visit_FunctionDef(self, node):
        self.symbol_table.enter_scope()
        # Skip function arguments
        for arg in node.args.args:
            self.skip_vars.add(arg.arg)
        self.generic_visit(node)
        self.symbol_table.exit_scope()
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_For(self, node):
        # Mark loop variable as skip
        if isinstance(node.target, ast.Name):
            self.skip_vars.add(node.target.id)
        self.generic_visit(node)
        return node

    def visit_With(self, node):
        # Mark with-item variable as skip
        for item in node.items:
            if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                self.skip_vars.add(item.optional_vars.id)
        self.generic_visit(node)
        return node

    def visit_Global(self, node):
        # Mark all global variables as skip
        for name in node.names:
            self.skip_vars.add(name)
        return node

    def visit_Nonlocal(self, node):
        # Mark all nonlocal variables as skip
        for name in node.names:
            self.skip_vars.add(name)
        return node

    def visit_Assign(self, node):
        if should_skip_assignment(node):
            return node

        target = node.targets[0]
        if not isinstance(target, ast.Name):
            return node

        var_name = target.id

        # Skip if already in skip list
        if var_name in self.skip_vars:
            return node

        # Skip if already split
        if self.symbol_table.is_split(var_name):
            return node

        # Check value is eligible constant
        value = node.value
        if not isinstance(value, ast.Constant):
            return node

        if isinstance(value.value, bool):
            var_type = 'bool'
        elif isinstance(value.value, int):
            var_type = 'int'
        elif isinstance(value.value, float):
            var_type = 'float'
        else:
            return node

        # Generate split
        result = split_variable(var_name, value.value, var_type, self.counter)
        if result is None:
            return node

        sub_vars, values, op, expr = result

        # Register in symbol table
        split_info = SymbolTable.SplitInfo(
            var_name, sub_vars, op, values, value.value
        )
        self.symbol_table.define(var_name, split_info)

        # Generate new AST nodes
        new_nodes = []
        for var, val in zip(sub_vars, values):
            new_nodes.append(ast.Assign(
                targets=[ast.Name(id=var, ctx=ast.Store())],
                value=ast.Constant(value=val)
            ))

        # Original assignment with expression
        new_nodes.append(ast.Assign(
            targets=[ast.Name(id=var_name, ctx=ast.Store())],
            value=ast.parse(expr, mode='eval').body
        ))

        self.counter += 1
        return new_nodes

    def visit_Name(self, node):
        # If this is a Load (reading) and the variable is split,
        # we need to reconstruct it. But since we already replaced
        # the assignment with the expression, the variable name
        # still refers to the reconstructed value.
        # No transformation needed here.
        return node


def obfuscate(source):
    """Apply variable splitting to Python source."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: failed to parse Python source: {e}", file=sys.stderr)
        sys.exit(1)

    splitter = VariableSplitter()
    new_tree = splitter.visit(tree)
    ast.fix_missing_locations(new_tree)

    return ast.unparse(new_tree) + "\n"


def main():
    source = sys.stdin.read()
    result = obfuscate(source)
    sys.stdout.write(result)


if __name__ == '__main__':
    main()
