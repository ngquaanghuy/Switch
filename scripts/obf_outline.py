#!/usr/bin/env python3
"""
Statement outlining obfuscation for Python source code.

Extracts 2-4 consecutive statements into new junk functions with meaningless
names, creating fake call graph complexity for reverse engineers.

Features:
- Data flow analysis: identifies input/output variables per group
- Loop-carried dependency detection: skips groups that would break loop state
- Skips try/except, break/continue/return in middle of group
- Skips groups with global/nonlocal/walrus operator
- Junk function names: _of<random_hex>
- Parent function must have ≥ 5 statements (avoid tiny function overhead)

Reads Python source from stdin, writes obfuscated source to stdout.
"""
import ast
import sys
import copy
import random
import string


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rand_hex(length=4):
    """Generate random hex string for junk function naming."""
    return ''.join(random.choices('0123456789abcdef', k=length))


def _get_read_names(node):
    """Get all names that are READ (loaded) in an AST node."""
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            names.add(child.id)
    return names


def _get_written_names(node):
    """Get all names that are WRITTEN (stored) in an AST node."""
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            names.add(child.id)
    return names


def _is_eligible_statement(stmt):
    """Check if a single statement can be part of an outlined group."""
    # Allow: Assign, AugAssign, Expr (function calls), If, For, While, With, Try
    # For simplicity in v1, only allow: Assign, AugAssign, Expr
    if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.Expr)):
        return True
    return False


def _group_has_control_flow(stmts):
    """Check if a group of statements has problematic control flow."""
    for stmt in stmts:
        if isinstance(stmt, ast.Break):
            return True
        if isinstance(stmt, ast.Continue):
            return True
        if isinstance(stmt, ast.Return):
            return True
        if isinstance(stmt, ast.Raise):
            return True
        if isinstance(stmt, ast.Global):
            return True
        if isinstance(stmt, ast.Nonlocal):
            return True
        # Check for walrus operator
        for child in ast.walk(stmt):
            if isinstance(child, ast.NamedExpr):
                return True
    return False


def _has_loop_carried_dep(stmts, loop_vars):
    """Check if statements have loop-carried dependencies.

    A loop-carried dependency exists when a variable is both read and written
    across iterations (e.g., total += x reads total from previous iteration).
    """
    all_read = set()
    all_written = set()
    for stmt in stmts:
        all_read |= _get_read_names(stmt)
        all_written |= _get_written_names(stmt)

    # If any written variable is also read, it's loop-carried
    # (the value from previous iteration feeds into current iteration)
    loop_carried = all_written & all_read
    return bool(loop_carried)


# ---------------------------------------------------------------------------
# Candidate detection
# ---------------------------------------------------------------------------

def _find_outline_candidates(body, parent_in_loop=False, loop_vars=None):
    """Find groups of 2-4 statements eligible for outlining in a body.

    Returns list of (start_index, end_index) tuples.
    """
    candidates = []
    if loop_vars is None:
        loop_vars = set()

    i = 0
    while i < len(body):
        # Try group sizes 4, 3, 2 (largest first for more obfuscation)
        for group_size in [4, 3, 2]:
            if i + group_size > len(body):
                continue

            group = body[i:i + group_size]

            # All statements must be eligible
            if not all(_is_eligible_statement(s) for s in group):
                continue

            # No control flow in the middle
            if _group_has_control_flow(group):
                continue

            # Check for loop-carried dependencies if inside a loop
            if parent_in_loop and _has_loop_carried_dep(group, loop_vars):
                continue

            candidates.append((i, i + group_size))
            break  # Take the largest valid group at this position

        i += 1

    return candidates


# ---------------------------------------------------------------------------
# Data flow analysis
# ---------------------------------------------------------------------------

def _analyze_data_flow(stmts, preceding_names):
    """Analyze input/output variables for a group of statements.

    Args:
        stmts: list of AST statements
        preceding_names: set of names defined before this group

    Returns: (inputs, outputs) where:
        inputs = names read before being written (need to be passed as args)
        outputs = names written in the group (need to be returned)
    """
    all_read = set()
    all_written = set()
    written_so_far = set()

    for stmt in stmts:
        read = _get_read_names(stmt) - written_so_far
        written = _get_written_names(stmt)
        all_read |= read
        all_written |= written
        written_so_far |= written

    # Inputs: names read that were defined before the group
    inputs = all_read & preceding_names

    # Outputs: names written that are used after the group
    # For simplicity, return all written names (conservative)
    outputs = all_written

    return inputs, outputs


# ---------------------------------------------------------------------------
# AST Transformer
# ---------------------------------------------------------------------------

class Outliner(ast.NodeTransformer):
    """Extract statement groups into junk functions."""

    def __init__(self):
        self.new_functions = []  # module-level function definitions to insert
        self.counter = 0

    def _make_junk_name(self):
        """Generate a junk function name."""
        self.counter += 1
        return f'_of{_rand_hex()}'

    def _outline_group(self, stmts, inputs, outputs):
        """Create an outlined function and return the call statement(s)."""
        func_name = self._make_junk_name()

        # Build function arguments
        args = ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg=name) for name in sorted(inputs)],
            vararg=None,
            kwonlyargs=[],
            kw_defaults=[],
            kwarg=None,
            defaults=[]
        )

        # Build function body: deep copy the statements
        body = [copy.deepcopy(s) for s in stmts]

        # Add return if there are outputs
        if outputs:
            sorted_outputs = sorted(outputs)
            if len(sorted_outputs) == 1:
                ret_val = ast.Name(id=sorted_outputs[0], ctx=ast.Load())
            else:
                ret_val = ast.Tuple(
                    elts=[ast.Name(id=n, ctx=ast.Load()) for n in sorted_outputs],
                    ctx=ast.Load()
                )
            body.append(ast.Return(value=ret_val))

        # Create function definition
        func_def = ast.FunctionDef(
            name=func_name,
            args=args,
            body=body,
            decorator_list=[],
            returns=None
        )
        self.new_functions.append(func_def)

        # Create call statement(s)
        call_args = [ast.Name(id=name, ctx=ast.Load()) for name in sorted(inputs)]
        call = ast.Call(
            func=ast.Name(id=func_name, ctx=ast.Load()),
            args=call_args,
            keywords=[]
        )

        if not outputs:
            # Void function: just call it
            return ast.Expr(value=call)
        elif len(outputs) == 1:
            # Single output: result = func(args)
            return ast.Assign(
                targets=[ast.Name(id=sorted(outputs)[0], ctx=ast.Store())],
                value=call
            )
        else:
            # Multiple outputs: a, b = func(args)
            return ast.Assign(
                targets=[ast.Tuple(
                    elts=[ast.Name(id=n, ctx=ast.Store()) for n in sorted(outputs)],
                    ctx=ast.Store()
                )],
                value=call
            )

    def _transform_body(self, body, in_loop=False, loop_vars=None, preceding_names=None):
        """Transform a body of statements, outlining eligible groups."""
        if loop_vars is None:
            loop_vars = set()
        if preceding_names is None:
            preceding_names = set()

        # Accumulate preceding names from statements
        accumulated = set(preceding_names)
        for stmt in body:
            accumulated |= _get_written_names(stmt)
        preceding_names = accumulated

        candidates = _find_outline_candidates(body, in_loop, loop_vars)
        if not candidates:
            return body

        # Process candidates (reverse order to maintain indices)
        # Randomly select ~50% of candidates for variety
        selected = []
        for start, end in candidates:
            if random.random() < 0.5:
                selected.append((start, end))

        if not selected:
            return body

        new_body = []
        skip_until = -1

        for i, stmt in enumerate(body):
            if i <= skip_until:
                continue

            # Check if this statement starts a selected group
            outlined = False
            for start, end in selected:
                if i == start:
                    group = body[start:end]
                    inputs, outputs = _analyze_data_flow(group, preceding_names)
                    call_stmt = self._outline_group(group, inputs, outputs)
                    new_body.append(call_stmt)
                    skip_until = end - 1
                    outlined = True
                    break

            if not outlined:
                new_body.append(stmt)

        return new_body

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        # Skip tiny functions (need ≥ 5 statements)
        if len(node.body) < 5:
            return node
        # Skip class methods (self complicates things)
        if node.args.args and node.args.args[0].arg == 'self':
            return node
        # Collect parameter names as "preceding" (they're defined before any body stmt)
        preceding_names = set()
        for arg in node.args.args:
            preceding_names.add(arg.arg)
        if node.args.vararg:
            preceding_names.add(node.args.vararg.arg)
        for arg in node.args.kwonlyargs:
            preceding_names.add(arg.arg)
        node.body = self._transform_body(node.body, preceding_names=preceding_names)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Module(self, node):
        self.generic_visit(node)
        # Outline at module level (after imports)
        import_end = 0
        for i, stmt in enumerate(node.body):
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                import_end = i + 1

        # Only outline after imports
        if import_end < len(node.body):
            before = node.body[:import_end]
            after = node.body[import_end:]
            outlined_after = self._transform_body(after)
            node.body = before + outlined_after

        # Insert new functions after imports, before other code
        for i, func in enumerate(self.new_functions):
            node.body.insert(import_end + i, func)

        return node


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def obfuscate(source):
    """Apply statement outlining to Python source code."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: failed to parse Python source: {e}", file=sys.stderr)
        sys.exit(1)

    outliner = Outliner()
    new_tree = outliner.visit(tree)
    ast.fix_missing_locations(new_tree)

    return ast.unparse(new_tree) + "\n"


def main():
    source = sys.stdin.read()
    result = obfuscate(source)
    sys.stdout.write(result)


if __name__ == '__main__':
    main()
