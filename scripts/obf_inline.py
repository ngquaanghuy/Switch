#!/usr/bin/env python3
"""
Function inlining obfuscation for Python source code.

Replaces function calls with the function body, substituting parameters
with actual arguments. Removes function abstraction from reverse engineer's view.

Features:
- Collects all function definitions and call counts
- Skips recursive, async, decorated, *args/**kwargs functions
- Skips functions with global/nonlocal declarations
- Unique prefix per inline site to avoid variable conflicts
- Bottom-up traversal for nested call handling
- Removes functions with no remaining callers

Eligibility: body_size × call_count ≤ 24

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
    """Generate random hex string for unique naming."""
    return ''.join(random.choices('0123456789abcdef', k=length))


def _has_global_or_nonlocal(body):
    """Check if a function body contains global or nonlocal declarations."""
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            return True
    return False


def _collect_calls_in_body(node):
    """Collect all function call names in an AST node."""
    calls = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name):
                calls.add(child.func.id)
    return calls


# ---------------------------------------------------------------------------
# Pass 1: Collect function info
# ---------------------------------------------------------------------------

class FunctionCollector(ast.NodeVisitor):
    """Collect all function definitions and count their calls."""

    def __init__(self):
        self.functions = {}      # name -> FunctionDef node
        self.call_counts = {}    # name -> count
        self.recursive = set()   # names of recursive functions
        self._in_function = None  # current function name for recursion detection

    def visit_FunctionDef(self, node):
        # Store function info (skip async, decorated, methods)
        if not node.decorator_list and not isinstance(node, ast.AsyncFunctionDef):
            self.functions[node.name] = node

        # Count calls within this function
        old_func = self._in_function
        self._in_function = node.name
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                name = child.func.id
                self.call_counts[name] = self.call_counts.get(name, 0) + 1
                # Detect self-recursion
                if name == node.name:
                    self.recursive.add(name)
        self._in_function = old_func

        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Module(self, node):
        # Count calls at module level only (not inside functions).
        # Walk each top-level statement's subtree, stopping at FunctionDef boundaries.
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # skip nested definitions — counted by their own visit_*
            for child in ast.walk(stmt):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                    name = child.func.id
                    self.call_counts[name] = self.call_counts.get(name, 0) + 1
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Pass 2: Filter eligible functions
# ---------------------------------------------------------------------------

def _count_returns(body):
    """Count return statements in a function body (recursively into if/else/for/while)."""
    count = 0
    for stmt in body:
        if isinstance(stmt, ast.Return):
            count += 1
        elif isinstance(stmt, (ast.If, ast.For, ast.While, ast.With)):
            count += _count_returns(stmt.body)
            if isinstance(stmt, ast.If):
                count += _count_returns(stmt.orelse)
            if isinstance(stmt, (ast.For, ast.While)):
                count += _count_returns(stmt.orelse)
    return count


def _is_eligible(name, func_node, collector):
    """Check if a function is eligible for inlining."""
    # Skip if no calls
    if collector.call_counts.get(name, 0) == 0:
        return False

    # Skip recursive
    if name in collector.recursive:
        return False

    # Skip async
    if isinstance(func_node, ast.AsyncFunctionDef):
        return False

    # Skip decorated
    if func_node.decorator_list:
        return False

    args = func_node.args

    # Skip *args, **kwargs
    if args.vararg or args.kwarg:
        return False

    # Skip default parameter values
    if args.defaults or args.kw_defaults:
        return False

    # Skip keyword-only args
    if args.kwonlyargs:
        return False

    # Skip functions with global/nonlocal
    if _has_global_or_nonlocal(func_node.body):
        return False

    # Skip functions with multiple return paths (v1 simplification)
    if _count_returns(func_node.body) > 1:
        return False

    # Body size limit
    body_size = len(func_node.body)
    if body_size > 8:
        return False

    # Product rule: body_size × call_count ≤ 24
    call_count = collector.call_counts.get(name, 0)
    if body_size * call_count > 24:
        return False

    return True


# ---------------------------------------------------------------------------
# Pass 3: Inline transform
# ---------------------------------------------------------------------------

class Inliner(ast.NodeTransformer):
    """Replace function calls with inlined bodies."""

    def __init__(self, functions, eligible):
        self.functions = functions      # name -> FunctionDef
        self.eligible = eligible        # set of eligible function names
        self.counter = 0
        self.removed = set()            # names of functions to remove
        self.call_counts = {}           # track remaining calls per function

    def _unique_prefix(self):
        """Generate a unique prefix for inlined variables."""
        self.counter += 1
        return f'_il{self.counter}_'

    def _compute_local_names(self, func_body):
        """Find all names that are assigned (written) in the function body.
        These are "local" to the inlined body and need prefix on both Store and Load."""
        local_names = set()
        for stmt in func_body:
            for child in ast.walk(stmt):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                    local_names.add(child.id)
        return local_names

    def _rename_node(self, node, prefix, param_map, local_names):
        """Rename all Name nodes in a deep copy, substituting params."""
        node = copy.deepcopy(node)

        class Renamer(ast.NodeTransformer):
            def __init__(self, prefix, param_map, local_names):
                self.prefix = prefix
                self.param_map = param_map  # original param name -> arg AST node
                self.local_names = local_names

            def visit_Name(self, n):
                if n.id in self.param_map:
                    # Replace parameter with actual argument
                    return copy.deepcopy(self.param_map[n.id])
                elif n.id in self.local_names:
                    # Rename both Store and Load for body-local variables
                    n.id = self.prefix + n.id
                return n

            def visit_arg(self, n):
                if n.arg in self.param_map:
                    n.arg = self.prefix + n.arg
                return n

            def visit_Global(self, n):
                return n  # keep as-is (shouldn't happen since we skip these)

            def visit_Nonlocal(self, n):
                return n  # keep as-is

        r = Renamer(prefix, param_map, local_names)
        return r.visit(node)

    def _make_param_map(self, func_node, call_node):
        """Map parameter names to argument AST nodes."""
        param_map = {}
        params = func_node.args.args
        for i, arg in enumerate(params):
            if i < len(call_node.args):
                param_map[arg.arg] = copy.deepcopy(call_node.args[i])
            else:
                # Not enough args — use default or None (shouldn't happen with valid code)
                param_map[arg.arg] = ast.Constant(value=None)
        return param_map

    def _inline_call(self, call_node, parent_context=None):
        """Inline a single function call. Returns list of replacement statements."""
        func_name = call_node.func.id
        func_node = self.functions[func_name]
        prefix = self._unique_prefix()
        param_map = self._make_param_map(func_node, call_node)
        local_names = self._compute_local_names(func_node.body)

        # Build inlined body with renamed variables
        inlined_body = []
        for stmt in func_node.body:
            renamed = self._rename_node(stmt, prefix, param_map, local_names)
            inlined_body.append(renamed)

        # Track this function for potential removal
        self.call_counts.setdefault(func_name, 0)
        self.call_counts[func_name] = self.call_counts.get(func_name, 0) + 1

        return inlined_body

    def visit_Call(self, node):
        self.generic_visit(node)
        if isinstance(node.func, ast.Name) and node.func.id in self.eligible:
            # Return the call node as-is; we handle inlining at statement level
            pass
        return node

    def visit_Expr(self, node):
        """Handle expression statements: print(foo()) → inline + print(temp)"""
        self.generic_visit(node)
        if (isinstance(node.value, ast.Call) and
            isinstance(node.value.func, ast.Name) and
            node.value.func.id in self.eligible):
            return self._inline_call(node.value)
        return node

    def visit_Assign(self, node):
        """Handle assignment: x = foo() → inline body + x = last_return"""
        self.generic_visit(node)
        if (isinstance(node.value, ast.Call) and
            isinstance(node.value.func, ast.Name) and
            node.value.func.id in self.eligible):

            func_name = node.value.func.id
            func_node = self.functions[func_name]
            prefix = self._unique_prefix()
            param_map = self._make_param_map(func_node, node.value)
            local_names = self._compute_local_names(func_node.body)

            stmts = []
            for stmt in func_node.body:
                renamed = self._rename_node(stmt, prefix, param_map, local_names)
                if isinstance(renamed, ast.Return) and renamed.value:
                    # Replace return with assignment to target
                    assign = ast.Assign(
                        targets=copy.deepcopy(node.targets),
                        value=renamed.value
                    )
                    ast.copy_location(assign, renamed)
                    stmts.append(assign)
                else:
                    stmts.append(renamed)
            return stmts
        return node

    def visit_Return(self, node):
        """Handle return foo() → inline body + return value"""
        self.generic_visit(node)
        if (node.value and isinstance(node.value, ast.Call) and
            isinstance(node.value.func, ast.Name) and
            node.value.func.id in self.eligible):
            func_name = node.value.func.id
            func_node = self.functions[func_name]
            prefix = self._unique_prefix()
            param_map = self._make_param_map(func_node, node.value)
            local_names = self._compute_local_names(func_node.body)

            stmts = []
            for stmt in func_node.body:
                renamed = self._rename_node(stmt, prefix, param_map, local_names)
                if isinstance(renamed, ast.Return) and renamed.value:
                    # Keep the return but with the inlined value
                    renamed.value = node.value  # will be handled by nested visit
                    stmts.append(renamed)
                else:
                    stmts.append(renamed)
            return stmts
        return node

    def _inline_to_temp(self, call_node, prefix):
        """Inline a call and assign result to a temp variable. Returns (stmts, temp_name)."""
        func_name = call_node.func.id
        func_node = self.functions[func_name]
        param_map = self._make_param_map(func_node, call_node)
        local_names = self._compute_local_names(func_node.body)
        temp_name = prefix + 'ret'

        stmts = []
        for stmt in func_node.body:
            renamed = self._rename_node(stmt, prefix, param_map, local_names)
            if isinstance(renamed, ast.Return) and renamed.value:
                assign = ast.Assign(
                    targets=[ast.Name(id=temp_name, ctx=ast.Store())],
                    value=renamed.value
                )
                ast.copy_location(assign, renamed)
                stmts.append(assign)
            else:
                stmts.append(renamed)
        return stmts, temp_name

    def visit_If(self, node):
        """Handle if f(x): → inline f, assign to temp, use temp in test"""
        self.generic_visit(node)
        if (isinstance(node.test, ast.Call) and
            isinstance(node.test.func, ast.Name) and
            node.test.func.id in self.eligible):
            prefix = self._unique_prefix()
            stmts, temp_name = self._inline_to_temp(node.test, prefix)
            node.test = ast.Name(id=temp_name, ctx=ast.Load())
            return stmts + [node]
        return node

    def visit_While(self, node):
        """Handle while f(x): → inline f, assign to temp, use temp in test"""
        self.generic_visit(node)
        if (isinstance(node.test, ast.Call) and
            isinstance(node.test.func, ast.Name) and
            node.test.func.id in self.eligible):
            prefix = self._unique_prefix()
            stmts, temp_name = self._inline_to_temp(node.test, prefix)
            node.test = ast.Name(id=temp_name, ctx=ast.Load())
            return stmts + [node]
        return node

    def visit_FunctionDef(self, node):
        """Remove functions that have been fully inlined."""
        self.generic_visit(node)
        if node.name in self.eligible:
            # Check if all calls have been inlined (function is now unused)
            # We mark for removal — cleanup happens in obfuscate()
            self.removed.add(node.name)
            # Don't remove yet — other functions might reference it
            # We'll do a final pass to remove truly unused functions
        return node


# ---------------------------------------------------------------------------
# Main obfuscation
# ---------------------------------------------------------------------------

def obfuscate(source):
    """Apply function inlining to Python source code."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: failed to parse Python source: {e}", file=sys.stderr)
        sys.exit(1)

    # Pass 1: Collect functions and calls
    collector = FunctionCollector()
    collector.visit(tree)

    # Pass 2: Filter eligible functions
    eligible = set()
    for name, func_node in collector.functions.items():
        if _is_eligible(name, func_node, collector):
            eligible.add(name)

    if not eligible:
        return source  # Nothing to inline

    # Pass 3: Inline (multiple passes for nested calls)
    for _ in range(3):  # max 3 passes for deep nesting
        inliner = Inliner(collector.functions, eligible)
        new_tree = inliner.visit(tree)
        ast.fix_missing_locations(new_tree)
        tree = new_tree

    # Remove functions that are no longer called
    # (they were fully inlined and have no remaining callers)
    class FuncRemover(ast.NodeTransformer):
        def __init__(self, eligible, call_counts):
            self.eligible = eligible
            self.call_counts = call_counts

        def visit_FunctionDef(self, node):
            self.generic_visit(node)
            if node.name in self.eligible and self.call_counts.get(node.name, 0) <= 0:
                return None  # remove
            return node

    # Recount calls after inlining
    final_collector = FunctionCollector()
    final_collector.visit(tree)
    remover = FuncRemover(eligible, final_collector.call_counts)
    tree = remover.visit(tree)
    ast.fix_missing_locations(tree)

    return ast.unparse(tree) + "\n"


def main():
    source = sys.stdin.read()
    result = obfuscate(source)
    sys.stdout.write(result)


if __name__ == '__main__':
    main()
