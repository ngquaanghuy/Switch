#!/usr/bin/env python3
"""
Opaque predicates obfuscation for Python source code.

Injects conditional branches whose outcome is known at obfuscation time
but difficult for static analysis to determine. Creates fake code paths
that confuse decompilers and reverse engineers.

Predicate families:
- Arithmetic (always True):  x*(x+1) % 2 == 0
- Arithmetic (always False): 7*y*y - 1 == x*x
- Object identity:           [] is not list()
- Runtime:                   bool([]) == False

Reads Python source from stdin, writes obfuscated source to stdout.
"""
import ast
import sys
import random
import math


# Variable name prefixes
OP_PREFIX = "_op"
JK_PREFIX = "_jk"


def random_int(low=-100, high=100):
    """Generate a random integer in range."""
    return random.randint(low, high)


# ---------------------------------------------------------------------------
# Predicate generators
# ---------------------------------------------------------------------------

def make_arith_true(var_name):
    """Generate an arithmetic predicate that is always True.

    Returns: (AST expression, list of (var_name, init_value) tuples)
    """
    v = var_name

    init_val = random_int(1, 100)
    inits = [(v, init_val)]

    templates = [
        # Template 1: x * (x + c1) % c2 == c3
        # With c1=1, c2=2, c3=0: consecutive integers, one is even
        lambda: (
            ast.Compare(
                left=ast.BinOp(
                    left=ast.BinOp(
                        left=ast.Name(id=v, ctx=ast.Load()),
                        op=ast.Mult(),
                        right=ast.BinOp(
                            left=ast.Name(id=v, ctx=ast.Load()),
                            op=ast.Add(),
                            right=ast.Constant(value=1)
                        )
                    ),
                    op=ast.Mod(),
                    right=ast.Constant(value=2)
                ),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=0)]
            ),
            inits
        ),
        # Template 2: (x*x + x) % 2 == 0
        lambda: (
            ast.Compare(
                left=ast.BinOp(
                    left=ast.BinOp(
                        left=ast.BinOp(
                            left=ast.Name(id=v, ctx=ast.Load()),
                            op=ast.Mult(),
                            right=ast.Name(id=v, ctx=ast.Load())
                        ),
                        op=ast.Add(),
                        right=ast.Name(id=v, ctx=ast.Load())
                    ),
                    op=ast.Mod(),
                    right=ast.Constant(value=2)
                ),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=0)]
            ),
            inits
        ),
        # Template 3: x*x*(x+1)*(x+1) % 4 == 0
        lambda: (
            ast.Compare(
                left=ast.BinOp(
                    left=ast.BinOp(
                        left=ast.BinOp(
                            left=ast.Name(id=v, ctx=ast.Load()),
                            op=ast.Mult(),
                            right=ast.Name(id=v, ctx=ast.Load())
                        ),
                        op=ast.Mult(),
                        right=ast.BinOp(
                            left=ast.BinOp(
                                left=ast.Name(id=v, ctx=ast.Load()),
                                op=ast.Add(),
                                right=ast.Constant(value=1)
                            ),
                            op=ast.Mult(),
                            right=ast.BinOp(
                                left=ast.Name(id=v, ctx=ast.Load()),
                                op=ast.Add(),
                                right=ast.Constant(value=1)
                            )
                        )
                    ),
                    op=ast.Mod(),
                    right=ast.Constant(value=4)
                ),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=0)]
            ),
            inits
        ),
    ]

    return random.choice(templates)()


def make_arith_false(var_name):
    """Generate an arithmetic predicate that is always False.

    Returns: (AST expression, list of (var_name, init_value) tuples)
    """
    v = var_name
    y_name = f"{v}_y"

    # 7*y*y - 1 == x*x  →  no integer solutions
    expr = ast.Compare(
        left=ast.BinOp(
            left=ast.BinOp(
                left=ast.Constant(value=7),
                op=ast.Mult(),
                right=ast.BinOp(
                    left=ast.Name(id=y_name, ctx=ast.Load()),
                    op=ast.Mult(),
                    right=ast.Name(id=y_name, ctx=ast.Load())
                )
            ),
            op=ast.Sub(),
            right=ast.Constant(value=1)
        ),
        ops=[ast.Eq()],
        comparators=[
            ast.BinOp(
                left=ast.Name(id=v, ctx=ast.Load()),
                op=ast.Mult(),
                right=ast.Name(id=v, ctx=ast.Load())
            )
        ]
    )

    inits = [
        (v, random_int(1, 100)),
        (y_name, random_int(1, 50)),
    ]

    return expr, inits


def make_object_identity_true():
    """Generate an object identity predicate that is always True.

    Returns: (AST expression, list of (var_name, init_value) tuples)
    """
    templates = [
        lambda: ast.Compare(
            left=ast.List(elts=[], ctx=ast.Load()),
            ops=[ast.IsNot()],
            comparators=[ast.Call(
                func=ast.Name(id='list', ctx=ast.Load()),
                args=[], keywords=[]
            )]
        ),
        lambda: ast.Compare(
            left=ast.Dict(keys=[], values=[], ctx=ast.Load()),
            ops=[ast.IsNot()],
            comparators=[ast.Call(
                func=ast.Name(id='dict', ctx=ast.Load()),
                args=[], keywords=[]
            )]
        ),
        lambda: ast.Compare(
            left=ast.Call(
                func=ast.Name(id='set', ctx=ast.Load()),
                args=[], keywords=[]
            ),
            ops=[ast.IsNot()],
            comparators=[ast.Call(
                func=ast.Name(id='set', ctx=ast.Load()),
                args=[], keywords=[]
            )]
        ),
        lambda: ast.Compare(
            left=ast.Call(
                func=ast.Name(id='bytes', ctx=ast.Load()),
                args=[], keywords=[]
            ),
            ops=[ast.IsNot()],
            comparators=[ast.Call(
                func=ast.Name(id='bytes', ctx=ast.Load()),
                args=[], keywords=[]
            )]
        ),
    ]

    return random.choice(templates)(), []


def make_runtime_true():
    """Generate a runtime predicate that is always True in Python 3.

    Returns: (AST expression, list of (var_name, init_value) tuples, list of import strings)
    """
    templates = [
        lambda: (
            ast.Compare(
                left=ast.Call(
                    func=ast.Name(id='bool', ctx=ast.Load()),
                    args=[ast.List(elts=[], ctx=ast.Load())],
                    keywords=[]
                ),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=False)]
            ),
            [],
            []
        ),
        lambda: (
            ast.Compare(
                left=ast.Constant(value=None),
                ops=[ast.IsNot()],
                comparators=[ast.Constant(value=True)]
            ),
            [],
            []
        ),
        lambda: (
            ast.Compare(
                left=ast.Attribute(
                    value=ast.Name(id='sys', ctx=ast.Load()),
                    attr='version_info',
                    ctx=ast.Load()
                ),
                ops=[ast.GtE()],
                comparators=[ast.Tuple(
                    elts=[ast.Constant(value=3), ast.Constant(value=0)],
                    ctx=ast.Load()
                )]
            ),
            [],
            ['import sys']
        ),
    ]

    return random.choice(templates)()


# ---------------------------------------------------------------------------
# Junk code generator
# ---------------------------------------------------------------------------

def make_junk_statements(count=None):
    """Generate side-effect-free junk statements.

    Returns: list of AST statements
    """
    if count is None:
        count = random.randint(2, 4)

    stmts = []

    for i in range(count):
        name = f"{JK_PREFIX}{i}"
        pattern = random.choice(['assign', 'math', 'pow_mod', 'shift', 'and'])

        if pattern == 'assign':
            stmts.append(ast.Assign(
                targets=[ast.Name(id=name, ctx=ast.Store())],
                value=ast.Constant(value=random_int())
            ))
        elif pattern == 'math':
            stmts.append(ast.Assign(
                targets=[ast.Name(id=name, ctx=ast.Store())],
                value=ast.BinOp(
                    left=ast.BinOp(
                        left=ast.Constant(value=random_int()),
                        op=ast.Mult(),
                        right=ast.Constant(value=random_int())
                    ),
                    op=ast.Add(),
                    right=ast.Constant(value=random_int())
                )
            ))
        elif pattern == 'pow_mod':
            stmts.append(ast.Assign(
                targets=[ast.Name(id=name, ctx=ast.Store())],
                value=ast.BinOp(
                    left=ast.BinOp(
                        left=ast.Constant(value=random_int(1, 10)),
                        op=ast.Pow(),
                        right=ast.Constant(value=2)
                    ),
                    op=ast.Mod(),
                    right=ast.Constant(value=random_int(2, 20))
                )
            ))
        elif pattern == 'shift':
            stmts.append(ast.Assign(
                targets=[ast.Name(id=name, ctx=ast.Store())],
                value=ast.BinOp(
                    left=ast.Constant(value=random_int(1, 50)),
                    op=ast.LShift(),
                    right=ast.Constant(value=random_int(1, 5))
                )
            ))
        else:  # and
            stmts.append(ast.Assign(
                targets=[ast.Name(id=name, ctx=ast.Store())],
                value=ast.BinOp(
                    left=ast.Constant(value=random_int(0, 255)),
                    op=ast.BitAnd(),
                    right=ast.Constant(value=random_int(0, 255))
                )
            ))

    return stmts


# ---------------------------------------------------------------------------
# AST Transformer
# ---------------------------------------------------------------------------

class OpaquePredicateTransformer(ast.NodeTransformer):
    """Inject opaque predicates into if/while/for statements."""

    def __init__(self):
        self.op_counter = 0
        self.jk_counter = 0
        self.imports_needed = set()

    def _next_op_name(self):
        name = f"{OP_PREFIX}{self.op_counter}"
        self.op_counter += 1
        return name

    def _generate_predicate(self, var_name):
        """Randomly select and generate an opaque predicate.

        Returns: (AST expr, list of init stmts, list of import strings, is_always_true)
        """
        family = random.choice([
            'arith_true', 'arith_true', 'arith_true',  # weight arithmetic true higher
            'arith_false',
            'object_true',
            'runtime_true',
        ])

        if family == 'arith_true':
            expr, inits = make_arith_true(var_name)
            init_stmts = []
            for vname, val in inits:
                init_stmts.append(ast.Assign(
                    targets=[ast.Name(id=vname, ctx=ast.Store())],
                    value=ast.Constant(value=val)
                ))
            return expr, init_stmts, [], True

        elif family == 'arith_false':
            expr, inits = make_arith_false(var_name)
            init_stmts = []
            for vname, val in inits:
                init_stmts.append(ast.Assign(
                    targets=[ast.Name(id=vname, ctx=ast.Store())],
                    value=ast.Constant(value=val)
                ))
            return expr, init_stmts, [], False

        elif family == 'object_true':
            expr, inits = make_object_identity_true()
            return expr, [], [], True

        else:  # runtime_true
            expr, inits, imports = make_runtime_true()
            return expr, [], imports, True

    def _should_skip(self, node):
        """Check if this node should be skipped."""
        if isinstance(node, ast.If):
            # Skip if __name__ == '__main__'
            if isinstance(node.test, ast.Compare):
                if (isinstance(node.test.left, ast.Constant) and
                    node.test.left.value == '__name__'):
                    return True
            # Skip empty bodies
            if len(node.body) < 1:
                return True

        if isinstance(node, (ast.While, ast.For)):
            # Skip empty loops
            if len(node.body) < 1:
                return True

        return False

    def _inject_predicate(self, node):
        """Wrap a node with an opaque predicate guard.

        Returns: list of AST statements to replace the original node
        """
        if self._should_skip(node):
            return [node]

        # Random skip (20% chance) to avoid over-injection
        if random.random() > 0.8:
            return [node]

        # Generate predicate
        pred_var = self._next_op_name()
        pred_expr, init_stmts, imports, is_always_true = self._generate_predicate(pred_var)

        # Track imports
        for imp in imports:
            self.imports_needed.add(imp)

        # Generate junk for the "wrong" branch
        junk_stmts = make_junk_statements()

        # Create the wrapper if statement
        # If always True: body = real code, else = junk
        # If always False: body = junk, else = real code
        if is_always_true:
            wrapper = ast.If(
                test=pred_expr,
                body=[node],
                orelse=junk_stmts
            )
        else:
            wrapper = ast.If(
                test=pred_expr,
                body=junk_stmts,
                orelse=[node]
            )

        return init_stmts + [wrapper]

    def visit_If(self, node):
        return self._inject_predicate(node)

    def visit_While(self, node):
        return self._inject_predicate(node)

    def visit_For(self, node):
        return self._inject_predicate(node)


def obfuscate(source):
    """Apply opaque predicates to Python source code."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: failed to parse Python source: {e}", file=sys.stderr)
        sys.exit(1)

    transformer = OpaquePredicateTransformer()
    new_tree = transformer.visit(tree)
    ast.fix_missing_locations(new_tree)

    # Add imports if needed
    for imp_str in transformer.imports_needed:
        imp_tree = ast.parse(imp_str)
        new_tree.body.insert(0, imp_tree.body[0])

    return ast.unparse(new_tree) + "\n"


def main():
    source = sys.stdin.read()
    result = obfuscate(source)
    sys.stdout.write(result)


if __name__ == '__main__':
    main()
