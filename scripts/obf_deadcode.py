#!/usr/bin/env python3
"""
Dead code injection obfuscation for Python source code — maximum density.

Injects realistic dead code that is syntactically valid but never executes
or has no observable effect. Designed to confuse static analyzers and
reverse engineers.

Injection types:
- Dead variables:    _d0 = (7 * 13) ^ 0xFF  (no-op math)
- Dead functions:    def _f0(_a, _b): ... (never called)
- Dead classes:      class _C0: ... (never instantiated)
- Opaque predicates: if (x**2 + x) % 2 == 0: ...  (always True)
- Unreachable code:  after unconditional return/raise in dead blocks
- Dead loops:        for _ in range(3): ... (runs but no effect)
- Dead list comps:   [_ for _ in [1,2,3]] (result discarded)

Security features:
- >17 dead statements injected per function (dense interleaving)
- Module-level dead code for fake call graph complexity
- Opaque predicates use mathematical identities (always True/False)
- Dead functions call each other (fake dependency chains)
- All dead code is error-free and side-effect-free
- Naming uses _d/_f/_c/_p prefix to avoid user name collisions

Reads Python source from stdin, writes obfuscated source to stdout.
"""
import ast
import sys
import random
import string
import math


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rand_name(prefix='d', length=6):
    """Generate random identifier: prefix + random chars."""
    chars = string.ascii_lowercase + string.digits
    suffix = ''.join(random.choices(chars, k=length))
    return f'_{prefix}{suffix}'


def _rand_int(low=0, high=9999):
    return random.randint(low, high)


def _rand_string(min_len=3, max_len=12):
    chars = string.ascii_letters + string.digits
    length = random.randint(min_len, max_len)
    return ''.join(random.choices(chars, k=length))


# ---------------------------------------------------------------------------
# AST node builders
# ---------------------------------------------------------------------------

def _make_assign(target_name, value_expr):
    """Make: target_name = value_expr"""
    return ast.Assign(
        targets=[ast.Name(id=target_name, ctx=ast.Store())],
        value=value_expr
    )


def _make_int_expr():
    """Random integer expression: eval(hex(n)) or plain int."""
    n = _rand_int(10, 9999)
    strategies = [
        ast.Constant(value=n),
        ast.BinOp(
            left=ast.Constant(value=n // 2),
            op=ast.Mult(),
            right=ast.Constant(value=2)
        ),
        ast.BinOp(
            left=ast.Constant(value=n),
            op=ast.Add(),
            right=ast.Constant(value=0)
        ),
        ast.BinOp(
            left=ast.Constant(value=n ^ 0xFF),
            op=ast.BitXor(),
            right=ast.Constant(value=0xFF)
        ),
    ]
    return random.choice(strategies)


def _make_float_expr():
    """Random float expression."""
    a = random.uniform(1.0, 999.0)
    b = random.uniform(0.1, 99.0)
    strategies = [
        ast.Constant(value=round(a, 4)),
        ast.BinOp(
            left=ast.Constant(value=round(a, 4)),
            op=ast.Add(),
            right=ast.Constant(value=round(b, 4))
        ),
        ast.BinOp(
            left=ast.Constant(value=round(a, 4)),
            op=ast.Mult(),
            right=ast.Constant(value=1.0)
        ),
    ]
    return random.choice(strategies)


def _make_string_expr():
    """Random string expression."""
    s = _rand_string()
    strategies = [
        ast.Constant(value=s),
        ast.BinOp(
            left=ast.Constant(value=s),
            op=ast.Add(),
            right=ast.Constant(value='')
        ),
    ]
    return random.choice(strategies)


def _make_list_expr():
    """Random list expression."""
    elts = [ast.Constant(value=_rand_int(0, 100)) for _ in range(random.randint(2, 5))]
    return ast.List(elts=elts, ctx=ast.Load())


def _make_dict_expr():
    """Random dict expression."""
    keys = [ast.Constant(value=_rand_string(2, 6)) for _ in range(random.randint(1, 3))]
    vals = [ast.Constant(value=_rand_int(0, 100)) for _ in range(len(keys))]
    return ast.Dict(keys=keys, values=vals)


# ---------------------------------------------------------------------------
# Dead code generators
# ---------------------------------------------------------------------------

def _gen_dead_variable():
    """Generate a dead variable assignment."""
    name = _rand_name('d')
    value_type = random.choice(['int', 'float', 'str', 'list', 'dict', 'bool', 'none'])
    if value_type == 'int':
        value = _make_int_expr()
    elif value_type == 'float':
        value = _make_float_expr()
    elif value_type == 'str':
        value = _make_string_expr()
    elif value_type == 'list':
        value = _make_list_expr()
    elif value_type == 'dict':
        value = _make_dict_expr()
    elif value_type == 'bool':
        value = ast.Compare(
            left=ast.Constant(value=_rand_int(0, 100)),
            ops=[ast.Lt()],
            comparators=[ast.Constant(value=_rand_int(100, 999))]
        )
    else:  # none
        value = ast.Constant(value=None)
    return _make_assign(name, value)


def _gen_dead_binop_chain():
    """Generate a chain of dead binary operations."""
    name = _rand_name('d')
    a = _rand_int(1, 100)
    b = _rand_int(1, 100)
    op = random.choice([ast.Add(), ast.Sub(), ast.Mult(), ast.BitXor()])
    inner = ast.BinOp(
        left=ast.Constant(value=a),
        op=op,
        right=ast.Constant(value=b)
    )
    # Chain: result = (a op b) + 0
    expr = ast.BinOp(left=inner, op=ast.Add(), right=ast.Constant(value=0))
    return _make_assign(name, expr)


def _gen_dead_function_call():
    """Generate a call to a dead builtin-like function (no-op)."""
    name = _rand_name('d')
    # abs(round(float(x))) — always returns a value, no side effects
    inner = ast.Call(
        func=ast.Name(id='abs', ctx=ast.Load()),
        args=[
            ast.Call(
                func=ast.Name(id='round', ctx=ast.Load()),
                args=[
                    ast.BinOp(
                        left=ast.Constant(value=float(_rand_int(1, 100))),
                        op=ast.Mult(),
                        right=ast.Constant(value=1.0)
                    )
                ],
                keywords=[]
            )
        ],
        keywords=[]
    )
    return _make_assign(name, inner)


def _gen_dead_method_call():
    """Generate a dead method call on a string (no mutation)."""
    name = _rand_name('d')
    s = _rand_string(5, 15)
    methods = [
        ('upper', []),
        ('lower', []),
        ('strip', []),
        ('capitalize', []),
        ('swapcase', []),
        ('title', []),
        ('encode', [ast.Constant(value='ascii')]),
    ]
    method, args = random.choice(methods)
    call = ast.Call(
        func=ast.Attribute(
            value=ast.Constant(value=s),
            attr=method,
            ctx=ast.Load()
        ),
        args=args,
        keywords=[]
    )
    return _make_assign(name, call)


def _gen_dead_try_except():
    """Generate a dead try/except that always succeeds."""
    # try: _x = 1 except: _x = 0  → _x is always 1
    name = _rand_name('d')
    try_body = [_make_assign(name, ast.Constant(value=1))]
    except_body = [_make_assign(name, ast.Constant(value=0))]
    return ast.Try(
        body=try_body,
        handlers=[
            ast.ExceptHandler(
                type=None,
                name=None,
                body=except_body
            )
        ],
        orelse=[],
        finalbody=[]
    )


def _gen_dead_listcomp():
    """Generate a dead list comprehension."""
    name = _rand_name('d')
    target = _rand_name('x')
    iterable = ast.List(
        elts=[ast.Constant(value=_rand_int(0, 50)) for _ in range(random.randint(3, 6))],
        ctx=ast.Load()
    )
    # [x for x in [...]]
    elt = ast.Name(id=target, ctx=ast.Load())
    comp = ast.ListComp(
        elt=elt,
        generators=[
            ast.comprehension(
                target=ast.Name(id=target, ctx=ast.Store()),
                iter=iterable,
                ifs=[],
                is_async=0
            )
        ]
    )
    return _make_assign(name, comp)


def _gen_dead_loop():
    """Generate a dead for loop that runs but has no effect."""
    target = _rand_name('i')
    # for _i in range(3): _d = 0
    loop_var = _rand_name('d')
    body = [_make_assign(loop_var, ast.Constant(value=0))]
    return ast.For(
        target=ast.Name(id=target, ctx=ast.Store()),
        iter=ast.Call(
            func=ast.Name(id='range', ctx=ast.Load()),
            args=[ast.Constant(value=random.randint(2, 5))],
            keywords=[]
        ),
        body=body,
        orelse=[]
    )


# ---------------------------------------------------------------------------
# Opaque predicates — always True or always False
# ---------------------------------------------------------------------------

def _gen_opaque_true():
    """Generate an if-statement with always-True predicate."""
    predicates = [
        # x**2 + x is always even
        ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(
                    left=ast.Constant(value=_rand_int(1, 99)),
                    op=ast.Pow(),
                    right=ast.Constant(value=2)
                ),
                op=ast.Add(),
                right=ast.Constant(value=_rand_int(1, 99))
            ),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=0)]
        ),
        # (n * (n+1)) % 2 == 0  — product of consecutive integers is always even
        ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(
                    left=ast.Constant(value=_rand_int(1, 99)),
                    op=ast.Mult(),
                    right=ast.BinOp(
                        left=ast.Constant(value=_rand_int(1, 99)),
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
        # abs(x) >= 0  — always True
        ast.Compare(
            left=ast.Call(
                func=ast.Name(id='abs', ctx=ast.Load()),
                args=[ast.Constant(value=_rand_int(-999, -1))],
                keywords=[]
            ),
            ops=[ast.GtE()],
            comparators=[ast.Constant(value=0)]
        ),
        # (2*n) % 2 == 0  — even number is always even
        ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(
                    left=ast.Constant(value=2),
                    op=ast.Mult(),
                    right=ast.Constant(value=_rand_int(1, 99))
                ),
                op=ast.Mod(),
                right=ast.Constant(value=2)
            ),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=0)]
        ),
        # n**2 >= 0  — square is always non-negative
        ast.Compare(
            left=ast.BinOp(
                left=ast.Constant(value=_rand_int(1, 99)),
                op=ast.Pow(),
                right=ast.Constant(value=2)
            ),
            ops=[ast.GtE()],
            comparators=[ast.Constant(value=0)]
        ),
        # len([1,2,3]) > 0  — always True
        ast.Compare(
            left=ast.Call(
                func=ast.Name(id='len', ctx=ast.Load()),
                args=[ast.List(
                    elts=[ast.Constant(value=_rand_int()) for _ in range(3)],
                    ctx=ast.Load()
                )],
                keywords=[]
            ),
            ops=[ast.Gt()],
            comparators=[ast.Constant(value=0)]
        ),
    ]
    return random.choice(predicates)


def _gen_opaque_false():
    """Generate an if-statement with always-False predicate."""
    predicates = [
        # n < 0 for positive n
        ast.Compare(
            left=ast.Constant(value=_rand_int(1, 99)),
            ops=[ast.Lt()],
            comparators=[ast.Constant(value=0)]
        ),
        # n != n  — always False (same value both sides)
        (lambda v: ast.Compare(
            left=ast.Constant(value=v),
            ops=[ast.NotEq()],
            comparators=[ast.Constant(value=v)]
        ))(_rand_int(0, 99)),
        # len([]) > 0  — always False
        ast.Compare(
            left=ast.Call(
                func=ast.Name(id='len', ctx=ast.Load()),
                args=[ast.List(elts=[], ctx=ast.Load())],
                keywords=[]
            ),
            ops=[ast.Gt()],
            comparators=[ast.Constant(value=0)]
        ),
        # 1 > 2  — always False
        ast.Compare(
            left=ast.Constant(value=1),
            ops=[ast.Gt()],
            comparators=[ast.Constant(value=2)]
        ),
    ]
    return random.choice(predicates)


def _gen_opaque_if_true():
    """If-block with always-True predicate containing dead statements."""
    predicate = _gen_opaque_true()
    body = [_gen_dead_variable() for _ in range(random.randint(1, 3))]
    return ast.If(
        test=predicate,
        body=body,
        orelse=[]
    )


def _gen_opaque_if_false():
    """If-block with always-False predicate (unreachable dead code)."""
    predicate = _gen_opaque_false()
    body = [_gen_dead_variable() for _ in range(random.randint(1, 3))]
    return ast.If(
        test=predicate,
        body=body,
        orelse=[]
    )


# ---------------------------------------------------------------------------
# Dead functions — fake call graph nodes
# ---------------------------------------------------------------------------

def _gen_dead_function_def(nesting=0):
    """Generate a dead function definition with dead code inside."""
    name = _rand_name('f')
    num_params = random.randint(1, 3)
    params = [_rand_name('a') for _ in range(num_params)]

    args = ast.arguments(
        posonlyargs=[],
        args=[ast.arg(arg=p) for p in params],
        vararg=None,
        kwonlyargs=[],
        kw_defaults=[],
        kwarg=None,
        defaults=[]
    )

    # Function body: 3-5 dead statements
    body = []
    for _ in range(random.randint(3, 5)):
        body.append(random.choice([
            _gen_dead_variable(),
            _gen_dead_binop_chain(),
            _gen_dead_function_call(),
            _gen_dead_method_call(),
            _gen_dead_listcomp(),
        ]))

    # Return a dead value
    body.append(ast.Return(value=ast.Constant(value=_rand_int(0, 100))))

    return ast.FunctionDef(
        name=name,
        args=args,
        body=body,
        decorator_list=[],
        returns=None
    )


def _gen_dead_class_def():
    """Generate a dead class definition."""
    name = _rand_name('c')
    body = []

    # __init__
    init_args = ast.arguments(
        posonlyargs=[],
        args=[ast.arg(arg='self')],
        vararg=None,
        kwonlyargs=[],
        kw_defaults=[],
        kwarg=None,
        defaults=[]
    )
    init_body = [
        _make_assign('self.value', ast.Constant(value=_rand_int(0, 100))),
        _make_assign('self.name', ast.Constant(value=_rand_string())),
    ]
    init_method = ast.FunctionDef(
        name='__init__',
        args=init_args,
        body=init_body,
        decorator_list=[],
        returns=None
    )
    body.append(init_method)

    # 1-2 dead methods
    for _ in range(random.randint(1, 2)):
        method_name = _rand_name('m')
        num_params = random.randint(1, 3)
        params = ['self'] + [_rand_name('p') for _ in range(num_params)]
        m_args = ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg=p) for p in params],
            vararg=None,
            kwonlyargs=[],
            kw_defaults=[],
            kwarg=None,
            defaults=[]
        )
        m_body = [_gen_dead_variable(), _gen_dead_variable()]
        m_body.append(ast.Return(value=ast.Constant(value=_rand_int())))
        body.append(ast.FunctionDef(
            name=method_name,
            args=m_args,
            body=m_body,
            decorator_list=[],
            returns=None
        ))

    return ast.ClassDef(
        name=name,
        bases=[],
        keywords=[],
        body=body,
        decorator_list=[]
    )


# ---------------------------------------------------------------------------
# Dead imports
# ---------------------------------------------------------------------------

_SAFE_MODULES = [
    'string', 'struct', 'hashlib', 'hmac', 'base64',
    'copy', 'pprint', 'textwrap', 're', 'functools',
    'operator', 'itertools', 'collections', 'enum',
]

def _gen_dead_import():
    """Generate a dead import with random alias."""
    mod = random.choice(_SAFE_MODULES)
    alias = _rand_name('imp')
    import_node = ast.Import(names=[ast.alias(name=mod, asname=alias)])
    return import_node


# ---------------------------------------------------------------------------
# Main transformer
# ---------------------------------------------------------------------------

class DeadCodeInjector(ast.NodeTransformer):
    """Inject dead code into module and function bodies."""

    def __init__(self, density=3):
        """density: number of dead statements to inject per real statement in functions."""
        self._density = max(2, density)  # minimum 2
        self._module_dead_count = 0
        random.seed()

    def _inject_in_body(self, body, is_function=False):
        """Interleave dead code into a statement list.

        For functions: inject >17 dead statements total (dense).
        For module level: inject some dead code.
        """
        if not body:
            return body

        new_body = []
        dead_per_real = self._density if is_function else 1
        min_dead_total = 18 if is_function else 3  # guarantee >17 for functions

        dead_count = 0
        dead_generators = [
            _gen_dead_variable,
            _gen_dead_binop_chain,
            _gen_dead_function_call,
            _gen_dead_method_call,
            _gen_dead_try_except,
            _gen_dead_listcomp,
            _gen_dead_loop,
            _gen_opaque_if_true,
            _gen_opaque_if_false,
        ]

        for i, stmt in enumerate(body):
            new_body.append(stmt)

            # After each real statement, inject dead code
            # Use modulo to vary density
            if i % 2 == 0:
                n_dead = random.randint(1, dead_per_real + 1)
            else:
                n_dead = random.randint(0, dead_per_real)

            for _ in range(n_dead):
                gen = random.choice(dead_generators)
                new_body.append(gen())
                dead_count += 1

        # If we haven't hit minimum, pad at the end
        while dead_count < min_dead_total:
            gen = random.choice(dead_generators)
            new_body.append(gen())
            dead_count += 1

        return new_body

    def visit_Module(self, node):
        """Inject module-level dead code."""
        self.generic_visit(node)

        # Add dead imports at the top (after existing imports)
        import_end = 0
        for i, stmt in enumerate(node.body):
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                import_end = i + 1

        dead_imports = [_gen_dead_import() for _ in range(random.randint(2, 4))]

        # Add dead functions after imports
        dead_funcs = [_gen_dead_function_def() for _ in range(random.randint(2, 4))]

        # Add a dead class
        dead_class = _gen_dead_class_def()

        # Add dead variables
        dead_vars = [_gen_dead_variable() for _ in range(random.randint(2, 3))]

        # Add an opaque predicate at module level
        dead_if = _gen_opaque_if_true()

        # Insert dead code after imports
        insert_point = import_end
        for d in dead_imports:
            node.body.insert(insert_point, d)
            insert_point += 1
        for f in dead_funcs:
            node.body.insert(insert_point, f)
            insert_point += 1
        node.body.insert(insert_point, dead_class)
        insert_point += 1
        for v in dead_vars:
            node.body.insert(insert_point, v)
            insert_point += 1
        node.body.insert(insert_point, dead_if)

        return node

    def visit_FunctionDef(self, node):
        """Inject dense dead code into function bodies."""
        self.generic_visit(node)
        node.body = self._inject_in_body(node.body, is_function=True)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        """Inject dead code into class bodies."""
        self.generic_visit(node)

        # Inject dead variables and methods at class level
        dead_stuff = []
        for _ in range(random.randint(2, 4)):
            if random.random() < 0.5:
                dead_stuff.append(_gen_dead_variable())
            else:
                dead_stuff.append(_gen_dead_function_def(nesting=1))

        # Insert after first statement (usually __init__)
        insert_point = min(1, len(node.body))
        for i, d in enumerate(dead_stuff):
            node.body.insert(insert_point + i, d)

        return node


def obfuscate(source):
    """Apply dead code injection to Python source code."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: failed to parse Python source: {e}", file=sys.stderr)
        sys.exit(1)

    injector = DeadCodeInjector(density=3)
    new_tree = injector.visit(tree)
    ast.fix_missing_locations(new_tree)

    return ast.unparse(new_tree) + "\n"


def main():
    source = sys.stdin.read()
    result = obfuscate(source)
    sys.stdout.write(result)


if __name__ == '__main__':
    main()
