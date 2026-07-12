# Control Flow Flattening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Control Flow Flattening (CFF) obfuscation technique that decomposes Python function bodies into basic blocks and reconstructs them inside a `while + match/case` dispatcher.

**Architecture:** Single Python AST transformer (`scripts/obf_cff.py`) that walks each `FunctionDef`, classifies statements, and rewrites the body into a flat state machine. C++ dispatch wiring follows the existing pattern (enum + parse + script name mapping).

**Tech Stack:** Python 3.10+ AST module (match/case in output), C++17, doctest

## Global Constraints

- Python ≥3.10 required for obfuscated output (match/case syntax)
- Top-level FunctionDef only — nested defs/classes are leaf nodes (treated as simple statements)
- No yield/generator support in first version
- No module-level code flattening
- Follow existing stdin → AST transform → stdout pattern
- Hex state IDs (`0x4f2a1b`) for obfuscation — not sequential integers

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `scripts/obf_cff.py` | Create | CFF transformer (~450 lines) |
| `include/switch/obfuscate.hpp:21` | Modify | Add `ControlFlowFlattening` to `ObfType` enum |
| `src/obfuscate.cpp:44-75` | Modify | Add to `parse_obf_type()`, `obf_type_name()`, `all_obf_names()`, `obfuscate()` |
| `src/main.cpp:44-55` | Modify | Add sort order entry (order=95, before ImportRewrite=90... actually after it) |
| `tests/test_obf.cpp` | Modify | Add CFF test cases |

---

### Task 1: Create `scripts/obf_cff.py` — Core Infrastructure + Simple Flattening

**Files:**
- Create: `scripts/obf_cff.py`

**Interfaces:**
- Consumes: Python source code via stdin
- Produces: Obfuscated Python source via stdout
- Function: `obfuscate(source: str) -> str`

- [ ] **Step 1: Create the script with core infrastructure**

Create `scripts/obf_cff.py` with:
- Imports (ast, sys, random, string)
- `CFFState` class — counter for hex state IDs
- `make_hex_id()` — generates random 6-digit hex IDs like `0x4f2a1b`
- `make_state_var()` — returns `ast.Name(id='_s', ctx=ast.Store())`
- `make_return_var()` — returns `ast.Name(id='_rv', ctx=ast.Store())`
- `make_state_assign(hex_id)` — returns `_s = 0xHEX`
- `make_dispatcher_body(cases)` — builds `while _s != 0: match _s: case ...`
- `flatten_sequential(stmts, next_state)` — merge simple statements into one block
- `FunctionFlattener` class — main transformer

```python
#!/usr/bin/env python3
"""
Control Flow Flattening obfuscation for Python source code.

Decomposes function bodies into basic blocks and reconstructs them
inside a while + match/case dispatcher. Destroys hierarchical control
flow (if/else, for, while, try/except) — all logic driven by state.

Requires Python 3.10+ for output (match/case syntax).

Reads Python source from stdin, writes obfuscated source to stdout.
"""
import ast
import sys
import random
import string


def _hex_id():
    """Generate random 6-hex-digit ID like 0x4f2a1b."""
    chars = '0123456789abcdef'
    return '0x' + ''.join(random.choices(chars, k=6))


def _make_name(name, ctx=None):
    """Build ast.Name node."""
    return ast.Name(id=name, ctx=ctx or ast.Load())


def _make_assign(target_name, value):
    """Build: target_name = value"""
    return ast.Assign(
        targets=[_make_name(target_name, ast.Store())],
        value=value
    )


def _make_state_assign(hex_id):
    """Build: _s = 0xHEX"""
    return _make_assign('_s', ast.Constant(value=hex_id))


def _make_state_cmp(hex_id):
    """Build: _s == 0xHEX  (for case matching)"""
    return ast.Compare(
        left=_make_name('_s'),
        ops=[ast.Eq()],
        comparators=[ast.Constant(value=hex_id)]
    )


def _wrap_in_try(stmts, except_state, loop_state=None):
    """Wrap stmts in try/except StopIteration: _s = except_state.
    Used for for-loop header (next(_iter) pattern)."""
    try_body = list(stmts)
    if loop_state:
        try_body.append(_make_state_assign(loop_state))

    except_handler = ast.ExceptHandler(
        type=ast.Name(id='StopIteration', ctx=ast.Load()),
        name=None,
        body=[_make_state_assign(except_state)]
    )

    return ast.Try(
        body=try_body,
        handlers=[except_handler],
        orelse=[],
        finalbody=[]
    )
```

- [ ] **Step 2: Test that the script is valid Python**

Run:
```bash
python3 -c "import ast; ast.parse(open('scripts/obf_cff.py').read()); print('OK')"
```
Expected: `OK`

- [ ] **Step 3: Add `flatten_sequential()` function**

This function merges a list of simple statements (assign, expr, etc.) into one case block and appends the state transition at the end.

```python
def flatten_sequential(stmts, next_state):
    """Merge simple statements into one block ending with state transition.
    Returns list of AST statements (body for a case block)."""
    result = []
    for s in stmts:
        result.append(s)
    result.append(_make_state_assign(next_state))
    return result
```

- [ ] **Step 4: Commit**

```bash
git add scripts/obf_cff.py
git commit -m "feat(obf): add CFF script skeleton with core helpers

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Implement `FunctionFlattener` — if/elif/else Flattening

**Files:**
- Modify: `scripts/obf_cff.py`

**Interfaces:**
- Consumes: `FunctionDef` AST node
- Produces: Rewritten `FunctionDef` body with dispatcher

- [ ] **Step 1: Add FunctionFlattener class skeleton**

Add the main class with state management and the `visit_FunctionDef` entry point:

```python
class FunctionFlattener(ast.NodeTransformer):
    """Flatten function bodies into while+match/case dispatchers."""

    def __init__(self):
        self._states = {}      # hex_id -> list[stmt] (case body)
        self._loop_stack = []  # [(header_state, exit_state)] for break/continue

    def _new_state(self):
        """Allocate a new unique hex state ID."""
        return _hex_id()

    def _add_case(self, hex_id, stmts):
        """Register a case block."""
        self._states[hex_id] = stmts

    def _flatten_body(self, stmts, next_state):
        """Flatten a list of statements into case blocks.
        next_state: where to go after the last statement (or None for _s=0).
        Returns: list of (hex_id, body_stmts) pairs."""
        if not stmts:
            return []

        # Classify the last statement separately (it may set next_state)
        *head, tail = stmts

        # Flatten head statements as sequential
        result = []
        for stmt in head:
            kind = self._classify(stmt)
            if kind == 'simple':
                pass  # handled in sequential merge below
            elif kind == 'if':
                result.extend(self._flatten_if(stmt))
                continue
            elif kind == 'for':
                result.extend(self._flatten_for(stmt))
                continue
            elif kind == 'while':
                result.extend(self._flatten_while(stmt))
                continue
            elif kind == 'try':
                result.extend(self._flatten_try(stmt))
                continue

        # Handle tail
        tail_kind = self._classify(tail)
        if tail_kind == 'simple':
            # Merge all remaining sequential stmts
            seq = [s for s in head if self._classify(s) == 'simple'] + [tail]
            # Actually, let's simplify: just flatten everything sequentially first
            pass

        return result

    def _classify(self, stmt):
        """Classify a statement for flattening strategy."""
        if isinstance(stmt, ast.If):
            return 'if'
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            return 'for'
        elif isinstance(stmt, (ast.While,)):
            return 'while'
        elif isinstance(stmt, ast.Try):
            return 'try'
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return 'leaf'  # nested func/class — treat as simple
        else:
            return 'simple'

    def visit_FunctionDef(self, node):
        """Entry point: flatten a function's body."""
        self.generic_visit(node)  # flatten nested functions first (leaf handling)

        # Skip empty bodies
        if not node.body:
            return node

        # Skip functions with only simple statements (nothing to flatten)
        has_control = any(self._classify(s) not in ('simple', 'leaf') for s in node.body)
        if not has_control:
            return node

        # Build dispatcher
        self._states = {}
        entry_state = self._new_state()

        # Flatten body — all statements go to exit state (0)
        case_bodies = self._flatten_body(node.body, exit_state='0')

        # Register entry state
        self._add_case(entry_state, case_bodies)

        # Build while + match
        dispatcher = self._build_dispatcher(entry_state)

        node.body = [dispatcher]
        ast.fix_missing_locations(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def _build_dispatcher(self, entry_state):
        """Build: _s = ENTRY; _rv = None; while _s != 0: match _s: case ..."""
        # ... will implement in next tasks
        pass
```

- [ ] **Step 2: Implement `_flatten_if()` for if/elif/else**

```python
def _flatten_if(self, stmt):
    """Flatten if/elif/else into decision + branch + merge cases.
    Returns list of (hex_id, body) pairs."""
    cases = []

    # For simple if/else:
    #   if test: body   else: orelse
    # Becomes:
    #   case DECISION: if test: _s = TRUE_STATE else: _s = FALSE_STATE
    #   case TRUE_STATE: ...body...; _s = MERGE
    #   case FALSE_STATE: ...orelse...; _s = MERGE

    merge_state = self._new_state()

    def build_if_chain(node, fallthrough_state):
        """Recursively build if/elif chain."""
        if isinstance(node, ast.If):
            decision_state = self._new_state()
            true_state = self._new_state()

            # Flatten true branch
            true_body = self._flatten_body(node.body, next_state=merge_state)
            self._add_case(true_state, true_body)

            if node.orelse:
                if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                    # elif: chain to next decision
                    false_state = self._new_state()
                    self._add_case(false_state, [ast.Pass()])  # placeholder
                    build_if_chain(node.orelse[0], false_state)

                    decision_body = [
                        ast.If(
                            test=node.test,
                            body=[_make_state_assign(true_state)],
                            orelse=[_make_state_assign(false_state)]
                        )
                    ]
                else:
                    # else block
                    false_state = self._new_state()
                    false_body = self._flatten_body(node.orelse, next_state=merge_state)
                    self._add_case(false_state, false_body)

                    decision_body = [
                        ast.If(
                            test=node.test,
                            body=[_make_state_assign(true_state)],
                            orelse=[_make_state_assign(false_state)]
                        )
                    ]
            else:
                # No else — fall through to merge
                decision_body = [
                    ast.If(
                        test=node.test,
                        body=[_make_state_assign(true_state)],
                        orelse=[_make_state_assign(merge_state)]
                    )
                ]

            self._add_case(decision_state, decision_body)
            return decision_state

    first_decision = build_if_chain(stmt, merge_state)

    # Collect all registered cases
    result = []
    for hex_id, body in self._states.items():
        result.append((hex_id, body))

    # Clear states for next flattening
    self._states = {}

    return result
```

- [ ] **Step 3: Test if/else flattening**

Create test file `tests/test_cff_if.py`:
```python
#!/usr/bin/env python3
"""Test CFF if/else flattening."""
import subprocess
import sys

CODE = '''
def check(x):
    if x > 10:
        print("big")
    else:
        print("small")
    return True
'''

proc = subprocess.run(
    [sys.executable, 'scripts/obf_cff.py'],
    input=CODE, capture_output=True, text=True
)
assert proc.returncode == 0, f"Script failed: {proc.stderr}"
output = proc.stdout
print("Output:")
print(output)

# Verify syntax
compile(output, '<test>', 'exec')
print("Syntax OK")

# Verify behavior
namespace = {}
exec(output, namespace)
import io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    assert namespace['check'](20) == True
    assert namespace['check'](5) == True
assert 'big' in buf.getvalue()
assert 'small' in buf.getvalue()
print("Behavior OK")
```

Run:
```bash
python3 tests/test_cff_if.py
```
Expected: Syntax OK + Behavior OK

- [ ] **Step 4: Commit**

```bash
git add scripts/obf_cff.py tests/test_cff_if.py
git commit -m "feat(obf): implement if/elif/else CFF flattening

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Implement for/while Loop Flattening

**Files:**
- Modify: `scripts/obf_cff.py`

**Interfaces:**
- Consumes: `For`/`While` AST nodes from FunctionFlattener
- Produces: Case blocks with iter/next pattern for for, header pattern for while

- [ ] **Step 1: Implement `_flatten_for()`**

For loop transformation:
- `for x in items: body` → 4 states:
  1. INIT: `_iter = iter(items); _s = HEADER`
  2. HEADER: `try: x = next(_iter); _s = BODY except StopIteration: _s = EXIT`
  3. BODY: `...flattened body...; _s = HEADER` (or _s = EXIT on break)
  4. EXIT: next state after loop

```python
def _flatten_for(self, stmt):
    """Flatten for loop into init + header + body + exit cases."""
    cases = []

    # stmt.target = loop variable (e.g., `x` in `for x in items`)
    # stmt.iter = iterable expression
    # stmt.body = loop body statements
    # stmt.orelse = else block (runs if no break)

    init_state = self._new_state()
    header_state = self._new_state()
    exit_state = self._new_state()
    body_state = self._new_state()

    # Push loop context for break/continue
    self._loop_stack.append((header_state, exit_state))

    # INIT: _iter = iter(items); _s = HEADER
    iter_name = f"_iter_{init_state}"
    init_body = [
        _make_assign(iter_name, ast.Call(
            func=ast.Name(id='iter', ctx=ast.Load()),
            args=[stmt.iter],
            keywords=[]
        )),
        _make_state_assign(header_state)
    ]
    self._add_case(init_state, init_body)

    # HEADER: try: target = next(_iter); _s = BODY  except StopIteration: _s = EXIT
    target_assign = ast.Assign(
        targets=[stmt.target],
        value=ast.Call(
            func=ast.Name(id='next', ctx=ast.Load()),
            args=[ast.Name(id=iter_name, ctx=ast.Load())],
            keywords=[]
        )
    )
    header_body = _wrap_in_try(
        [target_assign],
        except_state=exit_state,
        loop_state=body_state
    )
    self._add_case(header_state, [header_body])

    # BODY: flattened loop body, last stmt → _s = HEADER
    body_stmts = self._flatten_body(stmt.body, next_state=header_state)
    self._add_case(body_state, body_stmts)

    # Pop loop context
    self._loop_stack.pop()

    # EXIT: continue to next statement after loop
    # (will be connected by caller)

    return [(init_state, init_body), (header_state, [header_body]),
            (body_state, body_stmts), (exit_state, None)]
```

- [ ] **Step 2: Implement `_flatten_while()`**

```python
def _flatten_while(self, stmt):
    """Flatten while loop into header + body + exit cases."""
    header_state = self._new_state()
    body_state = self._new_state()
    exit_state = self._new_state()

    self._loop_stack.append((header_state, exit_state))

    # HEADER: if test: _s = BODY else: _s = EXIT
    header_body = [
        ast.If(
            test=stmt.test,
            body=[_make_state_assign(body_state)],
            orelse=[_make_state_assign(exit_state)]
        )
    ]
    self._add_case(header_state, header_body)

    # BODY: flattened body, last → _s = HEADER
    body_stmts = self._flatten_body(stmt.body, next_state=header_state)
    self._add_case(body_state, body_stmts)

    self._loop_stack.pop()

    return [(header_state, header_body), (body_state, body_stmts), (exit_state, None)]
```

- [ ] **Step 3: Implement break/continue transformation**

Inside `_flatten_body()`, handle `ast.Break` and `ast.Continue`:

```python
# In _classify():
elif isinstance(stmt, ast.Break):
    return 'break'
elif isinstance(stmt, ast.Continue):
    return 'continue'

# In the flattening loop, when encountering break:
# Replace with: _s = EXIT_STATE (top of _loop_stack)
# When encountering continue:
# Replace with: _s = HEADER_STATE (top of _loop_stack)
```

Replace break/continue statements inline:
```python
def _replace_break_continue(self, stmts):
    """Replace Break/Continue with state assignments."""
    result = []
    for s in stmts:
        if isinstance(s, ast.Break):
            if self._loop_stack:
                _, exit_state = self._loop_stack[-1]
                result.append(_make_state_assign(exit_state))
            else:
                result.append(s)  # bare break outside loop — keep as-is
        elif isinstance(s, ast.Continue):
            if self._loop_stack:
                header_state, _ = self._loop_stack[-1]
                result.append(_make_state_assign(header_state))
            else:
                result.append(s)
        else:
            result.append(s)
    return result
```

- [ ] **Step 4: Test for loop flattening**

Create `tests/test_cff_for.py`:
```python
#!/usr/bin/env python3
"""Test CFF for loop flattening."""
import subprocess, sys, io, contextlib

CODE = '''
def sum_positive(items):
    total = 0
    for x in items:
        if x > 0:
            total += x
    return total
'''

proc = subprocess.run(
    [sys.executable, 'scripts/obf_cff.py'],
    input=CODE, capture_output=True, text=True
)
assert proc.returncode == 0, f"Script failed: {proc.stderr}"
output = proc.stdout
print("Output:"); print(output)
compile(output, '<test>', 'exec')
print("Syntax OK")

namespace = {}
exec(output, namespace)
result = namespace['sum_positive']([1, -2, 3, 0, 5])
assert result == 9, f"Expected 9, got {result}"
print(f"Behavior OK: sum_positive([1,-2,3,0,5]) = {result}")
```

Run:
```bash
python3 tests/test_cff_for.py
```
Expected: Syntax OK + Behavior OK

- [ ] **Step 5: Test while loop flattening**

Create `tests/test_cff_while.py`:
```python
#!/usr/bin/env python3
"""Test CFF while loop flattening."""
import subprocess, sys

CODE = '''
def countdown(n):
    result = []
    while n > 0:
        result.append(n)
        n -= 1
    return result
'''

proc = subprocess.run(
    [sys.executable, 'scripts/obf_cff.py'],
    input=CODE, capture_output=True, text=True
)
assert proc.returncode == 0, f"Script failed: {proc.stderr}"
output = proc.stdout
print("Output:"); print(output)
compile(output, '<test>', 'exec')
print("Syntax OK")

namespace = {}
exec(output, namespace)
assert namespace['countdown'](3) == [3, 2, 1]
print("Behavior OK")
```

Run:
```bash
python3 tests/test_cff_while.py
```

- [ ] **Step 6: Commit**

```bash
git add scripts/obf_cff.py tests/test_cff_for.py tests/test_cff_while.py
git commit -m "feat(obf): implement for/while loop CFF flattening with break/continue

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Implement try/except + return Flattening

**Files:**
- Modify: `scripts/obf_cff.py`

**Interfaces:**
- Consumes: `Try` AST nodes and `Return` statements
- Produces: Case blocks with exception handling, return → _rv + _s=0

- [ ] **Step 1: Implement `_flatten_try()`**

```python
def _flatten_try(self, stmt):
    """Flatten try/except/finally into case blocks."""
    # Strategy: wrap the entire try/except in one case block,
    # with handler bodies as separate states.

    try_state = self._new_state()
    merge_state = self._new_state()

    # Flatten try body
    try_next = self._new_state()
    try_body_stmts = self._flatten_body(stmt.body, next_state=try_next)
    self._add_case(try_state, try_body_stmts)

    # Build except handlers — each handler body becomes a state
    handlers = []
    for handler in stmt.handlers:
        handler_state = self._new_state()
        handler_body = self._flatten_body(handler.body, next_state=merge_state)

        # Build ExceptHandler with state transition in body
        exc_type = handler.type
        exc_name = handler.name

        new_handler = ast.ExceptHandler(
            type=exc_type,
            name=exc_name,
            body=[_make_state_assign(merge_state)]  # just transition
        )
        handlers.append((handler_state, new_handler, handler_body))

    # Build the try/except structure
    try_node = ast.Try(
        body=[_make_state_assign(try_next)],
        handlers=[h for _, h, _ in handlers],
        orelse=[],
        finalbody=[]
    )

    # try_next case: actual try body
    self._add_case(try_next, [try_node])

    # Handler body cases
    for handler_state, _, handler_body in handlers:
        self._add_case(handler_state, handler_body)

    # finally block if present
    if stmt.finalbody:
        finally_state = self._new_state()
        finally_body = self._flatten_body(stmt.finalbody, next_state=merge_state)
        self._add_case(finally_state, finally_body)
        # TODO: integrate finally into exception flow

    return [(try_state, try_body_stmts), (try_next, [try_node]),
            (merge_state, None)]
```

- [ ] **Step 2: Handle `return` statements**

Replace `return expr` with `_rv = expr; _s = 0`:

```python
def _replace_returns(self, stmts):
    """Replace Return statements with _rv assignment + state=0."""
    result = []
    for s in stmts:
        if isinstance(s, ast.Return):
            if s.value is not None:
                result.append(_make_assign('_rv', s.value))
            result.append(_make_state_assign('0'))
        elif isinstance(s, ast.If):
            # Recurse into if body/orelse to find nested returns
            s.body = self._replace_returns(s.body)
            if s.orelse:
                s.orelse = self._replace_returns(s.orelse)
            result.append(s)
        else:
            result.append(s)
    return result
```

- [ ] **Step 3: Test try/except flattening**

Create `tests/test_cff_try.py`:
```python
#!/usr/bin/env python3
"""Test CFF try/except flattening."""
import subprocess, sys

CODE = '''
def safe_divide(a, b):
    try:
        result = a / b
    except ZeroDivisionError:
        result = None
    return result
'''

proc = subprocess.run(
    [sys.executable, 'scripts/obf_cff.py'],
    input=CODE, capture_output=True, text=True
)
assert proc.returncode == 0, f"Script failed: {proc.stderr}"
output = proc.stdout
print("Output:"); print(output)
compile(output, '<test>', 'exec')
print("Syntax OK")

namespace = {}
exec(output, namespace)
assert namespace['safe_divide'](10, 2) == 5.0
assert namespace['safe_divide'](10, 0) is None
print("Behavior OK")
```

Run:
```bash
python3 tests/test_cff_try.py
```

- [ ] **Step 4: Test return in nested context**

Create `tests/test_cff_return.py`:
```python
#!/usr/bin/env python3
"""Test CFF return flattening."""
import subprocess, sys

CODE = '''
def find_first(items, target):
    for item in items:
        if item == target:
            return item
    return None
'''

proc = subprocess.run(
    [sys.executable, 'scripts/obf_cff.py'],
    input=CODE, capture_output=True, text=True
)
assert proc.returncode == 0, f"Script failed: {proc.stderr}"
output = proc.stdout
print("Output:"); print(output)
compile(output, '<test>', 'exec')
print("Syntax OK")

namespace = {}
exec(output, namespace)
assert namespace['find_first']([1,2,3], 2) == 2
assert namespace['find_first']([1,2,3], 5) is None
print("Behavior OK")
```

Run:
```bash
python3 tests/test_cff_return.py
```

- [ ] **Step 5: Commit**

```bash
git add scripts/obf_cff.py tests/test_cff_try.py tests/test_cff_return.py
git commit -m "feat(obf): implement try/except and return CFF flattening

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Complete `obfuscate()` Entry Point + Leaf Node Handling

**Files:**
- Modify: `scripts/obf_cff.py`

**Interfaces:**
- Produces: Complete `obfuscate(source)` function matching existing script pattern

- [ ] **Step 1: Add the `obfuscate()` entry point and `main()`**

```python
def obfuscate(source):
    """Apply control flow flattening to Python source code."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: failed to parse Python source: {e}", file=sys.stderr)
        sys.exit(1)

    flattener = FunctionFlattener()
    new_tree = flattener.visit(tree)
    ast.fix_missing_locations(new_tree)

    return ast.unparse(new_tree) + "\n"


def main():
    source = sys.stdin.read()
    result = obfuscate(source)
    sys.stdout.write(result)


if __name__ == '__main__':
    main()
```

- [ ] **Step 2: Add leaf node handling in `FunctionFlattener.generic_visit()`**

Nested functions and classes should be treated as simple statements (not flattened):

```python
def generic_visit(self, node):
    """Skip flattening for nested func/class — treat as leaf nodes."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node  # Don't descend into nested scopes
    return super().generic_visit(node)
```

- [ ] **Step 3: Test nested function/class is NOT flattened**

Create `tests/test_cff_nested.py`:
```python
#!/usr/bin/env python3
"""Test CFF skips nested functions/classes."""
import subprocess, sys

CODE = '''
def outer(x):
    def inner(y):
        return y + 1
    return inner(x)
'''

proc = subprocess.run(
    [sys.executable, 'scripts/obf_cff.py'],
    input=CODE, capture_output=True, text=True
)
assert proc.returncode == 0, f"Script failed: {proc.stderr}"
output = proc.stdout
print("Output:"); print(output)
compile(output, '<test>', 'exec')
print("Syntax OK")

namespace = {}
exec(output, namespace)
assert namespace['outer'](5) == 6
print("Behavior OK: nested function preserved")
```

Run:
```bash
python3 tests/test_cff_nested.py
```

- [ ] **Step 4: Test simple function (no control flow) is NOT flattened**

```python
CODE = '''
def add(a, b):
    return a + b
'''
# Should return unchanged (no control flow to flatten)
```

Verify the output still works:
```bash
echo 'def add(a, b): return a + b' | python3 scripts/obf_cff.py
```
Expected: Output similar to input (no dispatcher created).

- [ ] **Step 5: Full integration test**

Create `tests/test_cff_full.py`:
```python
#!/usr/bin/env python3
"""Full CFF integration test — complex function."""
import subprocess, sys, io, contextlib

CODE = '''
def complex_func(data):
    result = []
    total = 0
    for item in data:
        if item > 0:
            total += item
            if item > 100:
                result.append("large")
            else:
                result.append("small")
        elif item == 0:
            continue
        else:
            break
    try:
        avg = total / len(result)
    except ZeroDivisionError:
        avg = 0
    return {"items": result, "total": total, "avg": avg}
'''

proc = subprocess.run(
    [sys.executable, 'scripts/obf_cff.py'],
    input=CODE, capture_output=True, text=True
)
assert proc.returncode == 0, f"Script failed:\n{proc.stderr}"
output = proc.stdout
print("Output:"); print(output)

# Syntax check
compile(output, '<test>', 'exec')
print("Syntax OK")

# Behavioral check
namespace = {}
exec(output, namespace)

# Test 1: normal data
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    r = namespace['complex_func']([5, 150, 0, -1, 3])
# -1 causes break, so only [5, 150] processed
assert r['total'] == 155, f"Expected total=155, got {r['total']}"
assert r['items'] == ['small', 'large'], f"Expected items=['small','large'], got {r['items']}"
print("Behavior OK: complex function")
```

Run:
```bash
python3 tests/test_cff_full.py
```

- [ ] **Step 6: Commit**

```bash
git add scripts/obf_cff.py tests/test_cff_nested.py tests/test_cff_full.py
git commit -m "feat(obf): complete CFF entry point with leaf node and integration tests

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: C++ Integration — Enum + Dispatch + Help

**Files:**
- Modify: `include/switch/obfuscate.hpp:21`
- Modify: `src/obfuscate.cpp:44-75,131-140`
- Modify: `src/main.cpp:44-55`

**Interfaces:**
- Consumes: `ObfType::ControlFlowFlattening` enum value
- Produces: `obfuscate()` dispatches to `obf_cff.py`

- [ ] **Step 1: Add enum value to `obfuscate.hpp`**

In `include/switch/obfuscate.hpp`, add after line 21 (`OpaquePredicates`):

```cpp
    ControlFlowFlattening,  // Flatten function bodies into while+match/case dispatcher
```

The enum should now have 11 values (was 10).

- [ ] **Step 2: Add to `parse_obf_type()` in `obfuscate.cpp`**

In `src/obfuscate.cpp`, add after line 53 (`opaquepredicates`):

```cpp
    if (ieq(name, "controlflowflattening")) return ObfType::ControlFlowFlattening;
```

- [ ] **Step 3: Add to `obf_type_name()` in `obfuscate.cpp`**

In `src/obfuscate.cpp`, add after the `OpaquePredicates` case in `obf_type_name()`:

```cpp
    case ObfType::ControlFlowFlattening: return "controlflowflattening";
```

- [ ] **Step 4: Add to `all_obf_names()` in `obfuscate.cpp`**

In `src/obfuscate.cpp`, add to the return string of `all_obf_names()`:

Change:
```cpp
return "namemangling, stringencoding, docstrip, literal, xorencoding, importrewrite, deadcode, scramble, variablesplitting, opaquepredicates";
```
To:
```cpp
return "namemangling, stringencoding, docstrip, literal, xorencoding, importrewrite, deadcode, scramble, variablesplitting, opaquepredicates, controlflowflattening";
```

- [ ] **Step 5: Add to `obfuscate()` switch in `obfuscate.cpp`**

In `src/obfuscate.cpp`, add after line 139 (`case ObfType::OpaquePredicates`):

```cpp
    case ObfType::ControlFlowFlattening: script_name = "obf_cff.py"; break;
```

- [ ] **Step 6: Add sort order in `main.cpp`**

In `src/main.cpp`, add after the `ImportRewrite` entry (line 54, order=90):

```cpp
                case switch_obf::ObfType::ControlFlowFlattening: return 95;
```

CFF gets order 95 — runs AFTER all other techniques (highest order = runs last).

- [ ] **Step 7: Build and verify compilation**

Run:
```bash
cmake -G Ninja -B build && cmake --build build 2>&1 | tail -20
```
Expected: Build succeeds with no errors.

- [ ] **Step 8: Commit**

```bash
git add include/switch/obfuscate.hpp src/obfuscate.cpp src/main.cpp
git commit -m "feat(obf): wire CFF into C++ dispatch and sort order

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: C++ Tests in `test_obf.cpp`

**Files:**
- Modify: `tests/test_obf.cpp`

**Interfaces:**
- Consumes: `ObfType::ControlFlowFlattening` and `obfuscate()` function
- Produces: Passing doctest test cases

- [ ] **Step 1: Add parse/type tests**

In `tests/test_obf.cpp`, add to the existing `parse_obf_type` test:

```cpp
CHECK(parse_obf_type("controlflowflattening") == ObfType::ControlFlowFlattening);
```

Add to the case-insensitive test:
```cpp
CHECK(parse_obf_type("ControlFlowFlattening") == ObfType::ControlFlowFlattening);
CHECK(parse_obf_type("CONTROLFLOWFLATTENING") == ObfType::ControlFlowFlattening);
```

Add to `obf_type_name` test:
```cpp
CHECK(obf_type_name(ObfType::ControlFlowFlattening) == "controlflowflattening");
```

Add to `all_obf_names` test:
```cpp
CHECK(names.find("controlflowflattening") != std::string::npos);
```

- [ ] **Step 2: Add CFF obfuscation test — simple function**

```cpp
TEST_CASE("obf: controlflowflattening — simple function unchanged") {
    std::string code = "def add(a, b):\n    return a + b\n";
    auto result = obfuscate(ObfType::ControlFlowFlattening, code);
    REQUIRE(result.has_value());
    // Simple functions with no control flow should be unchanged or minimal
    CHECK(result->find("return a + b") != std::string::npos);
}
```

- [ ] **Step 3: Add CFF obfuscation test — if/else**

```cpp
TEST_CASE("obf: controlflowflattening — if/else produces match/case") {
    std::string code =
        "def check(x):\n"
        "    if x > 10:\n"
        "        print('big')\n"
        "    else:\n"
        "        print('small')\n"
        "    return True\n";
    auto result = obfuscate(ObfType::ControlFlowFlattening, code);
    REQUIRE(result.has_value());
    // Must contain while + match dispatcher
    CHECK(result->find("while") != std::string::npos);
    CHECK(result->find("match") != std::string::npos);
    CHECK(result->find("case") != std::string::npos);
}
```

- [ ] **Step 4: Add CFF obfuscation test — for loop**

```cpp
TEST_CASE("obf: controlflowflattening — for loop uses iter/next") {
    std::string code =
        "def sum_pos(items):\n"
        "    total = 0\n"
        "    for x in items:\n"
        "        if x > 0:\n"
        "            total += x\n"
        "    return total\n";
    auto result = obfuscate(ObfType::ControlFlowFlattening, code);
    REQUIRE(result.has_value());
    // For loop should be converted to iter/next pattern
    CHECK(result->find("iter") != std::string::npos);
    CHECK(result->find("next") != std::string::npos);
    CHECK(result->find("StopIteration") != std::string::npos);
}
```

- [ ] **Step 5: Build and run tests**

Run:
```bash
cmake --build build 2>&1 | tail -5
./build/tests/test_obf -tc="obf: controlflowflattening*" -s
```
Expected: All CFF tests pass.

- [ ] **Step 6: Run full test suite**

Run:
```bash
ctest --test-dir build 2>&1
```
Expected: All 6 test binaries pass (no regressions).

- [ ] **Step 7: Commit**

```bash
git add tests/test_obf.cpp
git commit -m "test(obf): add CFF test cases for type parsing and obfuscation

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: End-to-End CLI Test + Cleanup

**Files:**
- Modify: `scripts/obf_cff.py` (final polish)
- Test: CLI end-to-end

**Interfaces:**
- Consumes: CLI invocation `switch --obf controlflowflattening file.py`
- Produces: Obfuscated .obf.py file with correct output

- [ ] **Step 1: Create test input file**

Create `tests/fixtures/cff_sample.py`:
```python
def process_data(items):
    """Process a list of items."""
    result = []
    total = 0
    for item in items:
        if item > 0:
            total += item
            if item > 100:
                result.append("large")
            else:
                result.append("small")
        elif item == 0:
            continue
        else:
            break
    try:
        avg = total / len(result)
    except ZeroDivisionError:
        avg = 0
    return {"items": result, "total": total, "avg": avg}

def simple_add(a, b):
    return a + b
```

- [ ] **Step 2: Run through CLI**

```bash
./build/switch --obf controlflowflattening tests/fixtures/cff_sample.py -o /tmp/cff_test_output.py
cat /tmp/cff_test_output.py
```
Expected: Output file created, contains while+match dispatcher in `process_data`, `simple_add` preserved.

- [ ] **Step 3: Verify semantic equivalence via CLI output**

```bash
python3 -c "
import sys
sys.path.insert(0, '/tmp')

# Original
exec(open('tests/fixtures/cff_sample.py').read())
orig = process_data([5, 150, 0, -1, 3])

# Obfuscated
ns = {}
exec(open('/tmp/cff_test_output.py').read(), ns)
obf = ns['process_data']([5, 150, 0, -1, 3])

print(f'Original: {orig}')
print(f'Obfuscated: {obf}')
assert orig == obf, f'Mismatch: {orig} != {obf}'
print('Semantic equivalence OK')
"
```

- [ ] **Step 4: Test combined with other techniques**

```bash
./build/switch --obf namemangling --obf controlflowflattening tests/fixtures/cff_sample.py -o /tmp/cff_combined.py
python3 -c "compile(open('/tmp/cff_combined.py').read(), '<test>', 'exec'); print('Combined syntax OK')"
```

- [ ] **Step 5: Final polish — remove debug prints, ensure clean output**

Review `scripts/obf_cff.py` for any debug prints or incomplete code. Ensure:
- No `print()` calls left in production code
- All error paths print to stderr and exit(1)
- Output always ends with `\n`

- [ ] **Step 6: Final commit**

```bash
git add scripts/obf_cff.py tests/fixtures/cff_sample.py
git commit -m "feat(obf): finalize CFF implementation with CLI and combined tests

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Summary

| Task | Deliverable | Test |
|------|------------|------|
| 1 | Script skeleton + core helpers | Python syntax check |
| 2 | if/elif/else flattening | `test_cff_if.py` |
| 3 | for/while + break/continue | `test_cff_for.py`, `test_cff_while.py` |
| 4 | try/except + return | `test_cff_try.py`, `test_cff_return.py` |
| 5 | Entry point + leaf nodes + integration | `test_cff_nested.py`, `test_cff_full.py` |
| 6 | C++ enum + dispatch | Build succeeds |
| 7 | C++ test cases | `test_obf` passes |
| 8 | CLI e2e + combined | Semantic equivalence |
