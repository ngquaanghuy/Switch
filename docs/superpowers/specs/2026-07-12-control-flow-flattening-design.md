# Control Flow Flattening — Design Spec

**Date:** 2026-07-12
**Status:** Approved
**Difficulty:** High
**Security:** Very High

## Summary

Add Control Flow Flattening (CFF) as a new obfuscation technique to Switch. CFF
decomposes function bodies into basic blocks, destroys hierarchical control flow
(if/else, for, while, try/except), and reconstructs everything inside a flat
`while + match/case` dispatcher. The result is "spaghetti code" where all
logic is driven by a state variable, making static analysis and manual reverse
engineering extremely difficult.

## Goals

1. Flatten Python function bodies into while+match/case dispatchers
2. Handle break/continue, return values, try/except/finally correctly
3. Treat nested functions/classes as leaf nodes (top-level only)
4. Follow existing project patterns (stdin → AST transform → stdout)
5. Support combination with other obfuscation techniques

## Non-Goals

- Module-level code flattening (only function bodies)
- Nested function/class body flattening (leaf nodes)
- yield/generator flattening (deferred to future version)
- match/case dispatcher for Python <3.10 (accepted constraint)

## Architecture

### Data Flow

```
Python source (stdin)
    │
    ▼
┌─────────────────────────────────┐
│ obf_cff.py — Main Script       │
│                                 │
│  1. ast.parse(source)           │
│  2. For each FunctionDef:       │
│     a. flatten_function_body()  │
│        → list of Case blocks    │
│     b. wrap in while+match      │
│     c. replace function body    │
│  3. ast.unparse(tree)           │
│  4. stdout                      │
└─────────────────────────────────┘

Flatten pipeline:
  FunctionDef.body (list[stmt])
    → analyze_structure()
    → emit_cases() (list[match_case])
    → build_dispatcher(while + match)
    → FunctionDef.body = [dispatcher]
```

### File Layout

| File | Role |
|------|------|
| `scripts/obf_cff.py` | New Python script (~400-500 lines) |
| `include/switch/obfuscate.hpp` | Add `ControlFlowFlattening` to `ObfType` enum |
| `src/obfuscate.cpp` | Add to `parse_obf_type()`, `obf_type_name()`, `all_obf_names()`, `obfuscate()` switch |
| `tests/test_obf.cpp` | Add CFF test cases |
| `src/main.cpp` | Add to help text |

## Core Algorithm

### Statement Classification

Each statement type has a specific flattening strategy:

| Statement Type | Strategy | States Generated |
|---------------|----------|-----------------|
| Simple (assign, expr, return) | Merge into sequential block | 1 |
| if/elif/else | Decision + branch blocks + merge | N+2 |
| for | Init → header → body → update → merge | 4 |
| while | Header → body → merge | 3 |
| try/except/finally | Try + N handlers + finally + merge | N+2 |
| break | → state = LOOP_EXIT + continue | (in-place) |
| continue | → state = LOOP_HEADER + continue | (in-place) |
| return expr | → return_flag=True, return_val=expr, state=FUNC_EXIT | (in-place) |
| Nested func/class | Leaf node — coi như simple stmt | 1 |

### State Numbering

- **Case states:** Auto-increment hex IDs `_s = 0x4f2a1b, 0x7c3d4e, ...`
- **Exit state:** `_s = 0` (while loop terminates)
- **Loop states:** Header `_sL`, exit `_sLE` per loop scope
- **Return:** Always via `_rv` (return value) variable + `_s = 0`

Hex IDs chosen for obfuscation — harder to read than sequential `case 0, 1, 2`.

### Dispatcher Structure

```python
def func(args):
    _s = 0x4f2a1b          # initial state
    _rv = None              # return value
    while _s != 0:
        match _s:
            case 0x4f2a1b:
                # ... state body ...
                _s = 0x7c3d4e   # next state
            case 0x7c3d4e:
                # ...
                _s = 0           # exit
    return _rv
```

## Example Transformation

### Input

```python
def process(items):
    total = 0
    for item in items:
        if item > 0:
            total += item
        else:
            total -= item
    return total
```

### Output

```python
def process(items):
    _s = 0x4f2a1b
    _rv = None
    while _s != 0:
        match _s:
            case 0x4f2a1b:  # entry
                total = 0
                _iter = iter(items)
                _s = 0x7c3d4e
            case 0x7c3d4e:  # for header
                try:
                    item = next(_iter)
                    _s = 0x1a2b3c
                except StopIteration:
                    _s = 0x9e0f1a
            case 0x1a2b3c:  # if decision
                if item > 0: _s = 0x5d6e7f
                else: _s = 0x8a9b0c
            case 0x5d6e7f:  # if true
                total += item
                _s = 0x7c3d4e
            case 0x8a9b0c:  # if false
                total -= item
                _s = 0x7c3d4e
            case 0x9e0f1a:  # for exit
                _rv = total
                _s = 0
    return _rv
```

**Key patterns:**
- `for` → `iter()` + `next()` + `StopIteration` handling
- `if/else` → decision block + branch blocks
- `return` → `_rv` + `state=0`
- All branches converge to same state (merge points)

## Edge Cases

### break/continue (inside flattened loops)

```python
# Input:
for x in items:
    if x == 0: continue
    if x == -1: break
    process(x)

# Output pattern:
case 0x1a:  # for header
    try: item = next(_iter); _s = 0x2b
    except StopIteration: _s = 0x9e
case 0x2b:  # if continue
    if item == 0: _s = 0x1a  # → loop header
    else: _s = 0x3c
case 0x3c:  # if break
    if item == -1: _s = 0x9e  # → loop exit
    else: _s = 0x4d
case 0x4d:  # process
    process(item)
    _s = 0x1a  # → loop header
```

### return (in nested context)

```python
# _rv + state=0 always. Even inside nested if/for:
case 0x5e:
    if found:
        _rv = result
        _s = 0   # → exit dispatcher
    else:
        _s = 0x6f
```

### try/except/finally

```python
case 0x7a:  # try block
    try:
        risky_op()
        _s = 0x8b
    except ValueError as e:
        _s = 0x9c  # → except handler
case 0x9c:  # except handler
    handle_error(e)
    _s = 0xad  # → finally/merge
case 0xad:  # finally (always runs)
    cleanup()
    _s = 0    # → exit
```

### Nested function/class

Treated as leaf nodes — merged into sequential block, NOT flattened. This keeps
the implementation manageable and covers the 90% use case.

## Obfuscation Order

CFF runs **LAST** in the obfuscation pipeline. Other techniques (namemangling,
stringencoding, deadcode, opaquepredicates, etc.) run first and their output
gets flattened by CFF. This means:

- Dead code blocks → become case blocks in dispatcher (harder to identify)
- Opaque predicates → branch within dispatcher (harder to analyze)
- Name mangling → state variables get mangled names

Usage: `switch --obf namemangling --obf deadcode --obf controlflowflattening file.py`

## Security Properties

1. **Destroys locality:** Statements that were adjacent in source code are
   scattered across different case blocks
2. **Eliminates structure:** No visible if/else/for/while hierarchy — all
   logic driven by state transitions
3. **Defeats static analysis:** Decompilers cannot recover original control
   flow from match/case dispatcher pattern
4. **Anti-pattern recognition:** Hex state IDs prevent pattern matching
   against common CFF signatures
5. **Composability:** Works with opaque predicates to create opaque state
   transitions, dead code to add unreachable cases

## Testing Strategy

| # | Test Case | Validates |
|---|-----------|-----------|
| 1 | Simple function (no control flow) | Sequential merge — output behavior = input |
| 2 | if/else | Decision + branch blocks |
| 3 | for loop with break/continue | Loop header/exit states, break→exit, continue→header |
| 4 | while loop | while → match/case conversion |
| 5 | try/except | Exception handling states |
| 6 | return in nested context | _rv pattern correctness |
| 7 | Nested func/class | Leaf node — body NOT flattened |
| 8 | Complex: if + for + try combined | Multi-strategy integration |
| 9 | Syntax validation | `ast.parse()` on output succeeds |
| 10 | Semantic equivalence | `exec()` original vs obfuscated produces same results |

### Semantic equivalence test pattern

```python
def test_semantic equivalence():
    original_output = exec_capture(original_code)
    obfuscated_output = exec_capture(obfuscated_code)
    assert original_output == obfuscated_output
```

## Constraints

- **Python ≥3.10** for obfuscated output (match/case syntax)
- **Top-level functions only** — nested defs/classes are leaf nodes
- **No yield/generator support** in first version
- **No module-level flattening** — only function bodies

## Estimated Effort

- **Script:** ~400-500 lines Python
- **C++ changes:** ~30 lines across 4 files
- **Tests:** ~200 lines C++ (test_obf.cpp additions)
- **Total:** 1-2 implementation sessions
