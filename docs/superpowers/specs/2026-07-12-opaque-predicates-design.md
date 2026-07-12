# Opaque Predicates — Design Spec

## Goal

Add `opaquepredicates` obfuscation technique that injects conditional branches whose outcome is known at obfuscation time but difficult for static analysis to determine. Creates fake code paths that confuse decompilers and reverse engineers.

## Predicate Families

Three families, randomly selected per injection point. Each uses random variable names and constant injection for uniqueness.

### Arithmetic (always True)

| Identity | Expression | Why always True |
|----------|-----------|-----------------|
| Even product | `x * (x+1) % 2 == 0` | Consecutive integers: one is always even |
| Square sum | `(x*x + x) % 2 == 0` | Factorable as `x(x+1)` |
| Quartic mod 4 | `(x*x * (x+1)*(x+1)) % 4 == 0` | `x²(x+1)² ≡ 0 (mod 4)` |
| Cube minus linear | `(x*x*x - x) % 6 == 0` | `x³-x = x(x-1)(x+1)`, three consecutive integers |

**Random constant injection**: Each predicate uses randomized constants that preserve the identity:
```python
# Template: (var * (var + const1)) % const2 == const3
# Original: (x * (x + 1)) % 2 == 0
# Randomized: (_op0 * (_op0 + 6//3)) % (4//2) == (10//5)
```

### Arithmetic (always False)

| Identity | Expression | Why always False |
|----------|-----------|------------------|
| Pell equation | `7*y*y - 1 == x*x` | No integer solutions |
| Sum of squares | `x*x + y*y == 3` | No integer solutions for 3 |
| Irrational square | `x*x == 2` | √2 is irrational |

**Random constant injection**: Replace constants with equivalent expressions:
```python
# Original: 7*y*y - 1 == x*x
# Randomized: (7+0)*_op1*_op1 - (5-4) == _op0*_op0
```

### Object Identity (always True)

| Identity | Expression | Why always True |
|----------|-----------|------------------|
| List identity | `[] is not [()]` | Separate list objects |
| Dict identity | `{} is not dict()` | Separate dict objects |
| Set identity | `set() is not set()` | Separate set objects |
| Tuple identity | `() is not ()` | Wait — actually `() is ()` may be True in CPython |

**Corrected**: Use types that are never interned:
```python
[] is not list()      # always True — new list objects
{} is not dict()      # always True — new dict objects
set() is not set()    # always True — new set objects
b'' is not bytes()    # always True — new bytes objects
```

### Runtime (platform-dependent, hard to static-analyze)

| Identity | Expression | Why always True/False |
|----------|-----------|----------------------|
| PID positive | `os.getpid() > 0` | Process IDs are always positive |
| Python 3+ | `sys.version_info >= (3, 0)` | True for Python 3+ |
| Empty falsy | `bool([]) == False` | Empty list is falsy |
| None identity | `None is not True` | None ≠ True |

**Note**: Runtime predicates import `os`/`sys` at injection time. The import is injected at module level if not already present.

## Injection Strategy

### Target Nodes
- `ast.If` — inject wrapper around existing if statements
- `ast.While` — inject wrapper around existing while loops
- `ast.For` — inject wrapper around existing for loops
- Skip: comprehensions, `if __name__`, `elif`/`else` branches, small loops (<3 statements)

### Injection Method — "Guard with Junk"

```python
# Original:
if condition:
    real_code()

# After injection (opaque predicate always True):
_op0 = <random_int>
_op1 = <random_int>
if (_op0 * (_op0 + 1)) % 2 == 0:  # always True
    if condition:
        real_code()
else:
    _jk0 = <random_math_expr>
    _jk1 = <random_math_expr>
```

### Variable Naming
- Predicate operands: `_op0`, `_op1`, `_op2` (with collision detection)
- Junk variables: `_jk0`, `_jk1`, `_jk2` (with collision detection)
- Random suffix added if name already exists in scope

## Junk Code Generation

Three patterns, randomly selected:

### Pattern 1: Simple assignment no-ops
```python
_jk0 = <random_int>
_jk1 = <random_int>
```

### Pattern 2: Math expressions (side-effect-free)
```python
_jk2 = <random_int> * <random_int> + <random_int>
_jk3 = (<random_int> ** 2) % <random_int>
```

### Pattern 3: Bitwise operations
```python
_jk4 = <random_int> << <random_int>
_jk5 = <random_int> & <random_int>
```

### Constraints
- All junk expressions must be side-effect-free (no function calls, no attribute access, no mutations)
- Junk variables use `_jk` prefix
- 2-4 junk statements per fake branch
- Random values within safe ranges (int: -100..100)

## Density Control

- **Light**: 1-2 predicates per function
- **Medium** (default): 3-5 predicates per function
- **Heavy**: 5-10 predicates per function

Density parameter passed via comment directive or hardcoded default.

## Architecture

### Files

| File | Change |
|------|--------|
| `scripts/obf_opaque.py` | NEW — AST-based opaque predicate injection |
| `include/switch/obfuscate.hpp` | Add `OpaquePredicates` enum value |
| `src/obfuscate.cpp` | Add parse/type_name/dispatch |
| `tests/test_obf.cpp` | Add 15+ unit + stacking tests |
| `CLAUDE.md` | Update technique list |

### Stacking Order (auto-sorted)

```
deadcode → namemangling → docstrip → literal → stringencoding
→ scramble → opaquepredicates → xorencoding → importrewrite → variablesplitting
```

Opaque predicates inject AFTER scramble (uses scrambled variable names) and BEFORE xorencoding/importrewrite (those generate code that predicates should not wrap).

### C++ Integration

Standard subprocess pattern — `obf_opaque.py` reads stdin, writes stdout. Same as all other Python obfuscation scripts.

### CLI

```
--obf opaquepredicates    # case-insensitive
```

## Testing

### Unit Tests
- Predicate evaluation: each family always True/False
- Random constant injection preserves identity
- Variable naming collision detection
- Junk code is side-effect-free

### E2E Tests
- Injected code is valid Python
- Injected code runs correctly (output matches original)
- Injection density matches parameter

### Stacking Tests
- `opaquepredicates → scramble` — valid Python
- `scramble → opaquepredicates` — valid Python
- `deadcode → opaquepredicates → scramble` — valid Python
- All 10 techniques sequential — valid Python

## Security Notes

- Each predicate instance uses unique random constants and variable names
- Arithmetic predicates are vulnerable to Z3 solvers but random constant injection forces Z3 to enumerate more cases, increasing solver time from ms to seconds. Object-identity and runtime predicates resist static analysis entirely.
- Predicates compose with deadcode injection (fake branches contain junk from deadcode)
- Performance cost: ~10-30% overhead depending on density
