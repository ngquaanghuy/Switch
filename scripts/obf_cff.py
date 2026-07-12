#!/usr/bin/env python3
"""
Control Flow Flattening obfuscation for Python source code.

Decomposes function bodies into basic blocks and reconstructs them
inside a while + match/case dispatcher. Destroys hierarchical control
flow (if/else, for, while, try/except) — all logic driven by state.

Requires Python 3.10+ for output (match/case syntax).

Reads Python source from stdin, writes obfuscated source to stdout.

Usage: echo 'code' | python3 obf_cff.py
       python3 obf_cff.py < input.py
"""
import ast
import sys
import random


def _hex_id():
    """Generate random 6-hex-digit ID like 0x4f2a1b."""
    return '0x' + ''.join(random.choices('0123456789abcdef', k=6))


# ---------------------------------------------------------------------------
# AST node builders
# ---------------------------------------------------------------------------

def _name(n, ctx=None):
    return ast.Name(id=n, ctx=ctx or ast.Load())


def _assign(name, value):
    return ast.Assign(targets=[_name(name, ast.Store())], value=value)


def _state_assign(hex_id):
    # Use integer 0 for exit state (must match while _s != 0 comparison)
    val = ast.Constant(value=0) if hex_id == '0' else ast.Constant(value=hex_id)
    return _assign('_s', val)


# ---------------------------------------------------------------------------
# Statement replacement helpers
# ---------------------------------------------------------------------------

def _replace_returns(stmts):
    """Replace Return with _rv assignment + _s = 0. Recurses into If."""
    result = []
    for s in stmts:
        if isinstance(s, ast.Return):
            if s.value is not None:
                result.append(ast.copy_location(_assign('_rv', s.value), s))
            result.append(ast.copy_location(_state_assign('0'), s))
        elif isinstance(s, ast.If):
            s.body = _replace_returns(s.body)
            if s.orelse:
                s.orelse = _replace_returns(s.orelse)
            result.append(s)
        else:
            result.append(s)
    return result


def _replace_break_continue(stmts, loop_stack):
    """Replace Break/Continue with state variable assignments. Recurses into If/For/While."""
    result = []
    for s in stmts:
        if isinstance(s, ast.Break) and loop_stack:
            _, exit_state = loop_stack[-1]
            result.append(ast.copy_location(_state_assign(exit_state), s))
        elif isinstance(s, ast.Continue) and loop_stack:
            header_state, _ = loop_stack[-1]
            result.append(ast.copy_location(_state_assign(header_state), s))
        elif isinstance(s, ast.If):
            s.body = _replace_break_continue(s.body, loop_stack)
            if s.orelse:
                s.orelse = _replace_break_continue(s.orelse, loop_stack)
            result.append(s)
        elif isinstance(s, (ast.For, ast.While)):
            s.body = _replace_break_continue(s.body, loop_stack)
            result.append(s)
        else:
            result.append(s)
    return result


def _extract_body(raw):
    """Extract flat statement list from _process_body result.

    Takes the first case's body per branch — merge/transition states
    from `_process_body` are handled separately by the caller.
    For elif chains, takes first case from each branch's _process_body result.
    """
    if not raw:
        return []
    # Group by branch: each (hex_id, stmts) is a separate branch's first case
    # For simple bodies: just take the first case
    # For elif chains: first case of each branch
    result = []
    for hex_id, stmts in raw:
        result.extend(stmts)
    return result


# ---------------------------------------------------------------------------
# Function Flattener
# ---------------------------------------------------------------------------

class FunctionFlattener(ast.NodeTransformer):
    """Flatten function bodies into while+match/case dispatchers."""

    def __init__(self):
        self._loop_stack = []  # [(header_state, exit_state)]

    def _new_id(self):
        return _hex_id()

    @staticmethod
    def _is_compound(stmt):
        return isinstance(stmt, (ast.If, ast.For, ast.AsyncFor,
                                 ast.While, ast.Try))

    # ------------------------------------------------------------------
    # Body processing — core algorithm
    # NOTE: Does NOT apply replacements. Caller must pre-process stmts.
    # ------------------------------------------------------------------

    def _process_body(self, stmts, next_state, return_expr=None, loop_merge=None):
        """Process pre-processed statements into case blocks.

        Two-pass: collect all cases first, then wire transitions.
        loop_merge: if inside a loop, the loop header state for if merge targets.
        Returns list of (hex_id, body_stmts) tuples.
        """
        if not stmts:
            return [(_hex_id(), [_state_assign(next_state)])]

        has_compound = any(self._is_compound(s) for s in stmts)

        if not has_compound:
            # Don't append next_state if last stmt already transitions
            # (e.g., break/continue replacement already set _s)
            last = stmts[-1] if stmts else None
            already_transitions = (
                isinstance(last, ast.Assign)
                and any(t.id == '_s' for t in last.targets
                        if isinstance(t, ast.Name))
            )
            if already_transitions:
                return [('__seq__', stmts)]
            return [('__seq__', stmts + [_state_assign(next_state)])]

        # Pass 1: collect all cases (seq blocks get placeholder body)
        cases = []
        seq_indices = []  # indices of seq blocks needing transitions
        seq = []

        for s in stmts:
            if self._is_compound(s):
                if seq:
                    seq_indices.append(len(cases))
                    cases.append((_hex_id(), list(seq)))
                    seq = []

                if isinstance(s, ast.If):
                    # Use loop_merge if inside a loop, else next_state for last compound
                    remaining_compounds = [x for x in stmts[stmts.index(s)+1:]
                                          if self._is_compound(x)]
                    if loop_merge:
                        hint = loop_merge
                    elif not remaining_compounds:
                        hint = next_state
                    else:
                        hint = None
                    cases.extend(self._flatten_if(s, merge_hint=hint,
                                                   return_expr=return_expr))
                elif isinstance(s, (ast.For, ast.AsyncFor)):
                    cases.extend(self._flatten_for(s, return_expr=return_expr))
                elif isinstance(s, ast.While):
                    cases.extend(self._flatten_while(s, return_expr=return_expr))
                elif isinstance(s, ast.Try):
                    cases.extend(self._flatten_try(s, return_expr=return_expr))
            else:
                seq.append(s)

        # Final seq block
        if seq:
            cases.append((_hex_id(), list(seq)))

        # Pass 2: wire transitions
        # 2a: intermediate seq blocks → next case's entry
        for idx in seq_indices:
            next_idx = idx + 1
            if next_idx < len(cases):
                next_id = cases[next_idx][0]
                _, body = cases[idx]
                cases[idx] = (cases[idx][0], body + [_state_assign(next_id)])

        # 2b: if merge states — handled by _flatten_if directly

        # Wire last block transition
        if cases:
            last_id, last_body = cases[-1]
            last_stmt = last_body[-1] if last_body else None
            already_transitions = (
                isinstance(last_stmt, ast.Assign)
                and any(t.id == '_s' for t in last_stmt.targets
                        if isinstance(t, ast.Name))
            )
            if not already_transitions:
                cases[-1] = (last_id, last_body + [_state_assign(next_state)])

        return cases

    # ------------------------------------------------------------------
    # If/elif/else flattening
    # ------------------------------------------------------------------

    def _flatten_if(self, stmt, merge_hint=None, return_expr=None):
        """Flatten if/elif/else into decision + branch cases.

        Returns: list of (hex_id, body_stmts) tuples.
        Includes merge state as last case.
        """
        cases = []
        merge = self._new_id()

        def _chain(node, loop_merge=None):
            dec = self._new_id()
            true_s = self._new_id()
            raw = self._process_body(node.body, merge, loop_merge=loop_merge)
            true_b = raw[0][1]
            cases.append((true_s, true_b))

            if node.orelse:
                if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                    _chain(node.orelse[0], loop_merge=loop_merge)
                    false_s = cases[0][0]
                else:
                    false_s = self._new_id()
                    raw = self._process_body(node.orelse, merge, loop_merge=loop_merge)
                    false_b = raw[0][1]
                    cases.append((false_s, false_b))
            else:
                false_s = merge

            dec_b = [ast.If(
                test=node.test,
                body=[_state_assign(true_s)],
                orelse=[_state_assign(false_s)])]
            cases.insert(0, (dec, dec_b))

        _chain(stmt, loop_merge=merge_hint)

        # Register merge state (outermost only — elif branches use the same merge)
        merge_body = []
        if return_expr is not None:
            merge_body.append(ast.copy_location(_assign('_rv', return_expr), stmt))
        merge_body.append(_state_assign(merge_hint or '0'))
        cases.append((merge, merge_body))

        return cases

    # ------------------------------------------------------------------
    # For loop flattening
    # ------------------------------------------------------------------

    def _flatten_for(self, stmt, merge_hint=None, return_expr=None):
        init_s = self._new_id()
        header_s = self._new_id()
        body_s = self._new_id()
        iter_name = f"_i_{init_s}"

        self._loop_stack.append((header_s, '0'))

        init_b = [
            _assign(iter_name, ast.Call(
                func=_name('iter'), args=[stmt.iter], keywords=[])),
            _state_assign(header_s)]

        target_stmt = ast.Assign(
            targets=[stmt.target],
            value=ast.Call(
                func=_name('next'), args=[_name(iter_name)], keywords=[]))

        # StopIteration handler — exit loop and set _rv if safe
        exit_b = []
        if return_expr is not None:
            _ref_names = {n.id for n in ast.walk(return_expr)
                         if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
            _loop_vars = {n.id for n in ast.walk(stmt)
                         if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
            if not (_ref_names - _loop_vars):
                exit_b.append(ast.copy_location(_assign('_rv', return_expr), stmt))
        if merge_hint:
            exit_b.append(_state_assign(merge_hint))
        else:
            exit_b.append(_state_assign('0'))

        header_b = [ast.Try(
            body=[target_stmt, _state_assign(body_s)],
            handlers=[ast.ExceptHandler(
                type=_name('StopIteration'), name=None,
                body=exit_b)],
            orelse=[], finalbody=[])]

        # Apply BC replacement to loop body (returns already replaced by pre-pass)
        body_bc = _replace_break_continue(stmt.body, self._loop_stack)
        body_raw = self._process_body(body_bc, header_s, loop_merge=header_s)
        body_b = body_raw[0][1]
        extra_cases = body_raw[1:] if len(body_raw) > 1 else []

        self._loop_stack.pop()

        for_cases = [(init_s, init_b), (header_s, header_b),
                     (body_s, body_b)]
        return for_cases + extra_cases

    # ------------------------------------------------------------------
    # While loop flattening
    # ------------------------------------------------------------------

    def _flatten_while(self, stmt, merge_hint=None, return_expr=None):
        header_s = self._new_id()
        body_s = self._new_id()

        self._loop_stack.append((header_s, '0'))

        # Exit handler — exit loop and optionally set _rv
        exit_b = []
        if return_expr is not None:
            exit_b.append(ast.copy_location(_assign('_rv', return_expr), stmt))
        if merge_hint:
            exit_b.append(_state_assign(merge_hint))
        else:
            exit_b.append(_state_assign('0'))

        header_b = [ast.If(
            test=stmt.test,
            body=[_state_assign(body_s)],
            orelse=exit_b)]

        body_bc = _replace_break_continue(stmt.body, self._loop_stack)
        body_raw = self._process_body(body_bc, header_s, loop_merge=header_s)
        body_b = body_raw[0][1]
        extra_cases = body_raw[1:] if len(body_raw) > 1 else []

        self._loop_stack.pop()

        return [(header_s, header_b), (body_s, body_b)] + extra_cases

    # ------------------------------------------------------------------
    # Try/except flattening
    # ------------------------------------------------------------------

    def _flatten_try(self, stmt, return_expr=None):
        merge_s = self._new_id()
        try_s = self._new_id()  # separate ID for the try case

        # Try body: returns already replaced by pre-pass, no BC in try body
        try_body = list(stmt.body)

        # Build exception handlers — each handler body becomes a case
        # that transitions to merge_s (not via _process_body which creates its own IDs)
        handlers = []
        handler_cases = []
        for handler in stmt.handlers:
            hs = self._new_id()
            handler_stmts = _replace_break_continue(handler.body, self._loop_stack)
            handler_stmts = _replace_returns(handler_stmts)
            hb = handler_stmts + [_state_assign(merge_s)]
            handler_cases.append((hs, hb))
            handlers.append(ast.ExceptHandler(
                type=handler.type,
                name=handler.name,
                body=[ast.copy_location(_state_assign(hs), handler)]))

        try_case = [ast.Try(
            body=try_body + [_state_assign(merge_s)],
            handlers=handlers,
            orelse=[], finalbody=[])]

        result = [(try_s, try_case)] + handler_cases

        if stmt.finalbody:
            finally_s = self._new_id()
            finally_bc = _replace_break_continue(stmt.finalbody, self._loop_stack)
            finally_b = _extract_body(self._process_body(finally_bc, merge_s))
            result.append((finally_s, finally_b))

        # Register merge state — set _rv if return_expr provided
        merge_body = []
        if return_expr is not None:
            merge_body.append(ast.copy_location(_assign('_rv', return_expr), stmt))
        merge_body.append(_state_assign('0'))
        result.append((merge_s, merge_body))

        return result

    # ------------------------------------------------------------------
    # Dispatcher builder
    # ------------------------------------------------------------------

    def _build_dispatcher(self, entry_id, cases):
        match_cases = []
        for hex_id, body in cases:
            if hex_id == '__seq__':
                hex_id = self._new_id()
            if body is None:
                continue  # skip exit states (while loop handles termination)
            match_cases.append(ast.match_case(
                pattern=ast.MatchValue(value=ast.Constant(value=hex_id)),
                guard=None,
                body=body))

        return ast.While(
            test=ast.Compare(
                left=_name('_s'),
                ops=[ast.NotEq()],
                comparators=[ast.Constant(value=0)]),
            body=[ast.Match(
                subject=_name('_s'),
                cases=match_cases)],
            orelse=[])

    # ------------------------------------------------------------------
    # Main visitor
    # ------------------------------------------------------------------

    def visit_FunctionDef(self, node):
        self.generic_visit(node)

        if not node.body:
            return node

        if not any(self._is_compound(s) for s in node.body):
            return node

        # Detect original return expression before replacing returns
        return_expr = None
        for s in reversed(node.body):
            if isinstance(s, ast.Return) and s.value is not None:
                return_expr = s.value
                break

        # Pre-pass: replace returns in entire body tree
        # (break/continue replacement happens inside _flatten_for/_flatten_while
        # where the loop stack is properly set up)
        body_stmts = _replace_returns(list(node.body))
        cases = self._process_body(body_stmts, '0', return_expr=return_expr)

        if cases and not isinstance(cases[0], tuple):
            return node

        if not cases:
            return node

        # Use first case's ID as the entry state (no separate entry state)
        entry_id = cases[0][0]
        if entry_id == '__seq__':
            entry_id = self._new_id()

        dispatcher = self._build_dispatcher(entry_id, cases)

        node.body = [
            _state_assign(entry_id),
            _assign('_rv', ast.Constant(value=None)),
            dispatcher,
            ast.Return(value=_name('_rv'))]
        ast.fix_missing_locations(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

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
