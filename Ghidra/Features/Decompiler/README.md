# Decompiler

## Simplification Rules

The decompiler's rule-based simplifier is implemented in
`src/decompile/cpp/ruleaction.cc`.  Rules are registered with the action database in
`src/decompile/cpp/coreaction.cc` and are repeatedly applied until the function reaches a
fixed point.

### Temporary Copy Folding

`RuleFoldTemporary` removes short-lived temporaries created by compiler-generated copies.
It recognizes the following data-flow pattern:

```text
t0 = OP(...)
t1 = COPY t0
```

When `t0` has no readers other than the `COPY`, the rule makes `OP` write directly to
`t1` and removes the `COPY`:

```text
t1 = OP(...)
```

The defining operation is not moved or duplicated.  Only its SSA output is renamed, so
instruction order, exception behavior, and other side effects are unchanged.  Copy chains
are folded transitively as the rule is reapplied.

Folding is deliberately conservative.  It is skipped when:

- either Varnode is not an internal `unique` temporary, or has mapped/address-tied storage;
- the source temporary has more than one reader;
- the destination temporary has no readers;
- the `COPY` is incidental or associated with a return value;
- the source and destination have different sizes or double-precision roles; or
- the rewrite would make the defining operation read its own output.

Tests for the positive transformations and the semantic guards are in
`src/decompile/unittests/testruleaction.cc`.
