# Dimension E6: 符号执行 (Symbolic Execution)

**Framework**: Execute programs with symbolic inputs (King 1976)

**Code mapping**: Path constraint analysis
- Each `if` doubles paths → exponential growth
- Solver-checked constraints expose unreachable / always-true paths

**security-vule implementation**:
- Read `path_count`, `solver_violations` features (precomputed by Z3 or similar)
- Risk = sigmoid(solver_violations)
- Optional: lazy import of `z3-solver` if available