# Dimension E4: 纯函数式安全 (Pure Functional Security)

**Framework**: Immutability + side-effect isolation → easier reasoning

**Code mapping**:
- `let` / `var` mutability = state risk
- Side-effect calls (I/O, network) in non-pure context = isolation failure
- Pure functions have no risk

**security-vule implementation**:
- Read `mutable_vars`, `side_effects` features
- Risk = (mutable × 0.5 + side_effects) / total