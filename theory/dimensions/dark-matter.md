# Dimension #8: 暗物质/暗能量 (Dark Matter)

**Cosmic-galaxy formula**: `M_dark(v) = observed_gravity(v) − visible_gravity(v)`

**Code mapping**: Hidden dependencies (reflection, dynamic loading, DI, callbacks)
- These produce "observed" data flow that AST cannot trace
- Risk = count of dynamic constructs in file

**security-vule implementation**:
- Reads `dynamic_calls` feature (externally populated)
- Plus heuristic: features named `reflection`, `eval`, `include`