# Dimension #12: 拓扑 (Topology)

**Cosmic-galaxy formula**: `β₀/β₁/β₂` (Betti numbers)

**Code mapping**:
- β₀ = connected components (modularity)
- β₁ = cycles (loop dependencies / infinite recursion)
- β₂ = cavities (missing abstraction layers)

**security-vule implementation**:
- Cycle count via DFS (β₁ proxy)
- Risk = sigmoid(cycle_count)