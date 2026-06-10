# Dimension E3: 拓扑数据分析 (Topological Data Analysis)

**Framework**: Persistent homology → Betti numbers β₀/β₁/β₂

**Code mapping**:
- β₀ = number of connected components (modularity)
- β₁ = cycles (circular dependencies)
- β₂ = cavities (missing abstraction layers)

**security-vule implementation**:
- Compute β₀/β₁ via BFS + DFS (no Ripser needed for graph CPG)
- β₀ = components; β₁ = edges - nodes + components (Euler formula)
- Risk = sigmoid(β₁ - threshold)