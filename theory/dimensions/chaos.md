# Dimension #13: 混沌 (Chaos)

**Cosmic-galaxy formula**: `λ > 0 → 混沌` (Lyapunov exponent)

**Code mapping**: Small input changes cause large output changes
- Long dependency chains amplify perturbations
- Risk ∝ chain length × branching factor

**security-vule implementation**:
- Read `path_depth` and `branching_factor` features
- Risk = sigmoid(path_depth × branching)