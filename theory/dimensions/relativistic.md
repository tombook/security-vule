# Dimension #7: 相对论修正 (Relativistic Correction)

**Cosmic-galaxy formula**: `G_μν + Λ·g_μν = κ·T_μν`
**Schwarzschild**: `r_s = 2·Γ·W_sink/c²`

**Code mapping**: Deep nesting = spacetime curvature
- Nesting depth > 5 = relativistic regime
- High cyclomatic complexity = mass

**security-vule implementation**:
- Read `nesting_depth` and `cyclomatic_complexity` features
- Risk = sigmoid of depth × complexity