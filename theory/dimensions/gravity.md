# Dimension #1: 引力场 (Gravity Field)

**Cosmic-galaxy formula**: `F_ij = Γ · (W_i · W_j) / d_ij²`

**Code mapping**:
- `Γ` (Gamma): project vulnerability density (calibrated by `GammaCalibrator`)
- `W_i`: source weight (CVSS impact + data sensitivity + exposure + privilege)
- `W_j`: sink weight (dangerousness + exploitability + reachability)
- `d_ij`: graph shortest-path distance in CPG

**security-vule implementation** (Sprint 3, P0):
- Reads CPG via `downstreamNodes(cpg, sourceNode)` to enumerate reachable sinks
- For each (source, sink) pair: compute `risk = (W_src * W_sink) / distance²`
- Returns 0-1 normalized risk contribution to UVRS

**Test fixture**: `tests/unit/dimensions/gravity.test.ts` (Sprint 3)

**References**:
- cosmic-galaxy `engine/gravity.py`
- cosmic-galaxy `theory/equations.json` dimension 3_gravity