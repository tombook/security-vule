# Dimension #6: 潮汐力 (Tidal Force)

**Cosmic-galaxy formula**: `F_tidal = 2·Γ·W_A·W_B·C_coupling/d³`
**Roche limit**: `d_Roche = C_coupling·(2·Defense(A)/Defense(B))^(1/3)`

**Code mapping**: Multi-sink vulnerability chain risk
- W_A, W_B = sink weights; C_coupling = shared ancestor coupling
- d³ decay: closer sinks couple much more strongly

**security-vule implementation**:
- For each pair of sinks within distance ≤ 3: compute tidal coupling
- Risk = count of close-sink pairs × coupling strength