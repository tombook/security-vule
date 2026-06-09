# Dimension #3: 轨道六要素 (Orbital Elements)

**Cosmic-galaxy formulas**: `[a, e, i, Ω, ω, θ]` — six-element feature vector

**Code mapping**:
- `a` (semi-major axis): mean shortest path to all sinks
- `e` (eccentricity): std of [betweenness, closeness, eigenvector, pagerank] / mean
- `i` (inclination): arccos(neighbor_overlap_with_security_apis / total_neighbors)
- `Ω` (longitude of ascending node): pageRank angle (placeholder)
- `ω` (argument of periapsis): argmax of risk gradient
- `θ` (true anomaly): current UVRS × time decay (placeholder: UVRS-derived)

**security-vule implementation**:
- Reads from CPG node features (pagerank/betweenness precomputed)
- Risk = f(a, e, i) — first three elements that can be derived from CPG