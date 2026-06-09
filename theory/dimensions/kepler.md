# Dimension #2: 开普勒轨道 (Kepler Orbit)

**Cosmic-galaxy formula**: `r(θ) = a(1-e²)/(1+e·cosθ)`

**Code mapping**:
- `r(θ)` — probability of vulnerability at graph distance θ
- `a` — mean shortest path from node to sinks
- `e` — eccentricity = std(distances) / mean(distances)
- `θ` — graph embedding angle (via node2vec)

**security-vule implementation**:
- For each node: collect distances to all sinks
- `risk = 1 / (1 + mean_distance)` if any sink is reachable, else 0
- Eccentricity > 1 (hyperbolic orbit) increases risk