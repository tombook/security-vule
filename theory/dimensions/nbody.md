# Dimension #4: N体 (N-Body Multi-Model Consensus)

**Cosmic-galaxy formula**: `m_i · d²r_i/dt² = Σ_{j≠i} G·m_j·(r_j-r_i)/|r_j-r_i|³`

**Code mapping**: Multi-LLM consensus (already implemented in `src/llm/consensus.ts`)
- Each LLM is a "body" with mass = confidence
- Consensus = pairwise gravitational attraction
- Barnes-Hut O(N log N) optimization for many LLMs

**security-vule implementation**:
- Reuses `runConsensus()` from `src/llm/consensus.ts`
- Returns agreement ratio (0-1) as dimension contribution
- Without LLM call: defaults to 0 (no consensus info)