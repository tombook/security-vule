# Dimension #17: 信息论 (Information Theory)

**Cosmic-galaxy formula**: `H = −Σ p log p` (Shannon entropy)

**Code mapping**: Token-level entropy
- Low entropy = repetitive code (often auto-generated)
- High entropy = random/unpredictable code (often obfuscated)
- Optimal: 3.5-5.5 bits/token (per cosmic-galaxy)

**security-vule implementation**:
- Reads `token_entropy` feature (externally computed)
- Risk = sigmoid(|entropy - 4.5|) — too high or too low is risky