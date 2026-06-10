# Dimension E5: 抽象解释 (Abstract Interpretation)

**Framework**: Cousot & Cousot 1977 — sound approximation of program semantics

**Code mapping**: Static value-range analysis
- Interval analysis: `[min, max]` for numeric vars
- String length analysis: `[min_len, max_len]` for string vars
- Taint domain: {clean, dirty}

**security-vule implementation**:
- Read precomputed `taint_range` (min/max taint value)
- Read `value_range` (numeric min/max)
- Risk = probability of dangerous value given range