# Dimension E1: 类型论 (Type Theory)

**Framework**: Dependent types + linear types → security guarantees

**Code mapping**: TypeScript strict mode violations
- `any` usage = unsafe escape hatch
- Missing type annotations = unverifiable contract
- `as` casts = trust assertions

**security-vule implementation**:
- Read `any_count`, `untyped_count`, `cast_count` features
- Risk = (any × 2 + untyped + cast) / total_loc