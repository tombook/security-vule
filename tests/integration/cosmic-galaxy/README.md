# Cosmic-Galaxy Equivalence Test

Cross-project integration test: runs the same CPG through both security-vule
(TypeScript) and cosmic-galaxy (Python), asserts UVRS match within `< 0.10`.

## How to run

### One-time setup
```bash
cd /Users/tombook/Documents/work/ai_openclaw/dev_work/cosmic-galaxy
source .venv/bin/activate  # or uv venv
pip install -e .
```

### Run cosmic-galaxy on the fixture
```bash
cd /Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule
python3 tests/integration/cosmic-galaxy/run_cosmic.py
# Writes expected-cosmic.json
```

### Run the TypeScript test
```bash
bun test tests/integration/cosmic-galaxy/equivalence.test.ts
```

## Tolerance: 0.10

Rationale (from spec §8.5):
- Cross-language floating-point differences
- AST → CPG conversion may have small numerical variance
- LLM-driven dimensions (nbody) add noise

## Interchange format

`cpg-fixture.json` is a JSON serialization of `CPG` (subset of
`src/engine/cpg/types.ts`): nodes (id, type, file, line, features) +
edges (source, target, kind).

## Updating snapshots

Regenerate `expected-vule.json`:
```bash
bun --bun scripts/snapshot-vule.ts
```

Regenerate `expected-cosmic.json`:
```bash
python3 tests/integration/cosmic-galaxy/run_cosmic.py
```