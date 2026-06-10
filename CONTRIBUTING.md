# Contributing to security-vule

Thank you for your interest in contributing! security-vule is a cosmic-galaxy-aligned vulnerability scanner, and we welcome contributions of all kinds.

## Code of Conduct

This project adheres to the [Contributor Covenant](https://www.contributor-covenant.org/). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- **Bun** ≥ 1.3.0 ([install](https://bun.sh))
- **Git** ≥ 2.30
- **Docker** (optional, for PoC verification against real vulnerable apps)

### Setup

```bash
# 1. Fork and clone
git clone https://github.com/<your-username>/security-vule.git
cd security-vule

# 2. Install dependencies
bun install

# 3. Install git hooks (husky)
bun run prepare

# 4. Run tests to verify setup
bun test
```

### IDE Setup

We recommend **VS Code** with the following extensions:
- `dbaeumer.vscode-eslint` (ESLint)
- `esbenp.prettier-vscode` (Prettier)
- `bun bun-vscode` (Bun runtime)

## Development Workflow

### Branch Naming

- `feat/<short-description>` — new feature
- `fix/<short-description>` — bug fix
- `docs/<short-description>` — documentation only
- `refactor/<short-description>` — code refactoring
- `test/<short-description>` — test additions

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`

Examples:
- `feat(cpg): add 29 cosmic-galaxy dimension detectors`
- `fix(llm): handle MiniMax-M3 <think/> tags in JSON parsing`
- `docs(readme): update comparison table with Harness v2`

### Pre-commit Hooks

The repo uses **Husky + lint-staged** to enforce quality on every commit:
- ESLint auto-fixes TypeScript files
- Prettier auto-formats TS/JSON/MD/YAML files

To run manually:
```bash
bun run lint:fix
bun run format
```

### Tests

All new features must include tests. We follow **TDD** where practical:

```bash
# Run all tests
bun test

# Run with coverage (target: ≥ 80% line coverage)
bun test --coverage

# Run specific test file
bun test tests/unit/engine/cpg/builder.test.ts

# Watch mode
bun run test:watch
```

### Pull Request Process

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** with tests.

3. **Verify locally**:
   ```bash
   bun run lint        # ESLint passes
   bun run format:check  # Prettier formatted
   bun test            # All tests pass
   bun test --coverage # Coverage not decreased
   ```

4. **Commit** with conventional message (pre-commit hook runs automatically).

5. **Push and create a PR**:
   ```bash
   git push origin feat/my-feature
   gh pr create --title "feat(scope): subject" --body "..."
   ```

6. **PR review**: Requires **1 approval** from a CODEOWNER. CI must pass.

### Code Style

- **TypeScript strict mode** (no `any` unless absolutely necessary)
- **ESLint + Prettier** (auto-formatted)
- **File size**: prefer < 400 lines per file
- **Naming**: PascalCase for types/classes, camelCase for functions/variables
- **Comments**: explain *why*, not *what*

## Architecture

security-vule implements a 29-dimension cosmic-galaxy-aligned risk scoring framework:

```
File → CPG (Code Property Graph) → 29 Dimension Detectors → UVRS Score → VuleEngine
```

- **CPG core** (`src/engine/cpg/`) — 5-edge-kind code property graph
- **29 dimensions** (`src/engine/dimensions/`) — cosmic-galaxy theory detectors
- **UVRS** (`src/engine/uvrs.ts`) — unified vulnerability risk score
- **VuleEngine** (`src/engine/vule-engine.ts`) — unified entry point

See [docs/design-philosophy.md](docs/design-philosophy.md) for the full design rationale.

## Adding a New Dimension Detector

1. Extend `BaseDimension` in `src/engine/dimensions/base.ts`:
   ```typescript
   import { BaseDimension } from './base.js';
   import type { CPG, CPGNode } from '../cpg/types.js';

   export class MyDimension extends BaseDimension {
     readonly name = 'myDim';
     readonly weight = 0.02;
     compute(node: CPGNode, cpg: CPG): number {
       // Return 0-1 risk contribution
       return Math.min(1, /* your logic */);
     }
   }
   ```

2. Register in `src/engine/dimensions/registry.ts`:
   ```typescript
   import { MyDimension } from './my-dimension.js';
   // ...
   export const DIMENSIONS = {
     // ...existing
     myDim: new MyDimension(),
   };
   ```

3. Add theory doc at `theory/dimensions/my-dim.md`.

4. Add tests at `tests/unit/engine/dimensions/my-dim.test.ts`.

5. Update `docs/competitive-analysis-*.md` if your dimension is novel.

## Release Process

Releases are managed by [release-please](https://github.com/googleapis/release-please) (automated):

- `feat:` commits → minor version bump (0.x.0)
- `fix:` commits → patch version bump (0.0.x)
- `BREAKING CHANGE:` footer → major version bump (x.0.0)

PRs merged to `main` automatically create a release PR with updated `CHANGELOG.md`.

## Getting Help

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/security-vule/security-vule/issues)
- **Discussions**: [GitHub Discussions](https://github.com/security-vule/security-vule/discussions)
- **Security issues**: See [SECURITY.md](SECURITY.md)

## Recognition

Contributors are recognized in:
- `CHANGELOG.md` (per release)
- GitHub contributors page (automatic)
- Annual contributor spotlight (in roadmap docs)

Thank you for making security-vule better! 🌌
