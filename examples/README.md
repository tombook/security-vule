# security-vule Examples

Quick-start examples demonstrating how to use security-vule as a library.

## Prerequisites

```bash
# Install Bun
curl -fsSL https://bun.sh/install | bash

# Install dependencies
bun install
```

## Available Examples

| Example | Description | Run |
|---------|-------------|-----|
| [`basic-ast/`](./basic-ast/) | AST-only scan (5s, no LLM) | `bun run basic-ast/scan.sh` |
| [`llm-scan/`](./llm-scan/) | LLM-enhanced scan (default) | `bun run llm-scan/scan.ts` |
| [`cpg-construction/`](./cpg-construction/) | Build CPG from a file | `bun run cpg-construction/build.ts` |
| [`web-ui/`](./web-ui/) | Start the web UI server | `bun run web-ui/start.sh` |
| [`custom-dimension/`](./custom-dimension/) | Add your own dimension detector | `bun run custom-dimension/example.ts` |

## Quick Reference

### CLI usage (most common)

```bash
# AST scan (5s, zero LLM cost)
bun --bun src/integration/vule-cli.ts analyze ./test-targets/php-vulns/

# LLM scan (with provider)
export MINIMAX_API_KEY="sk-cp-..."
export ZHIPU_API_KEY="..."
bun --bun scripts/llm-scan.ts --mode failover --max-findings 5 --verify test-targets/php-vulns/

# List all 29 dimensions
bun --bun src/integration/vule-cli.ts list-dimensions
```

### Library usage (TypeScript)

```typescript
import { VuleEngine, CPGBuilder } from 'security-vule';
import { CPGBuilder } from 'security-vule/src/engine/cpg/builder.js';

// 1. Build CPG from source code
const cpg = new CPGBuilder('php', 'test.php').build(programGraph);

// 2. Find sink functions (mysql_query, shell_exec, etc.)
const sinks = cpg.sinkNodes().map(n => n.id);

// 3. Run VuleEngine with all dimensions
const engine = new VuleEngine(cpg, sinks);
const report = engine.analyze();

// 4. Top risk nodes with UVRS scoring
console.log(report.topRisk);
```

See individual example directories for detailed walkthroughs.