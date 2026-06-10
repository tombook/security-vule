#!/usr/bin/env bash
# Run the basic AST scan on a target file.
# Usage: ./scan.sh [target_file]
set -euo pipefail
TARGET="${1:-test-targets/php-vulns/dvwa_sqli_low.php}"
echo "Running AST scan on: $TARGET"
bun run examples/basic-ast/scan.ts "$TARGET"
