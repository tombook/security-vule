#!/usr/bin/env bun
/**
 * scripts/generate-sandbox-dockerfile.ts
 *
 * Generate a Dockerfile for sandbox-deploying a git-cloned source
 * tree. This is the canonical helper that encodes the "sandbox
 * deploy standard" — runtime comes from a base image, application
 * code comes from the cloned repo.
 *
 * Usage:
 *   bun run scripts/generate-sandbox-dockerfile.ts <src-root> [base-image]
 *
 *   <src-root>   Path to the extracted source (e.g.
 *                 /tmp/security-vule-sources/<tenant>/<project>/<run>/extracted)
 *   [base-image] Optional override for the runtime base. Defaults are
 *                 inferred from project markers (package.json → node:20,
 *                 requirements.txt → python:3.11, etc.)
 *
 * The output is written next to a sentinel file inside the source
 * tree:  <src-root>/.svule.dockerfile
 *
 * If the source already ships its own Dockerfile, the script copies it
 * to .svule.dockerfile and parses its EXPOSE directive (logged to
 * stdout, not modified) so the deploy route can map the host port
 * correctly.
 *
 * Examples:
 *   bun run scripts/generate-sandbox-dockerfile.ts /tmp/dvwa-sandbox
 *   bun run scripts/generate-sandbox-dockerfile.ts /tmp/myapp vulnerables/web-dvwa
 */
import { readdirSync, statSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { join, resolve } from 'path';

const srcRoot = resolve(process.argv[2] ?? '.');
const overrideBase = process.argv[3];

if (!existsSync(srcRoot)) {
  console.error(`[err] source root does not exist: ${srcRoot}`);
  process.exit(1);
}
if (!statSync(srcRoot).isDirectory()) {
  console.error(`[err] source root is not a directory: ${srcRoot}`);
  process.exit(1);
}

// ── Detect project type ────────────────────────────
const entries = readdirSync(srcRoot, { withFileTypes: false });
const has = (name: string) => entries.includes(name);

type Stack = 'dockerfile' | 'node' | 'python' | 'go' | 'php-implicit' | 'generic';

let stack: Stack = 'generic';
let exposedPort = '8080';
let baseImage = overrideBase ?? '';

if (has('Dockerfile') || has('Dockerfile.dockerignore')) {
  // Use the user-supplied Dockerfile. Parse EXPOSE so the deploy
  // route can map the host port to the right container port.
  stack = 'dockerfile';
  const userDf = readFileSync(join(srcRoot, 'Dockerfile'), 'utf8');
  const m = userDf.match(/^\s*EXPOSE\s+(\d+)/im);
  if (m) exposedPort = m[1];
  console.log(`[info] project ships its own Dockerfile, EXPOSE=${exposedPort}`);
  // If user gave an override base, prepend a FROM line using the
  // runtime they want. Otherwise we pass the user Dockerfile through
  // unchanged.
  if (overrideBase) {
    baseImage = overrideBase;
    // Re-emit the user Dockerfile with the override FROM line.
    const rewritten = userDf.replace(/^FROM\s+\S+(.*)$/im, `FROM ${baseImage}$1`);
    writeFileSync(join(srcRoot, '.svule.dockerfile'), rewritten);
    console.log(`[ok] wrote .svule.dockerfile with FROM=${baseImage}`);
  } else {
    writeFileSync(join(srcRoot, '.svule.dockerfile'), userDf);
    console.log(`[ok] copied user Dockerfile to .svule.dockerfile (unchanged)`);
  }
  process.exit(0);
}

// No Dockerfile — generate one based on detected stack.
if (has('package.json')) {
  stack = 'node';
  if (!baseImage) baseImage = 'docker.1ms.run/node:20-alpine';
  exposedPort = '3000';
} else if (has('requirements.txt') || has('pyproject.toml')) {
  stack = 'python';
  if (!baseImage) baseImage = 'docker.1ms.run/python:3.11-slim';
  exposedPort = '8080';
} else if (has('go.mod')) {
  stack = 'go';
  if (!baseImage) baseImage = 'docker.1ms.run/golang:1.22-alpine';
  exposedPort = '8080';
} else if (has('index.php')) {
  // PHP without a Dockerfile — common case for legacy apps like DVWA
  // that ship a README but no container config. Use the official
  // image that *does* ship a Dockerfile in the wild, then COPY the
  // git source on top — runtime is preserved, app code comes from
  // the repo.
  stack = 'php-implicit';
  if (!baseImage) baseImage = 'vulnerables/web-dvwa';
  exposedPort = '80';
} else {
  stack = 'generic';
  if (!baseImage) baseImage = 'docker.1ms.run/python:3.11-slim';
  exposedPort = '8080';
}

let df = '';
if (stack === 'node') {
  df = `FROM ${baseImage}
WORKDIR /app
COPY . .
RUN npm install --omit=dev || true
EXPOSE ${exposedPort}
CMD ["npm", "start"]
`;
} else if (stack === 'python') {
  df = `FROM ${baseImage}
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt || true
EXPOSE ${exposedPort}
CMD ["python", "app.py"]
`;
} else if (stack === 'go') {
  df = `FROM ${baseImage}
WORKDIR /app
COPY . .
RUN go build -o server . || true
EXPOSE ${exposedPort}
CMD ["./server"]
`;
} else if (stack === 'php-implicit') {
  // PHP without Dockerfile: use the official runtime image as
  // the base, then COPY the cloned repo on top. This is the
  // canonical approach for projects like DVWA that don't ship
  // a Dockerfile but have an official Docker image.
  df = `FROM ${baseImage}

# Replace the default app code with the actual git-cloned source
# so the sandbox is running the code we want to audit, not the
# default that's bundled in the image.
COPY . /var/www/html/

# Suppress noisy deprecation warnings on PHP 5.x so the response
# body is clean HTML for the PoC verifier to match against.
RUN echo 'error_reporting=E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_STRICT' > /etc/php5/apache2/conf.d/99-dvwa.ini \\
 || echo 'error_reporting=E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_STRICT' > /usr/local/etc/php/conf.d/99-dvwa.ini \\
 || true

EXPOSE ${exposedPort}
`;
} else {
  // Generic — just serve the directory with python http.server.
  df = `FROM ${baseImage}
WORKDIR /app
COPY . .
EXPOSE ${exposedPort}
CMD ["python", "-m", "http.server", "${exposedPort}"]
`;
}

writeFileSync(join(srcRoot, '.svule.dockerfile'), df);
console.log(`[ok] generated .svule.dockerfile`);
console.log(`     stack=${stack} base=${baseImage} exposedPort=${exposedPort}`);
console.log(`---`);
console.log(df);
