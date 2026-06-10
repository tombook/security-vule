# syntax=docker/dockerfile:1.7
# security-vule Dockerfile (multi-stage, multi-arch)
# Stage 1: Build - install deps and compile
FROM oven/bun:1 AS builder
WORKDIR /app

# Install dependencies (cached layer if package.json/bun.lock unchanged)
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# Copy source
COPY . .

# Build CLI entry point
RUN bun build src/integration/vule-cli.ts --outdir /app/dist --target bun --minify

# Stage 2: Runtime - minimal image
FROM oven/bun:1-slim AS runtime
WORKDIR /app

# Copy built artifacts
COPY --from=builder /app/dist /app/dist
COPY --from=builder /app/node_modules /app/node_modules
COPY --from=builder /app/package.json /app/package.json

# Copy non-code assets needed at runtime
COPY --from=builder /app/config /app/config
COPY --from=builder /app/theory /app/theory

# Create non-root user (Bun ships with `bun` user)
USER bun

# Expose web UI port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD bun --bun dist/vule-cli.js --version || exit 1

# Default entry point
ENTRYPOINT ["bun", "--bun", "dist/vule-cli.js"]
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="security-vule" \
      org.opencontainers.image.description="Cosmic-galaxy-aligned vulnerability scanner" \
      org.opencontainers.image.source="https://github.com/security-vule/security-vule" \
      org.opencontainers.image.licenses="AGPL-3.0" \
      org.opencontainers.image.version="0.3.0"
