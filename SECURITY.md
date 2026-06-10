# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :x:                |
| 0.1.x   | :white_check_mark: (security fixes only) |
| < 0.1   | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

### Preferred: GitHub Security Advisories

Report privately via [GitHub Security Advisories](https://github.com/security-vule/security-vule/security/advisories/new):

1. Click "New draft security advisory"
2. Fill in:
   - Title (e.g., "XSS in HTML report generator")
   - Severity (CVSS v3.1 if known)
   - Affected versions
   - Reproduction steps
   - Impact description
3. Submit as **draft** (private)

### Alternative: Email

Send to **security@security-vule.org** (PGP key: [link](https://security-vule.org/.well-known/pgp-key.asc))

### What to Include

- Vulnerability type (e.g., XSS, RCE, SSRF)
- Affected component (e.g., `src/visualization/html-report.ts`)
- Affected versions (commit SHA or version range)
- Step-by-step reproduction
- Sample PoC (if applicable)
- Potential impact
- Suggested fix (optional)

## Response SLA

| Stage | SLA |
|-------|-----|
| **Initial acknowledgment** | 7 days |
| **Triage + severity assessment** | 14 days |
| **Fix + disclosure timeline** | 30 days for HIGH/CRITICAL, 90 days for MEDIUM/LOW |
| **Public CVE** (if applicable) | Coordinated with reporter |

## Security Considerations for security-vule Users

### AI/LLM Providers

When using LLM-backed scanning (`--mode consensus`, `--verify`), be aware:

| Provider | Trains on API data? | Retention | Data residency |
|----------|---------------------|-----------|----------------|
| MiniMax (default) | No (per API ToS) | 30 days | CN |
| GLM (Zhipu) | No | 30 days | CN |
| Anthropic Claude | No (per API ToS) | 0 days | US |
| OpenAI | No (opt-out) | 30 days | US |
| Ollama (local) | No (fully local) | 0 | local |

**Recommendation**: For proprietary code, use Ollama locally. For public/open-source code, MiniMax or GLM with `--verify` are safe defaults.

### Data Sanitization

security-vule redacts 17 secret patterns before sending to LLM providers:
- AWS Access Keys (`AKIA...`)
- AWS Secret Keys
- GitHub tokens (`ghp_...`, `ghs_...`, `gho_...`)
- GitLab tokens
- Slack tokens (`xox[abprs]-...`)
- JWTs
- Private keys (`-----BEGIN ... PRIVATE KEY-----`)
- Generic API keys (`api[_-]?key`, `apikey`, `access[_-]?token`)
- Hardcoded passwords

If you find a pattern we should add, please open an issue (non-sensitive description only).

### Output Sanitization

`security-vule` outputs may contain:
- Code snippets (from `--verify` or HTML reports)
- File paths
- Finding descriptions

**Do NOT publish raw reports to public PRs** without sanitization. Use:
```bash
vule analyze --format json --export report.json
# Then redact codeSnippet fields before sharing
```

### CI/CD Considerations

- `LLM_API_KEY` is required for LLM features — use **GitHub Secrets** (encrypted)
- SARIF output is uploaded to GitHub Code Scanning — review permissions
- Mock DVWA test fixtures in `poc-validator/` are intentionally vulnerable — never run in production

## Threat Model

security-vule is itself an **AI system** subject to:

| Threat | Mitigation |
|--------|------------|
| **Prompt injection via scanned code** | XML isolation (`<file>` tags) + 12-pattern detection + UNTRUSTED DATA labels |
| **Training data leakage** | No provider trains on API data (per ToS); use Ollama for full privacy |
| **Secret exfiltration** | 17-pattern redaction before LLM call |
| **Cost DoS** | Rate limit + cost cap ($5/scan, 1M tokens) — coming in Sprint 9 |
| **SARIF injection** | Output sanitization before publishing — see Sprint E6 |

See [docs/ai-security-expert-recommendations.md](docs/ai-security-expert-recommendations.md) for the full threat model.

## Security Hall of Fame

We thank the following researchers for responsibly disclosing vulnerabilities:

*(none yet — be the first!)*

## License

security-vule is licensed under **AGPL-3.0**. See [LICENSE](LICENSE) for details.

For commercial licensing inquiries: **licensing@security-vule.org**
