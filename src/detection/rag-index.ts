export type EmbeddingVector = number[];

export interface KnowledgeEntry {
  id: string;
  content: string;
  metadata: {
    type: 'vulnerability' | 'pattern' | 'cwe' | 'fix' | 'documentation';
    cwe?: string;
    owasp?: string;
    language?: string;
    severity?: string;
    tags: string[];
  };
  embedding?: EmbeddingVector;
}

export interface SearchResult {
  entry: KnowledgeEntry;
  score: number;
}

function cosineSimilarity(a: EmbeddingVector, b: EmbeddingVector): number {
  if (a.length !== b.length || a.length === 0) return 0;
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom > 0 ? dot / denom : 0;
}

export function embedText(text: string, dimensions: number = 128): EmbeddingVector {
  const tokens = text.toLowerCase().split(/\W+/).filter(t => t.length > 0);
  const vector = new Array(dimensions).fill(0);
  for (const token of tokens) {
    let h = 0x811c9dc5;
    for (let i = 0; i < token.length; i++) {
      h ^= token.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    const idx = (h >>> 0) % dimensions;
    vector[idx] += 1;
    const idx2 = ((h >>> 16) ^ (h & 0xffff)) % dimensions;
    vector[idx2] += 0.5;
  }
  const norm = Math.sqrt(vector.reduce((s, v) => s + v * v, 0));
  if (norm > 0) for (let i = 0; i < dimensions; i++) vector[i] /= norm;
  return vector;
}

export class VectorIndex {
  private entries: KnowledgeEntry[] = [];
  private dimensions: number;

  constructor(dimensions = 128) {
    this.dimensions = dimensions;
  }

  add(entry: KnowledgeEntry): void {
    if (!entry.embedding) {
      entry.embedding = embedText(entry.content + ' ' + entry.metadata.tags.join(' '), this.dimensions);
    }
    this.entries.push(entry);
  }

  addBatch(entries: KnowledgeEntry[]): void {
    for (const entry of entries) this.add(entry);
  }

  search(query: string, topK = 5, threshold = 0.3): SearchResult[] {
    const queryEmbedding = embedText(query, this.dimensions);
    const scored = this.entries
      .map(entry => ({
        entry,
        score: entry.embedding ? cosineSimilarity(queryEmbedding, entry.embedding) : 0,
      }))
      .filter(r => r.score >= threshold)
      .sort((a, b) => b.score - a.score);
    return scored.slice(0, topK);
  }

  searchByType(query: string, type: KnowledgeEntry['metadata']['type'], topK = 5): SearchResult[] {
    const queryEmbedding = embedText(query, this.dimensions);
    return this.entries
      .filter(e => e.metadata.type === type)
      .map(entry => ({ entry, score: entry.embedding ? cosineSimilarity(queryEmbedding, entry.embedding) : 0 }))
      .filter(r => r.score >= 0.2)
      .sort((a, b) => b.score - a.score)
      .slice(0, topK);
  }

  size(): number { return this.entries.length; }

  getByCwe(cwe: string): KnowledgeEntry[] {
    return this.entries.filter(e => e.metadata.cwe === cwe);
  }

  getByType(type: KnowledgeEntry['metadata']['type']): KnowledgeEntry[] {
    return this.entries.filter(e => e.metadata.type === type);
  }

  getAll(): KnowledgeEntry[] { return [...this.entries]; }

  clear(): void { this.entries = []; }
}

export class VulnerabilityKnowledgeBase {
  private index: VectorIndex;

  constructor() {
    this.index = new VectorIndex(128);
    this.loadBuiltInKnowledge();
  }

  private loadBuiltInKnowledge(): void {
    const builtIn: KnowledgeEntry[] = [
      { id: 'cwe-89', content: 'SQL Injection: User input is directly concatenated into SQL query strings without parameterization. Attackers can inject arbitrary SQL commands.', metadata: { type: 'cwe', cwe: 'CWE-89', owasp: 'A03:2021', severity: 'critical', tags: ['sql', 'injection', 'database', 'query', 'input'] } },
      { id: 'cwe-78', content: 'OS Command Injection: User input is passed to system shell commands via exec(), system(), spawn() without sanitization.', metadata: { type: 'cwe', cwe: 'CWE-78', owasp: 'A03:2021', severity: 'critical', tags: ['command', 'injection', 'shell', 'exec', 'system', 'os'] } },
      { id: 'cwe-79', content: 'Cross-Site Scripting (XSS): User input is rendered in HTML without proper encoding/escaping, allowing script injection.', metadata: { type: 'cwe', cwe: 'CWE-79', owasp: 'A03:2021', severity: 'high', tags: ['xss', 'html', 'script', 'injection', 'browser', 'dom'] } },
      { id: 'cwe-22', content: 'Path Traversal: User input is used in file paths without validation, allowing access to files outside intended directory via ../ sequences.', metadata: { type: 'cwe', cwe: 'CWE-22', owasp: 'A01:2021', severity: 'high', tags: ['path', 'traversal', 'file', 'directory', '../'] } },
      { id: 'cwe-787', content: 'Buffer Overflow: Writing data beyond the bounds of allocated memory buffer, common in C/C++ when using strcpy, sprintf, gets without bounds checking.', metadata: { type: 'cwe', cwe: 'CWE-787', severity: 'critical', tags: ['buffer', 'overflow', 'memory', 'c', 'cpp', 'strcpy', 'sprintf'] } },
      { id: 'cwe-352', content: 'Cross-Site Request Forgery (CSRF): Web application does not verify the origin of requests, allowing attackers to forge authenticated requests.', metadata: { type: 'cwe', cwe: 'CWE-352', owasp: 'A01:2021', severity: 'medium', tags: ['csrf', 'token', 'request', 'forgery', 'session'] } },
      { id: 'cwe-502', content: 'Deserialization of Untrusted Data: Application deserializes untrusted data without validation, leading to remote code execution.', metadata: { type: 'cwe', cwe: 'CWE-502', owasp: 'A08:2021', severity: 'high', tags: ['deserialization', 'pickle', 'unserialize', 'object', 'serialization'] } },
      { id: 'cwe-94', content: 'Code Injection: Application dynamically evaluates user-supplied code via eval(), Function(), exec(), leading to arbitrary code execution.', metadata: { type: 'cwe', cwe: 'CWE-94', owasp: 'A03:2021', severity: 'critical', tags: ['eval', 'code', 'injection', 'dynamic', 'exec', 'Function'] } },
      { id: 'cwe-200', content: 'Information Exposure: Application exposes sensitive information such as stack traces, database errors, or debug info to end users.', metadata: { type: 'cwe', cwe: 'CWE-200', owasp: 'A01:2021', severity: 'medium', tags: ['information', 'exposure', 'leak', 'debug', 'error', 'stack trace'] } },
      { id: 'cwe-798', content: 'Hardcoded Credentials: Application contains hardcoded passwords, API keys, or secrets in source code.', metadata: { type: 'cwe', cwe: 'CWE-798', owasp: 'A07:2021', severity: 'high', tags: ['hardcoded', 'credentials', 'password', 'secret', 'api key'] } },
      { id: 'cwe-327', content: 'Use of Broken or Risky Cryptographic Algorithm: Using weak hashing (MD5, SHA1) or encryption (DES, RC4) algorithms.', metadata: { type: 'cwe', cwe: 'CWE-327', owasp: 'A02:2021', severity: 'medium', tags: ['crypto', 'hash', 'md5', 'sha1', 'encryption', 'weak'] } },
      { id: 'cwe-295', content: 'Improper Certificate Validation: Application does not properly validate SSL/TLS certificates, enabling man-in-the-middle attacks.', metadata: { type: 'cwe', cwe: 'CWE-295', severity: 'medium', tags: ['ssl', 'tls', 'certificate', 'validation', 'https'] } },
      { id: 'cwe-611', content: 'XXE (XML External Entity): Application parses XML with external entity processing enabled, allowing file disclosure and SSRF.', metadata: { type: 'cwe', cwe: 'CWE-611', owasp: 'A05:2021', severity: 'high', tags: ['xml', 'xxe', 'external', 'entity', 'parser'] } },
      { id: 'cwe-918', content: 'SSRF (Server-Side Request Forgery): Application makes HTTP requests based on user input without URL validation.', metadata: { type: 'cwe', cwe: 'CWE-918', owasp: 'A10:2021', severity: 'high', tags: ['ssrf', 'request', 'fetch', 'url', 'server-side'] } },
    ];

    this.index.addBatch(builtIn);
  }

  search(query: string, topK = 5): SearchResult[] {
    return this.index.search(query, topK, 0.25);
  }

  lookupCwe(cwe: string): KnowledgeEntry[] {
    return this.index.getByCwe(cwe);
  }

  addEntry(entry: KnowledgeEntry): void {
    this.index.add(entry);
  }

  enrichFinding(finding: { type: string; description: string }): SearchResult[] {
    return this.search(finding.type + ' ' + finding.description, 3);
  }

  get size(): number { return this.index.size(); }
}
