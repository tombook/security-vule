import { describe, expect, test } from 'bun:test';
import { VectorIndex, embedText, VulnerabilityKnowledgeBase } from '../../../src/detection/rag-index.js';

describe('embedText', () => {
  test('returns vector of correct dimensions', () => {
    const vec = embedText('hello world', 64);
    expect(vec.length).toBe(64);
  });

  test('produces unit-normalized vector', () => {
    const vec = embedText('test input', 128);
    const norm = Math.sqrt(vec.reduce((s, v) => s + v * v, 0));
    expect(Math.abs(norm - 1.0) < 0.001).toBe(true);
  });

  test('produces deterministic embeddings', () => {
    const a = embedText('same text', 64);
    const b = embedText('same text', 64);
    expect(a).toEqual(b);
  });

  test('produces different embeddings for different text', () => {
    const a = embedText('sql injection', 64);
    const b = embedText('buffer overflow', 64);
    const dot = a.reduce((s, v, i) => s + v * b[i], 0);
    expect(dot < 0.99).toBe(true);
  });
});

describe('VectorIndex', () => {
  test('adds and searches entries', () => {
    const idx = new VectorIndex(64);
    idx.add({ id: 'test-1', content: 'SQL injection vulnerability in user input', metadata: { type: 'vulnerability', tags: ['sql', 'injection'] } });
    idx.add({ id: 'test-2', content: 'Buffer overflow in C memory allocation', metadata: { type: 'vulnerability', tags: ['buffer', 'overflow'] } });

    const results = idx.search('SQL injection attack', 5);
    expect(results.length > 0).toBe(true);
    expect(results[0].entry.id).toBe('test-1');
    expect(results[0].score > 0).toBe(true);
  });

  test('filters by type', () => {
    const idx = new VectorIndex(64);
    idx.add({ id: 'v1', content: 'SQL injection', metadata: { type: 'vulnerability', tags: ['sql'] } });
    idx.add({ id: 'f1', content: 'Use parameterized queries', metadata: { type: 'fix', tags: ['sql'] } });

    const results = idx.searchByType('sql', 'fix', 5);
    expect(results.every(r => r.entry.metadata.type === 'fix')).toBe(true);
  });

  test('getByCwe returns matching entries', () => {
    const idx = new VectorIndex(64);
    idx.add({ id: 'cwe89', content: 'SQL Injection', metadata: { type: 'cwe', cwe: 'CWE-89', tags: ['sql'] } });
    idx.add({ id: 'cwe79', content: 'XSS', metadata: { type: 'cwe', cwe: 'CWE-79', tags: ['xss'] } });

    const results = idx.getByCwe('CWE-89');
    expect(results.length).toBe(1);
    expect(results[0].id).toBe('cwe89');
  });

  test('clear removes all entries', () => {
    const idx = new VectorIndex(64);
    idx.add({ id: 't', content: 'test', metadata: { type: 'vulnerability', tags: [] } });
    expect(idx.size()).toBe(1);
    idx.clear();
    expect(idx.size()).toBe(0);
  });
});

describe('VulnerabilityKnowledgeBase', () => {
  test('has built-in CWE entries', () => {
    const kb = new VulnerabilityKnowledgeBase();
    expect(kb.size > 10).toBe(true);
  });

  test('searches for SQL injection', () => {
    const kb = new VulnerabilityKnowledgeBase();
    const results = kb.search('SQL injection user input');
    expect(results.length > 0).toBe(true);
    expect(results[0].entry.metadata.cwe).toBeDefined();
  });

  test('looks up by CWE ID', () => {
    const kb = new VulnerabilityKnowledgeBase();
    const results = kb.lookupCwe('CWE-89');
    expect(results.length > 0).toBe(true);
    expect(results[0].metadata.cwe).toBe('CWE-89');
  });

  test('adds custom entries', () => {
    const kb = new VulnerabilityKnowledgeBase();
    const initialSize = kb.size;
    kb.addEntry({ id: 'custom-1', content: 'Custom vulnerability pattern', metadata: { type: 'pattern', tags: ['custom'] } });
    expect(kb.size).toBe(initialSize + 1);
  });

  test('enriches findings', () => {
    const kb = new VulnerabilityKnowledgeBase();
    const results = kb.enrichFinding({ type: 'SQL Injection', description: 'User input directly in query' });
    expect(results.length > 0).toBe(true);
  });
});
