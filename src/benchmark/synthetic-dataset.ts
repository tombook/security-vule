import type { BenchmarkSample } from './evaluator.js';

export const SYNTHETIC_DATASET: BenchmarkSample[] = [
  {
    id: 'syn-sqli-001',
    code: `app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.params.id;
  db.query(query, (err, result) => {
    res.json(result);
  });
});`,
    language: 'javascript',
    isVulnerable: true,
    cwe: ['CWE-89'],
    vulnerableLines: [2],
  },
  {
    id: 'syn-sqli-002',
    code: `app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = ?";
  db.query(query, [req.params.id], (err, result) => {
    res.json(result);
  });
});`,
    language: 'javascript',
    isVulnerable: false,
  },
  {
    id: 'syn-cmdi-001',
    code: `const { exec } = require('child_process');
function pingHost(host) {
  exec('ping -c 3 ' + host, (err, stdout) => {
    console.log(stdout);
  });
}`,
    language: 'javascript',
    isVulnerable: true,
    cwe: ['CWE-78'],
    vulnerableLines: [3],
  },
  {
    id: 'syn-cmdi-002',
    code: `const { execFile } = require('child_process');
function pingHost(host) {
  execFile('ping', ['-c', '3', host], (err, stdout) => {
    console.log(stdout);
  });
}`,
    language: 'javascript',
    isVulnerable: false,
  },
  {
    id: 'syn-xss-001',
    code: `function showComment(comment) {
  document.getElementById('comments').innerHTML = comment.text;
}`,
    language: 'javascript',
    isVulnerable: true,
    cwe: ['CWE-79'],
    vulnerableLines: [2],
  },
  {
    id: 'syn-xss-002',
    code: `function showComment(comment) {
  const el = document.getElementById('comments');
  el.textContent = comment.text;
}`,
    language: 'javascript',
    isVulnerable: false,
  },
  {
    id: 'syn-path-001',
    code: `const fs = require('fs');
function readFile(name) {
  const data = fs.readFileSync('/var/data/' + name, 'utf8');
  return data;
}`,
    language: 'javascript',
    isVulnerable: true,
    cwe: ['CWE-22'],
    vulnerableLines: [3],
  },
  {
    id: 'syn-path-002',
    code: `const fs = require('fs');
const path = require('path');
function readFile(name) {
  const safe = path.basename(name);
  const data = fs.readFileSync(path.join('/var/data', safe), 'utf8');
  return data;
}`,
    language: 'javascript',
    isVulnerable: false,
  },
  {
    id: 'syn-hardcred-001',
    code: `const DB_PASSWORD = "super_secret_123";
const API_KEY = "sk-proj-abc123def456";
function connect() {
  return db.connect({ password: DB_PASSWORD });
}`,
    language: 'javascript',
    isVulnerable: true,
    cwe: ['CWE-798'],
    vulnerableLines: [1, 2],
  },
  {
    id: 'syn-weakcrypto-001',
    code: `const crypto = require('crypto');
function hashPassword(pwd) {
  return crypto.createHash('md5').update(pwd).digest('hex');
}`,
    language: 'javascript',
    isVulnerable: true,
    cwe: ['CWE-327'],
    vulnerableLines: [3],
  },
  {
    id: 'syn-weakcrypto-002',
    code: `const crypto = require('crypto');
function hashPassword(pwd, salt) {
  return crypto.pbkdf2Sync(pwd, salt, 100000, 64, 'sha512').toString('hex');
}`,
    language: 'javascript',
    isVulnerable: false,
  },
  {
    id: 'syn-buf-001',
    code: `#include <string.h>
void copy_name(char* dest, const char* src) {
  strcpy(dest, src);
}`,
    language: 'c',
    isVulnerable: true,
    cwe: ['CWE-119'],
    vulnerableLines: [3],
  },
  {
    id: 'syn-buf-002',
    code: `#include <string.h>
void copy_name(char* dest, size_t dest_size, const char* src) {
  strncpy(dest, src, dest_size - 1);
  dest[dest_size - 1] = '\\0';
}`,
    language: 'c',
    isVulnerable: false,
  },
  {
    id: 'syn-safe-001',
    code: `function add(a, b) {
  return a + b;
}
function multiply(x, y) {
  return x * y;
}`,
    language: 'javascript',
    isVulnerable: false,
  },
  {
    id: 'syn-safe-002',
    code: `const express = require('express');
const helmet = require('helmet');
const app = express();
app.use(helmet());
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});`,
    language: 'javascript',
    isVulnerable: false,
  },
  {
    id: 'syn-eval-001',
    code: `function calculate(expr) {
  return eval(expr);
}`,
    language: 'javascript',
    isVulnerable: true,
    cwe: ['CWE-94'],
    vulnerableLines: [2],
  },
  {
    id: 'syn-jwt-001',
    code: `const jwt = require('jsonwebtoken');
function verifyToken(token) {
  return jwt.verify(token, 'secret', { algorithms: ['none'] });
}`,
    language: 'javascript',
    isVulnerable: true,
    cwe: ['CWE-347'],
    vulnerableLines: [3],
  },
  {
    id: 'syn-deser-001',
    code: `const pickle = require('pickle');
function loadUserData(data) {
  return pickle.loads(data);
}`,
    language: 'python',
    isVulnerable: true,
    cwe: ['CWE-502'],
    vulnerableLines: [3],
  },
  {
    id: 'syn-ssrf-001',
    code: `app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  const response = await fetch(url);
  const data = await response.text();
  res.send(data);
});`,
    language: 'javascript',
    isVulnerable: true,
    cwe: ['CWE-918'],
    vulnerableLines: [3],
  },
  {
    id: 'syn-xxe-001',
    code: `const xml2js = require('xml2js');
function parseXml(input) {
  xml2js.parseString(input, { explicitCharkey: true }, (err, result) => {
    return result;
  });
}`,
    language: 'javascript',
    isVulnerable: true,
    cwe: ['CWE-611'],
    vulnerableLines: [3],
  },
];
