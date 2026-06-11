/**
 * Tests for Patch generator + verifier (Anthropic Harness-inspired).
 */
import { describe, expect, test } from 'bun:test';
import {
  generatePatch,
  verifyPatch,
  generatePatchesForFindings,
  summarizePatches,
  PATCH_RULES,
  type GeneratedPatch,
} from '../../../src/patch/patcher.js';
import type { Finding } from '../../../src/triage/triage.js';

const sqliFinding: Finding = {
  id: 'a.php:3:sqli',
  file: 'a.php',
  line: 3,
  vulnType: 'SQL Injection',
  severity: 'CRITICAL',
  uvrs: 0.95,
};

describe('generatePatch — PHP SQL Injection', () => {
  test('generates PDO prepared statement replacement', () => {
    const original = '$result = mysql_query("SELECT * FROM users WHERE id=" . $id);';
    const patch = generatePatch(sqliFinding, 'php', original);
    expect(patch).toBeTruthy();
    expect(patch?.strategy).toBe('parameterized');
    expect(patch?.patchedCode).toContain('$stmt = $pdo->prepare');
    expect(patch?.patchedCode).toContain('execute');
    expect(patch?.patchedCode).not.toContain('mysql_query');
    expect(patch?.description).toContain('PDO');
  });

  test('produces a unified diff', () => {
    const original = '$r = mysql_query($sql);';
    const patch = generatePatch(sqliFinding, 'php', original);
    expect(patch?.diff).toContain('--- a/original');
    expect(patch?.diff).toContain('+++ b/patched');
    expect(patch?.diff).toMatch(/^[+-]/m);
  });
});

describe('generatePatch — PHP Command Injection', () => {
  const finding: Finding = {
    id: 'a.php:5:cmdi',
    file: 'a.php',
    line: 5,
    vulnType: 'Command Injection',
    severity: 'CRITICAL',
    uvrs: 0.95,
  };

  test('wraps with escapeshellarg', () => {
    const original = 'system($cmd);';
    const patch = generatePatch(finding, 'php', original);
    expect(patch?.patchedCode).toContain('escapeshellarg');
  });
});

describe('generatePatch — PHP eval Code Injection', () => {
  const finding: Finding = {
    id: 'a.php:7:eval',
    file: 'a.php',
    line: 7,
    vulnType: 'Code Injection (eval)',
    severity: 'CRITICAL',
    uvrs: 0.95,
  };

  test('removes eval()', () => {
    const original = 'eval($userInput);';
    const patch = generatePatch(finding, 'php', original);
    expect(patch?.patchedCode).not.toContain('eval(');
    expect(patch?.strategy).toBe('disable');
  });
});

describe('generatePatch — PHP Hardcoded Credential', () => {
  const finding: Finding = {
    id: 'a.php:9:cred',
    file: 'a.php',
    line: 9,
    vulnType: 'Hardcoded Credential',
    severity: 'HIGH',
    uvrs: 0.7,
  };

  test('replaces with getenv()', () => {
    const original = '$key = "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaa";';
    const patch = generatePatch(finding, 'php', original);
    expect(patch?.patchedCode).toContain('getenv');
    expect(patch?.patchedCode).not.toContain('sk-proj-');
  });
});

describe('generatePatch — PHP Reflected XSS', () => {
  const finding: Finding = {
    id: 'a.php:11:xss',
    file: 'a.php',
    line: 11,
    vulnType: 'Reflected XSS',
    severity: 'HIGH',
    uvrs: 0.7,
  };

  test('wraps with htmlspecialchars', () => {
    const original = 'echo $name;';
    const patch = generatePatch(finding, 'php', original);
    expect(patch?.patchedCode).toContain('htmlspecialchars');
  });
});

describe('generatePatch — Python variants', () => {
  const sqlFinding: Finding = {
    id: 'a.py:5:sqli',
    file: 'a.py',
    line: 5,
    vulnType: 'SQL Injection',
    severity: 'CRITICAL',
    uvrs: 0.95,
  };
  const cmdiFinding: Finding = {
    id: 'a.py:7:cmdi',
    file: 'a.py',
    line: 7,
    vulnType: 'Command Injection',
    severity: 'CRITICAL',
    uvrs: 0.95,
  };

  test('Python SQLi uses parameterized query', () => {
    const patch = generatePatch(
      sqlFinding,
      'python',
      'cursor.execute(f"SELECT * FROM x WHERE id = {user_id}")'
    );
    expect(patch?.patchedCode).toContain('execute');
    expect(patch?.patchedCode).toContain('?');
  });

  test('Python Command Injection uses shlex', () => {
    const patch = generatePatch(cmdiFinding, 'python', 'os.system("ls " + user_input)');
    expect(patch?.patchedCode).toContain('shlex');
    expect(patch?.patchedCode).toContain('shell=False');
  });
});

describe('generatePatch — no rule available', () => {
  test('returns manual-review patch when no rule matches', () => {
    const finding: Finding = {
      id: '1',
      file: 'a.php',
      line: 1,
      vulnType: 'Unknown Vuln Type',
      severity: 'MEDIUM',
      uvrs: 0.5,
    };
    const patch = generatePatch(finding, 'php', 'something bad');
    expect(patch).toBeTruthy();
    expect(patch?.verified).toBe(false);
    expect(patch?.verificationNotes.length).toBeGreaterThan(0);
  });
});

describe('verifyPatch', () => {
  test('flags eval() still present', () => {
    const patch: GeneratedPatch = {
      finding: sqliFinding,
      strategy: 'parameterized',
      originalCode: 'eval($x)',
      patchedCode: 'eval($x)',
      description: '',
      diff: '',
      verified: true,
      verificationNotes: [],
    };
    const result = verifyPatch(patch);
    expect(result.verified).toBe(false);
    expect(result.verificationNotes.some((n) => n.includes('eval'))).toBe(true);
  });

  test('flags weak hash', () => {
    const patch: GeneratedPatch = {
      finding: sqliFinding,
      strategy: 'sanitize',
      originalCode: '$h = md5($x)',
      patchedCode: '$h = md5($x)',
      description: '',
      diff: '',
      verified: true,
      verificationNotes: [],
    };
    const result = verifyPatch(patch);
    expect(result.verified).toBe(false);
    expect(result.verificationNotes.some((n) => n.toLowerCase().includes('weak'))).toBe(true);
  });

  test('passes clean patch', () => {
    const patch: GeneratedPatch = {
      finding: sqliFinding,
      strategy: 'parameterized',
      originalCode: '$r = mysql_query($sql . $id)',
      patchedCode: '$stmt = $pdo->prepare("SELECT ?");\n$stmt->execute([$id]);',
      description: 'good',
      diff: 'diff',
      verified: true,
      verificationNotes: [],
    };
    const result = verifyPatch(patch);
    expect(result.verified).toBe(true);
    expect(result.verificationNotes).toHaveLength(0);
  });
});

describe('generatePatchesForFindings', () => {
  test('generates patches for multiple findings', () => {
    const findings = [
      sqliFinding,
      {
        id: 'a.php:5:cmdi',
        file: 'a.php',
        line: 5,
        vulnType: 'Command Injection',
        severity: 'CRITICAL',
        uvrs: 0.95,
      } as Finding,
    ];
    const codeLines = new Map<string, string>([
      ['a.php:3', '$result = mysql_query("SELECT * FROM x WHERE id=" . $id);'],
      ['a.php:5', 'system($cmd);'],
    ]);
    const patches = generatePatchesForFindings(findings, 'php', codeLines);
    expect(patches.length).toBe(2);
  });
});

describe('summarizePatches', () => {
  test('counts and groups by strategy', () => {
    const patches: GeneratedPatch[] = [
      {
        finding: sqliFinding,
        strategy: 'parameterized',
        originalCode: '',
        patchedCode: '',
        description: '',
        diff: '',
        verified: true,
        verificationNotes: [],
      },
      {
        finding: sqliFinding,
        strategy: 'parameterized',
        originalCode: '',
        patchedCode: '',
        description: '',
        diff: '',
        verified: false,
        verificationNotes: ['x'],
      },
      {
        finding: sqliFinding,
        strategy: 'escape',
        originalCode: '',
        patchedCode: '',
        description: '',
        diff: '',
        verified: true,
        verificationNotes: [],
      },
    ];
    const summary = summarizePatches(patches);
    expect(summary.total).toBe(3);
    expect(summary.verified).toBe(2);
    expect(summary.byStrategy.parameterized).toBe(2);
    expect(summary.byStrategy.escape).toBe(1);
  });
});

describe('PATCH_RULES catalog', () => {
  test('has rules for all common vuln types', () => {
    const vulnTypes = new Set(PATCH_RULES.map((r) => `${r.vulnType}:${r.language}`));
    expect(vulnTypes.has('SQL Injection:php')).toBe(true);
    expect(vulnTypes.has('SQL Injection:python')).toBe(true);
    expect(vulnTypes.has('Command Injection:php')).toBe(true);
    expect(vulnTypes.has('Command Injection:python')).toBe(true);
    expect(vulnTypes.has('Code Injection (eval):php')).toBe(true);
    expect(vulnTypes.has('Reflected XSS:php')).toBe(true);
    expect(vulnTypes.has('Hardcoded Credential:php')).toBe(true);
    expect(vulnTypes.has('Hardcoded Credential:python')).toBe(true);
    expect(vulnTypes.has('Local File Inclusion:php')).toBe(true);
    expect(vulnTypes.has('Insecure Deserialization:php')).toBe(true);
    expect(vulnTypes.has('Weak Cryptography:php')).toBe(true);
  });

  test('all rules have description, generate, verify', () => {
    for (const rule of PATCH_RULES) {
      expect(rule.description.length).toBeGreaterThan(10);
      expect(typeof rule.generate).toBe('function');
      expect(typeof rule.verify).toBe('function');
    }
  });
});
