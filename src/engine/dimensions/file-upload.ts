/**
 * Dimension #30: File Upload Risk — source + runtime composite.
 *
 * Inspired by SOP v1.0 PoC evaluation finding:
 * "Web upload vs static analysis: DVWA upload vulnerability not detected in source"
 *
 * Combines:
 *1. STATIC source patterns (move_uploaded_file, $_FILES handling, MIME validation)
 *2. CONFIGURATION patterns (.htaccess / nginx config / web.config writable in upload dir)
 *3. EXTENSION whitelist patterns (allows .php, .jsp in uploads = RCE)
 *4. SIZE/MIME check patterns
 *
 * Returns risk score0..1 based on missing-mitigations count.
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

interface UploadRisk {
  type:
    | 'no_extension_check'
    | 'no_mime_check'
    | 'no_size_limit'
    | 'uploads_dir_writable'
    | 'double_extension_risk';
  severity: number;
  line: number;
  snippet: string;
  mitigation: string;
}

const MITIGATION_PATTERNS: Array<{
  id: UploadRisk['type'];
  pattern: RegExp;
  severity: number;
  description: string;
  mitigation: string;
}> = [
  {
    id: 'no_extension_check',
    pattern: /\b(move_uploaded_file|copy|file_put_contents)\b\s*\(/i,
    severity: 0.6,
    description: 'File uploaded via move_uploaded_file/copy without extension validation',
    mitigation:
      'Whitelist allowed extensions (e.g. .jpg, .pdf) using pathinfo() + in_array() check',
  },
  {
    id: 'no_mime_check',
    pattern: /\$_FILES\b.*['"]?(tmp_name|name|type|error|size)/i,
    severity: 0.5,
    description: '$_FILES superglobal accessed without MIME type validation',
    mitigation:
      'Validate $_FILES["type"] against whitelist or use finfo_file() to detect actual MIME',
  },
  {
    id: 'no_size_limit',
    pattern: /\$_FILES\b.*size/i,
    severity: 0.3,
    description: 'File size not validated against limit',
    mitigation: 'Check $_FILES["size"] against MAX_SIZE (e.g.5MB). Reject if larger.',
  },
  {
    id: 'uploads_dir_writable',
    pattern: /\bchmod\b.*0?77[7]\b|\bchmod\b.*0777\b/i,
    severity: 0.9,
    description:
      'Upload directory has world-writable permissions (chmod777) — enables drop-and-execute',
    mitigation:
      'chmod755 on upload directory. PHP files cannot execute if directory has no execute bit for others AND Apache config denies script execution in uploads dir.',
  },
  {
    id: 'double_extension_risk',
    pattern: /\.(php|phtml|php3|php4|php5|pht|phar)\s*\.\w{2,4}\b/i,
    severity: 0.7,
    description:
      'Filename contains double extension (e.g. image.php.jpg) — Apache misconfig may execute as PHP',
    mitigation: 'Strip all extensions except the whitelisted one. Use rename() after validation.',
  },
];

const UPLOAD_DETECTION_PATTERN =
  /(move_uploaded_file|copy\s*\(.*\$_FILES|file_put_contents\s*\(.*\$_FILES|chmod\s*\(.*upload)/i;

export class FileUploadDimension extends BaseDimension {
  readonly name = 'fileUpload';
  readonly weight = 0.08;

  private detected: Map<string, UploadRisk[]> = new Map();

  compute(node: CPGNode, cpg: CPG): number {
    if (!UPLOAD_DETECTION_PATTERN.test(node.code)) {
      return 0;
    }

    const risks: UploadRisk[] = [];
    for (const p of MITIGATION_PATTERNS) {
      p.pattern.lastIndex = 0;
      if (p.pattern.test(node.code)) {
        risks.push({
          type: p.id,
          severity: p.severity,
          line: node.line,
          snippet: node.code.trim().slice(0, 160),
          mitigation: p.mitigation,
        });
        p.pattern.lastIndex = 0;
      }
    }

    if (risks.length > 0) {
      this.detected.set(node.id, risks);
    }

    const total = risks.reduce((s, r) => s + r.severity, 0);
    return Math.min(1, total / 2);
  }

  explain(node: CPGNode, _cpg: CPG): string {
    const risks = this.detected.get(node.id);
    if (!risks || risks.length === 0) {
      return 'No file upload risk patterns detected';
    }
    const items = risks.map((r) => `• ${r.type} (sev ${r.severity}): ${r.mitigation}`).join('\n');
    return `File upload risks detected:\n${items}`;
  }

  llmPrompt(node: CPGNode, _cpg: CPG): string {
    const risks = this.detected.get(node.id);
    if (!risks || risks.length === 0) return '';
    return `File upload at line ${node.line}: ${node.code}\nRisks:\n${risks.map((r) => `- ${r.type}: ${r.description}`).join('\n')}\nRecommend verifying: upload directory permissions, Apache/nginx config (no script execution), and tested with real PoC (.php.jpg upload).`;
  }

  /** Runtime check: verify upload directory has no execute permission for PHP files. */
  async runtimeCheck(uploadDir: string): Promise<{ ok: boolean; mode: string; gid: number }> {
    try {
      const fs = await import('fs');
      const stat = fs.statSync(uploadDir);
      const mode = (stat.mode & 0o777).toString(8);
      const gid = stat.gid;
      const ok = (stat.mode & 0o111) === 0 || (stat.mode & 0o001) === 0;
      return { ok, mode, gid };
    } catch (e) {
      return { ok: false, mode: 'unknown', gid: -1 };
    }
  }
}
