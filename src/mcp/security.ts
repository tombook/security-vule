import crypto from 'crypto';
import { realpathSync, statSync } from 'fs';
import { resolve, sep } from 'path';

export function verifyAuth(provided: string | undefined, expected: string | undefined): boolean {
  if (!provided || !expected) return false;
  if (typeof provided !== 'string' || typeof expected !== 'string') return false;
  if (provided.length !== expected.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
  } catch {
    return false;
  }
}

export function isPathAllowed(filePath: string, allowedDirs: string[]): boolean {
  if (allowedDirs.length === 0) return false;
  let resolved: string;
  try {
    resolved = realpathSync(filePath);
  } catch {
    resolved = resolve(filePath);
  }
  return allowedDirs.some((dir) => {
    let allowed: string;
    try {
      allowed = realpathSync(dir);
    } catch {
      allowed = resolve(dir);
    }
    return resolved === allowed || resolved.startsWith(allowed + sep);
  });
}

export function checkFileSize(sizeBytes: number, maxSizeMB: number): void {
  const maxBytes = maxSizeMB * 1024 * 1024;
  if (sizeBytes > maxBytes) {
    throw new Error(`File size ${sizeBytes} bytes exceeds limit of ${maxSizeMB}MB`);
  }
}

export function getMcpAuthStatus(): { required: boolean; reason?: string } {
  const secret = process.env.MCP_SHARED_SECRET;
  if (!secret) {
    return { required: true, reason: 'MCP_SHARED_SECRET not configured' };
  }
  return { required: true };
}

export function checkFileSizeFromPath(filePath: string, maxSizeMB: number): { size: number; ok: boolean } {
  try {
    const stats = statSync(filePath);
    return { size: stats.size, ok: stats.size <= maxSizeMB * 1024 * 1024 };
  } catch {
    return { size: 0, ok: false };
  }
}
