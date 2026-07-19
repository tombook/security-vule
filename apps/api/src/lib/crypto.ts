// apps/api/src/lib/crypto.ts
//
// Symmetric envelope encryption for short secrets stored alongside
// resources (target passwords, auth tokens, integration API keys).
//
// Format: a single byte buffer whose first 12 bytes are the IV
// (GCM standard), followed by the 16-byte auth tag, followed by the
// ciphertext. Key is sourced from SECURITY_VULE_ENC_KEY env var or
// from the database connection URL password as a deterministic
// fallback for dev environments. Prod must set the env var.
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto';

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;

function getKey(): Buffer {
  const env = process.env.SECURITY_VULE_ENC_KEY;
  if (env) {
    // 32-byte raw key, or hex / base64.
    if (/^[0-9a-f]{64}$/i.test(env)) return Buffer.from(env, 'hex');
    if (env.length === 44) return Buffer.from(env, 'base64');
    return createHash('sha256').update(env).digest();
  }
  // Dev fallback: derive from a stable secret in DATABASE_URL or
  // throw if neither is set. This keeps tests reproducible.
  const dbUrl = process.env.DATABASE_URL ?? '';
  const pass = dbUrl.match(/:([^@]+)@/)?.[1] ?? '';
  if (!pass) {
    throw new Error('SECURITY_VULE_ENC_KEY not set and DATABASE_URL has no password');
  }
  return createHash('sha256').update('security-vule:' + pass).digest();
}

export function encryptSecret(plaintext: string): Buffer {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, getKey(), iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

export function decryptSecret(blob: Buffer): string {
  if (blob.length < IV_LEN + TAG_LEN + 1) throw new Error('ciphertext too short');
  const iv = blob.subarray(0, IV_LEN);
  const tag = blob.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ct = blob.subarray(IV_LEN + TAG_LEN);
  const decipher = createDecipheriv(ALGO, getKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}
