/**
 * Deterministic seeded PRNG for reproducible experiments.
 * Uses xoshiro128** — fast, high-quality, no dependencies.
 */

export type Rng = () => number;

/** Create a seeded PRNG returning values in [0, 1). */
export function createRng(seed: number): Rng {
  // Seed state using SplitMix32
  let s0 = splitMix32(seed);
  let s1 = splitMix32(seed + 1);
  let s2 = splitMix32(seed + 2);
  let s3 = splitMix32(seed + 3);

  return () => {
    // xoshiro128**
    const result = Math.imul(rotl(Math.imul(s1, 5), 7), 9);
    const t = s1 << 9;
    s2 ^= s0;
    s3 ^= s1;
    s1 ^= s2;
    s0 ^= s3;
    s2 ^= t;
    s3 = rotl(s3, 11);
    return (result >>> 0) / 4294967296;
  };
}

/** Integer in [0, max) */
export function rngInt(rng: Rng, max: number): number {
  return Math.floor(rng() * max);
}

/** Random element from array */
export function rngChoice<T>(rng: Rng, arr: T[]): T {
  return arr[rngInt(rng, arr.length)];
}

/** Uniform in [lo, hi) */
export function rngUniform(rng: Rng, lo: number, hi: number): number {
  return lo + rng() * (hi - lo);
}

/** Bernoulli trial — true with probability p */
export function rngBool(rng: Rng, p: number): boolean {
  return rng() < p;
}

/** Create an auto-incrementing ID generator (no Math.random needed) */
export function createIdGen(prefix: string = 'id') {
  let counter = 0;
  return () => `${prefix}_${++counter}`;
}

function splitMix32(a: number): number {
  let h = (a + 0x9e3779b9) | 0;
  h = Math.imul(h ^ (h >>> 16), 0x85ebca6b);
  h = Math.imul(h ^ (h >>> 13), 0xc2b2ae35);
  return (h ^ (h >>> 16)) >>> 0;
}

function rotl(x: number, k: number): number {
  return (x << k) | (x >>> (32 - k));
}
