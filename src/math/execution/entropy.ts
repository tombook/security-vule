/**
 * Shannon Entropy Analysis Module
 * H(X) = -Σ p(x) log₂ p(x)
 */

export interface EntropyResult {
  value: number;
  base: number;
  distribution: Map<string, number>;
}

/**
 * Calculate Shannon entropy for a sequence of values
 */
export function entropy(values: string[] | number[], base: number = 2): EntropyResult {
  const frequency = new Map<string, number>();
  const n = values.length;

  for (const v of values) {
    const key = String(v);
    frequency.set(key, (frequency.get(key) || 0) + 1);
  }

  const distribution = new Map<string, number>();
  let h = 0;

  for (const [key, count] of frequency) {
    const p = count / n;
    distribution.set(key, p);
    if (p > 0) {
      h -= p * Math.log(p) / Math.log(base);
    }
  }

  return { value: h, base, distribution };
}

/**
 * Calculate entropy of function metrics (cyclomatic complexity, lines of code, etc.)
 */
export function functionEntropy(metrics: Array<{ complexity: number; loc: number; args: number }>): number {
  const values = metrics.map(m => `${m.complexity}-${m.loc}-${m.args}`);
  return entropy(values).value;
}

/**
 * Calculate entropy of call graph (outgoing/incoming edges distribution)
 */
export function callGraphEntropy(outgoingEdges: Map<string, string[]>): number {
  const edgeCounts: number[] = [];

  for (const [, targets] of outgoingEdges) {
    edgeCounts.push(targets.length);
  }

  return entropy(edgeCounts).value;
}

/**
 * Calculate token-level entropy for code tokens
 */
export function tokenEntropy(tokens: string[]): EntropyResult {
  return entropy(tokens);
}

/**
 * Calculate normalized entropy (0 to 1 scale)
 */
export function normalizedEntropy(values: string[] | number[], base: number = 2): number {
  const result = entropy(values, base);
  const maxEntropy = Math.log(values.length) / Math.log(base);
  return maxEntropy > 0 ? result.value / maxEntropy : 0;
}

/**
 * Calculate joint entropy H(X,Y)
 */
export function jointEntropy(pairs: Array<[string, string]>): number {
  const values = pairs.map(p => `${p[0]}|${p[1]}`);
  return entropy(values).value;
}

/**
 * Calculate conditional entropy H(Y|X)
 */
export function conditionalEntropy(
  jointPairs: Array<[string, string]>,
  xDistribution: Map<string, number>
): number {
  const xyEntropy = jointEntropy(jointPairs);
  const xEntropy = entropy(Array.from(xDistribution.keys())).value;
  return Math.max(0, xyEntropy - xEntropy);
}