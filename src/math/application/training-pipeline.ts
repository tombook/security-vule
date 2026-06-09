/**
 * Training Data Pipeline for Data-Driven Vulnerability Mining
 * Process benchmark samples → extract features → train classifiers
 * Inspired by SARD, D2A, Devign datasets
 */
import { readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync } from 'fs';
import { join, extname, resolve } from 'path';
import { CPGBuilder, type CodePropertyGraph } from '../execution/cpg.js';
import { initializeNodeFeatures, VulnerabilityGNN } from './gnn-classifier.js';
import { graphEmbedding } from '../../detection/ml-classifier.js';

export interface TrainingSample {
  id: string;
  code: string;
  filePath: string;
  language: string;
  label: number; // 1=vulnerable, 0=safe
  vulnerabilityType?: string; // CWE type
  cpg: CodePropertyGraph;
  features: FeatureVector;
  graphEmbedding?: number[];
}

export type FeatureVector = number[];

// Dataset directories
const BENIGN_DIR = resolve(process.cwd(), 'data/benign');
const VULN_DIR = resolve(process.cwd(), 'data/vuln_samples');
const TRAIN_DIR = resolve(process.cwd(), 'data/training');

// Load code samples from directory
export function loadSamplesFromDir(dir: string, label: number): TrainingSample[] {
  const samples: TrainingSample[] = [];
  
  if (!existsSync(dir)) {
    console.warn(`[Pipeline] Directory not found: ${dir}`);
    return samples;
  }
  
  const files = readdirSync(dir).filter(f =>
    ['.py', '.js', '.ts', '.java', '.c', '.cpp', '.h', '.go', '.rs'].includes(extname(f))
  );
  
  for (const file of files) {
    try {
      const filePath = join(dir, file);
      const code = readFileSync(filePath, 'utf-8');
      const lang = detectLang(file);
      
      samples.push({
        id: `sample_${file}`,
        code,
        filePath,
        language: lang,
        label,
        cpg: buildCPGFromCode(code, lang, file),
        features: extractFeatures(code, lang)
      });
    } catch (e) {
      // Skip files that fail
    }
  }
  
  return samples;
}

// Build CPG from source code
export function buildCPGFromCode(code: string, lang: string, filePath: string) {
  const cpgBuilder = new CPGBuilder();
  cpgBuilder.setLanguage(lang).setProjectPath(filePath);
  cpgBuilder.addFile('file_1', filePath, code);
  
  // Parse functions (simplified)
  const lines = code.split('\n');
  let funcId = 1;
  let nodeId = 1;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const lineNum = i + 1;
    
    // Detect function definitions
    if (/^(def|function|func|public|private|protected)/.test(line) && line.includes('(')) {
      const funcName = extractFunctionName(line);
      cpgBuilder.addFunction(`func_${funcId}`, funcName, lineNum);
      const parentFunc = `func_${funcId++}`;
      
      // Parse body within function
      let stmtId = nodeId;
      for (let j = i + 1; j < lines.length && !lines[j].trim().startsWith('function') && !lines[j].trim().startsWith('def ') && !lines[j].trim().startsWith('func '); j++) {
        const bodyLine = lines[j].trim();
        if (bodyLine && !bodyLine.startsWith('#') && !bodyLine.startsWith('//')) {
          cpgBuilder.addStatement(`stmt_${stmtId}`, bodyLine, j + 1);
          cpgBuilder.addASTEdge(parentFunc, `stmt_${stmtId}`);
          stmtId++;
          nodeId = stmtId;
        }
      }
    }
    
    // Also add standalone statements
    if (line && !line.startsWith('#') && !line.startsWith('//') && !line.startsWith('import') && !line.startsWith('package')) {
      cpgBuilder.addExpression(`expr_${nodeId}`, line, lineNum);
      nodeId++;
    }
  }
  
  return cpgBuilder.build();
}

// Extract function name from definition line
function extractFunctionName(line: string): string {
  const match = line.match(/(?:def|function|func)\s+(\w+)\s*\(/);
  if (match) return match[1];
  const classMatch = line.match(/(?:public|private|protected)?\s*(?:class|interface)\s+(\w+)/);
  if (classMatch) return classMatch[1];
  return 'anonymous';
}

// Detect language from extension
function detectLang(filePath: string): string {
  const ext = extname(filePath).toLowerCase();
  const map: Record<string, string> = {
    '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
    '.java': 'java', '.c': 'c', '.cpp': 'c', '.h': 'c',
    '.go': 'go', '.rs': 'rust'
  };
  return map[ext] || 'python';
}

// Feature extraction for ML training
export function extractFeatures(code: string, lang: string): FeatureVector {
  const features: number[] = [];
  
  // Code complexity features
  const lines = code.split('\n');
  const loc = lines.length;
  features.push(Math.min(loc / 1000, 1)); // Normalized LOC
  
  // Cyclomatic complexity proxies
  const decisionPoints = (code.match(/\b(if|while|for|case|catch|\?\??)\b/g) || []).length;
  features.push(Math.min(decisionPoints / 50, 1));
  
  // Nesting depth
  let maxNesting = 0, currentNesting = 0;
  for (const line of lines) {
    currentNesting += (line.match(/{/g) || []).length - (line.match(/}/g) || []).length;
    maxNesting = Math.max(maxNesting, currentNesting);
  }
  features.push(Math.min(maxNesting / 10, 1));
  
  // Function count
  const funcCount = (code.match(/(?:^|\n)(?:def|function|func|public|private|protected)\s+\w+/g) || []).length;
  features.push(Math.min(funcCount / 20, 1));
  
  // Import/use count (attack surface)
  const importCount = (code.match(/(?:^|\n)(?:import|from|require|include)\s+/g) || []).length;
  features.push(Math.min(importCount / 30, 1));
  
  // Dangerous function calls
  const dangerousCount = (code.match(/\b(exec|eval|system|shell|popen|spawn|compile)\s*\(/gi) || []).length;
  features.push(Math.min(dangerousCount / 10, 1));
  
  // User input points
  const inputCount = (code.match(/\b(input|read|get|request|query|body|param)\s*\(/gi) || []).length;
  features.push(Math.min(inputCount / 20, 1));
  
  // String concat/format (potential injection)
  const concatCount = (code.match(/(\+|[%`](?:[^`]*`)+|\bf\b\.format\s*\(|f"|f'|\$\{|\\?")/g) || []).length;
  features.push(Math.min(concatCount / 50, 1));
  
  // Comment ratio (code quality indicator)
  const commentCount = (code.match(/(#|\/\/|<\!--|\/\*)/g) || []).length;
  features.push(commentCount / Math.max(loc, 1));
  
  // Entropy-based features
  const charFreq = new Map<string, number>();
  for (const ch of code) {
    charFreq.set(ch, (charFreq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of charFreq.values()) {
    const p = count / code.length;
    entropy -= p * Math.log(p) / Math.log(2);
  }
  features.push(Math.min(entropy / 8, 1));
  
  // Line length statistics
  const lineLengths = lines.map(l => l.length);
  const avgLineLen = lineLengths.reduce((a, b) => a + b, 0) / Math.max(lineLengths.length, 1);
  const maxLineLen = Math.max(...lineLengths, 0);
  features.push(Math.min(avgLineLen / 200, 1));
  features.push(Math.min(maxLineLen / 500, 1));
  
  // Pad or truncate to fixed size
  const FEATURE_SIZE = 64;
  while (features.length < FEATURE_SIZE) features.push(0);
  return features.slice(0, FEATURE_SIZE);
}

// Build training dataset
export function buildTrainingDataset(): TrainingSample[] {
  console.log('[Pipeline] Building training dataset...');
  
  const benignSamples = loadSamplesFromDir(BENIGN_DIR, 0);
  const vulnSamples = loadSamplesFromDir(VULN_DIR, 1);
  
  console.log(`[Pipeline] Loaded ${benignSamples.length} benign, ${vulnSamples.length} vulnerable`);
  
  const allSamples = [...benignSamples, ...vulnSamples];
  
  // Compute graph embeddings for each sample
  for (const sample of allSamples) {
    try {
      // Build adjacency map for graph embedding
      const adjacency = new Map<string, string[]>();
      for (const [nodeId, _] of sample.cpg.nodes) {
        adjacency.set(nodeId, []);
      }
      for (const [_, edge] of sample.cpg.edges) {
        adjacency.get(edge.source)?.push(edge.target);
      }
      
      // Compute graph embedding
      const graphEmbed = graphEmbedding(adjacency, 64);
      const embedVec = Array.from(graphEmbed.values())[0] || new Array(64).fill(0);
      sample.graphEmbedding = embedVec;
    } catch (e) {
      sample.graphEmbedding = new Array(64).fill(0);
    }
  }
  
  return allSamples;
}

// Save training state
export function saveTrainingState(samples: TrainingSample[], round: number): void {
  const dir = join(TRAIN_DIR, `round_${round}`);
  
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  
  const serialized = samples.map(s => ({
    id: s.id,
    filePath: s.filePath,
    language: s.language,
    label: s.label,
    features: s.features
  }));
  
  writeFileSync(join(dir, 'samples.json'), JSON.stringify(serialized));
  console.log(`[Pipeline] Saved ${samples.length} samples for round ${round}`);
}

// Load training state
export function loadTrainingState(round: number): TrainingSample[] | null {
  const path = join(TRAIN_DIR, `round_${round}`, 'samples.json');
  
  if (!existsSync(path)) return null;
  
  try {
    const data = JSON.parse(readFileSync(path, 'utf-8'));
    return data.map((s: any) => ({
      ...s,
      code: '',
      cpg: { nodes: new Map(), edges: new Map(), metadata: {} }
    }));
  } catch {
    return null;
  }
}

// Cross-validate on training data
export function crossValidate(samples: TrainingSample[], k: number = 5): {
  precision: number;
  recall: number;
  f1: number;
  accuracy: number;
} {
  if (samples.length < k) {
    return { precision: 0, recall: 0, f1: 0, accuracy: 0 };
  }
  
  const foldSize = Math.floor(samples.length / k);
  let tp = 0, fp = 0, tn = 0, fn = 0;
  
  for (let fold = 0; fold < k; fold++) {
    const testStart = fold * foldSize;
    const testEnd = testStart + foldSize;
    const testSamples = samples.slice(testStart, testEnd);
    const trainSamples = [...samples.slice(0, testStart), ...samples.slice(testEnd)];
    
    // Train simple classifier on train samples
    const trainFeatures = trainSamples.map(s => s.features);
    const trainLabels = trainSamples.map(s => s.label);
    
    // Simple nearest neighbor classifier
    for (const test of testSamples) {
      const distances = trainFeatures.map(f => 
        f.reduce((s, v, i) => s + (v - test.features[i]) ** 2, 0)
      );
      const minIdx = distances.indexOf(Math.min(...distances));
      const predicted = trainLabels[minIdx];
      
      if (predicted === 1 && test.label === 1) tp++;
      else if (predicted === 1 && test.label === 0) fp++;
      else if (predicted === 0 && test.label === 0) tn++;
      else if (predicted === 0 && test.label === 1) fn++;
    }
  }
  
  const precision = tp / Math.max(tp + fp, 1);
  const recall = tp / Math.max(tp + fn, 1);
  const f1 = 2 * precision * recall / Math.max(precision + recall, 0.001);
  const accuracy = (tp + tn) / samples.length;
  
  return { precision, recall, f1, accuracy };
}
