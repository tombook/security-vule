import type ParserType from 'tree-sitter';
import type { SyntaxNode, Tree } from 'tree-sitter';

export type Language = 'python' | 'javascript' | 'typescript' | 'java' | 'c' | 'go' | 'rust' | 'php';

export interface ASTNode {
  id: string;
  type: string;
  code?: string;
  lineNumber?: number;
  endLineNumber?: number;
  column?: number;
  children?: ASTNode[];
  properties?: Map<string, unknown>;
}

export interface ParseResult {
  ast: ASTNode;
  language: Language;
  errors: string[];
}

export function detectLanguage(filename: string): Language {
  const ext = filename.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'py': return 'python';
    case 'js': case 'jsx': case 'ts': case 'tsx': case 'mjs': case 'cjs': return 'javascript';
    case 'php': case 'phtml': case 'php5': case 'php7': return 'php';
    case 'java': return 'java';
    case 'c': case 'h': case 'cpp': case 'hpp': case 'cc': case 'cxx': return 'c';
    case 'go': return 'go';
    default: return 'javascript';
  }
}

let nodeCounter = 0;
function generateId(): string { return `n${++nodeCounter}`; }

function createNode(type: string, code?: string, lineNumber?: number, endLineNumber?: number, column?: number): ASTNode {
  return { id: generateId(), type, code, lineNumber, endLineNumber, column, children: [], properties: new Map() };
}

function addChild(parent: ASTNode, child: ASTNode): void {
  if (!parent.children) parent.children = [];
  parent.children.push(child);
}

// ─── Tree-sitter lazy loading ───

let _Parser: typeof ParserType | null = null;
let _treeSitterGrammars: Record<string, unknown> = {};

function loadTreeSitter(): typeof ParserType | null {
  if (_Parser) return _Parser;
  try {
    _Parser = require('tree-sitter') as typeof ParserType;
    const phpGrammar = require('tree-sitter-php');
    _treeSitterGrammars = {
      python: require('tree-sitter-python'),
      java: require('tree-sitter-java'),
      c: require('tree-sitter-c'),
      go: require('tree-sitter-go'),
      php: phpGrammar.php ?? phpGrammar,
    };
    return _Parser;
  } catch {
    return null;
  }
}

function getGrammar(lang: 'python' | 'java' | 'c' | 'go' | 'php'): unknown {
  return _treeSitterGrammars[lang];
}

/** Node types to skip when building the AST (punctuation, delimiters) */
const SKIP_TYPES = new Set([
  ',', ';', '(', ')', '{', '}', '[', ']', ':', '.', '@', '->', '=>',
  '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>=',
  'comment', 'line_comment', 'block_comment', 'string_start', 'string_end',
]);

/** Properties to extract from tree-sitter named children */
function extractNodeProperties(tsNode: SyntaxNode): Map<string, unknown> {
  const props = new Map<string, unknown>();

  const nameChild = tsNode.childForFieldName('name');
  if (nameChild) props.set('name', nameChild.text);

  const kindChild = tsNode.childForFieldName('kind');
  if (kindChild) props.set('kind', kindChild.text);

  const paramsChild = tsNode.childForFieldName('parameters');
  if (paramsChild) props.set('params', paramsChild.text);

  const receiverChild = tsNode.childForFieldName('receiver');
  if (receiverChild) props.set('receiver', receiverChild.text);

  const returnTypeChild = tsNode.childForFieldName('return_type');
  if (returnTypeChild) props.set('returnType', returnTypeChild.text);

  const superclassList = tsNode.childForFieldName('superclass');
  if (superclassList) props.set('superclass', superclassList.text);

  const bodyChild = tsNode.childForFieldName('body');
  if (bodyChild) props.set('bodyLength', bodyChild.text.length);

  const valueChild = tsNode.childForFieldName('value');
  if (valueChild) props.set('value', valueChild.text.substring(0, 100));

  const typeChild = tsNode.childForFieldName('type');
  if (typeChild) props.set('declaredType', typeChild.text);

  const moduleChild = tsNode.childForFieldName('module') || tsNode.childForFieldName('source') || tsNode.childForFieldName('path');
  if (moduleChild) props.set('module', moduleChild.text);

  // C/Java: dig through declarator chain to find function/variable name
  if (!props.has('name') && tsNode.type === 'function_definition') {
    const declarator = tsNode.childForFieldName('declarator');
    if (declarator) {
      const funcDecl = findDeepestIdentifier(declarator);
      if (funcDecl) props.set('name', funcDecl.text);
      const paramList = declarator.childForFieldName('parameters');
      if (paramList) props.set('params', paramList.text);
    }
  }

  return props;
}

/** Walk through pointer_declarator/function_declarator chain to find the identifier */
function findDeepestIdentifier(node: SyntaxNode): SyntaxNode | null {
  if (node.type === 'identifier' || node.type === 'field_identifier') return node;
  const declarator = node.childForFieldName('declarator');
  if (declarator) return findDeepestIdentifier(declarator);
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child && (child.type.endsWith('_declarator') || child.type === 'identifier' || child.type === 'field_identifier')) {
      return findDeepestIdentifier(child);
    }
  }
  return null;
}

/** Convert a tree-sitter SyntaxNode to our ASTNode format */
function treeSitterToCustomAST(tsNode: SyntaxNode, sourceCode: string, depth = 0): ASTNode {
  const text = tsNode.text.length > 200 ? tsNode.text.substring(0, 200) + '...' : tsNode.text;
  const node = createNode(
    tsNode.type,
    text,
    tsNode.startPosition.row + 1,
    tsNode.endPosition.row + 1,
    tsNode.startPosition.column,
  );

  // Extract semantic properties
  const props = extractNodeProperties(tsNode);
  for (const [k, v] of props) {
    node.properties?.set(k, v);
  }

  // Mark error nodes
  if (tsNode.hasError) {
    node.properties?.set('_hasError', true);
  }

  // Recursively convert named children (skip punctuation)
  if (depth < 20) {
    for (let i = 0; i < tsNode.namedChildCount; i++) {
      const child = tsNode.namedChild(i);
      if (child && !SKIP_TYPES.has(child.type)) {
        addChild(node, treeSitterToCustomAST(child, sourceCode, depth + 1));
      }
    }
  }

  return node;
}

/** Root type mapping for each tree-sitter language */
const TS_ROOT_TYPES: Record<string, string> = {
  python: 'Module',
  java: 'CompilationUnit',
  c: 'TranslationUnit',
  go: 'File',
  php: 'Program',
};

/** Parse source code with tree-sitter, falling back to regex on failure */
function parseWithTreeSitter(
  code: string,
  lang: 'python' | 'java' | 'c' | 'go' | 'php',
  fallback: (code: string) => ParseResult,
): ParseResult {
  const Parser = loadTreeSitter();
  if (!Parser) return fallback(code);

  try {
    const grammar = getGrammar(lang);
    if (!grammar) return fallback(code);

    const parser = new Parser();
    parser.setLanguage(grammar as Parameters<typeof parser.setLanguage>[0]);
    const tree: Tree = parser.parse(code);
    if (!tree) return fallback(code);

    const root = tree.rootNode;
    const ast = treeSitterToCustomAST(root, code);

    // Override root type to match our convention
    ast.type = TS_ROOT_TYPES[lang] || root.type;

    const errors: string[] = [];
    if (root.hasError) {
      // Collect error node messages
      const collectErrors = (n: SyntaxNode): void => {
        if (n.type === 'ERROR') {
          errors.push(`Syntax error at line ${n.startPosition.row + 1}:${n.startPosition.column}`);
        }
        for (let i = 0; i < n.childCount; i++) {
          const child = n.child(i);
          if (child) collectErrors(child);
        }
      };
      collectErrors(root);
    }

    return { ast, language: lang, errors };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const result = fallback(code);
    result.errors.push(`Tree-sitter parse failed: ${msg}`);
    return result;
  }
}

// ─── JS/TS: Real AST via @typescript-eslint/parser ───

function estreeToCustomAST(estreeNode: Record<string, unknown>, code: string, depth = 0): ASTNode {
  const type = String(estreeNode.type || 'Unknown');
  const loc = estreeNode.loc as { start: { line: number; column: number }; end: { line: number; column: number } } | undefined;
  const range = estreeNode.range as [number, number] | undefined;

  const node = createNode(
    type,
    range ? code.slice(range[0], range[1]) : undefined,
    loc?.start?.line,
    loc?.end?.line,
    loc?.start?.column,
  );

  const skipKeys = new Set(['type', 'loc', 'range', 'parent', 'tokens', 'comments']);
  const interestingKeys = ['name', 'value', 'raw', 'operator', 'kind', 'async', 'generator', 'id', 'declarations', 'init', 'test', 'consequent', 'alternate', 'body', 'params', 'arguments', 'left', 'right', 'object', 'property', 'callee', 'elements', 'properties', 'key', 'computed', 'static', 'method', 'shorthand', 'superClass', 'directive', 'source', 'specifiers', 'imported', 'local', 'exported'];

  for (const key of interestingKeys) {
    const val = estreeNode[key];
    if (val === undefined || val === null) continue;

    if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') {
      node.properties?.set(key, val);
    } else if (typeof val === 'object' && !Array.isArray(val) && val !== null && 'name' in (val as Record<string, unknown>)) {
      node.properties?.set(key, (val as Record<string, unknown>).name);
    }
  }

  if (depth < 12) {
    const childKeys = ['body', 'declarations', 'consequent', 'alternate', 'cases', 'block', 'handler', 'finalizer', 'test', 'update', 'init'];
    for (const key of childKeys) {
      const val = estreeNode[key];
      if (Array.isArray(val)) {
        for (const child of val) {
          if (child && typeof child === 'object' && 'type' in (child as Record<string, unknown>)) {
            addChild(node, estreeToCustomAST(child as Record<string, unknown>, code, depth + 1));
          }
        }
      } else if (val && typeof val === 'object' && 'type' in (val as Record<string, unknown>)) {
        addChild(node, estreeToCustomAST(val as Record<string, unknown>, code, depth + 1));
      }
    }

    const pairKeys = ['left', 'right', 'argument', 'discriminant', 'object', 'property', 'callee', 'key', 'value', 'expression', 'test'];
    for (const key of pairKeys) {
      const val = estreeNode[key];
      if (val && typeof val === 'object' && !Array.isArray(val) && 'type' in (val as Record<string, unknown>)) {
        const childNode = estreeToCustomAST(val as Record<string, unknown>, code, depth + 1);
        childNode.properties?.set('_role', key);
        addChild(node, childNode);
      }
    }

    const arrayKeys = ['params', 'arguments', 'elements', 'properties', 'specifiers', 'guardedHandlers'];
    for (const key of arrayKeys) {
      const val = estreeNode[key];
      if (Array.isArray(val)) {
        for (const child of val) {
          if (child && typeof child === 'object' && 'type' in (child as Record<string, unknown>)) {
            const childNode = estreeToCustomAST(child as Record<string, unknown>, code, depth + 1);
            childNode.properties?.set('_role', key.replace(/s$/, ''));
            addChild(node, childNode);
          }
        }
      }
    }
  }

  return node;
}

function parseWithTypescriptESLint(code: string): ASTNode {
  let parserModule: typeof import('@typescript-eslint/parser') | null = null;
  try {
    parserModule = require('@typescript-eslint/parser');
  } catch { /* parser not available */ }

  if (!parserModule) return parseJavaScriptFallback(code);

  try {
    const ast = parserModule.parse(code, {
      sourceType: 'module',
      loc: true,
      range: true,
      comment: true,
      ecmaVersion: 'latest' as const,
      ecmaFeatures: { jsx: true },
    });
    return estreeToCustomAST(ast as unknown as Record<string, unknown>, code);
  } catch (e: unknown) {
    const err = e as { message?: string };
    try {
      const ast = parserModule.parse(code, {
        sourceType: 'script',
        loc: true,
        range: true,
        ecmaVersion: 'latest' as const,
      });
      return estreeToCustomAST(ast as unknown as Record<string, unknown>, code);
    } catch {
      return parseJavaScriptFallback(code, [err.message || 'Parse error']);
    }
  }
}

export function parseJavaScript(code: string): ParseResult {
  const errors: string[] = [];
  try {
    const ast = parseWithTypescriptESLint(code);
    return { ast, language: 'javascript', errors };
  } catch (e: unknown) {
    errors.push(`Parse error: ${e}`);
    return { ast: createNode('Program', code), language: 'javascript', errors };
  }
}

function parseJavaScriptFallback(code: string, _errors?: string[]): ASTNode {
  const root = createNode('Program', code);
  try {
    const ast = require('@typescript-eslint/parser').parse(code, { sourceType: 'module', loc: true, range: true });
    return estreeToCustomAST(ast, code);
  } catch {
    // intentionally empty — regex fallback below
  }
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const ln = i + 1;
    if (/^function\s+\w+/.test(line)) {
      const m = line.match(/function\s+(\w+)\s*\(([^)]*)\)/);
      const n = createNode('FunctionDeclaration', line, ln);
      if (m) { n.properties?.set('name', m[1]); n.properties?.set('params', m[2]); }
      addChild(root, n);
    } else if (/^(export\s+)?(const|let|var)\s+/.test(line)) {
      const m = line.match(/(const|let|var)\s+(\w+)/);
      const n = createNode('VariableDeclaration', line, ln);
      if (m) { n.properties?.set('kind', m[1]); n.properties?.set('name', m[2]); }
      addChild(root, n);
    } else if (/^class\s+/.test(line)) {
      const m = line.match(/class\s+(\w+)/);
      const n = createNode('ClassDeclaration', line, ln);
      if (m) n.properties?.set('name', m[1]);
      addChild(root, n);
    } else if (/^import\s/.test(line)) {
      addChild(root, createNode('ImportDeclaration', line, ln));
    } else if (/^export\s/.test(line)) {
      addChild(root, createNode('ExportNamedDeclaration', line, ln));
    } else if (/^if\s*\(/.test(line)) {
      addChild(root, createNode('IfStatement', line, ln));
    } else if (/^(for|while)\s*\(/.test(line)) {
      addChild(root, createNode('ForStatement', line, ln));
    } else if (/^return\b/.test(line)) {
      addChild(root, createNode('ReturnStatement', line, ln));
    } else if (line.startsWith('try')) {
      addChild(root, createNode('TryStatement', line, ln));
    } else if (line.startsWith('throw')) {
      addChild(root, createNode('ThrowStatement', line, ln));
    } else {
      addChild(root, createNode('ExpressionStatement', line, ln));
    }
  }
  return root;
}

// ─── Python: Improved regex parser ───

const PY_PATTERNS = [
  { re: /^(from\s+[\w.]+\s+)?import\s+/, type: 'Import' },
  { re: /^class\s+(\w+)/, type: 'ClassDef', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^async\s+def\s+(\w+)\s*\(([^)]*)\)/, type: 'AsyncFunctionDef', extract: (m: RegExpMatchArray) => ({ name: m[1], args: m[2] }) },
  { re: /^def\s+(\w+)\s*\(([^)]*)\)/, type: 'FunctionDef', extract: (m: RegExpMatchArray) => ({ name: m[1], args: m[2] }) },
  { re: /^@/, type: 'Decorator' },
  { re: /^if\s+/, type: 'If' },
  { re: /^elif\s+/, type: 'If' },
  { re: /^else\s*:/, type: 'If' },
  { re: /^for\s+/, type: 'For' },
  { re: /^while\s+/, type: 'While' },
  { re: /^try\s*:/, type: 'Try' },
  { re: /^except\b/, type: 'ExceptHandler' },
  { re: /^finally\s*:/, type: 'Try' },
  { re: /^with\s+/, type: 'With' },
  { re: /^return\b/, type: 'Return' },
  { re: /^yield\b/, type: 'Yield' },
  { re: /^raise\b/, type: 'Raise' },
  { re: /^(async\s+)?for\s+/, type: 'For' },
];

export function parsePython(code: string): ParseResult {
  return parseWithTreeSitter(code, 'python', parsePythonFallback);
}

function parsePythonFallback(code: string): ParseResult {
  const errors: string[] = [];
  const root = createNode('Module', code);
  const lines = code.split('\n');
  const scopeStack: ASTNode[] = [root];
  let prevIndent = 0;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const ln = i + 1;
    const indent = raw.search(/\S/);
    if (indent === -1) continue;

    // Dedent: pop scope stack
    while (scopeStack.length > 1 && indent <= prevIndent) {
      scopeStack.pop();
    }

    let matched = false;
    for (const pat of PY_PATTERNS) {
      const m = line.match(pat.re);
      if (m) {
        const node = createNode(pat.type, line, ln);
        if (pat.extract) {
          const props = pat.extract(m);
          for (const [k, v] of Object.entries(props)) node.properties?.set(k, v);
        }
        addChild(scopeStack[scopeStack.length - 1], node);
        if (pat.type === 'FunctionDef' || pat.type === 'AsyncFunctionDef' || pat.type === 'ClassDef' || pat.type === 'For' || pat.type === 'While' || pat.type === 'If' || pat.type === 'Try' || pat.type === 'With') {
          scopeStack.push(node);
        }
        matched = true;
        break;
      }
    }
    if (!matched) {
      addChild(scopeStack[scopeStack.length - 1], createNode('Expr', line, ln));
    }
    prevIndent = indent;
  }
  return { ast: root, language: 'python', errors };
}

// ─── Java: Improved regex parser ───

const JAVA_PATTERNS = [
  { re: /^package\s+([\w.]+)\s*;/, type: 'PackageDeclaration', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^import\s+(?:static\s+)?([\w.*]+)\s*;/, type: 'ImportDeclaration', extract: (m: RegExpMatchArray) => ({ path: m[1] }) },
  { re: /^(?:public|protected|private)?\s*(?:abstract\s+)?(?:final\s+)?(?:class|interface|enum)\s+(\w+)/, type: 'ClassDeclaration', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^@\w+/, type: 'Annotation' },
  { re: /^(?:public|protected|private)?\s*(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?(?:[\w<>\[\]]+\s+)+(\w+)\s*\(([^)]*)\)/, type: 'MethodDeclaration', extract: (m: RegExpMatchArray) => ({ name: m[1], params: m[2] }) },
  { re: /^if\s*\(/, type: 'IfStatement' },
  { re: /^for\s*\(/, type: 'ForStatement' },
  { re: /^while\s*\(/, type: 'WhileStatement' },
  { re: /^switch\s*\(/, type: 'SwitchStatement' },
  { re: /^try\s*\{?/, type: 'TryStatement' },
  { re: /^catch\s*\(/, type: 'CatchClause' },
  { re: /^return\b/, type: 'ReturnStatement' },
  { re: /^throw\b/, type: 'ThrowStatement' },
];

export function parseJava(code: string): ParseResult {
  return parseWithTreeSitter(code, 'java', parseJavaFallback);
}

function parseJavaFallback(code: string): ParseResult {
  const errors: string[] = [];
  const root = createNode('CompilationUnit', code);
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('//') || line.startsWith('/*') || line.startsWith('*')) continue;
    const ln = i + 1;

    let matched = false;
    for (const pat of JAVA_PATTERNS) {
      const m = line.match(pat.re);
      if (m) {
        const node = createNode(pat.type, line, ln);
        if (pat.extract) {
          const props = pat.extract(m);
          for (const [k, v] of Object.entries(props)) node.properties?.set(k, v);
        }
        addChild(root, node);
        matched = true;
        break;
      }
    }
    if (!matched) {
      addChild(root, createNode('Statement', line, ln));
    }
  }
  return { ast: root, language: 'java', errors };
}

// ─── C/C++: Improved regex parser ───

const C_PATTERNS = [
  { re: /^#include\s*[<"]([^>"]+)[>"]/, type: 'IncludeDirective', extract: (m: RegExpMatchArray) => ({ path: m[1] }) },
  { re: /^#define\s+(\w+)/, type: 'MacroDefinition', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^#ifdef\s+(\w+)/, type: 'IfdefDirective', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^#ifndef\s+(\w+)/, type: 'IfndefDirective', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^typedef\s+/, type: 'TypedefDeclaration' },
  { re: /^(?:typedef\s+)?struct\s+(\w+)/, type: 'StructDeclaration', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^(?:typedef\s+)?enum\s+(\w+)/, type: 'EnumDeclaration', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^(?:typedef\s+)?union\s+(\w+)/, type: 'UnionDeclaration', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^(?:(?:static|extern|inline|const|unsigned|signed|volatile)\s+)*(?:int|char|void|long|short|float|double|size_t|ssize_t|bool|FILE)\s*\**\s*(\w+)\s*\(([^)]*)\)/, type: 'FunctionDefinition', extract: (m: RegExpMatchArray) => ({ name: m[1], params: m[2] }) },
  { re: /^if\s*\(/, type: 'IfStatement' },
  { re: /^for\s*\(/, type: 'ForStatement' },
  { re: /^while\s*\(/, type: 'WhileStatement' },
  { re: /^switch\s*\(/, type: 'SwitchStatement' },
  { re: /^return\b/, type: 'ReturnStatement' },
  { re: /^goto\b/, type: 'GotoStatement' },
];

export function parseC(code: string): ParseResult {
  return parseWithTreeSitter(code, 'c', parseCFallback);
}

function parseCFallback(code: string): ParseResult {
  const errors: string[] = [];
  const root = createNode('TranslationUnit', code);
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('//') || line.startsWith('/*')) continue;
    const ln = i + 1;

    let matched = false;
    for (const pat of C_PATTERNS) {
      const m = line.match(pat.re);
      if (m) {
        const node = createNode(pat.type, line, ln);
        if (pat.extract) {
          const props = pat.extract(m);
          for (const [k, v] of Object.entries(props)) node.properties?.set(k, v);
        }
        addChild(root, node);
        matched = true;
        break;
      }
    }
    if (!matched) {
      addChild(root, createNode('Statement', line, ln));
    }
  }
  return { ast: root, language: 'c', errors };
}

// ─── Go: Improved regex parser ───

const GO_PATTERNS = [
  { re: /^package\s+(\w+)/, type: 'PackageClause', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^import\s*\(/, type: 'ImportDecl' },
  { re: /^import\s+"([^"]+)"/, type: 'ImportSpec', extract: (m: RegExpMatchArray) => ({ path: m[1] }) },
  { re: /^func\s+(?:\(\s*(\w+)\s+\*?(\w+)\s*\)\s+)?(\w+)\s*\(([^)]*)\)/, type: 'FuncDecl', extract: (m: RegExpMatchArray) => ({ receiver_name: m[1], receiver_type: m[2], name: m[3], params: m[4] }) },
  { re: /^type\s+(\w+)\s+struct/, type: 'TypeSpec', extract: (m: RegExpMatchArray) => ({ name: m[1], kind: 'struct' }) },
  { re: /^type\s+(\w+)\s+interface/, type: 'TypeSpec', extract: (m: RegExpMatchArray) => ({ name: m[1], kind: 'interface' }) },
  { re: /^type\s+(\w+)/, type: 'TypeSpec', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^var\s+(\w+)/, type: 'VarDecl', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^const\s+(\w+)/, type: 'ConstDecl', extract: (m: RegExpMatchArray) => ({ name: m[1] }) },
  { re: /^if\s+/, type: 'IfStmt' },
  { re: /^for\s+/, type: 'ForStmt' },
  { re: /^switch\s+/, type: 'SwitchStmt' },
  { re: /^case\s+/, type: 'CaseClause' },
  { re: /^return\b/, type: 'ReturnStmt' },
  { re: /^defer\s+/, type: 'DeferStmt' },
  { re: /^go\s+/, type: 'GoStmt' },
  { re: /^interface\s*\{/, type: 'InterfaceType' },
];

export function parseGo(code: string): ParseResult {
  return parseWithTreeSitter(code, 'go', parseGoFallback);
}

export function parsePhp(code: string): ParseResult {
  return parseWithTreeSitter(code, 'php', parsePhpFallback);
}

function parsePhpFallback(code: string): ParseResult {
  const errors: string[] = [];
  const root = createNode('Program', code, 1, code.split('\n').length);
  return { ast: root, language: 'php', errors };
}

function parseGoFallback(code: string): ParseResult {
  const errors: string[] = [];
  const root = createNode('File', code);
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('//')) continue;
    const ln = i + 1;

    let matched = false;
    for (const pat of GO_PATTERNS) {
      const m = line.match(pat.re);
      if (m) {
        const node = createNode(pat.type, line, ln);
        if (pat.extract) {
          const props = pat.extract(m);
          for (const [k, v] of Object.entries(props)) node.properties?.set(k, v);
        }
        addChild(root, node);
        matched = true;
        break;
      }
    }
    if (!matched) {
      addChild(root, createNode('Statement', line, ln));
    }
  }
  return { ast: root, language: 'go', errors };
}

// ─── Dispatch ───

export function parse(code: string, language: Language): ParseResult {
  nodeCounter = 0;
  switch (language) {
    case 'python': return parsePython(code);
    case 'javascript': return parseJavaScript(code);
    case 'php': return parsePhp(code);
    case 'java': return parseJava(code);
    case 'c': return parseC(code);
    case 'go': return parseGo(code);
    default: return parseJavaScript(code);
  }
}

export function astToJSON(node: ASTNode): string {
  return JSON.stringify(node, (key, value) => {
    if (value instanceof Map) return Object.fromEntries(value);
    return value;
  }, 2);
}

export function findNodesByType(node: ASTNode, type: string): ASTNode[] {
  const results: ASTNode[] = [];
  function traverse(n: ASTNode): void {
    if (n.type === type) results.push(n);
    n.children?.forEach(traverse);
  }
  traverse(node);
  return results;
}

export function findNodesByProperty(node: ASTNode, key: string, value: unknown): ASTNode[] {
  const results: ASTNode[] = [];
  function traverse(n: ASTNode): void {
    if (n.properties?.get(key) === value) results.push(n);
    n.children?.forEach(traverse);
  }
  traverse(node);
  return results;
}
