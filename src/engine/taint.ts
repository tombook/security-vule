import type { ASTNode } from './parser.js';
import { findNodesByType } from './parser.js';

export interface TaintSource {
  id: string;
  type: 'user_input' | 'file_io' | 'network' | 'env' | 'db' | 'cookie' | 'header';
  name: string;
  line: number;
  scope: string;
  variable?: string;
}

export interface TaintSink {
  id: string;
  type: 'sql' | 'shell' | 'file_write' | 'network_send' | 'eval' | 'dynamic_code' | 'deserialization' | 'nosql' | 'ssrf' | 'xss' | 'crypto' | 'hash' | 'weakrand' | 'ldap' | 'xpath' | 'xxe' | 'trustbound' | 'trust_bound' | 'securecookie' | 'secure_cookie' | 'filewrite' | 'ldapi' | 'xpathi' | 'file_include';
  name: string;
  line: number;
  scope: string;
  variable?: string;
}

export interface Sanitizer {
  id: string;
  type: 'encoding' | 'validation' | 'escaping' | 'normalization' | 'sanitization' | 'type_cast';
  name: string;
  line: number;
  scope: string;
  appliesTo?: string;
}

export interface TaintPath {
  source: TaintSource;
  sink: TaintSink;
  path: string[];
  confidence: number;
  sanitizers: Sanitizer[];
}

export interface TaintResult {
  isTainted: boolean;
  sources: TaintSource[];
  sinks: TaintSink[];
  paths: TaintPath[];
  confidence: number;
}

interface TaintedVariable {
  name: string;
  sourceIds: string[];
  sanitized: boolean;
  sanitizerIds: string[];
  line: number;
}

interface ScopeInfo {
  name: string;
  startLine: number;
  endLine?: number;
  taintedVars: Map<string, TaintedVariable>;
}

const SOURCE_PATTERNS: Record<string, RegExp[]> = {
  user_input: [/\bread\s*\(/gi, /\binput\s*\(/gi, /\bget\s*\(['"](?:user|request|body|data|query|param|params|form)['"]\s*\)/gi, /\$\_(?:GET|POST|REQUEST|COOKIE|FILES)\b/gi, /request\.body/gi, /request\.query/gi, /request\.params/gi, /req\.body/gi, /req\.query/gi, /req\.params/gi, /ctx\.request\.body/gi, /request\.getParameter\s*\(/gi, /request\.getHeader\s*\(/gi, /servletRequest\.getParameter/gi, /HttpServletRequest/gi],
  file_io: [/\breadFile\s*\(/gi, /\breadFileSync\s*\(/gi, /fopen\s*\(/gi, /fread\s*\(/gi, /stdin/gi, /fs\.read/gi],
  network: [/http\.get\s*\(/gi, /http\.post\s*\(/gi, /\bfetch\s*\(/gi, /axios\./gi, /requests?\s*\./gi, /\.text\(\s*\)/gi, /\.json\(\s*\)/gi, /URLConnection/gi, /HttpURLConnection/gi, /request\.getRequestURL\s*\(\s*\)/gi, /request\.getRequestURI\s*\(\s*\)/gi],
  env: [/process\.env/gi, /os\.environ/gi, /getenv\s*\(/gi, /System\.getenv/gi],
  db: [/\.query\s*\(/gi, /\.execute\s*\(/gi, /executeQuery\s*\(/gi, /\.find\s*\(\s*\{/gi, /\.findOne\s*\(/gi],
  cookie: [/document\.cookie/gi, /req\.cookies/gi, /\$_COOKIE/gi],
  header: [/request\.headers/gi, /req\.headers/gi, /req\.get\s*\(/gi, /\$_SERVER\s*\[/gi],
  redirect: [/req\.query\.url/gi, /request\.getParameter\s*\(\s*['"]url/gi, /res\.redirect\s*\(/gi],
  mongo_query: [/\.find\s*\(\s*\{/gi, /\.findOne\s*\(\s*\{/gi, /\.update\s*\(\s*\{/gi, /\.remove\s*\(\s*\{/gi, /db\.collection\s*\(/gi],
};

const SINK_PATTERNS: Record<string, RegExp[]> = {
  sql: [/\.query\s*\(\s*["'][^"]*["']\s*[\.+]/gi, /executeQuery\s*\(/gi, /\.executeQuery\s*\(/gi, /\.execute\s*\(\s*["'][^"]*["']\s*[\.+]/gi, /\.raw\s*\(/gi, /Statement\s*\.\s*execute(?:Update|Query)?\s*\(/gi, /PreparedStatement\s*\.\s*execute(?:Update|Query)?\s*\(\s*[^,)]*[\.+]/gi, /conn\.createStatement\s*\(\s*\)/gi, /connection\.prepareCall\s*\(/gi, /connection\.prepareStatement\s*\(\s*[^,)]*[\.+]/gi, /CallableStatement\s*=/gi, /\bsql\s*\+=/gi, /\$where\s*:/gi, /\{\s*call\s+/gi, /\bsql\s*=\s*["'][^"]*["']\s*[\.+]/gi, /queryForObject\s*\(/gi, /queryForLong\s*\(/gi, /queryForList\s*\(/gi, /queryForMap\s*\(/gi, /queryForRowSet\s*\(/gi, /query\s*\(\s*[^,)]*[\.+]/gi, /JDBCtemplate\./gi, /jdbcTemplate\./gi, /hibernate\.createQuery\s*\(/gi, /createQuery\s*\(/gi, /createNativeQuery\s*\(/gi, /\bdb\.\w*\.execute\s*\(\s*["'][^"]*["']\s*[\.+]/gi, /\bdb\.\w*\.query\s*\(\s*["'][^"]*["']\s*[\.+]/gi, /mysqli_query\s*\(/gi, /mysql_query\s*\(/gi, /\$db->query\s*\(/gi, /\$pdo->query\s*\(/gi, /\$pdo->prepare\s*\(/gi, /\$pdo->exec\s*\(/gi, /\$this->db->query\s*\(/gi, /\$this->db->prepare\s*\(/gi, /pg_query\s*\(/gi, /\$stmt->execute\s*\(/gi, /\$pdo->exec\s*\(/gi],
  nosql: [/\.find\s*\(\s*\{[^}]*\$where/gi, /\.find\s*\(\s*req\.body/gi, /\.find\s*\(\s*req\.query/gi, /\$where\s*:/gi, /\{\s*\$where/gi, /Collection\s*\.find\s*\(\s*request/gi, /Collection\s*\.insert\s*\(/gi, /\.insert\s*\(\s*req\.body/gi, /\.insert\s*\(\s*req\.params/gi, /\.insert\s*\(\s*req\.query/gi, /\.update\s*\(\s*req\.body/gi, /\.remove\s*\(\s*req\.body/gi, /\.save\s*\(\s*req\.body/gi, /\.save\s*\(\s*req\.params/gi, /\.save\s*\(\s*req\.query/gi, /\bdb\.\w+\.insert\s*\(\s*req\./gi, /\bdao\.\w+\.insert\s*\(\s*req\./gi, /\bdao\.\w+\.update\s*\(\s*req\./gi, /\bdao\.\w+\.find\s*\(\s*req\./gi, /\bdao\.\w+\.save\s*\(\s*req\./gi],
  shell: [/\bexec\s*\(\s*[^"'`)]*\+/gi, /execSync\s*\(\s*[^"'`)]*\+/gi, /Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(/gi, /Runtime\.exec\s*\(/gi, /ProcessBuilder\s*\(/gi, /\bspawn\s*\(\s*[^)]*\+/gi, /\bsystem\s*\(\s*[^"'`)]*\+/gi, /os\s*\.\s*system\s*\(\s*[^)]*\+/gi, /shell_exec\s*\(/gi, /popen\s*\(/gi, /subprocess\.[a-zA-Z]+\s*\(\s*[^,)]*\+/gi, /\.command\s*\(\s*[^)]*\+/gi, /ProcessBuilder\(\s*\)\s*\.command\s*\(/gi, /pb\.command\s*\(/gi],
  file_write: [/\bwriteFile\s*\(/gi, /writeFileSync\s*\(/gi, /appendFile\s*\(/gi, /fwrite\s*\(/gi, /fs\.write/gi, /new\s+FileWriter\s*\(/gi, /FileOutputStream\s*\(/gi, /Files\.write\s*\(/gi, /new\s+FileInputStream\s*\(\s*new\s+java\.io\.File\s*\(/gi, /new\s+File\s*\(\s*[^)]*[\.+]/gi, /Paths\.get\s*\(\s*[^)]*[\.+]/gi, /FileInputStream\s*\(/gi, /getResourceAsStream\s*\(/gi, /File\s*\.\s*createTempFile\s*\(/gi, /new\s+java\.io\.File\s*\(\s*[^)]*[\.+]/gi, /TESTFILES_DIR\s*\+/gi, /move_uploaded_file\s*\(/gi, /copy\s*\(\s*\$\w+/gi, /rename\s*\(\s*\$\w+/gi, /\$target_path\s*\.\s*=\s*["'][^"']*["']\s*\.[\.\s]+\$/gi],
  network_send: [/http\.post\s*\(/gi, /http\.put\s*\(/gi, /http\.request\s*\(/gi, /\bfetch\s*\(\s*[^,)]*\+/gi, /requests?\.post\s*\(/gi, /requests?\.put\s*\(/gi, /HttpClient\.newHttpClient\s*\(/gi, /HttpRequest\.newBuilder\s*\(/gi],
  ssrf: [/\bfetch\s*\(\s*[^,)]*\+/gi, /axios\s*\(\s*[^,)]*\+/gi, /requests?\.[a-zA-Z]+\s*\(\s*[^,)]*\+/gi, /http\.get\s*\(\s*[^,)]*\+/gi, /res\.redirect\s*\(/gi, /response\.sendRedirect\s*\(/gi, /HttpClient\.send\s*\(/gi, /URL\s*\.\s*openConnection\s*\(/gi, /openConnection\s*\(\s*\)/gi, /ImageIO\.read\s*\(\s*new\s+URL/gi, /needle\s*\.\s*get\s*\(/gi, /needle\s*\.\s*post\s*\(/gi, /axios\s*\.\s*get\s*\(/gi, /axios\s*\.\s*post\s*\(/gi, /\bsuperagent\s*\(\s*/gi, /\bsuperagent\s*\.\s*get\s*\(/gi],
  xss: [/res\.send\s*\(\s*[^,)]*[\.+]/gi, /innerHTML\s*=/gi, /document\.write\s*\(/gi, /outerHTML\s*=/gi, /\$\{[^}]*\}/gi, /\{\{\{[^}]+\}\}\}/gi, /v-html\s*=/gi, /\[innerHTML\]\s*=/gi, /\$\(?\s*\{/gi, /dangerouslySetInnerHTML/gi, /\$\{[^}]*req\./gi, /response\.getWriter\s*\(\s*\)\s*\.format\s*\(\s*[^,)]*[\.+]/gi, /getWriter\s*\(\s*\)\s*\.print\s*\(\s*[^)]*[\.+]/gi, /getWriter\s*\(\s*\)\s*\.println\s*\(\s*[^)]*[\.+]/gi, /getWriter\s*\(\s*\)\s*\.write\s*\(\s*[^)]*[\.+]/gi, /response\.sendError\s*\(\s*[^,)]*[\.+]/gi, /render\s*\(\s*[^,)]*[\.+]/gi, /res\.render\s*\(\s*[^,)]*[\.+]/gi, /res\.write\s*\(\s*[^)]*[\.+]/gi, /PageContext\s*\.\s*pushBody/gi, /pageContext\.pushBody\s*\(/gi, /JspWriter\s*\.\s*print\s*\(/gi, /echo\s+\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/gi, /echo\s+\$\{?[^}]*\$\{?\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)/gi, /print\s+\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/gi, /<\?=\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /\$html\s*\.\s*=\s*['"][^'"]*['"]\s*\.[\.\s]+\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /\$html\s*\.\s*=\s*['"][^'"]*['"]\s*\.[\.\s]+\$\w+\[/gi, /header\s*\(\s*['"][^'"]*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /\$message\s*\.\s*=\s*['"][^'"]*['"]\s*\.[\.\s]+\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /\$output\s*\.\s*=\s*['"][^'"]*['"]\s*\.[\.\s]+\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /\$body\s*\.\s*=\s*['"][^'"]*['"]\s*\.[\.\s]+\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi],
  eval: [/\beval\s*\(/gi, /\bFunction\s*\(/gi, /new\s+Function\s*\(/gi, /setTimeout\s*\(\s*['"]/gi, /setInterval\s*\(\s*['"]/gi, /groovy\.utils\.Eval/gi, /groovy\.Eval/gi, /invoke\s*\(\s*null\s*,\s*request/gi, /\beval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /\bassert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /\bpreg_replace\s*\(\s*['"][^"']*\/e/gi, /\bcreate_function\s*\(/gi],
  dynamic_code: [/\bcompile\s*\(/gi, /py_compile\s*\(/gi, /exec\s*\(\s*['"]/gi, /Class\.forName\s*\(/gi, /ScriptEngine\.eval\s*\(/gi, /NashornScriptEngine/gi],
  deserialization: [/\bunserialize\s*\(/gi, /pickle\.loads\s*\(/gi, /yaml\.load\s*\(/gi, /yaml\.unsafe_load\s*\(/gi, /ObjectInputStream/gi, /readObject\s*\(/gi, /XMLDecoder\s*\(/gi, /XStream\s*\(/gi, /SnakeYAML\s*\(/gi],
  crypto: [/MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-?1|DES)['"]/gi, /Cipher\.getInstance\s*\(\s*['"]DES/gi, /KeyGenerator\.getInstance\s*\(\s*['"]DES/gi, /new\s+IvParameterSpec\s*\(/gi, /\bmd5\s*\(/gi, /\bsha1\s*\(/gi, /\bDES\s*\(/gi, /mcrypt_create_iv/gi, /\bhash\s*\(\s*['"](?:md5|sha1)/gi, /crypt\s*\(\s*['"](?:DES|md5)/gi, /openssl_encrypt\s*\(/gi, /openssl_decrypt\s*\(/gi, /openssl_sign\s*\(/gi, /openssl_verify\s*\(/gi, /\$hash\s*=\s*['"](?:md5|sha1)/gi, /\$_SERVER\s*\[\s*['"]HTTPS/gi, /mcrypt_module_open\s*\(/gi, /hash_hmac\s*\(\s*['"](?:md5|sha1)/gi, /xor_this\s*\(/gi, /\bxor\s*\(/gi],
  weak_random: [/Math\.random\s*\(\s*\)/gi, /new\s+Random\s*\(\s*\)/gi, /Random\s*\.next[A-Z]\w*\s*\(\s*\)/gi, /SecureRandom/gi],
  ldap: [/ldapTemplate\.search\s*\(/gi, /ldapTemplate\.authenticate\s*\(/gi, /DirContext\.search\s*\(/gi, /InitialDirContext\s*\(/gi, /\bldap_search\s*\(/gi, /ldap_simple_bind\s*\(/gi],
  xpath: [/xpath\.compile\s*\(/gi, /xpath\.evaluate\s*\(/gi, /XPathFactory\.newInstance\s*\(/gi, /DocumentBuilderFactory\.newInstance\s*\(/gi, /SAXParserFactory\.newInstance\s*\(/gi, /TransformerFactory\.newInstance\s*\(/gi, /XMLInputFactory\.newInstance\s*\(/gi, /SchemaFactory\.newInstance\s*\(/gi],
  xxe: [/DocumentBuilderFactory\.newInstance\s*\(/gi, /SAXParserFactory\.newInstance\s*\(/gi, /XMLInputFactory\.newInstance\s*\(/gi, /TransformerFactory\.newInstance\s*\(/gi, /SchemaFactory\.newInstance\s*\(/gi, /setFeature\s*\(\s*["']http:\/\/apache\.org\/xml\/features\/disallow-doctype-decl/gi],
  trustbound: [/\.setAttribute\s*\(/gi, /request\.setAttribute\s*\(/gi, /HttpSession\.setAttribute\s*\(/gi, /\bsession\.set\s*\(/gi, /\bjwt\.sign\s*\(/gi, /JWT\.create\s*\(/gi],
  secure_cookie: [/new\s+Cookie\s*\(/gi, /Set-Cookie/gi, /response\.addCookie\s*\(/gi],
  file_include: [/include\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /include_once\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /require\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /require_once\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /include\s*\(\s*\$\w+\s*\)/gi, /require\s*\(\s*\$\w+\s*\)/gi, /file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /fopen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /readfile\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /\$file\s*=\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /\$page\s*=\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /\$path\s*=\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /include\s*\(\s*['"][^"']*['"]\s*\.\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi, /\$this->include\s*\(/gi, /JLoader::import\s*\(/gi, /require_once\s*\(\s*['"][^"']*['"]\s*\.\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[/gi],
};

const SANITIZER_PATTERNS: Record<string, RegExp[]> = {
  encoding: [/htmlspecialchars\s*\(/gi, /htmlentities\s*\(/gi, /urlencode\s*\(/gi, /\bescape\s*\(/gi, /encodeURI\s*\(/gi, /encodeURIComponent\s*\(/gi, /DOMPurify\.sanitize\s*\(/gi],
  validation: [/\bvalidate\s*\(/gi, /isValid\s*\(/gi, /\bcheck\s*\(/gi, /sanitize\s*\(/gi, /joi\.validate\s*\(/gi, /z\.parse\s*\(/gi, /validator\.\w+\s*\(/gi],
  escaping: [/addslashes\s*\(/gi, /mysqli_escape_string\s*\(/gi, /mysqli_real_escape_string\s*\(/gi, /pg_escape_string\s*\(/gi, /mysql_real_escape_string\s*\(/gi],
  normalization: [/normalize\s*\(/gi, /\btrim\s*\(/gi, /toLowerCase\s*\(/gi, /toUpperCase\s*\(/gi, /strip_tags\s*\(/gi],
  sanitization: [/sanitiz\w+\s*\(/gi, /clean\s*\(/gi, /purify\s*\(/gi, /filter_var\s*\(/gi],
};

const ASSIGNMENT_PATTERN = /^(?:const|let|var|auto|int|char|void|string|String|long|short|byte|float|double|boolean|List<[^>]+>|Map<[^>]+>|final\s+\w+)\s+(\$?\w+)\s*=\s*(.+?);?\s*$/;
const JS_ASSIGNMENT = /^(?:const|let|var)\s+(\w+)\s*=\s*(.+?)$/;
const PHP_ASSIGNMENT = /^\s*(\$\w+)\s*=\s*(.+?)$/;

function getLineNumber(code: string, index: number): number {
  return code.substring(0, index).split('\n').length;
}

function extractVariableFromAssignment(line: string): { name: string; value: string } | null {
  const jsMatch = line.match(JS_ASSIGNMENT);
  if (jsMatch) return { name: jsMatch[1], value: jsMatch[2] };

  const phpMatch = line.match(PHP_ASSIGNMENT);
  if (phpMatch) return { name: phpMatch[1], value: phpMatch[2] };

  const genericMatch = line.match(ASSIGNMENT_PATTERN);
  if (genericMatch) return { name: genericMatch[1], value: genericMatch[2] };

  const plainAssign = line.match(/^(\$?\w+)\s*=\s*(.+?)$/);
  if (plainAssign && !['if', 'for', 'while', 'switch', 'return', 'else', 'function', 'class'].includes(plainAssign[1])) {
    return { name: plainAssign[1], value: plainAssign[2] };
  }
  return null;
}

function detectScopes(code: string): ScopeInfo[] {
  const scopes: ScopeInfo[] = [{ name: 'global', startLine: 1, taintedVars: new Map() }];
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const ln = i + 1;

    const funcMatch = line.match(/(?:async\s+)?function\s+(\w+)/)
      || line.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)/)
      || line.match(/def\s+(\w+)\s*\(/)
      || line.match(/(?:public|private|protected)?\s*(?:static\s+)?(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(/)
      || line.match(/func\s+(\w+)\s*\(/);
    if (funcMatch) {
      scopes.push({ name: funcMatch[1], startLine: ln, taintedVars: new Map() });
    }
  }
  return scopes;
}

function getScopeForLine(scopes: ScopeInfo[], line: number): ScopeInfo {
  let best = scopes[0];
  for (const scope of scopes) {
    if (scope.startLine <= line) best = scope;
  }
  return best;
}

export function detectSources(code: string, scope: string): TaintSource[] {
  const sources: TaintSource[] = [];
  let sourceId = 0;
  for (const [type, patterns] of Object.entries(SOURCE_PATTERNS)) {
    for (const pattern of patterns) {
      const matches = code.matchAll(pattern);
      for (const match of matches) {
        if (match.index !== undefined) {
          const line = getLineNumber(code, match.index);
          const lines = code.split('\n');
          const lineText = lines[line - 1]?.trim() || '';
          const assignment = extractVariableFromAssignment(lineText);
          sources.push({
            id: `source_${sourceId++}`,
            type: type as TaintSource['type'],
            name: match[0],
            line,
            scope,
            variable: assignment?.name,
          });
        }
      }
    }
  }
  return sources;
}

export function detectSinks(code: string, scope: string): TaintSink[] {
  const sinks: TaintSink[] = [];
  let sinkId = 0;
  for (const [type, patterns] of Object.entries(SINK_PATTERNS)) {
    for (const pattern of patterns) {
      const matches = code.matchAll(pattern);
      for (const match of matches) {
        if (match.index !== undefined) {
          const line = getLineNumber(code, match.index);
          sinks.push({
            id: `sink_${sinkId++}`,
            type: type as TaintSink['type'],
            name: match[0],
            line,
            scope,
          });
        }
      }
    }
  }
  return sinks;
}

export function detectSanitizers(code: string, scope: string): Sanitizer[] {
  const sanitizers: Sanitizer[] = [];
  let sanId = 0;
  for (const [type, patterns] of Object.entries(SANITIZER_PATTERNS)) {
    for (const pattern of patterns) {
      const matches = code.matchAll(pattern);
      for (const match of matches) {
        if (match.index !== undefined) {
          const line = getLineNumber(code, match.index);
          const lines = code.split('\n');
          const lineText = lines[line - 1]?.trim() || '';
          const assignment = extractVariableFromAssignment(lineText);
          sanitizers.push({
            id: `san_${sanId++}`,
            type: type as Sanitizer['type'],
            name: match[0],
            line,
            scope,
            appliesTo: assignment?.name,
          });
        }
      }
    }
  }
  return sanitizers;
}

// ─── AST-enhanced detection ───

const AST_CALL_SOURCE_MAP: Record<string, TaintSource['type']> = {
  'input': 'user_input', 'read': 'user_input', 'readline': 'user_input',
  'gets': 'user_input', 'raw_input': 'user_input',
  'readFile': 'file_io', 'readFileSync': 'file_io', 'fopen': 'file_io', 'fread': 'file_io',
  'open': 'file_io', 'file_get_contents': 'file_io',
  'fetch': 'network', 'urlopen': 'network',
  'getenv': 'env',
};

const AST_CALL_SINK_MAP: Record<string, TaintSink['type']> = {
  'eval': 'eval', 'exec': 'shell', 'system': 'shell', 'popen': 'shell',
  'shell_exec': 'shell', 'subprocess_call': 'shell', 'subprocess_run': 'shell',
  'query': 'sql', 'execute': 'sql', 'raw': 'sql',
  'writeFile': 'file_write', 'writeFileSync': 'file_write', 'fwrite': 'file_write',
  'unserialize': 'deserialization', 'pickle_loads': 'deserialization',
};

const AST_SANITIZER_MAP: Record<string, Sanitizer['type']> = {
  'htmlspecialchars': 'encoding', 'htmlentities': 'encoding', 'urlencode': 'encoding',
  'encodeURI': 'encoding', 'encodeURIComponent': 'encoding', 'escape': 'encoding',
  'DOMPurify_sanitize': 'sanitization',
  'addslashes': 'escaping', 'mysqli_real_escape_string': 'escaping', 'pg_escape_string': 'escaping',
  'intval': 'type_cast', 'parseInt': 'type_cast', 'parseFloat': 'type_cast', 'Number': 'type_cast',
  'validate': 'validation', 'isValid': 'validation', 'sanitize': 'validation',
};

function collectAllCalls(ast: ASTNode): ASTNode[] {
  return [
    ...(findNodesByType(ast, 'call') as ASTNode[]),
    ...(findNodesByType(ast, 'function_call_expression') as ASTNode[]),
    ...(findNodesByType(ast, 'method_invocation') as ASTNode[]),
  ];
}

function classifyCallNode(callCode: string): { role: 'source' | 'sink' | 'sanitizer' | 'unknown'; type?: string } {
  const name = callCode.split('(')[0].split('.').pop() || callCode;
  if (AST_CALL_SOURCE_MAP[name]) return { role: 'source', type: AST_CALL_SOURCE_MAP[name] };
  if (AST_CALL_SINK_MAP[name]) return { role: 'sink', type: AST_CALL_SINK_MAP[name] };
  if (AST_SANITIZER_MAP[name]) return { role: 'sanitizer', type: AST_SANITIZER_MAP[name] };
  return { role: 'unknown' };
}

function detectSourcesFromAST(ast: ASTNode, scope: string): TaintSource[] {
  const sources: TaintSource[] = [];
  let sourceId = 0;
  const calls = collectAllCalls(ast);
  for (const call of calls) {
    const classification = classifyCallNode(call.code || '');

    if (classification.role === 'source' && classification.type) {
      sources.push({
        id: `ast_src_${sourceId++}`,
        type: classification.type as TaintSource['type'],
        name: call.code?.split('(')[0] || 'call',
        line: call.lineNumber || 0,
        scope,
        variable: call.properties?.get('_assignedTo') as string | undefined,
      });
    }
  }
  return sources;
}
function detectSinksFromAST(ast: ASTNode, scope: string): TaintSink[] {
  const sinks: TaintSink[] = [];
  let sinkId = 0;
  const calls = collectAllCalls(ast);
  for (const call of calls) {
    const classification = classifyCallNode(call.code || '');
    if (classification.role === 'sink' && classification.type) {
      sinks.push({
        id: `ast_sink_${sinkId++}`,
        type: classification.type as TaintSink['type'],
        name: call.code?.split('(')[0] || 'call',
        line: call.lineNumber || 0,
        scope,
      });
    }
  }
  return sinks;
}

function detectSanitizersFromAST(ast: ASTNode, scope: string): Sanitizer[] {
  const sanitizers: Sanitizer[] = [];
  let sanId = 0;
  const calls = collectAllCalls(ast);
  for (const call of calls) {
    const classification = classifyCallNode(call.code || '');
    if (classification.role === 'sanitizer' && classification.type) {
      sanitizers.push({
        id: `ast_san_${sanId++}`,
        type: classification.type as Sanitizer['type'],
        name: call.code?.split('(')[0] || 'call',
        line: call.lineNumber || 0,
        scope,
        appliesTo: call.properties?.get('_assignedTo') as string | undefined,
      });
    }
  }
  return sanitizers;
}

function extractAssignmentsFromAST(ast: ASTNode): Array<{ name: string; value: string; line: number }> {
  const assignments: Array<{ name: string; value: string; line: number }> = [];
  const varDecls = findNodesByType(ast, 'variable_declarator') as ASTNode[];
  for (const decl of varDecls) {
    const name = decl.properties?.get('name') as string | undefined;
    const value = decl.properties?.get('value') as string | undefined;
    if (name && value) {
      assignments.push({ name, value, line: decl.lineNumber || 0 });
    }
  }
  const assignments2 = findNodesByType(ast, 'assignment_expression') as ASTNode[];
  for (const decl of assignments2) {
    let name = decl.properties?.get('left') as string | undefined;
    let value = decl.properties?.get('right') as string | undefined;
    if (!name || !value) {
      const children = decl.children || [];
      if (children.length >= 2) {
        name = name || (children[0].code || '').trim();
        value = value || (children[1].code || '').trim();
      }
    }
    if (name && value) {
      assignments.push({ name, value, line: decl.lineNumber || 0 });
    }
  }
  return assignments;
}

function propagateTaintAST(
  sources: TaintSource[],
  ast: ASTNode,
  scopes: ScopeInfo[],
): Map<string, TaintedVariable> {
  const taintedVars = new Map<string, TaintedVariable>();
  const assignments = extractAssignmentsFromAST(ast);

  for (const source of sources) {
    if (source.variable) {
      const scope = getScopeForLine(scopes, source.line);
      const key = `${scope.name}:${source.variable}`;
      taintedVars.set(key, {
        name: source.variable,
        sourceIds: [source.id],
        sanitized: false,
        sanitizerIds: [],
        line: source.line,
      });
    }
  }

  for (let pass = 0; pass < 5; pass++) {
    for (const { name, value, line } of assignments) {
      const scope = getScopeForLine(scopes, line);
      const key = `${scope.name}:${name}`;
      for (const [, tv] of taintedVars) {
        if (tv.sanitized) continue;
        if (value.includes(tv.name)) {
          const existing = taintedVars.get(key);
          if (existing) {
            for (const sid of tv.sourceIds) {
              if (!existing.sourceIds.includes(sid)) existing.sourceIds.push(sid);
            }
          } else {
            taintedVars.set(key, {
              name,
              sourceIds: [...tv.sourceIds],
              sanitized: false,
              sanitizerIds: [],
              line,
            });
          }
          break;
        }
      }
    }
  }

  return taintedVars;
}

function propagateTaint(code: string, sources: TaintSource[], scopes: ScopeInfo[]): Map<string, TaintedVariable> {
  const taintedVars = new Map<string, TaintedVariable>();
  const lines = code.split('\n');

  for (const source of sources) {
    if (source.variable) {
      const scope = getScopeForLine(scopes, source.line);
      const key = `${scope.name}:${source.variable}`;
      taintedVars.set(key, {
        name: source.variable,
        sourceIds: [source.id],
        sanitized: false,
        sanitizerIds: [],
        line: source.line,
      });
    }
  }

  // Forward propagation through assignments
  for (let pass = 0; pass < 3; pass++) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      const ln = i + 1;
      const assignment = extractVariableFromAssignment(line);
      if (!assignment) continue;

      const scope = getScopeForLine(scopes, ln);
      const key = `${scope.name}:${assignment.name}`;

      for (const [, tv] of taintedVars) {
        if (tv.sanitized) continue;
        const varRefPatterns = [
          new RegExp(tv.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b'),
          new RegExp('\\$\\{' + tv.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\}'),
        ];
        for (const pat of varRefPatterns) {
          if (pat.test(assignment.value)) {
            const existing = taintedVars.get(key);
            if (existing) {
              if (!existing.sourceIds.includes(tv.sourceIds[0])) {
                existing.sourceIds.push(...tv.sourceIds);
              }
            } else {
              taintedVars.set(key, {
                name: assignment.name,
                sourceIds: [...tv.sourceIds],
                sanitized: false,
                sanitizerIds: [],
                line: ln,
              });
            }
            break;
          }
        }
      }
    }
  }

  return taintedVars;
}

export function findTaintPaths(sources: TaintSource[], sinks: TaintSink[], sanitizers: Sanitizer[], code?: string): TaintPath[] {
  if (!code) {
    const paths: TaintPath[] = [];
    for (const source of sources) {
      for (const sink of sinks) {
        if (source.scope === sink.scope && sink.line >= source.line) {
          const blocking = sanitizers.find(s => s.scope === source.scope && s.line > source.line && s.line < sink.line);
          if (!blocking) {
            paths.push({ source, sink, path: [source.id, sink.id], confidence: 0.85, sanitizers: [] });
          } else {
            paths.push({ source, sink, path: [source.id, blocking.id, sink.id], confidence: 0.4, sanitizers: [blocking] });
          }
        }
      }
    }
    return paths;
  }
  const scopes = detectScopes(code);
  const taintedVars = propagateTaint(code, sources, scopes);
  return findTaintPathsFromVars(sources, sinks, sanitizers, code, scopes, taintedVars);
}

function findTaintPathsFromVars(
  sources: TaintSource[],
  sinks: TaintSink[],
  sanitizers: Sanitizer[],
  code: string,
  scopes: ScopeInfo[],
  taintedVars: Map<string, TaintedVariable>,
): TaintPath[] {
  const paths: TaintPath[] = [];
  const lines = code.split('\n');

  for (const source of sources) {
    for (const sink of sinks) {
      if (sink.line < source.line) continue;
      const sinkLine = lines[sink.line - 1] || '';
      const sourceLine = lines[source.line - 1] || '';
      const blocking = sanitizers.filter(s => s.line > source.line && s.line < sink.line);

      let confidence = 0.9;
      const pathIds = [source.id];
      let hasConnection = false;

      if (source.variable) {
        const escapedVar = source.variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const directUseRegex = new RegExp(escapedVar + '\\b');
        if (directUseRegex.test(sinkLine)) {
          hasConnection = true;
        } else {
          for (const [, tv] of taintedVars) {
            if (tv.sourceIds.includes(source.id) && tv.name !== source.variable) {
              const propRegex = new RegExp(tv.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
              if (propRegex.test(sinkLine)) {
                pathIds.push(`${tv.name}_alias`);
                hasConnection = true;
                confidence = 0.75;
                break;
              }
            }
          }
        }
      } else {
        const sameLineOrCall = source.line === sink.line ||
          Math.abs(source.line - sink.line) <= 1 ||
          /\b(fetch|query|execute|exec|eval|find|insert|update|remove|save|write|send|redirect|compile|load)\s*\(/.test(sourceLine);
        if (sameLineOrCall) {
          hasConnection = true;
          confidence = 0.5;
        }
      }

      if (!hasConnection) continue;

      if (blocking.length > 0) {
        for (const san of blocking) pathIds.push(san.id);
        confidence *= 0.45;
        paths.push({ source, sink, path: [...pathIds, sink.id], confidence, sanitizers: blocking });
      } else {
        paths.push({ source, sink, path: [...pathIds, sink.id], confidence, sanitizers: [] });
      }
    }
  }

  for (const [, tv] of taintedVars) {
    if (tv.sanitized) continue;
    const originalSource = sources.find(s => tv.sourceIds.includes(s.id));
    if (!originalSource) continue;

    for (const sink of sinks) {
      if (sink.line <= tv.line) continue;
      const sinkLine = lines[sink.line - 1] || '';
      const varRefRegex = new RegExp(tv.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
      if (!varRefRegex.test(sinkLine)) continue;

      const alreadyExists = paths.some(p => p.source.id === originalSource.id && p.sink.id === sink.id);
      if (alreadyExists) continue;

      const blocking = sanitizers.filter(s => s.line > originalSource.line && s.line < sink.line);
      const confidence = blocking.length > 0 ? 0.35 : 0.75;
      paths.push({ source: originalSource, sink, path: [originalSource.id, `${tv.name}_alias`, sink.id], confidence, sanitizers: blocking });
    }
  }

  return paths.sort((a, b) => b.confidence - a.confidence);
}

export function analyzeTaint(code: string, scope: string, ast?: ASTNode): TaintResult {
  let sources: TaintSource[];
  let sinks: TaintSink[];
  let sanitizers: Sanitizer[];

  let effectiveCode = code;
  if (/<\?php|<\?=/.test(code)) {
    effectiveCode = code.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
    effectiveCode = effectiveCode.replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, '');
    effectiveCode = effectiveCode.replace(/<!--[\s\S]*?-->/g, '');
  }

  if (ast) {
    const astSources = detectSourcesFromAST(ast, scope);
    const regexSources = detectSources(effectiveCode, scope);
    const sourceSet = new Set(astSources.map(s => `${s.type}:${s.line}`));
    sources = [...astSources, ...regexSources.filter(s => !sourceSet.has(`${s.type}:${s.line}`))];

    const astSinks = detectSinksFromAST(ast, scope);
    const regexSinks = detectSinks(effectiveCode, scope);
    const sinkSet = new Set(astSinks.map(s => `${s.type}:${s.line}`));
    sinks = [...astSinks, ...regexSinks.filter(s => !sinkSet.has(`${s.type}:${s.line}`))];

    const astSans = detectSanitizersFromAST(ast, scope);
    const regexSans = detectSanitizers(effectiveCode, scope);
    const sanSet = new Set(astSans.map(s => `${s.type}:${s.line}`));
    sanitizers = [...astSans, ...regexSans.filter(s => !sanSet.has(`${s.type}:${s.line}`))];
  } else {
    sources = detectSources(effectiveCode, scope);
    sinks = detectSinks(effectiveCode, scope);
    sanitizers = detectSanitizers(effectiveCode, scope);
  }

  const scopes = detectScopes(code);
  const taintedVars = ast
    ? propagateTaintAST(sources, ast, scopes)
    : propagateTaint(code, sources, scopes);
  const paths = findTaintPathsFromVars(sources, sinks, sanitizers, code, scopes, taintedVars);

  const maxConfidence = paths.length > 0 ? Math.max(...paths.map(p => p.confidence)) : 0;
  return {
    isTainted: paths.some(p => p.confidence >= 0.6),
    sources,
    sinks,
    paths,
    confidence: maxConfidence,
  };
}
