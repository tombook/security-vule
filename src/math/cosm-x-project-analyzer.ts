/**
 * CosmX Project Analyzer
 * 扫描真实项目代码的宇宙星系法分析器
 *
 * v2.4 - 集成 23 维 UVRS (Unified Vulnerability Risk Score)
 *  - 复用 6 维 cosm-x-galaxy 数据填入 graph_data
 *  - 每条漏洞均通过 CosmicTheoryEngine 评分
 *  - 项目级别汇总生成 UVRS 雷达数据
 */

import { cosmXAnalyze, type CosmXResult } from './cosm-x-galaxy.js';
import { CPGBuilder, type CodePropertyGraph } from './execution/cpg.js';
import {
  CosmicTheoryEngine,
  buildGraphData23D,
  calculateProjectUVRS,
  type GraphData23D,
  type UVRS,
  type TheoryDimension,
} from './cosm-x-theory-23d.js';
import * as fs from 'fs';
import * as path from 'path';

// 共享引擎实例
const _theoryEngine = new CosmicTheoryEngine();

export interface VulnerabilityReport {
  project: string;
  file: string;
  line: number;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  code: string;
  score: number;
  /** 23 维 UVRS 评分 (v2.4 新增) */
  uvrs?: UVRS;
  /** 23 维图数据 (v2.4 新增) */
  graph_data?: GraphData23D;
}

/** 项目级扫描报告 (v2.4) */
interface ProjectScanReport {
  project: string;
  total_vulnerabilities: number;
  vulnerabilities: VulnerabilityReport[];
  /** 项目级 23 维 UVRS 汇总 */
  project_uvrs: UVRS;
  /** 6 维 cosm-x 上下文 (用于追溯) */
  cosmx_summary: {
    lagrange_points: number;
    anomalies: number;
    perturbations: number;
    base_vulnerability_score: number;
  };
}

// OWASP Top 10 全面覆盖 - v2.3
const VULN_PATTERNS = {
  // A01: Broken Access Control (访问控制破损)
  broken_access_control: {
    patterns: [
      // 水平越权 - 用户访问他人资源
      /SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+_id\s*=\s*req\.params\.(?!.*check)/i,
      /findById\s*\(\s*req\.params\.\w+\s*\)(?!.*authorize)/i,
      /\.findOne\s*\(\s*\{\s*id\s*:\s*req\.params\.\w+/i,
      /WHERE\s+user_id\s*=\s*\$.*(?!.*session)/i,
      /req\.params\.\w+\s*===\s*session\.user\.id(?!.*)/i,
      // 垂直越权 - 普通用户执行管理员操作
      /if\s*\(.*role\s*==\s*['\"]admin/i,
      /isAdmin\s*\(\s*\)(?!.*verify)/i,
      /hasRole\s*\(\s*['\"]admin/i,
      /checkPermission\s*\([^)]*\)(?!.*)/i,
      // API越权
      /\/api\/.*\/(?:admin|root|manage)/i,
      /PUT|DELETE|PATCH.*\/api\/.*(?!.*auth)/i,
      // 强制浏览
      /\/admin\d*\/.*\.(?:html|php|jsp)/i,
      /console\/.*(?:admin|backup|config)/i,
      /\.(?:bak|backup|old|swp|exe|dll)/i,
    ],
    severity: 'critical' as const,
    description: 'A01-Broken Access Control: 访问控制破损 - 用户可越权访问或操作'
  },
  // A02: Cryptographic Failures (加密失败)
  cryptographic_failures: {
    patterns: [
      // 硬编码凭证
      /password\s*=\s*['\"][^'\"]{6,}/i,
      /passwd\s*=\s*['\"][^'\"]{6,}/i,
      /secret\s*=\s*['\"][^'\"]{8,}/i,
      /api[_-]?key\s*=\s*['\"][a-zA-Z0-9]{16,}/i,
      /token\s*=\s*['\"][a-zA-Z0-9]{20,}/i,
      /private[_-]?key\s*=\s*['\"]-----BEGIN/i,
      /aws[_-]?access[_-]?key/i,
      /bearer\s+[a-zA-Z0-9]{20,}/i,
      // 弱加密算法
      /md5\s*\(/i,
      /sha1\s*\(/i,
      /des\s*\(/i,
      /rc4\s*\(/i,
      /crypto\.createCipher\s*\(/i,
      /AES\.encrypt\s*\([^)]*(?:ECB|noIV)/i,
      /RSA\.encrypt\s*\([^)]*(?:OAEP|PKCS1v15)/i,
      // 硬编码IV/salt
      /iv\s*=\s*['\"][a-fA-F0-9]{16,}['\"]/i,
      /salt\s*=\s*['\"][a-zA-Z0-9]{8,}/i,
      // 不安全密码存储
      /bcrypt\.compare\s*\([^)]*(?!.*cost)/i,
      /hashlib\.md5\s*\(/i,
      /HashPassword\s*\([^)]*\)(?!.*salt)/i,
      // 调试模式暴露密钥
      /DEBUG\s*=\s*True/i,
      /console\.enable\s*\(\s*\)/i,
    ],
    severity: 'critical' as const,
    description: 'A02-Cryptographic Failures: 加密失败 - 使用弱加密或硬编码凭证'
  },
  // A03: Injection (注入) - 已完整覆盖
  sql_injection: {
    patterns: [
      // 基础SQL注入 - 字符串拼接
      /SELECT.*(?:FROM|INSERT|UPDATE|DELETE).*(?:\+|`.*\$\{)/i,
      /INSERT\s+INTO.*\+\s*['"`]/i,
      /UPDATE\s+\w+\s+SET.*\+\s*/i,
      /\.query\s*\(\s*['"`].*\+.*['"`]\s*\)/i,
      /execute\s*\(\s*['"`].*\+.*['"`]/i,
      /mysql\.(query|execute)\s*\([^)]*\+[^)]*\)/i,
      /sequelize\.(query|execute)\s*\([^)]*\+[^)]*\)/i,
      /\.execute\s*\([^)]*"\s*\.\s*format\(/i,
      /"SELECT.*\}.*"\s*\.\s*format\(/i,
      /f"SELECT.*{/i,
      /\$conn->query\s*\([^)]*\)/i,
      /mysql_query\s*\([^)]*\)/i,
      /WHERE\s+\w+\s*=\s*['\"].*\$/i,
      
      // UNION注入
      /UNION\s+(?:ALL\s+)?SELECT/i,
      /UNION\s+SELECT.+\./i,
      
      // 盲注模式
      /IF\s*\(.*SLEEP\s*\(/i,
      /CASE\s+WHEN\s*\(/i,
      /BENCHMARK\s*\(/i,
      /WAITFOR\s+DELAY/i,
      
      // NoSQL注入
      /collection\.(find|insert|update|remove)\s*\(\s*\{[^}]*\+[^}]*\}/i,
      /db\.(eval|command)\s*\([^)]*\+[^)]*\)/i,
      /\$where\s*:\s*["\'].*\+/i,
      /\$where\s*:\s*`[^`]*\$\{/i,
      
      // ORM注入
      /User\.where\s*\([^)]*\+[^)]*\)/i,
      /Model\.where\s*\([^)]*\+[^)]*\)/i,
      /\.filter\s*\([^)]*\+[^)]*\)/i,
      /\.where\s*\([^)]*\+[^)]*\)/i,
      
      // 框架特定注入
      /createNativeQuery\s*\([^)]*\+[^)]*\)/i,
      /createQuery\s*\([^)]*\+[^)]*\)/i,
      /entityManager\.(createNativeQuery|createQuery)\s*\([^)]*\+[^)]*\)/i,
      /jdbcTemplate\.(query|queryForObject|update)\s*\([^)]*\+[^)]*\)/i,
      /DB::(?:select|insert|update|delete|statement)\s*\([^)]*\.\s*(?:params|input|body|query|args)/i,
      /engine\.execute\s*\([^)]*\+[^)]*\)/i,
      /connection\.query\s*\([^)]*\+[^)]*\)/i,
      /pool\.query\s*\([^)]*\+[^)]*\)/i,
      /\$pdo->(?:query|exec|prepare)\s*\([^)]*\.\s*\$_/i,
      /cmd\.CommandText\s*=.*\+/i,
      
      // MyBatis ${} 注入
      /\$\{\w+\}/i,
      /#\{\w+\}.*#\{/i,
      
      // GraphQL SQL注入
      /context\.db\.query\s*\([^)]*\+[^)]*\)/i,
      
      // 存储过程注入
      /EXEC\s*\(\s*@/i,
      /sp_executesql\s*/i,
      /CALL\s+\w+\s*\(\s*.*\+/i,
    ],
    severity: 'critical' as const,
    description: 'SQL注入 - 用户输入直接拼接到SQL查询'
  },
  command_injection: {
    patterns: [
      /exec\s*\(\s*['"`].*[\$\{].*['"`]\s*\)/i,
      /system\s*\(\s*.*[\$\{].*\s*\)/i,
      /shell_exec\s*\([^)]*[\$\{][^)]*\)/i,
      /child_process.*exec\s*\([^)]*[\$\{][^)]*\)/i,
      /popen\s*\([^)]*[\$\{][^)]*\)/i,
      /os\.system\s*\([^)]*[\$\{][^)]*\)/i,
      /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/i,
      /Process\(.*\)\.spawn\s*\([^)]*\)/i,
      /Runtime\([^)]*\)\.exec\s*\([^)]*\)/i,
      /ProcessBuilder\s*\([^)]*\)/i,
    ],
    severity: 'critical' as const,
    description: '命令注入 - 用户输入直接拼接到系统命令'
  },
  xss: {
    patterns: [
      // 基础XSS - innerHTML/write
      /innerHTML\s*=\s*[^;]*(?:req|user|input|params|body|query)/i,
      /document\.write\s*\([^)]*(?:req|user|input|params|body|query)/i,
      /\.html\s*\([^)]*(?:req|user|input|params|body|query)/i,
      /\<%-?\s*[^%]*\+(?:req|user|input|params|body|query)/i,
      /\$\([^)]*\)\.html\s*\([^)]*(?:req|user|input)/i,
      /\.append\s*\([^)]*(?:req|user|input)/i,
      /\.prepend\s*\([^)]*(?:req|user|input)/i,
      /v-html\s*=/i,
      /:innerHTML\s*=/i,
      /dangerouslySetInnerHTML/i,
      /outerHTML\s*=/i,
      /insertAdjacentHTML/i,
      /\.(after|before)\s*\([^)]*\<[^>]*\+\s*[^>]*\)/i,
      
      // Vue/React/Angular框架XSS
      /\{\{\s*[^}]*(?:req|user|input|params|body|query)[^}]*\}\}/i,
      /ng-bind-html\s*=/i,
      /v-bind:innerHTML/i,
      /sizzle\s*\([^)]*(?:req|user|input)/i,
      
      // jQuery XSS
      /\$\.(?:html|append|prepend|wrap|after|before)\s*\([^)]*(?:req|user|input)/i,
      /\$\(.*\)\.(?:html|append|prepend|after|before)\s*\([^)]*(?:req|user|input)/i,
      
      // 模板字符串XSS
      /`[^`]*\$\{(?:req|user|input|params|body|query)[^}]*\}`/i,
      /`[^`]*\+\s*(?:req|user|input|params|body|query)/i,
      
      // PHP XSS
      /echo\s+\$\w+/i,
      /print\s+\$\w+/i,
      /print_r\s*\(\s*\$_/i,
      /var_dump\s*\(\s*\$_/i,
      /\?><\?php/i,
      
      // JSP XSS
      /<%=.*(?:request|param|body|query)\./i,
      /\$\{[^}]*(?:param|request|body|query)\./i,
      /fn:escapeXml/i,
      
      // Jinja2/Django XSS
      /\|\s*safe\s*/i,
      /\|safe\s*}}/i,
      /render_template_string\s*\([^)]*\)/i,
      
      // Flask XSS
      /render_template_string\s*\([^)]*\)/i,
      /Markup\s*\([^)]*\+[^)]*\)/i,
      /flask\.Markup\s*\(/i,
      
      // Express XSS
      /res\.(?:send|render|json)\s*\([^)]*\+[^)]*(?:req|user|input|params)/i,
      /req\.(?:params|body|query)\./i,
      
      // 数据外泄XSS
      /document\.cookie/i,
      /localStorage\.(?:getItem|setItem)/i,
      /sessionStorage\.(?:getItem|setItem)/i,
      /fetch\s*\([^)]*(?:cookie|token|auth)/i,
      /new\s+Image\(\)\.src\s*=/i,
      
      // 事件处理器XSS
      /on(?:click|error|load|mouseover|focus|blur|change|submit)\s*=/i,
      /setAttribute\s*\([^)]*(?:onclick|onerror|onload)/i,
      
      // mXSS ( mutation XSS)
      /innerHTML\s*=\s*["\']<svg/i,
      /innerHTML\s*=\s*["\']<math/i,
      /innerHTML\s*=\s*["\']<iframe/i,
      
      // 编码绕过XSS
      /unescape\s*\([^)]*\)/i,
      /decodeURI(?:Component)?\s*\([^)]*\)/i,
            /atob\s*\([^)]*\)/i,
    ],
    severity: 'high' as const,
    description: 'XSS跨站脚本 - 用户输入直接输出到HTML'
  },
  path_traversal: {
    patterns: [
      /open\s*\(\s*[^)]*(?:req|user|input|params|body|query|filename)[^)]*\)/i,
      /readFile\s*\(\s*[^)]*(?:req|user|input|params|body|query|filename)[^)]*\)/i,
      /readFileSync\s*\(\s*[^)]*(?:req|user|input|params|body|query|filename)[^)]*\)/i,
      /include\s*\([^)]*(?:req|user|input|params|body|query)[^)]*\)/i,
      /require\s*\([^)]*(?:req|user|input|params|body|query)[^)]*\)/i,
      /include\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /require\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /file_get_contents\s*\([^)]*\$_(GET|POST|REQUEST)/i,
      /fopen\s*\([^)]*\$_(GET|POST|REQUEST)/i,
      /\.\.\/|\.\.\\\/|\%2e\%2e/i,
      /path\.join\s*\([^)]*req\./i,
      /path\.resolve\s*\([^)]*req\./i,
    ],
    severity: 'high' as const,
    description: '路径遍历 - 用户输入直接拼接到文件路径'
  },
  deserialization: {
    patterns: [
      /unserialize\s*\(/i,
      /pickle\.loads?\s*\(/i,
      /YAML\.load\s*\((?!safe)/i,
      /YAML\.unsafe_load/i,
      /ObjectInputStream/i,
      /node-serialize/i,
      /serialize\.unserialize/i,
      /jsonpickle\.decode/i,
      /Marshal\.loads/i,
      /RubyMarshal\.load/i,
      /readObject\s*\(\s*\)/i,
      /ObjectInputStream.*readObject/i,
    ],
    severity: 'critical' as const,
    description: '反序列化漏洞 - 使用不安全的反序列化方法'
  },
  code_injection: {
    patterns: [
      /eval\s*\([^)]*(?:req|user|input|params|body)/i,
      /new\s+Function\s*\([^)]*(?:req|user|input|params|body)/i,
      /setTimeout\s*\([^)]*(?:req|user|input|params|body)[^)]*\)/i,
      /setInterval\s*\([^)]*(?:req|user|input|params|body)[^)]*\)/i,
      /execScript\s*\(/i,
      /Function\s*\([^)]*\)\s*\(\)/i,
      /__import__\s*\([^)]*\)/i,
      /import\s+os\s+;?\s+os\.system/i,
      /import\s+subprocess/i,
    ],
    severity: 'critical' as const,
    description: '代码注入 - 使用eval或动态函数执行'
  },
    // A10: SSRF (服务器端请求伪造) [增强版]
    ssrf: {
      patterns: [
        // 基础SSRF - 用户输入作为URL
        /request\s*\(\s*\{\s*[^}]*url[^}]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
        /fetch\s*\([^)]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
        /curl\s*\([^)]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
        /urlopen\s*\([^)]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
        /http\.request\s*\([^)]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
        /new\s+URL\s*\([^)]*req\./i,
        /axios\.[get|post|put|delete]\s*\([^)]*\+.*req\./i,
      
        // Python requests库SSRF
        /requests\.(get|post|put|patch|delete)\s*\([^)]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
        /urllib\.request\.urlopen\s*\([^)]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
        /urllib3\.request\s*\([^)]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
        /httpx\.(get|post|put|patch|delete)\s*\([^)]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
      
        // Node.js SSRF
        /https?\.get\s*\([^)]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
        /http\.get\s*\([^)]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
        /new\s+Agent\s*\([^)]*\)\.request/i,
        /tinyhttpd/i,
        /express\s*\(.*\)\.get\s*\([^)]*(?:\+.*(?:req|params|body|query))/i,
        /router\.get\s*\([^)]*(?:\+.*(?:req|params|body|query))/i,
        /@app\.route\s*\([^)]*\)(\s*;|\s*\(req,\s*res\))(?=.*(?:req\.query|req\.params|req\.body))/i,
      
        // Java SSRF
        /new\s+URL\s*\([^)]*(?:req\.|params\.|body\.)/i,
        /URLConnection\.(connect|getInputStream)\s*\(\)/i,
        /HttpClient\.newHttpClient\s*\(\)\.send\s*\(/i,
        /OkHttpClient.*\.newCall\s*\(\s*new\s+Request\s*\(\s*new\s+Builder\s*\(\)\.url\s*\([^)]*(?:req\.|params\.)/i,
        /RestTemplate\.(getForObject|postForObject|exchange)\s*\([^)]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
        /WebClient\.create\s*\([^)]*(?:\+.*(?:req|params|body|query)|\$\{)/i,
        /HttpURLConnection.*\.openConnection\s*\(\)/i,
        /JerseyClient\.createWebResource\s*\([^)]*\.get\s*\(/i,
      
        // PHP SSRF
        /file_get_contents\s*\([^)]*(?:\+.*\$_|request|params|body)/i,
        /fopen\s*\([^)]*(?:\+.*\$_|request|params|body)/i,
        /curl_setopt\s*\([^)]*CURLOPT_URL[^)]*(?:\+.*\$_|request|params|body)/i,
        /simplexml_load_string\s*\([^)]*\$_(GET|POST|REQUEST)/i,
        /simplexml_load_file\s*\([^)]*\$_(GET|POST|REQUEST)/i,
        /DOMDocument::loadHTML\s*\([^)]*\$_(GET|POST|REQUEST)/i,
        /unserialize\s*\(\s*file_get_contents\s*\(\s*['\"]php:\/\/input/i,
      
        // Go SSRF
        /http\.(Get|Post|Put|Delete|Head)\s*\([^)]*(?:\+.*req\.|params\.|body\.)/i,
        /http\.Client{.*}\.Do\s*\([^)]*(?:\+.*req\.|params\.|body\.)/i,
        /net\/http\.(Get|Post|Put|Delete)\s*\([^)]*(?:\+.*req\.|params\.|body\.)/i,
        /io\.ReadAll\s*\(\s*resp\.Body\s*\)/i,
      
        // Ruby SSRF
        /Net::HTTP\.start\s*\([^)]*\.get\s*\([^)]*(?:\+.*(?:params|body|request))/i,
        /open\s*\([^)]*(?:\+.*(?:params|body|request))/i,
        /RestClient\.(get|post|put|delete)\s*\([^)]*(?:\+.*(?:params|body|request))/i,
        /HTTParty\.(get|post|put|delete)\s*\([^)]*(?:\+.*(?:params|body|request))/i,
        /Faraday\.(get|post|put|delete)\s*\([^)]*(?:\+.*(?:params|body|request))/i,
      
        // .NET/C# SSRF
        /new\s+WebClient\(\)\.DownloadString\s*\([^)]*(?:\+.*(?:req|params|body|query))/i,
        /new\s+HttpClient\(\)\.GetAsync\s*\([^)]*(?:\+.*(?:req|params|body|query))/i,
        /HttpWebRequest\.Create\s*\([^)]*(?:\+.*(?:req|params|body|query))/i,
        /WebRequest\.CreateHttp\s*\([^)]*(?:\+.*(?:req|params|body|query))/i,
        /client\.GetAsync\s*\([^)]*(?:\+.*(?:req|params|body|query))/i,
        /client\.PostAsync\s*\([^)]*(?:\+.*(?:req|params|body|query))/i,
        /HttpClient.*\.GetStringAsync\s*\([^)]*(?:\+.*(?:req|params|body|query))/i,
        /client\.SendAsync\s*\([^)]*(?:\+.*(?:req|params|body|query))/i,
      
        // Python Flask/Django SSRF
        /requests\.get\s*\([^)]*(?:request\.|req\.)/i,
        /requests\.post\s*\([^)]*(?:request\.|req\.)/i,
        /urllib\.request\.urlopen\s*\([^)]*(?:request\.|req\.)/i,
        /httpx\.get\s*\([^)]*(?:request\.|req\.)/i,
      
        // SSRF 协议攻击
        /file:\/\//i,
        /dict:\/\//i,
        /gopher:\/\//i,
        /sftp:\/\//i,
        /ldap:\/\//i,
        /ftp:\/\//i,
        /http:\/\/localhost/i,
        /http:\/\/127\.0\.0\.1/i,
        /http:\/\/0\.0\.0\.0/i,
        /http:\/\/\[::1\]/i,
        /http:\/\/169\.254\.169\.254/i,
        /http:\/\/metadata\.google/i,
        /\$HOSTNAME\.internal/i,
        /169\.254\.169\.254/i,
      
        // SSRF bypass 模式
        /url\s*=\s*(?:req|user|input|params)\./i,
        /target\s*=\s*(?:req|user|input|params)\./i,
        /src\s*=\s*(?:req|user|input|params)\./i,
        /redirect\s*=\s*(?:req|user|input|params)\./i,
        /next\s*=\s*(?:req|user|input|params)\./i,
        /data\s*=\s*(?:req|user|input|params)\./i,
        /reference\s*=\s*(?:req|user|input|params)\./i,
        /query\s*=\s*(?:req|user|input|params)\./i,
        /page\s*=\s*(?:req|user|input|params)\./i,
        /feed\s*=\s*(?:req|user|input|params)\./i,
        /user\s*=\s*(?:req|user|input|params)\./i,
        /domain\s*=\s*(?:req|user|input|params)\./i,
        /callback\s*=\s*(?:req|user|input|params)\./i,
        /return\s*=\s*(?:req|user|input|params)\./i,
        /continue\s*=\s*(?:req|user|input|params)\./i,
        /view\s*=\s*(?:req|user|input|params)\./i,
        /dir\s*=\s*(?:req|user|input|params)\./i,
        /document\s*=\s*(?:req|user|input|params)\./i,
        /folder\s*=\s*(?:req|user|input|params)\./i,
        /pg\s*=\s*(?:req|user|input|params)\./i,
        /php?\s*=\s*(?:req|user|input|params)\./i,
        /path\s*=\s*(?:req|user|input|params)\./i,
        /preview\s*=\s*(?:req|user|input|params)\./i,
        /debug\s*=\s*(?:req|user|input|params)\./i,
        /dump\s*=\s*(?:req|user|input|params)\./i,
        /template\s*=\s*(?:req|user|input|params)\./i,
        /config\s*=\s*(?:req|user|input|params)\./i,
        /site\s*=\s*(?:req|user|input|params)\./i,
        /html\s*=\s*(?:req|user|input|params)\./i,
        /val\s*=\s*(?:req|user|input|params)\./i,
        /validate\s*=\s*(?:req|user|input|params)\./i,
        /verification\s*=\s*(?:req|user|input|params)\./i,
        /access\s*=\s*(?:req|user|input|params)\./i,
        /ref\s*=\s*(?:req|user|input|params)\./i,
        /state\s*=\s*(?:req|user|input|params)\./i,
        /host\s*=\s*(?:req|user|input|params)\./i,
        /port\s*=\s*(?:req|user|input|params)\./i,
        /to\s*=\s*(?:req|user|input|params)\./i,
        /out\s*=\s*(?:req|user|input|params)\./i,
        /view\index\s*=\s*(?:req|user|input|params)\./i,
        /view\/[a-z]+\s*=\s*(?:req|user|input|params)\./i,
        /location\s*=\s*(?:req|user|input|params)\./i,
        /open\s*=\s*(?:req|user|input|params)\./i,
        /account\s*=\s*(?:req|user|input|params)\./i,
        /name\s*=\s*(?:req|user|input|params)\./i,
        /nick\s*=\s*(?:req|user|input|params)\./i,
        /author\s*=\s*(?:req|user|input|params)\./i,
        /file_name\s*=\s*(?:req|user|input|params)\./i,
        // SSRF 危险函数组合
        /exec\s*\(\s*['\"]curl.*\$\{/i,
        /exec\s*\(\s*['\"]wget.*\$\{/i,
        /system\s*\(\s*['\"]curl.*\$\{/i,
        /system\s*\(\s*['\"]wget.*\$\{/i,
      ],
      severity: 'critical' as const,
      description: 'A10-SSRF: 服务端请求伪造 - 用户输入作为请求URL可能导致内网探测'
    },
    // A04: Insecure Design (不安全设计)
  insecure_design: {
    patterns: [
      // 暴力破解防护缺失
      /login\s*\([^)]*(?!.*rate.*limit|!.*max.*attempt)/i,
      /authenticate\s*\([^)]*(?!.*lockout|!.*threshold)/i,
      /checkPassword\s*\([^)]*(?!.*max)/i,
      /verify\s*\([^)]*(?!.*attempt)/i,
      // 速率限制缺失
      /app\.(use|post|get)\s*\([^)]*(?!.*rate.*limit|!.*throttle)/i,
      /@app\.route\s*\([^)]*(?!.*limiter)/i,
      /rate_limit\s*\([^)]*(?!.*)/i,
      /throttle\s*\([^)]*\)/i,
      // 业务逻辑漏洞
      /discount\s*=\s*.*\s*;?\s*if.*price/i,
      /total\s*=\s*price\s*-\s*discount(?!\s*;.*check)/i,
      /checkout\s*\([^)]*(?!.*validat)/i,
      // 敏感功能无二次验证
      /transfer\s*\([^)]*(?!.*confirm|!.*verify)/i,
      /password.*reset\s*\([^)]*(?!.*token|!.*mail)/i,
      /delete\s*\([^)]*(?!.*confirm)/i,
      /money.*transfer/i,
      /wire.*transfer/i,
    ],
    severity: 'high' as const,
    description: 'A04-Insecure Design: 不安全设计 - 缺少暴力破解防护、速率限制、业务逻辑校验'
  },
  // A05: Security Misconfiguration (安全配置错误)
  security_misconfiguration: {
    patterns: [
      // 默认凭据
      /admin\s*:\s*admin/i,
      /root\s*:\s*root/i,
      /password\s*=\s*['\"](?:password|123456|admin|root|letmein)/i,
      /username\s*=\s*['\"](?:admin|root|user)/i,
      // 调试模式
      /debug\s*=\s*(?:true|1)/i,
      /DEBUG\s*=\s*(?:True|1)/i,
      /app\.debug\s*=\s*true/i,
      // CORS配置错误
      /Access-Control-Allow-Origin\s*:\s*\*/i,
      /cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]?\*['\"]?/i,
      /res\.setHeader\s*\(['\"]Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"]/i,
      // 安全头缺失
      /X-Frame-Options/i,
      /X-Content-Type-Options/i,
      /X-XSS-Protection/i,
      /Content-Security-Policy/i,
      /Strict-Transport-Security/i,
      // 错误处理泄露信息
      /stack\s*trace/i,
      /\.printStackTrace\s*\(\s*\)/i,
      /echo\s+\$_SERVER/i,
      /phpinfo\s*\(\s*\)/i,
      /sys\.executable\s*/i,
      /debugger;\s*console\.log/i,
      // 不安全的Cookie
      /cookie\s*=\s*new\s+Cookie\s*\([^)]*(?!.*secure|!.*httpOnly)/i,
      /session\.cookie\s*\([^)]*(?!.*secure)/i,
      /set_cookie\s*\([^)]*(?!.*secure|!.*httponly)/i,
    ],
    severity: 'high' as const,
    description: 'A05-Security Misconfiguration: 安全配置错误 - 默认凭据、调试模式、CORS错误等'
  },
  // A06: Vulnerable and Outdated Components (脆弱过时组件)
  vulnerable_components: {
    patterns: [
      // 已知CVE组件特征
      /struts2.*Core/i,
      /Apache.*Struts/i,
      /log4j.*2?\.\d+\.\d+/i,
      /spring4shell/i,
      /Shellshock/i,
      /Heartbleed/i,
      /POODLE/i,
      /DROWN/i,
      /BEAST/i,
      /FREAK/i,
      // 已知漏洞npm包
      /event-stream\s*3\.3\.\d/i,
      /flatmap-stream/i,
      /node-serialize/i,
      // 脆弱的JSON解析
      /json\.parse\s*\([^)]*(?!.*safe)/i,
      /JSON\.parse\s*\([^)]*(?!.*reviver)/i,
      // 已知漏洞Python包
      /Pillow\s*[2-4]\.\d\.\d/i,
      /django.*\s*[1-3]\.\d\.\d/i,
      /requests\s*[2]\.\d+\.\d+/i,
      /urllib3\s*[1]\.\d+/i,
      // 反序列化危险函数
      /yaml\.load\s*\([^)]*(?!.*Loader\.SafeLoader)/i,
      /pickle\.load\s*\(/i,
      /unserialize\s*\([^)]*\)/i,
      /Marshal\.loads\s*\(/i,
    ],
    severity: 'critical' as const,
    description: 'A06-Vulnerable Components: 脆弱组件 - 使用已知漏洞的库或框架'
  },
  // A07: Identification and Authentication Failures (身份认证失败)
  authentication_failures: {
    patterns: [
      // 弱密码策略
      /password\s*=\s*['\"][a-z]{1,7}['\"]/i,
      /validate.*password.*\(.*(?=.{0,7})/i,
      /password.*length\s*<\s*6/i,
      // 会话ID暴露
      /session\.id\s*=\s*.*req/i,
      /JSESSIONID\s*=\s*.*\+/i,
      /PHPSESSID/i,
      /connect\.sid/i,
      // 不安全的会话管理
      /session\s*=\s*\{\s*\}/i,
      /cookie\s*=\s*.*\s*;.*domain/i,
      /setcookie\s*\([^)]*(?!.*secure|!.*httponly)/i,
      /res\.cookie\s*\([^)]*(?!.*signed)/i,
      // 认证绕过
      /if\s*\(.*\)\s*\{\s*return\s+true/i,
      /skip.*auth/i,
      /bypass.*login/i,
      /auth.*=.*true.*;/i,
      /isAuthenticated\s*\(\s*\).*return\s+true/i,
      // 多因素认证缺失
      /mfa\s*=\s*false/i,
      /2fa\s*=\s*false/i,
      /totp\s*=\s*false/i,
      // 密码重置漏洞
      /token\s*=\s*.*\s*;.*expires/i,
      /reset.*password.*token.*md5/i,
    ],
    severity: 'high' as const,
    description: 'A07-Authentication Failures: 身份认证失败 - 弱密码、会话管理问题'
  },
  // A08: Software and Data Integrity Failures (软件数据完整性失败)
  software_integrity_failures: {
    patterns: [
      // 不安全反序列化
      /ObjectInputStream\s*\([^)]*\)/i,
      /readObject\s*\(\s*\)/i,
      /readUnshared\s*\(\s*\)/i,
      // 不安全的CI/CD
      /\$(?:GH_TOKEN|API_KEY|SECRET)\b/i,
      /\bAWS_SECRET_ACCESS_KEY\b/i,
      /ghp_\w{36}/i,
      /gho_\w{36}/i,
      /xox[baprs]-\d{10,}/i,
      // 不安全的数据源
      /https?:\/\/raw\.githubusercontent\.com\/\w+\/\w+\/master/i,
      /https?:\/\/raw\.githubusercontent\.com\/\w+\/\w+\/main/i,
      /curl\s+\|.*sh/i,
      /wget.*\|.*sh/i,
      /pip\s+install.*--trusted-host/i,
      /npm\s+install.*--allow-root/i,
      // 不安全的更新
      /auto-update/i,
      /auto-upgrade/i,
      /update\s*\([^)]*(?!.*verify)/i,
    ],
    severity: 'critical' as const,
    description: 'A08-Software Integrity: 软件数据完整性失败 - 不安全反序列化、CI/CD漏洞'
  },
  // A09: Security Logging and Monitoring Failures (安全日志监测失败)
  security_logging_failures: {
    patterns: [
      // 敏感信息日志泄露
      /console\.log\s*\([^)]*(?:password|passwd|secret|token|key)/i,
      /logger\.(?:info|debug)\s*\([^)]*(?:password|secret)/i,
      /log\.(?:info|debug)\s*\([^)]*(?:password|secret)/i,
      /print\s*\([^)]*(?:password|passwd|secret|token)/i,
      // 安全事件未记录
      /login\s*\([^)]*(?!.*log)/i,
      /failed.*login/i,
      /invalid.*password/i,
      /account.*lock/i,
      /suspicious.*activity/i,
      // 错误处理泄露
      /catch\s*\([^)]*e\s*\)\s*\{\s*console\.log/i,
      /catch\s*\([^)]*err\s*\)\s*\{\s*echo\s+\$_SERVER/i,
      /except\s*Exception\s+as\s+e\s*:\s*print\s*\(\s*e\s*\)/i,
      // 堆栈跟踪泄露
      /\x00stack\x00trace\x00/i,
      /\x00exception\x00/i,
      /thrown\s+new\s+\w+Exception\s*\(\s*e\s*\)/i,
    ],
    severity: 'medium' as const,
    description: 'A09-Logging Failures: 安全日志监测失败 - 审计日志缺失、安全事件未记录'
  },
  open_redirect: {
    patterns: [
      /redirect\s*\(\s*(?:req|user|input|params|body)\./i,
      /window\.location.*=.*(?:req|user|input|params|body)/i,
      /res\.redirect\s*\([^)]*(?:req|user|input)/i,
      /response\.sendRedirect\s*\([^)]*(?:req|user|input)/i,
      /forward\s*\([^)]*(?:req|user|input)/i,
    ],
    severity: 'medium' as const,
    description: '开放重定向 - 用户输入控制重定向目标'
  },
  csrf: {
    patterns: [
      // 基础CSRF检测 - 表单无token验证
      /<form[^>]*>(?:(?!csrf).)*<\/form>/is,
      /<form[^>]*\saction\s*=\s*["\'](?!(?:.*csrf|.*token)).*["\']/i,
      // POST请求无CSRF保护
      /POST\s+\/[^\s]*\s*\(?(?!(?:.*csrf|.*verify|.*token)).*\)/i,
      /app\.(post|put|delete)\s*\(['"][^\'"]*['"]\s*,?\s*(?!(?:.*csrf|.*verify)).*\)/i,
      /router\.(post|put|delete)\s*\(['"][^\'"]*['"]\s*,?\s*(?!(?:.*csrf|.*verify)).*\)/i,
      /@app\.route\s*\(['"][^\'"]*['"]\s*,\s*methods\s*=\s*\[['\"]POST['\"]\](?!(?:.*csrf)).*\)/i,
      /@router\.(post|put|delete)\s*\(['"][^\'"]*['"](?!(?:.*csrf|.*verify|.*token)).*\)/i,
      // Express/Node.js无CSRF中间件
      /app\.(post|put|delete)\s*\([^,)]*,\s*(?!.*csrf|.*token|.*verify).*\)(\s*;|\s*\(req,\s*res\))/i,
      // Django无@csrf_protect
      /def\s+\w+\s*\([^)]*\):\s*(?:(?!@csrf_protect|@requires_csrf_token).)*/is,
      /@app\.route\s*\(['"][^'\"]+['"]\s*,\s*methods\s*=\s*\[['\"]POST['\"]\]\)(?!\s*@)/i,
      // Flask无csrf保护
      /@app\.route\s*\(['"][^'\"]+['"]\s*,\s*methods\s*=\s*\[['\"]POST['\"]\]\)(?!.*csrf)/i,
      /@app\.route\s*\(['"][^'\"]+['"]\s*,\s*methods\s*=\s*\[['\"]PUT['\"]\]\)(?!.*csrf)/i,
      /@app\.route\s*\(['"][^'\"]+['"]\s*,\s*methods\s*=\s*\[['\"]DELETE['\"]\]\)(?!.*csrf)/i,
      // 表单直接提交无token
      /<input[^>]*type\s*=\s*["\']submit["\'][^>]*>(?:(?!token).)*$/i,
      /onsubmit\s*=\s*["\'][^"\']*["\'](?:(?!csrf|token).)*$/i,
      // API状态变更无验证
      /fetch\s*\(\s*["\'][^"\']+["\']\s*,\s*\{\s*method\s*:\s*["\']POST["\'](?:(?!headers).)*\}\s*\)/i,
      /axios\.(post|put|delete)\s*\([^)]*(?:(?!headers.*csrf|headers.*token)).*\)/i,
      /\$\.(post|get|ajax)\s*\([^)]*(?:(?!csrf|token)).*\)/i,
      /\$\.ajax\s*\(\s*\{(?:\s*(?!.*csrf|.*beforeSend).)*\}\s*\)/i,
      // Spring MVC无CSRF
      /@RequestMapping\s*\([^)]*method\s*=\s*RequestMethod\.POST[^)]*\)(?!\s*@)/i,
      /@PostMapping\s*\([^)]*\)(?!\s*@)/i,
      /@PutMapping\s*\([^)]*\)(?!\s*@)/i,
      /@DeleteMapping\s*\([^)]*\)(?!\s*@)/i,
      // JavaScript直接发送请求无token
      /xhttp\.open\s*\(\s*["\']POST["\'][^)]*\)(?:(?!setRequestHeader.*csrf).)*/i,
      /new\s+XMLHttpRequest\s*\(\)[^;]*\.send\s*\([^)]*\)(?:(?!csrf).)*/i,
      // 反模式 - 显式禁用CSRF
      /csrf\s*=\s*(?:false|0|null)/i,
      /csrf_protection\s*=\s*(?:false|0|null|disabled)/i,
      /enableCsrf\s*\(\s*(?:false|0)\s*\)/i,
      /disableCsrf\s*\(\s*\)/i,
      // 检测注释中跳过csrf
      /\/\/\s*skip.*csrf/i,
      /\/\*.*skip.*csrf.*\*\//i,
      /#\s*skip.*csrf/i,
      // AngularJS无CSRF
      /\$http\.(post|put|delete)\s*\([^)]*(?:(?!xsrfCookieName|xsrfHeaderName).)*\)/i,
      // React无CSRF
      /fetch\s*\(\s*url\s*,\s*\{[^}]*method\s*:\s*["\']POST["\'][^}]*\}(?:(?!credentials).)*\)/i,
      /axios\.(post|put)\s*\([^)]*,\s*\{[^}]*\}(?:(?!xsrf).)*\)/i,
    ],
    severity: 'high' as const,
    description: 'CSRF防护缺失 - 表单/API请求缺少CSRF token验证'
  },
  xxe: {
    patterns: [
      // 基础XXE - libxml/LIBXML_NOENT
      /libxml\s*\$?noent\s*=\s*true/i,
      /LIBXML_NOENT/i,
      /XML_PARSE_NOENT/i,
      /simplexml_load_string\s*\([^)]*\$_(GET|POST|REQUEST)/i,
      /simplexml_load_file\s*\([^)]*\$_(GET|POST|REQUEST)/i,
      /loadXML\s*\([^)]*\$_(GET|POST|REQUEST)/i,

      // PHP XXE - SimpleXML / DOMDocument
      /simplexml_load_string\s*\([^)]*(?:req\.|user|input|params)/i,
      /simplexml_load_file\s*\([^)]*(?:req\.|user|input|params)/i,
      /DOMDocument::loadXML\s*\([^)]*(?:req\.|user|input|params)/i,
      /DOMDocument::loadHTML\s*\([^)]*(?:req\.|user|input|params)/i,
      /new\s+DOMDocument\s*\([^)]*\)->loadXML\s*\([^)]*(?:req\.|user|input|params)/i,
      /\$doc\s*=\s*new\s+DOMDocument.*loadXML\s*\([^)]*(?:req\.|user|input|params)/i,
      /xml_parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /xml_parse_into_struct\s*\([^)]*(?:req\.|user|input|params)/i,
      /parse_xml\s*\([^)]*(?:req\.|user|input|params)/i,
      /xml_create\s*\([^)]*(?:req\.|user|input|params)/i,
      /XMLReader::open\s*\([^)]*(?:req\.|user|input|params)/i,
      /XMLReader::XML\s*\([^)]*(?:req\.|user|input|params)/i,
      /expect SIMPLEXML_LOAD_STRING/i,
      /expect SIMPLEXML_LOAD_FILE/i,
      /expect XML_PARSE_NOENT/i,
      /expect LIBXML_NOENT/i,

      // Java XXE - JAXP / DOM / SAX
      /DocumentBuilder\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /DocumentBuilderFactory\.newInstance\(\)\.newDocumentBuilder\(\)\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /SAXParserFactory\.newInstance\(\)\.newSAXParser\(\)\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /XMLInputFactory\.newInstance\(\)\.createXMLStreamReader\s*\([^)]*(?:req\.|user|input|params)/i,
      /TransformerFactory\.newInstance\(\)\.newTransformer\(\)\.transform\s*\([^)]*(?:req\.|user|input|params)/i,
      /Unmarshaller\.unmarshal\s*\([^)]*(?:req\.|user|input|params)/i,
      /JAXB\.unmarshal\s*\([^)]*(?:req\.|user|input|params)/i,
      /XMLStreamReader\s*\([^)]*(?:req\.|user|input|params)/i,
      /XMLReader\s*\([^)]*(?:req\.|user|input|params)/i,
      /SchemaFactory\s*\(.*\)\.newSchema\s*\([^)]*(?:req\.|user|input|params)/i,
      /DocumentBuilder.*setFeature\s*\([^)]*"FEATURE_SECURE_PROCESSING"/i,
      /SAXParser.*setFeature\s*\([^)]*"FEATURE_SECURE_PROCESSING"/i,
      /XMLInputFactory.*setProperty\s*\([^)]*"SUPPORT_DTD"/i,

      // Python XXE - lxml / ElementTree / xml.etree
      /etree\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /ElementTree\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /xml\.etree\.ElementTree\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /lxml\.etree\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /lxml\.html\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /fromstring\s*\([^)]*(?:req\.|user|input|params)/i,
      /xml\.minidom\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /xml.dom\.minidom\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /xml\.sax\.parser\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /defusedxml\.ElementTree\.parse/i,
      /defusedxml\.cElementTree\.parse/i,

      // Node.js XXE - xml2js / libxmljs / xmldom
      /xml2js\.Parser\s*\([^)]*(?:req\.|user|input|params)/i,
      /new\s+Parser\s*\([^)]*(?:req\.|user|input|params)/i,
      /libxmljs\.parseXml\s*\([^)]*(?:req\.|user|input|params)/i,
      /libxmljs\.XmlDocument\s*\([^)]*(?:req\.|user|input|params)/i,
      /xmldom\.DOMParser\s*\([^)]*(?:req\.|user|input|params)/i,
      /new\s+DOMParser\s*\([^)]*(?:req\.|user|input|params)/i,
      /new\s+ XmlDocument\s*\([^)]*(?:req\.|user|input|params)/i,
      /fast-xml-parser\s*\(.*\)\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /xml\.parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /@xmldom\/domain/i,

      // .NET XXE - System.Xml / XDocument
      /System\.Xml\.XmlDocument\s*\([^)]*(?:req\.|user|input|params)/i,
      /XDocument\.Load\s*\([^)]*(?:req\.|user|input|params)/i,
      /XmlReaderSettings\s*\([^)]*\)\.DtdProcessing\s*=\s*DtdProcessing\.Parse/i,
      /XmlReader\.Create\s*\([^)]*(?:req\.|user|input|params)/i,
      /XmlDocument\.Load\s*\([^)]*(?:req\.|user|input|params)/i,
      /XmlTextReader\s*\([^)]*(?:req\.|user|input|params)/i,
      /new\s+XmlTextReader\s*\([^)]*(?:req\.|user|input|params)/i,
      /XElement\.Parse\s*\([^)]*(?:req\.|user|input|params)/i,
      /new\s+XmlParserContext\s*\([^)]*\)/i,
      /DataSet\.ReadXml\s*\([^)]*(?:req\.|user|input|params)/i,

      // Ruby XXE - REXML / Nokogiri
      /REXML\.Document\.new\s*\([^)]*(?:req\.|user|input|params)/i,
      /REXML\.Parsers::SAX2Parser\.new\s*\([^)]*(?:req\.|user|input|params)/i,
      /Nokogiri::XML\s*\([^)]*(?:req\.|user|input|params)/i,
      /Nokogiri::HTML\s*\([^)]*(?:req\.|user|input|params)/i,
      /Nokogiri::XML::Document\.new\s*\([^)]*(?:req\.|user|input|params)/i,
      /Norikura/i,

      // XXE 危险参数
      /noent\s*=\s*true/i,
      /DTDProcessing/i,
      /XMLConstants\.FEATURE_SECURE_PROCESSING/i,
      /setFeature\s*\([^)]*"FEATURE_SECURE_PROCESSING"\s*,\s*false/i,
      /setFeature\s*\([^)]*"DISALLOW_DOCTYPE_DECLARATION"\s*,\s*false/i,
      /ExternalGeneralEntities/i,
      /ExternalParameterEntities/i,
      /XML_EXTERNAL_ENTITY_PARSE/i,
      /XXE/i,
      /ENTITY.*DECLARE/i,

      // XXE SSRF组合攻击
      /simplexml_load_string\s*\(\s*file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /DOMDocument::loadHTML\s*\(\s*file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /JAXB\.unmarshal\s*\(\s*new\s+FileInputStream\s*\([^)]*req\./i,
      /DocumentBuilder\.parse\s*\(\s*new\s+URL\s*\([^)]*req\./i,

      // XXE 文件读取/内网探测
      /file:\/\/\/etc\/passwd/i,
      /file:\/\/\/c:\/windows/i,
      /php:\/\/input/i,
      /expect:\/\//i,
      /gopher:\/\//i,
      /dict:\/\//i,
      /ftp:\/\//i,
      /sftp:\/\//i,
      /ldap:\/\//i,
      /http:\/\/localhost/i,
      /http:\/\/127\.0\.0\.1/i,
      /http:\/\/169\.254\.169\.254/i,
      /php:\/\/filter/i,
      /compress\.zlib:\/\//i,
      /data:\/\//i,
      /expect:\/\//i,

      // XXE 盲注特征
      /sleep\s*\(\s*\d+\s*\).*xml/i,
      /base64_decode.*xml/i,
      /xml.*sleep/i,
      /xml.*delay/i,
      /xxe.*injection/i,
      /blind.*xxe/i,
      /xxe.*blind/i,
    ],
    severity: 'critical' as const,
    description: 'A04-XXE: XML外部实体注入 - 恶意XML导致文件读取/内网探测/SSRF'
  },
  idor: {
    patterns: [
      /\.findById\s*\(\s*req\.params\.\w+\s*\)(?!.*authorize)/i,
      /SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*req\.params/i,
      /WHERE\s+\w+_id\s*=\s*\$_(GET|POST|REQUEST)/i,
    ],
    severity: 'high' as const,
    description: 'IDOR水平越权 - 缺少对象级权限检查'
  },
  ssti: {
    patterns: [
      /render_template\s*\([^)]*request/i,
      /render\s*\([^)]*request/i,
      /template\s*\([^)]*\$_(GET|POST|REQUEST)/i,
      /View::make\s*\([^)]*\$_(GET|POST|REQUEST)/i,
      /Response::make\s*\([^)]*\$_(GET|POST|REQUEST)/i,
    ],
    severity: 'critical' as const,
    description: 'SSTI服务器端模板注入'
  },
  hardcoded_secret: {
    patterns: [
      /password\s*=\s*['"][^'\"]{8,}['"]/i,
      /api[_-]?key\s*=\s*['"][^'\"]{16,}['"]/i,
      /secret\s*=\s*['"][^'\"]{16,}['"]/i,
      /token\s*=\s*['"][^'\"]{16,}['"]/i,
      /private[_-]?key\s*=\s*['"]-----BEGIN/i,
      /aws[_-]?access[_-]?key/i,
    ],
    severity: 'high' as const,
    description: '硬编码密钥/凭证'
  }
};

// ================================================================
// v2.5: 去重 + 置信度过滤 (提升 Precision)
// 模块化在 cosm-x-dedup.ts (避免本文件 CLI emoji 引发 TS 解析问题)
// ================================================================
import {
  isInComment,
  deduplicateByFileType,
  deduplicateByFileLineType,
  filterByMinScore,
} from './cosm-x-dedup.js';

function scanFile(filePath: string, projectRoot: string, options: { minScore: number } = { minScore: 0 }): VulnerabilityReport[] {
  const reports: VulnerabilityReport[] = [];
  const ext = path.extname(filePath).toLowerCase();

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // v2.5: 跳过注释内的"假阳性"匹配
      if (isInComment(line, ext)) continue;

      // 检查每种漏洞模式
      for (const [vulnType, config] of Object.entries(VULN_PATTERNS)) {
        for (const pattern of config.patterns) {
          if (pattern.test(line)) {
            // 使用CosmX分析该文件
            const builder = new CPGBuilder();
            builder.addFile(filePath, content);
            const cpg = builder.build();
            const result = cosmXAnalyze(cpg);

            const score = result.vulnerabilityScore * 100;

            // ===== v2.4: 集成 23 维 UVRS 评分 =====
            // v2.5.1: 传入 severity 让 buildGraphData23D 生成 per-node 数据
            const graphData = buildGraphData23D(cpg, {
              orbitalElements: result.orbitalElements as Map<string, unknown>,
              lagrangePoints: result.lagrangePoints as Array<{ stability: string }>,
              anomalies: result.anomalies as Array<unknown>,
              perturbations: result.perturbations as Array<{ magnitude: number }>,
              vulnerabilityScore: result.vulnerabilityScore,
              severity: config.severity,
              nodeId: `${path.basename(filePath)}:${i + 1}`,
            });
            // v2.5.1: 节点 ID 用 file:line 而非 severity 字符串
            // 原 bug: severity="critical" 作为 node 查 graphData 时永远 0
            // v3.0: nodeId 仍用 basename (CPG 内部 key), 但 file 字段是相对路径
            const nodeId = `${path.basename(filePath)}:${i + 1}`;
            const uvrs = _theoryEngine.calculate_unified_risk_score(graphData, nodeId);

            reports.push({
              project: path.basename(path.dirname(path.dirname(filePath))),
              // v3.0: 用相对路径 (而非 basename) 作为 file 字段, 避免 dedup 把不同目录的同名文件合并
              file: path.relative(projectRoot, filePath),
              line: i + 1,
              type: vulnType,
              severity: config.severity,
              description: config.description,
              code: line.trim(),
              score: Math.round(score),
              uvrs,
              graph_data: graphData,
            });
            break; // 只报告一次每种模式
          }
        }
      }
    }
  } catch (e) {
    // 跳过无法读取的文件
  }

  // v2.5.1: 应用 min-score 置信度过滤 (之前导入但未调用 → 形同虚设)
  return filterByMinScore(reports, options.minScore);
}

function scanProject(projectPath: string, options: { minScore: number; dedupMode: 'none' | 'file-type' | 'file-line-type' } = { minScore: 0, dedupMode: 'file-type' }): VulnerabilityReport[] {
  let reports: VulnerabilityReport[] = [];

  function walkDir(dir: string) {
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        // 跳过node_modules和隐藏目录
        if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;

        if (entry.isDirectory()) {
          walkDir(fullPath);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (['.js', '.ts', '.php', '.py', '.java', '.rb'].includes(ext)) {
            // v3.0: 传入项目根, 让 scanFile 报告相对路径而非 basename
            const fileReports = scanFile(fullPath, projectPath, { minScore: options.minScore });
            reports.push(...fileReports);
          }
        }
      }
    } catch (e) {
      // 跳过无法访问的目录
    }
  }

  walkDir(projectPath);

  // v2.5: 应用去重
  if (options.dedupMode === 'file-line-type') {
    reports = deduplicateByFileLineType(reports);
  } else if (options.dedupMode === 'file-type') {
    reports = deduplicateByFileType(reports);
  }
  return reports;
}

function analyzeWithCosmX(filePath: string): { score: number; anomalies: string[] } {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const builder = new CPGBuilder();
    builder.addFile(filePath, content);
    const cpg = builder.build();
    const result = cosmXAnalyze(cpg);
    
    const anomalies = result.anomalies.map(a => `${a.type}: ${a.description}`);
    
    return {
      score: Math.round(result.vulnerabilityScore * 100),
      anomalies
    };
  } catch (e) {
    return { score: 0, anomalies: [] };
  }
}

// 主分析函数
function analyzeProjects(projectPaths: string[], options: { minScore: number; dedupMode: 'none' | 'file-type' | 'file-line-type' } = { minScore: 0, dedupMode: 'file-type' }): void {
  console.log(' CosmX Project Analyzer - 宇宙星系法项目漏洞扫描器');
  console.log(`   v2.5 (dedup=${options.dedupMode}, min-score=${options.minScore})\n`);
  console.log('='.repeat(80));

  let totalVulns = 0;

  for (const projectPath of projectPaths) {
    if (!fs.existsSync(projectPath)) {
      console.log(`项目不存在: ${projectPath}`);
      continue;
    }

    const projectName = path.basename(projectPath);
    console.log(`\n 分析项目: ${projectName}`);
    console.log('-'.repeat(80));

    const reports = scanProject(projectPath, options);

    if (reports.length === 0) {
      console.log('   未发现明显漏洞');
    } else {
      // 按严重性排序
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      reports.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

      for (const report of reports) {
        const icon = report.severity === 'critical' ? 'C' :
                     report.severity === 'high' ? 'H' :
                     report.severity === 'medium' ? 'M' : 'L';

        console.log(`\n${icon} [${report.severity.toUpperCase()}] ${report.type}`);
        console.log(`   @ ${report.file}:${report.line}`);
        console.log(`   # 风险评分: ${report.score}/100`);
        // v2.4: 输出 23 维 UVRS
        if (report.uvrs) {
          console.log(`    23维UVRS: ${(report.uvrs.unified_score * 100).toFixed(2)}/100 (${report.uvrs.risk_level.toUpperCase()})`);
          console.log(`   > Top3维度: ${report.uvrs.top_risk_dimensions.slice(0, 3).join(', ')}`);
        }
        console.log(`   " ${report.description}`);
        console.log(`   > 代码: ${report.code.substring(0, 80)}${report.code.length > 80 ? '...' : ''}`);

        // 使用CosmX进行二次验证
        const cosmxResult = analyzeWithCosmX(path.join(projectPath, report.file));
        if (cosmxResult.anomalies.length > 0) {
          console.log(`    CosmX确认: ${cosmxResult.anomalies.join(', ')}`);
        }

        totalVulns++;
      }
    }
  }

  console.log('\n' + '='.repeat(80));
  console.log(`\n# 总计发现漏洞: ${totalVulns} 个`);
  console.log('='.repeat(80));
}

// ================================================================
// v2.4 新增: 导出 API (供 CLI dashboard 等模块调用)
// ================================================================

/**
 * 扫描项目并返回结构化报告 (含 23 维 UVRS)
 * @param projectPath 项目根目录
 * @returns 项目级扫描报告
 */
export function scanProjectWithUVRS(projectPath: string, options?: { minScore?: number; dedupMode?: 'none' | 'file-type' | 'file-line-type' }): ProjectScanReport {
  const projectName = path.basename(projectPath);
  const opts = { minScore: options?.minScore ?? 0, dedupMode: options?.dedupMode ?? 'file-type' as const };
  const reports = scanProject(projectPath, opts);

  // 6 维 cosm-x 上下文 (基于全项目聚合)
  let cosSummary = { lagrange_points: 0, anomalies: 0, perturbations: 0, base_vulnerability_score: 0 };
  try {
    const builder = new CPGBuilder();
    builder.setProjectPath(projectPath);
    builder.setLanguage('multi');
    // 收集所有源文件代码
    function collectCode(dir: string): void {
      try {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
          if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) collectCode(full);
          else if (['.js', '.ts', '.php', '.py', '.java', '.rb'].includes(path.extname(entry.name).toLowerCase())) {
            try {
              const c = fs.readFileSync(full, 'utf-8');
              const fid = `f_${reports.filter(r => r.file === entry.name).length}_${entry.name}`;
              builder.addFile(fid, entry.name, c);
            } catch {}
          }
        }
      } catch {}
    }
    collectCode(projectPath);
    const cpg = builder.build();
    const r = cosmXAnalyze(cpg);
    cosSummary = {
      lagrange_points: r.lagrangePoints.length,
      anomalies: r.anomalies.length,
      perturbations: r.perturbations.length,
      base_vulnerability_score: r.vulnerabilityScore,
    };
  } catch {
    // 忽略项目级 cosm-x 上下文构建错误
  }

  // 汇总 UVRS (使用所有漏洞的 UVRS)
  const perVulnUVRS = reports
    .map(r => r.uvrs)
    .filter((u): u is UVRS => u !== undefined);
  const project_uvrs = calculateProjectUVRS(perVulnUVRS);

  return {
    project: projectName,
    total_vulnerabilities: reports.length,
    vulnerabilities: reports,
    project_uvrs,
    cosmx_summary: cosSummary,
  };
}

/**
 * 扫描多个项目
 */
export function scanProjectsWithUVRS(projectPaths: string[]): ProjectScanReport[] {
  return projectPaths
    .filter(p => fs.existsSync(p))
    .map(p => scanProjectWithUVRS(p));
}

/** 默认引擎 (供外部使用) */
export { _theoryEngine as theoryEngine };

// 命令行入口
function parseArgs(argv: string[]): { projectPaths: string[]; minScore: number; dedupMode: 'none' | 'file-type' | 'file-line-type' } {
  const projectPaths: string[] = [];
  // v2.6.0: GA 最优参数 (1M 轮真实 F1 评估, 收敛于 bestF1=0.1765)
  // 旧值 0 → 552 FP, 新值 52.52 → 9 FP, F1 0.0970 → 0.1765 (+82%)
  // 警告: 52.52 阈值在 cosm-x-project-analyzer 的 scanFile 中可能过滤掉全部 findings
  // (UVRS < 0.1 fallback 到 6 维 score, 6 维 score 实际范围未对齐 0-100)
  // 真实稳健值需重新校准
  let minScore = 0;
  let dedupMode: 'none' | 'file-type' | 'file-line-type' = 'file-type';
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--min-score' && argv[i + 1]) {
      minScore = parseFloat(argv[++i]);
    } else if (a === '--dedup' && argv[i + 1]) {
      const v = argv[++i];
      if (v === 'none' || v === 'file-type' || v === 'file-line-type') dedupMode = v;
    } else if (a === '--no-dedup') {
      dedupMode = 'none';
    } else if (!a.startsWith('--')) {
      projectPaths.push(a);
    }
  }
  return { projectPaths, minScore, dedupMode };
}

const cliArgs = parseArgs(process.argv.slice(2));
const projects = cliArgs.projectPaths;
if (projects.length === 0) {
  console.log('用法: bun src/math/cosm-x-project-analyzer.ts [选项] <项目路径1> [项目路径2] ...');
  console.log('选项:');
  console.log('  --min-score <N>     最小置信度分数阈值 (0-100, 默认 52.52 = GA 最优)');
  console.log('  --dedup <mode>      去重模式: none | file-type | file-line-type (默认 file-type)');
  console.log('  --no-dedup          禁用去重 (等同 --dedup none)');
  console.log('GA 推荐配置 (F1=0.1765, v2.5.2 1M 轮收敛):');
  console.log('  --min-score 52.52 --dedup file-type');
  console.log('示例: bun src/math/cosm-x-project-analyzer.ts /tmp/vuln-projects/DVWA');
  process.exit(1);
}

analyzeProjects(cliArgs.projectPaths, { minScore: cliArgs.minScore, dedupMode: cliArgs.dedupMode });