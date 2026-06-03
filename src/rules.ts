import { SecurityRule, RuleContext, AstNode } from "./types";

const SENSITIVE_KEYWORDS = [
  "token",
  "password",
  "passwd",
  "pwd",
  "pws",
  "pwsd",
  "secret",
  "key",
  "jwt",
  "auth",
  "credential",
  "api_key",
  "apikey",
  "access_token",
  "private_key",
  " bearer",
];

const HARDCODED_CREDENTIAL_KEYWORDS = [
  "password",
  "passwd",
  "pwd",
  "pws",
  "pwsd",
  "secret",
  "token",
  "api_key",
  "apikey",
  "access_token",
  "auth_token",
  "credentials",
  "private_key",
  "secret_key",
  "jwt_secret",
  "app_secret",
  "db_password",
  "database_password",
  "redis_password",
  "mysql_password",
];

const CONSOLE_SENSITIVE_KEYWORDS = [
  "token",
  "password",
  "passwd",
  "pwd",
  "pws",
  "pwsd",
  "secret",
  "key",
  "jwt",
  "credential",
  "authorization",
];

const INTERNAL_IP_PATTERN =
  /https?:\/\/(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost)/;

/** 辅助：安全访问嵌套属性 */
function get(obj: unknown, ...keys: string[]): unknown {
  let cur: unknown = obj;
  for (const k of keys) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[k];
  }
  return cur;
}

function hasSensitiveKey(node: AstNode): boolean {
  if (node.type === "MemberExpression" && node.property) {
    const propName = (get(node, "property", "name") ||
      get(node, "property", "value")) as string | undefined;
    if (typeof propName === "string") {
      const lower = propName.toLowerCase();
      return SENSITIVE_KEYWORDS.some((k) => lower.includes(k));
    }
  }
  return false;
}

function getCallExprName(node: AstNode): string | null {
  const callee = node.callee as AstNode | undefined;
  if (!callee) return null;

  if (callee.type === "MemberExpression") {
    const obj = callee.object as AstNode | undefined;
    const prop = callee.property as AstNode | undefined;
    if (obj && prop) {
      const objName = ((obj.name as string) || (get(obj, "callee", "name") as string) || "") as string;
      const propName = ((prop.name as string) || (prop.value as string) || "") as string;
      return `${objName}.${propName}`;
    }
  }
  if (callee.type === "Identifier") {
    return callee.name as string;
  }
  return null;
}

/** 检查节点是否在 fetch/axios/request 等网络请求上下文中 */
function isInNetworkRequestContext(node: AstNode): boolean {
  const parent = node.parent as AstNode | undefined;
  if (!parent) return false;

  // 检查父级 CallExpression
  if (parent.type === "CallExpression") {
    const name = getCallExprName(parent);
    if (name && /^(fetch|axios|request|get|post|put|delete|patch|head)\b/.test(name)) {
      return true;
    }
  }
  // 检查祖父级（参数传递）
  const grandParent = parent.parent as AstNode | undefined;
  if (grandParent?.type === "CallExpression") {
    const name = getCallExprName(grandParent);
    if (name && /^(fetch|axios|request|get|post|put|delete|patch|head)\b/.test(name)) {
      return true;
    }
  }
  return false;
}

export const rules: SecurityRule[] = [
  {
    name: "xss-v-html",
    severity: "high",
    message:
      "潜在的XSS风险：检测到v-html指令。用户输入的内容直接插入HTML可能导致XSS攻击。",
    fix: "使用 v-text 或 {{ }} 插值代替 v-html；若必须渲染HTML，请先用 DOMPurify.sanitize() 过滤。",
    match: (node, context) => {
      // 此规则主要在 scanner.ts 的 scanVueTemplate 中通过正则检测
      // AST 匹配作为后备
      if (node.type !== "DirectiveLiteral") return false;
      const parent = node.parent as AstNode | undefined;
      if (!parent || parent.type !== "Directive") return false;
      const grandParent = parent.parent as AstNode | undefined;
      if (!grandParent || grandParent.type !== "Element") return false;
      return (grandParent.name as string) === "v-html";
    },
  },
  {
    name: "xss-dangerously-set-inner-html",
    severity: "high",
    message:
      "潜在的XSS风险：检测到dangerouslySetInnerHTML。避免从用户输入中设置原始HTML。",
    fix: "使用 DOMPurify.sanitize() 对 HTML 内容消毒后再传入，或改用安全的文本渲染方式。",
    match: (node) => {
      if (node.type !== "JSXAttribute") return false;
      return (node.name as AstNode)?.name === "dangerouslySetInnerHTML";
    },
  },
  {
    name: "xss-innerHTML-assignment",
    severity: "high",
    message:
      "潜在的XSS风险：检测到innerHTML赋值。用户输入的内容直接插入HTML可能导致XSS攻击。",
    fix: "使用 textContent 代替 innerHTML；若需渲染HTML，请先用 DOMPurify.sanitize() 过滤用户输入。",
    match: (node) => {
      if (node.type !== "AssignmentExpression") return false;
      const left = node.left as AstNode | undefined;
      if (!left || left.type !== "MemberExpression") return false;
      const prop = left.property as AstNode | undefined;
      if (!prop) return false;
      const propName = (prop.name || prop.value) as string;
      return propName === "innerHTML";
    },
  },
  {
    name: "unsafe-location-href",
    severity: "medium",
    message: "潜在的开放重定向风险：location.href赋值使用了潜在的不可信输入。",
    fix: "对 URL 进行白名单校验，确保只跳转到可信域名；或使用 new URL() 解析后检查 hostname。",
    match: (node) => {
      if (node.type !== "AssignmentExpression") return false;
      const left = node.left as AstNode | undefined;
      if (!left || left.type !== "MemberExpression") return false;
      const obj = left.object as AstNode | undefined;
      const prop = left.property as AstNode | undefined;
      if (!obj || !prop) return false;
      const objName = (obj.name as string) || "";
      const propName = ((prop.name || prop.value) as string) || "";
      return objName === "location" && propName === "href";
    },
  },
  {
    name: "unsafe-window-open",
    severity: "medium",
    message: "潜在的开放重定向风险：window.open使用了潜在的不可信URL输入。",
    fix: "对 URL 参数进行白名单验证，确保只打开可信域名的页面。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      return name === "window.open";
    },
  },
  {
    name: "unsafe-link-target",
    severity: "low",
    message: '外部链接应包含rel="noopener noreferrer"以防止安全问题。',
    fix: '为带有 target="_blank" 的链接添加 rel="noopener noreferrer" 属性。',
    match: (node) => {
      if (node.type !== "JSXAttribute") return false;
      if ((node.name as AstNode)?.name !== "target") return false;
      const value = ((node.value as AstNode)?.value ||
        (get(node, "value", "expression", "value"))) as string | undefined;
      return value === "_blank";
    },
  },
  {
    name: "sensitive-storage-localStorage",
    severity: "high",
    message:
      "在localStorage中检测到敏感数据。确保对敏感令牌/密钥使用加密存储。",
    fix: "避免在 localStorage 中存储 token/密码；改用 httpOnly cookie 或加密后存储，清除时使用 removeItem。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      if (name !== "localStorage.setItem") return false;
      if (!node.arguments || (node.arguments as unknown[]).length < 2) return false;
      const args = node.arguments as AstNode[];
      const keyArg = args[0];
      let keyValue = "";
      if (keyArg.type === "StringLiteral") {
        keyValue = keyArg.value as string;
      } else if (keyArg.type === "Literal" && typeof keyArg.value === "string") {
        keyValue = keyArg.value as string;
      }
      if (!keyValue) return false;
      const lower = keyValue.toLowerCase();
      return SENSITIVE_KEYWORDS.some((k) => lower.includes(k));
    },
  },
  {
    name: "sensitive-storage-sessionStorage",
    severity: "high",
    message:
      "在sessionStorage中检测到敏感数据。确保对敏感令牌/密钥使用加密存储。",
    fix: "避免在 sessionStorage 中直接存储敏感信息；改用 httpOnly cookie 或对数据加密后存储。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      if (name !== "sessionStorage.setItem") return false;
      // 修复：与 localStorage 规则一致，必须检查 key 是否包含敏感关键词
      if (!node.arguments || (node.arguments as unknown[]).length < 2) return false;
      const args = node.arguments as AstNode[];
      const keyArg = args[0];
      let keyValue = "";
      if (keyArg.type === "StringLiteral") {
        keyValue = keyArg.value as string;
      } else if (keyArg.type === "Literal" && typeof keyArg.value === "string") {
        keyValue = keyArg.value as string;
      }
      if (!keyValue) return false;
      const lower = keyValue.toLowerCase();
      return SENSITIVE_KEYWORDS.some((k) => lower.includes(k));
    },
  },
  {
    name: "dangerous-eval",
    severity: "high",
    message: "危险的API：eval()可以执行任意代码。避免使用eval与不可信输入。",
    fix: "使用 JSON.parse()、Function 构造器的安全替代方案、或重构逻辑避免动态代码执行。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      return name === "eval";
    },
  },
  {
    name: "dangerous-new-function",
    severity: "high",
    message:
      "危险的API：new Function()可以执行任意代码。考虑使用更安全的替代方案。",
    fix: "避免使用 new Function() 动态创建函数；改用预定义函数映射或安全的表达式解析库。",
    match: (node) => {
      if (node.type !== "CallExpression" && node.type !== "NewExpression")
        return false;
      const name = getCallExprName(node);
      return name === "Function";
    },
  },
  {
    name: "dangerous-settimeout-string",
    severity: "medium",
    message: "危险的API：setTimeout与字符串参数一起使用可能导致代码注入。",
    fix: "将字符串参数改为箭头函数或函数引用：setTimeout(() => { ... }, delay)。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      if (name !== "setTimeout" && name !== "setInterval") return false;
      if (!node.arguments || (node.arguments as unknown[]).length === 0) return false;
      const args = node.arguments as AstNode[];
      const firstArg = args[0];
      const safeTypes = [
        "FunctionExpression",
        "ArrowFunctionExpression",
        "MemberExpression",
      ];
      if (safeTypes.includes(firstArg.type)) return false;
      if (firstArg.type === "Identifier") return false;
      if (firstArg.type === "CallExpression") return false;
      return true;
    },
  },
  {
    name: "hardcoded-credentials",
    severity: "high",
    message:
      "检测到硬编码的账号密码/凭证信息。请勿在代码中明文存储敏感凭证，应使用环境变量或密钥管理服务。",
    fix: "将凭证迁移到 .env 文件并通过 import.meta.env 引用；生产环境使用密钥管理服务（如 Vault、AWS Secrets Manager）。",
    match: (node) => {
      // 检测变量声明中的硬编码凭证: const password = "xxx"
      if (node.type === "VariableDeclarator") {
        const varName = ((node.id as AstNode)?.name as string) || "";
        const lower = varName.toLowerCase();
        const isSensitiveName = HARDCODED_CREDENTIAL_KEYWORDS.some((k) =>
          lower.includes(k),
        );
        if (!isSensitiveName) return false;
        const init = node.init as AstNode | undefined;
        if (!init) return false;
        // 排除空字符串和环境变量引用
        if (
          init.type === "StringLiteral" &&
          init.value &&
          (init.value as string).length > 0 &&
          (init.value as string).length < 3
        )
          return false; // 空或极短字符串不算硬编码
        if (
          init.type === "StringLiteral" &&
          init.value &&
          (init.value as string).length >= 3
        )
          return true;
        if (init.type === "TemplateLiteral") return true;
        return false;
      }
      // 检测对象属性中的硬编码凭证: { password: "xxx" }
      if (node.type === "ObjectProperty" || node.type === "Property") {
        const key = node.key as AstNode | undefined;
        let keyName = "";
        if (key?.type === "Identifier") keyName = key.name as string;
        else if (key?.type === "StringLiteral") keyName = key.value as string;
        if (!keyName) return false;
        const lower = keyName.toLowerCase();
        const isSensitiveName = HARDCODED_CREDENTIAL_KEYWORDS.some((k) =>
          lower.includes(k),
        );
        if (!isSensitiveName) return false;
        const value = node.value as AstNode | undefined;
        if (!value) return false;
        if (
          value.type === "StringLiteral" &&
          value.value &&
          (value.value as string).length >= 3
        )
          return true;
        if (value.type === "TemplateLiteral") return true;
        return false;
      }
      // 检测赋值表达式中的硬编码凭证: this.password = "xxx"
      if (node.type === "AssignmentExpression") {
        const left = node.left as AstNode | undefined;
        let propName = "";
        if (left?.type === "MemberExpression" && left.property) {
          propName =
            ((left.property as AstNode).name as string) ||
            ((left.property as AstNode).value as string) ||
            "";
        } else if (left?.type === "Identifier") {
          propName = (left.name as string) || "";
        }
        if (!propName) return false;
        const lower = propName.toLowerCase();
        const isSensitiveName = HARDCODED_CREDENTIAL_KEYWORDS.some((k) =>
          lower.includes(k),
        );
        if (!isSensitiveName) return false;
        const right = node.right as AstNode | undefined;
        if (!right) return false;
        if (
          right.type === "StringLiteral" &&
          right.value &&
          (right.value as string).length >= 3
        )
          return true;
        if (right.type === "TemplateLiteral") return true;
        return false;
      }
      return false;
    },
  },
  {
    name: "unsafe-math-random",
    severity: "medium",
    message:
      "不安全的随机数：Math.random()不应用于生成token、验证码等安全场景，应使用crypto.getRandomValues()。",
    fix: "替换为 crypto.getRandomValues(new Uint32Array(1))[0] 或使用 uuid 库生成安全随机值。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      return name === "Math.random";
    },
  },
  {
    name: "xss-document-write",
    severity: "high",
    message:
      "潜在的XSS风险：document.write()可被利用进行XSS攻击，避免使用该API。",
    fix: "使用 document.createElement() + appendChild() 或框架的模板渲染方式代替 document.write。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      return name === "document.write" || name === "document.writeln";
    },
  },
  {
    name: "unsafe-postmessage-handler",
    severity: "medium",
    message:
      "postMessage事件监听缺少来源验证：应检查event.origin以防止接收恶意跨域消息。",
    fix: "在 message 事件回调中添加 if (event.origin !== 'https://trusted-domain.com') return; 进行来源校验。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      if (name !== "window.addEventListener" && name !== ".addEventListener")
        return false;
      if (!node.arguments || (node.arguments as unknown[]).length < 2) return false;
      const args = node.arguments as AstNode[];
      const firstArg = args[0];
      let eventName = "";
      if (firstArg.type === "StringLiteral") eventName = firstArg.value as string;
      else if (firstArg.type === "Literal" && typeof firstArg.value === "string")
        eventName = firstArg.value as string;
      return eventName === "message";
    },
  },
  {
    name: "unsafe-http-url",
    severity: "medium",
    message:
      "检测到HTTP明文传输：敏感数据应通过HTTPS传输，避免使用http://协议。",
    fix: "将 URL 协议从 http:// 改为 https://；或使用协议相对 URL（//domain.com）。",
    match: (node) => {
      if (node.type !== "StringLiteral") return false;
      const value = (node.value as string) || "";
      if (!value.startsWith("http://")) return false;
      // 排除 localhost 开发环境
      if (value.includes("localhost") || value.includes("127.0.0.1"))
        return false;
      // 只在 fetch/axios/request 等网络请求调用的参数中检测，降低误报
      return isInNetworkRequestContext(node);
    },
  },
  {
    name: "unsafe-iframe-no-sandbox",
    severity: "medium",
    message:
      "iframe缺少sandbox属性：嵌入外部页面应添加sandbox限制以防止安全风险。",
    fix: '添加 sandbox 属性限制 iframe 能力：<iframe sandbox="allow-scripts allow-same-origin" ...>。',
    match: (node) => {
      if (node.type !== "JSXOpeningElement") return false;
      const elementName = (node.name as AstNode)?.name as string;
      if (elementName !== "iframe") return false;
      const attributes = (node.attributes as AstNode[]) || [];
      const hasSandbox = attributes.some(
        (attr: AstNode) =>
          attr.type === "JSXAttribute" &&
          (attr.name as AstNode)?.name === "sandbox",
      );
      return !hasSandbox;
    },
  },
  {
    name: "redos-vulnerable-regex",
    severity: "medium",
    message:
      "潜在的正则表达式DoS（ReDoS）风险：嵌套量词可能导致灾难性回溯，应简化正则。",
    fix: "避免嵌套量词（如 (a+)+）；使用原子分组或改写为非回溯的等价表达式；考虑使用 re2 库。",
    match: (node) => {
      if (node.type !== "RegExpLiteral") return false;
      const pattern = (node.pattern as string) || "";
      // 检测嵌套量词模式，如 (a+)+, (a*)+, (a+)*, ([^x]+)+ 等
      const nestedQuantifiers =
        /(\([^)]*[+*][^)]*\))[+*]|\(\?:[^)]*[+*][^)]*\)[+*]/;
      if (nestedQuantifiers.test(pattern)) return true;
      // 检测多个重叠的 .* 或 .+ 模式
      const overlapping = /(\.\*.*\.\*)|(\.\+.*\.\+)/;
      if (overlapping.test(pattern)) return true;
      return false;
    },
  },
  {
    name: "xss-outerhtml-assignment",
    severity: "high",
    message:
      "潜在的XSS风险：检测到outerHTML赋值。与innerHTML类似，直接插入HTML可能导致XSS攻击。",
    fix: "使用 textContent 或 DOM API（createElement + replaceWith）代替 outerHTML 赋值。",
    match: (node) => {
      if (node.type !== "AssignmentExpression") return false;
      const left = node.left as AstNode | undefined;
      if (!left || left.type !== "MemberExpression") return false;
      const prop = left.property as AstNode | undefined;
      if (!prop) return false;
      const propName = (prop.name || prop.value) as string;
      return propName === "outerHTML";
    },
  },
  {
    name: "unsafe-cookie-operation",
    severity: "medium",
    message:
      "不安全的cookie操作：通过document.cookie直接操作cookie缺少secure/httpOnly保护，应通过后端Set-Cookie设置安全标志。",
    fix: "改由后端通过 Set-Cookie 响应头设置 cookie，并添加 Secure; HttpOnly; SameSite=Strict 标志。",
    match: (node) => {
      if (node.type !== "AssignmentExpression") return false;
      const left = node.left as AstNode | undefined;
      if (!left || left.type !== "MemberExpression") return false;
      const obj = left.object as AstNode | undefined;
      const prop = left.property as AstNode | undefined;
      if (!obj || !prop) return false;
      const objName = (obj.name as string) || "";
      const propName = ((prop.name || prop.value) as string) || "";
      return objName === "document" && propName === "cookie";
    },
  },
  {
    name: "unsafe-dynamic-import",
    severity: "medium",
    message:
      "动态import使用了变量参数：可能导致任意模块加载，应使用静态路径或白名单校验。",
    fix: "使用静态字符串路径 import('./modules/xxx')；若必须动态加载，维护允许的模块白名单并校验。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const callee = node.callee as AstNode | undefined;
      if (!callee || callee.type !== "Import") return false;
      if (!node.arguments || (node.arguments as unknown[]).length === 0) return false;
      const args = node.arguments as AstNode[];
      const arg = args[0];
      // 如果参数是字符串字面量则安全
      if (arg.type === "StringLiteral") return false;
      // 如果是模板字面量且没有表达式部分也安全
      if (
        arg.type === "TemplateLiteral" &&
        (!(arg.expressions as unknown[]) || (arg.expressions as unknown[]).length === 0)
      )
        return false;
      return true;
    },
  },
  {
    name: "console-sensitive-info",
    severity: "low",
    message:
      "console输出可能包含敏感信息：生产环境中不应打印token、密码等敏感数据。",
    fix: "移除含敏感信息的 console 输出；使用 vite-plugin-remove-console 在生产构建时自动清除。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      if (
        name !== "console.log" &&
        name !== "console.warn" &&
        name !== "console.error" &&
        name !== "console.info" &&
        name !== "console.debug"
      )
        return false;
      if (!node.arguments || (node.arguments as unknown[]).length === 0) return false;
      // 检查参数中是否包含敏感关键词
      for (const arg of node.arguments as AstNode[]) {
        if (arg.type === "StringLiteral") {
          const lower = ((arg.value as string) || "").toLowerCase();
          if (CONSOLE_SENSITIVE_KEYWORDS.some((k) => lower.includes(k)))
            return true;
        }
        if (arg.type === "TemplateLiteral" && arg.quasis) {
          for (const quasi of arg.quasis as AstNode[]) {
            const lower = (((quasi.value as AstNode)?.raw as string) || "").toLowerCase();
            if (CONSOLE_SENSITIVE_KEYWORDS.some((k) => lower.includes(k)))
              return true;
          }
        }
        // 检查变量名是否包含敏感关键词
        if (arg.type === "Identifier") {
          const lower = ((arg.name as string) || "").toLowerCase();
          if (CONSOLE_SENSITIVE_KEYWORDS.some((k) => lower.includes(k)))
            return true;
        }
      }
      return false;
    },
  },
  {
    name: "prototype-pollution",
    severity: "medium",
    message:
      "潜在的原型链污染风险：Object.assign合并不可信数据时应过滤__proto__、constructor等危险属性。",
    fix: "使用 Object.create(null) 作为目标对象；或在合并前过滤 __proto__、constructor、prototype 属性。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      if (name !== "Object.assign") return false;
      if (!node.arguments || (node.arguments as unknown[]).length < 2) return false;
      // 降低误报：只在目标对象为空对象字面量 {} 时才报告
      const args = node.arguments as AstNode[];
      const target = args[0];
      if (target?.type === "ObjectExpression") {
        const properties = target.properties as unknown[] | undefined;
        if (properties && properties.length === 0) return true;
      }
      return false;
    },
  },
  {
    name: "hardcoded-internal-ip",
    severity: "low",
    message:
      "检测到硬编码的内网地址/IP：暴露内部基础设施信息，应使用环境变量配置服务地址。",
    fix: "将内网地址迁移到 .env 文件中通过 import.meta.env.VITE_API_URL 引用，避免代码中硬编码。",
    match: (node) => {
      if (node.type !== "StringLiteral") return false;
      const value = (node.value as string) || "";
      return INTERNAL_IP_PATTERN.test(value);
    },
  },

  // ========== 新增高严重等级规则 ==========

  {
    name: "xss-insertAdjacentHTML",
    severity: "high",
    message:
      "潜在的XSS风险：insertAdjacentHTML()可将未经过滤的HTML插入DOM，与innerHTML同样危险。",
    fix: "使用 textContent 或 createElement + appendChild 代替；若必须插入HTML，请先用 DOMPurify.sanitize() 过滤。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      return name === ".insertAdjacentHTML" || (name != null && name.endsWith(".insertAdjacentHTML"));
    },
  },
  {
    name: "unsafe-postmessage-wildcard",
    severity: "high",
    message:
      "postMessage 使用通配符 '*' 作为目标源：可能将敏感数据泄露给任意页面，应指定明确的目标 origin。",
    fix: "将 postMessage 的第二个参数从 '*' 改为具体的目标域名，如 'https://trusted-domain.com'。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      if (name !== "window.postMessage" && name !== ".postMessage") return false;
      if (!node.arguments || (node.arguments as unknown[]).length < 2) return false;
      const args = node.arguments as AstNode[];
      // 检查第二个参数是否为 '*'
      const targetOrigin = args[1];
      if (targetOrigin.type === "StringLiteral" && targetOrigin.value === "*") return true;
      return false;
    },
  },
  {
    name: "prototype-pollution-__proto__",
    severity: "high",
    message:
      "检测到直接操作 __proto__ 属性：可导致原型链污染攻击，影响所有对象的属性继承。",
    fix: "避免直接操作 __proto__；使用 Object.create(null) 创建纯净对象，或用 Object.getPrototypeOf/Object.setPrototypeOf 替代。",
    match: (node) => {
      // 检测 obj.__proto__ = xxx 或 obj['__proto__'] = xxx
      if (node.type === "AssignmentExpression") {
        const left = node.left as AstNode | undefined;
        if (!left) return false;
        if (left.type === "MemberExpression") {
          const prop = left.property as AstNode | undefined;
          if (!prop) return false;
          const propName = (prop.name || prop.value) as string;
          if (propName === "__proto__") return true;
        }
      }
      // 检测 Object.defineProperty(obj, '__proto__', ...)
      if (node.type === "CallExpression") {
        const name = getCallExprName(node);
        if (name === "Object.defineProperty" || name === "Object.defineProperties") {
          const args = node.arguments as AstNode[];
          if (args && args.length >= 2) {
            const propArg = args[1];
            if (propArg.type === "StringLiteral" && propArg.value === "__proto__") return true;
          }
        }
      }
      return false;
    },
  },
  {
    name: "dangerous-dom-script-injection",
    severity: "high",
    message:
      "动态创建 script 元素并设置 src 属性：可被利用加载外部恶意脚本，造成XSS攻击。",
    fix: "避免动态创建 script 元素；如需加载外部脚本，使用静态 <script> 标签配合 SRI integrity 属性。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      if (name !== "document.createElement") return false;
      if (!node.arguments || (node.arguments as unknown[]).length === 0) return false;
      const args = node.arguments as AstNode[];
      const tagName = args[0];
      if (tagName.type !== "StringLiteral") return false;
      return (tagName.value as string).toLowerCase() === "script";
    },
  },
  {
    name: "unsafe-url-redirect",
    severity: "high",
    message:
      "检测到 location.replace()/location.assign() 调用：可能导致开放重定向攻击，应校验跳转目标。",
    fix: "对跳转 URL 进行白名单校验，确保只跳转到可信域名；使用 new URL() 解析后检查 hostname。",
    match: (node) => {
      if (node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      return (
        name === "location.replace" ||
        name === "location.assign" ||
        name === "window.location.replace" ||
        name === "window.location.assign"
      );
    },
  },
  {
    name: "unsafe-regexp-constructor",
    severity: "high",
    message:
      "使用 new RegExp() 动态构造正则表达式：若参数来自用户输入，可导致 ReDoS 攻击或正则注入。",
    fix: "避免使用 new RegExp(userInput)；若必须动态构建，对输入进行严格校验和转义（使用 lodash.escapeRegExp 等）。",
    match: (node) => {
      if (node.type !== "NewExpression" && node.type !== "CallExpression") return false;
      const name = getCallExprName(node);
      if (name !== "RegExp") return false;
      if (!node.arguments || (node.arguments as unknown[]).length === 0) return false;
      const args = node.arguments as AstNode[];
      const patternArg = args[0];
      // 如果参数是字符串字面量则安全（静态正则）
      if (patternArg.type === "StringLiteral") return false;
      // 变量、模板字面量等动态来源不安全
      return true;
    },
  },
];

export function getRules(): SecurityRule[] {
  return rules;
}

/**
 * 根据配置过滤规则
 * @param options.enableRules - 白名单模式，仅启用指定规则
 * @param options.disableRules - 黑名单模式，禁用指定规则
 * @param options.customRules - 追加自定义规则
 */
export function getFilteredRules(options: {
  enableRules?: string[];
  disableRules?: string[];
  customRules?: SecurityRule[];
}): SecurityRule[] {
  let filtered = [...rules];

  // 白名单模式：仅启用指定的规则
  if (options.enableRules && options.enableRules.length > 0) {
    filtered = filtered.filter((r) => options.enableRules!.includes(r.name));
  }

  // 黑名单模式：禁用指定的规则
  if (options.disableRules && options.disableRules.length > 0) {
    filtered = filtered.filter((r) => !options.disableRules!.includes(r.name));
  }

  // 追加自定义规则
  if (options.customRules && options.customRules.length > 0) {
    filtered = [...filtered, ...options.customRules];
  }

  return filtered;
}

export function matchRules(
  node: AstNode,
  context: RuleContext,
  activeRules?: SecurityRule[],
): SecurityRule | null {
  const rulesToCheck = activeRules || rules;
  for (const rule of rulesToCheck) {
    try {
      if (rule.match(node, context)) {
        return rule;
      }
    } catch (e) {
      // 规则执行异常时跳过，不影响其他规则
    }
  }
  return null;
}