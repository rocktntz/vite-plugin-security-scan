import { SecurityFinding } from "./types";
import * as fs from "fs";
import * as path from "path";

/**
 * 构建产物安全检查
 * 检测 source map 文件泄露和环境变量暴露
 */
export function checkBuildOutput(
  bundle: Record<string, any>,
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const [fileName, chunk] of Object.entries(bundle)) {
    // 检测 source map 文件
    if (fileName.endsWith(".map")) {
      findings.push({
        rule: "build-sourcemap-exposed",
        severity: "high",
        message:
          "构建产物中包含 source map 文件：生产环境暴露源码会导致代码逻辑泄露，建议配置 build.sourcemap = false 或设置为 'hidden'。",
        location: { file: fileName, line: 0, column: 0 },
      });
    }

    // 检测 JS 产物中的环境变量泄露
    if ((fileName.endsWith(".js") || fileName.endsWith(".mjs")) && chunk.code) {
      const code = chunk.code as string;

      // 检测未替换的 process.env 引用
      if (code.includes("process.env")) {
        findings.push({
          rule: "build-env-process-exposed",
          severity: "medium",
          message: `构建产物中存在 process.env 引用：可能导致服务端环境变量泄露到客户端 bundle。`,
          location: { file: fileName, line: 0, column: 0 },
        });
      }

      // 检测常见敏感环境变量模式
      const sensitivePatterns = [
        /["'](?:sk|pk)[-_](?:live|test|prod)[a-zA-Z0-9_-]{10,}["']/,
        /["'](?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}["']/,
        /["']AKIA[A-Z0-9]{16}["']/,
        /["'][a-zA-Z0-9+/]{40,}={0,2}["']/,
      ];

      for (const pattern of sensitivePatterns) {
        if (pattern.test(code)) {
          findings.push({
            rule: "build-secret-key-exposed",
            severity: "high",
            message: `构建产物中可能包含硬编码的密钥/令牌：请检查是否有敏感凭证被打包到客户端。`,
            location: { file: fileName, line: 0, column: 0 },
          });
          break;
        }
      }
    }
  }

  return findings;
}

/**
 * HTML 安全检查
 * 检测 SRI (Subresource Integrity)、CSP (Content Security Policy) 等
 */
export function checkHtmlSecurity(html: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // 检测外部 script 标签是否缺少 integrity 属性
  const scriptRegex =
    /<script[^>]*src\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*>/gi;
  let match: RegExpExecArray | null;

  while ((match = scriptRegex.exec(html)) !== null) {
    const fullTag = match[0];
    const src = match[1];

    // 跳过本地资源
    if (src.includes("localhost") || src.includes("127.0.0.1")) continue;

    if (!fullTag.includes("integrity")) {
      const line = html.substring(0, match.index).split("\n").length;
      findings.push({
        rule: "html-missing-sri",
        severity: "medium",
        message: `外部脚本缺少 integrity 属性（SRI）：${src}，可能遭受 CDN 供应链攻击。`,
        location: { file: "index.html", line, column: 0 },
      });
    }
  }

  // 检测外部 link[stylesheet] 是否缺少 integrity
  const linkRegex =
    /<link[^>]*href\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*rel\s*=\s*["']stylesheet["'][^>]*>|<link[^>]*rel\s*=\s*["']stylesheet["'][^>]*href\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*>/gi;

  while ((match = linkRegex.exec(html)) !== null) {
    const fullTag = match[0];
    const href = match[1] || match[2];

    if (href.includes("localhost") || href.includes("127.0.0.1")) continue;

    if (!fullTag.includes("integrity")) {
      const line = html.substring(0, match.index).split("\n").length;
      findings.push({
        rule: "html-missing-sri",
        severity: "medium",
        message: `外部样式表缺少 integrity 属性（SRI）：${href}，可能遭受 CDN 供应链攻击。`,
        location: { file: "index.html", line, column: 0 },
      });
    }
  }

  // 检测是否有 CSP meta 标签
  const hasCSP =
    html.includes('http-equiv="Content-Security-Policy"') ||
    html.includes("http-equiv='Content-Security-Policy'");

  if (!hasCSP) {
    findings.push({
      rule: "html-missing-csp",
      severity: "low",
      message:
        "HTML 中未设置 Content-Security-Policy meta 标签：建议添加 CSP 策略限制资源加载来源，防御 XSS 攻击。",
      location: { file: "index.html", line: 1, column: 0 },
    });
  }

  // 检测 iframe 是否缺少 sandbox（在 HTML 模板中）
  const iframeRegex = /<iframe[^>]*>/gi;
  while ((match = iframeRegex.exec(html)) !== null) {
    const fullTag = match[0];
    if (!fullTag.includes("sandbox")) {
      const line = html.substring(0, match.index).split("\n").length;
      findings.push({
        rule: "html-iframe-no-sandbox",
        severity: "medium",
        message:
          "HTML 中 iframe 缺少 sandbox 属性：嵌入外部页面应添加 sandbox 限制。",
        location: { file: "index.html", line, column: 0 },
      });
    }
  }

  return findings;
}

/**
 * 依赖漏洞检查
 * 读取 package-lock.json 或 package.json 检查已知不安全的依赖
 */
export function checkDependencies(rootDir: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // 已知有安全风险的 npm 包（维护一个常见列表）
  const knownVulnerablePackages: Record<
    string,
    { severity: "low" | "medium" | "high"; message: string; fixedIn?: string }
  > = {
    lodash: {
      severity: "medium",
      message: "lodash < 4.17.21 存在原型链污染漏洞（CVE-2021-23337）",
      fixedIn: "4.17.21",
    },
    minimist: {
      severity: "medium",
      message: "minimist < 1.2.6 存在原型链污染漏洞（CVE-2021-44906）",
      fixedIn: "1.2.6",
    },
    axios: {
      severity: "medium",
      message: "axios < 1.6.0 存在 SSRF 漏洞（CVE-2023-45857）",
      fixedIn: "1.6.0",
    },
    jsonwebtoken: {
      severity: "high",
      message: "jsonwebtoken < 9.0.0 存在签名验证绕过漏洞（CVE-2022-23529）",
      fixedIn: "9.0.0",
    },
    "node-fetch": {
      severity: "medium",
      message: "node-fetch < 2.6.7 存在信息泄露漏洞（CVE-2022-0235）",
      fixedIn: "2.6.7",
    },
    "shell-quote": {
      severity: "high",
      message: "shell-quote < 1.7.3 存在命令注入漏洞（CVE-2021-42740）",
      fixedIn: "1.7.3",
    },
    "glob-parent": {
      severity: "medium",
      message: "glob-parent < 5.1.2 存在 ReDoS 漏洞（CVE-2020-28469）",
      fixedIn: "5.1.2",
    },
    "nth-check": {
      severity: "medium",
      message: "nth-check < 2.0.1 存在 ReDoS 漏洞（CVE-2021-3803）",
      fixedIn: "2.0.1",
    },
  };

  // 尝试读取 package.json
  const pkgJsonPath = path.resolve(rootDir, "package.json");
  if (!fs.existsSync(pkgJsonPath)) return findings;

  try {
    const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
    const allDeps = {
      ...(pkgJson.dependencies || {}),
      ...(pkgJson.devDependencies || {}),
    };

    for (const [pkgName, versionRange] of Object.entries(allDeps)) {
      const vuln = knownVulnerablePackages[pkgName];
      if (!vuln) continue;

      // 简单版本比较：提取版本号
      const versionStr = (versionRange as string).replace(/[\^~>=<]/g, "");
      if (vuln.fixedIn && compareVersions(versionStr, vuln.fixedIn) < 0) {
        findings.push({
          rule: "dep-known-vulnerability",
          severity: vuln.severity,
          message: `依赖漏洞预警：${pkgName}@${versionStr} - ${vuln.message}。建议升级至 >=${vuln.fixedIn}`,
          location: { file: "package.json", line: 0, column: 0 },
        });
      }
    }

    // 检查是否使用了已废弃/不安全的包
    const deprecatedPackages: Record<string, string> = {
      request: "request 已废弃，建议迁移到 node-fetch 或 axios",
      querystring: "querystring 已废弃，使用 URLSearchParams 替代",
      uuid: "",
    };

    for (const [pkgName, message] of Object.entries(deprecatedPackages)) {
      if (allDeps[pkgName] && message) {
        findings.push({
          rule: "dep-deprecated-package",
          severity: "low",
          message: `依赖安全提示：${message}`,
          location: { file: "package.json", line: 0, column: 0 },
        });
      }
    }
  } catch (e) {
    // 解析失败静默忽略
  }

  return findings;
}

/**
 * 简单语义化版本比较
 * 返回 -1 (a < b), 0 (a == b), 1 (a > b)
 */
function compareVersions(a: string, b: string): number {
  const partsA = a.split(".").map(Number);
  const partsB = b.split(".").map(Number);

  for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
    const numA = partsA[i] || 0;
    const numB = partsB[i] || 0;
    if (numA < numB) return -1;
    if (numA > numB) return 1;
  }
  return 0;
}
