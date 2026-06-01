import * as parser from "@babel/parser";
import traverseModule from "@babel/traverse";
import { SecurityFinding, SecurityRule, RuleContext } from "./types";
import { matchRules } from "./rules";

const traverse = (traverseModule.default || traverseModule) as any;

const vueExtensions = [".vue"];
const jsExtensions = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"];

function shouldProcess(filename: string): boolean {
  return [...vueExtensions, ...jsExtensions].some((e) => filename.endsWith(e));
}

/**
 * 清理文件路径：移除 Vite 查询参数，提取干净的文件路径
 */
function cleanFilePath(id: string): string {
  return id.split("?")[0];
}

/**
 * 计算 Vue SFC 中 <script> 块的起始行偏移量
 */
function getVueScriptOffset(code: string): number {
  const scriptMatch = code.match(/^([\s\S]*?)<script[^>]*>/m);
  if (scriptMatch) {
    const beforeScript = scriptMatch[0];
    return (beforeScript.match(/\n/g) || []).length;
  }
  return 0;
}

/**
 * 从 Vue SFC 中提取 <script> 块内容
 */
function extractVueScript(
  code: string,
): { script: string; offset: number } | null {
  const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  let match: RegExpExecArray | null;
  let result: { script: string; offset: number } | null = null;

  while ((match = scriptRegex.exec(code)) !== null) {
    const fullMatch = match[0];
    const scriptContent = match[1];
    const beforeScript = code.substring(
      0,
      match.index + fullMatch.indexOf(">") + 1,
    );
    const offset = (beforeScript.match(/\n/g) || []).length;
    if (fullMatch.includes("setup") || !result) {
      result = { script: scriptContent, offset };
    }
  }
  return result;
}

/**
 * 从 Vue SFC 中提取 <template> 块内容
 */
function extractVueTemplate(
  code: string,
): { template: string; offset: number } | null {
  const templateRegex = /<template[^>]*>([\s\S]*?)<\/template>/gi;
  const match = templateRegex.exec(code);
  if (!match) return null;

  const fullMatch = match[0];
  const templateContent = match[1];
  const beforeTemplate = code.substring(
    0,
    match.index + fullMatch.indexOf(">") + 1,
  );
  const offset = (beforeTemplate.match(/\n/g) || []).length;

  return { template: templateContent, offset };
}

const IGNORE_COMMENT = "@security-ignore";

/**
 * 收集所有带 @security-ignore 注释的行号集合
 */
function getIgnoredLines(code: string): Set<number> {
  const ignoredLines = new Set<number>();
  const lines = code.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes(IGNORE_COMMENT)) {
      // 忽略当前行（注释本身可能就是带代码的同一行）
      ignoredLines.add(i + 1);
      // 忽略下一行（注释在上一行，标记下一行跳过）
      ignoredLines.add(i + 2);
    }
  }
  return ignoredLines;
}

/**
 * 扫描 Vue template 中的安全问题（基于正则匹配）
 */
function scanVueTemplate(
  template: string,
  filename: string,
  lineOffset: number,
  activeRules?: SecurityRule[],
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const lines = template.split("\n");

  // 检查规则是否激活的辅助函数
  const isRuleActive = (ruleName: string): SecurityRule | undefined => {
    const rulesToCheck = activeRules;
    if (!rulesToCheck) return undefined;
    return rulesToCheck.find((r) => r.name === ruleName);
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1 + lineOffset;

    // 支持 @security-ignore 跳过
    if (line.includes(IGNORE_COMMENT)) continue;
    if (i > 0 && lines[i - 1].includes(IGNORE_COMMENT)) continue;

    // 检测 v-html
    const vHtmlRule = isRuleActive("xss-v-html");
    if (vHtmlRule && /\bv-html\b/.test(line)) {
      findings.push({
        rule: "xss-v-html",
        severity: "high",
        message: vHtmlRule.message,
        fix: vHtmlRule.fix,
        location: {
          file: filename,
          line: lineNum,
          column: line.indexOf("v-html"),
        },
      });
    }

    // 检测 target="_blank" 缺少 rel="noopener noreferrer"
    const linkRule = isRuleActive("unsafe-link-target");
    if (linkRule && /target\s*=\s*["']_blank["']/.test(line)) {
      // 检查同一标签是否有 rel="noopener"
      // 简单方式：向上/向下搜索同一标签
      if (!/rel\s*=\s*["'][^"']*noopener[^"']*["']/.test(line)) {
        findings.push({
          rule: "unsafe-link-target",
          severity: "low",
          message: linkRule.message,
          fix: linkRule.fix,
          location: {
            file: filename,
            line: lineNum,
            column: line.indexOf("target"),
          },
        });
      }
    }

    // 检测 iframe 缺少 sandbox
    const iframeRule = isRuleActive("unsafe-iframe-no-sandbox");
    if (iframeRule && /<iframe\b/.test(line)) {
      // 查找 iframe 完整标签（可能跨行）
      let fullTag = line;
      let j = i + 1;
      while (j < lines.length && !fullTag.includes(">")) {
        fullTag += " " + lines[j];
        j++;
      }
      if (!fullTag.includes("sandbox")) {
        findings.push({
          rule: "unsafe-iframe-no-sandbox",
          severity: "medium",
          message: iframeRule.message,
          fix: iframeRule.fix,
          location: {
            file: filename,
            line: lineNum,
            column: line.indexOf("<iframe"),
          },
        });
      }
    }

    // 检测模板中的 onclick 等内联事件处理器使用字符串
    if (
      /\bonclick\s*=\s*["']/.test(line) ||
      /\bonerror\s*=\s*["']/.test(line) ||
      /\bonload\s*=\s*["']/.test(line)
    ) {
      findings.push({
        rule: "template-inline-event-handler",
        severity: "medium",
        message:
          "模板中检测到内联事件处理器(onclick/onerror/onload)：可能导致XSS风险，应使用 Vue 事件绑定 @click。",
        fix: '将 onclick="..." 改为 Vue 事件绑定 @click="handler"，避免内联 JS 执行。',
        location: { file: filename, line: lineNum, column: 0 },
      });
    }

    // 检测 :href 绑定 javascript: 协议
    if (
      /:href\s*=\s*["'].*javascript:/i.test(line) ||
      /v-bind:href\s*=\s*["'].*javascript:/i.test(line)
    ) {
      findings.push({
        rule: "template-javascript-url",
        severity: "high",
        message: "模板中检测到 javascript: URL 绑定：可导致 XSS 攻击。",
        fix: "移除 javascript: 协议 URL；使用 @click 事件处理替代。",
        location: { file: filename, line: lineNum, column: 0 },
      });
    }
  }

  return findings;
}

export function scanCode(
  code: string,
  filename: string,
  activeRules?: SecurityRule[],
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const cleanedFilename = cleanFilePath(filename);
  const context: RuleContext = {
    filename: cleanedFilename,
    code,
    results: findings,
  };

  let codeToParse = code;
  let lineOffset = 0;

  // 检测是否为 Vue SFC 原始源码
  const isVueSFC = cleanedFilename.endsWith(".vue") && code.includes("<script");
  if (isVueSFC) {
    // 扫描 template 部分
    const templateExtracted = extractVueTemplate(code);
    if (templateExtracted) {
      const templateFindings = scanVueTemplate(
        templateExtracted.template,
        cleanedFilename,
        templateExtracted.offset,
        activeRules,
      );
      findings.push(...templateFindings);
    }

    // 提取 script 部分进行 AST 分析
    const extracted = extractVueScript(code);
    if (extracted) {
      codeToParse = extracted.script;
      lineOffset = extracted.offset;
    }
  }

  // 收集源码中 @security-ignore 标记的行号
  const ignoredLines = getIgnoredLines(code);

  let ast: any;
  try {
    ast = parser.parse(codeToParse, {
      sourceType: "module",
      plugins: ["typescript", "jsx"],
    });
  } catch (e) {
    return findings;
  }

  traverse(ast, {
    enter(path: any) {
      const rule = matchRules(path.node, context, activeRules);
      if (rule) {
        const location = path.node.loc?.start || { line: 1, column: 0 };
        const originalLine = location.line + lineOffset;

        // 跳过带 @security-ignore 注释的行
        if (ignoredLines.has(originalLine)) return;

        findings.push({
          rule: rule.name,
          severity: rule.severity,
          message: rule.message,
          fix: rule.fix,
          location: {
            file: cleanedFilename,
            line: originalLine,
            column: location.column,
          },
        });
      }
    },
  });

  return findings;
}

export function isBuildFile(filename: string): boolean {
  return !filename.includes("node_modules") && shouldProcess(filename);
}
