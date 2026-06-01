import {
  ViteSecurityScan,
  PluginOptions,
  SecurityFinding,
  SecurityRule,
} from "./types";
import { scanCode } from "./scanner";
import { Reporter } from "./reporter";
import { getFilteredRules } from "./rules";
import {
  checkBuildOutput,
  checkHtmlSecurity,
  checkDependencies,
} from "./checkers";
import * as fs from "fs";

let globalReporter: Reporter;
let globalOptions: PluginOptions;
let activeRules: SecurityRule[];

function isExcluded(
  filename: string,
  excludePatterns?: string | string[],
): boolean {
  if (!excludePatterns) return false;
  const patterns = Array.isArray(excludePatterns)
    ? excludePatterns
    : [excludePatterns];
  return patterns.some((pattern) => {
    // 处理 **/xxx/** 模式（匹配路径中包含 /xxx/ 的文件）
    const doubleStarMatch = pattern.match(/^\*\*\/(.+?)\/\*\*$/);
    if (doubleStarMatch) {
      const segment = doubleStarMatch[1];
      return (
        filename.includes(`/${segment}/`) || filename.includes(`\\${segment}\\`)
      );
    }
    // 处理 **/xxx 模式（匹配路径中包含 /xxx 的文件）
    const prefixStarMatch = pattern.match(/^\*\*\/(.+)$/);
    if (prefixStarMatch) {
      const suffix = prefixStarMatch[1];
      // 如果 suffix 还包含 *，做 includes 检查中间部分
      if (suffix.includes("*")) {
        const corePart = suffix.replace(/\*/g, "");
        return filename.includes(corePart);
      }
      return filename.includes(`/${suffix}`) || filename.endsWith(suffix);
    }
    // 处理 *.ext 模式
    if (pattern.startsWith("*") && !pattern.includes("/")) {
      return filename.endsWith(pattern.slice(1));
    }
    // 兜底：直接 includes 匹配
    return filename.includes(pattern);
  });
}

function isIncluded(
  filename: string,
  includePatterns?: string | string[],
): boolean {
  if (
    !includePatterns ||
    (Array.isArray(includePatterns) && includePatterns.length === 0)
  ) {
    return true;
  }
  const patterns = Array.isArray(includePatterns)
    ? includePatterns
    : [includePatterns];
  return patterns.some((pattern) => {
    // 处理 **/*.{ext1,ext2} 模式
    const extMatch = pattern.match(/\*\*\/\*\.\{([^}]+)\}$/);
    if (extMatch) {
      const exts = extMatch[1].split(",").map((e) => e.trim());
      return exts.some((ext) => filename.endsWith(`.${ext}`));
    }
    // 处理 **/*.ext 模式
    const singleExtMatch = pattern.match(/\*\*\/\*(\.[a-zA-Z]+)$/);
    if (singleExtMatch) {
      return filename.endsWith(singleExtMatch[1]);
    }
    // 处理 src/**/*.{ext} 路径前缀模式
    const pathExtMatch = pattern.match(/^(.+?)\/\*\*\/\*\.\{([^}]+)\}$/);
    if (pathExtMatch) {
      const dir = pathExtMatch[1];
      const exts = pathExtMatch[2].split(",").map((e) => e.trim());
      return (
        (filename.includes(`/${dir}/`) || filename.includes(`\\${dir}\\`)) &&
        exts.some((ext) => filename.endsWith(`.${ext}`))
      );
    }
    // 处理 *.ext 模式
    if (pattern.startsWith("*") && !pattern.includes("/")) {
      return filename.endsWith(pattern.slice(1));
    }
    // 兜底
    return filename.includes(pattern);
  });
}

function viteSecurityScan(options: PluginOptions = {}): ViteSecurityScan {
  globalOptions = {
    include: ["**/*.{js,ts,jsx,tsx,vue}"],
    exclude: ["**/node_modules/**"],
    reporter: "console",
    failOnError: false,
    severityThreshold: "low",
    devMode: false,
    checkBuildOutput: true,
    checkHtmlSecurity: true,
    checkDependencies: true,
    ...options,
  };

  globalReporter = new Reporter(globalOptions);

  // 根据配置过滤规则
  activeRules = getFilteredRules({
    enableRules: globalOptions.rules,
    disableRules: globalOptions.disableRules,
    customRules: globalOptions.customRules,
  });

  const processedFiles = new Set<string>();

  /** 格式化输出安全发现 */
  function printFindings(findings: SecurityFinding[]): void {
    const severityColors: Record<string, string> = {
      high: "\x1b[31m",
      medium: "\x1b[33m",
      low: "\x1b[36m",
    };
    const reset = "\x1b[0m";
    const green = "\x1b[32m";

    for (const finding of findings) {
      const color = severityColors[finding.severity] || "";
      console.warn(
        `${color}[${finding.severity.toUpperCase()}]${reset} vite-plugin-security-scan: ${finding.message}`,
      );
      console.warn(
        `  \x1b[36m-> ${finding.location.file}:${finding.location.line}${reset}`,
      );
      if (finding.fix) {
        console.warn(`  ${green}💡 修复建议：${finding.fix}${reset}`);
      }
    }
  }

  return {
    name: "vite-plugin-security-scan",
    enforce: "pre" as const,

    buildStart(): void {
      // 依赖漏洞检查（构建开始时执行）
      if (globalOptions.checkDependencies) {
        try {
          const rootDir = process.cwd();
          const depFindings = checkDependencies(rootDir);
          if (depFindings.length > 0) {
            globalReporter.addFindings(depFindings);
            printFindings(depFindings);
          }
        } catch (e) {}
      }
    },

    handleHotUpdate(ctx: any): any {
      // Dev 模式热更新：文件修改时重新扫描
      const file = ctx.file;
      if (!file) return;
      if (isExcluded(file, globalOptions.exclude)) return;
      if (!isIncluded(file, globalOptions.include)) return;
      if (file.includes("node_modules")) return;

      // 清除该文件之前的 findings
      const existingFindings = globalReporter.getFindings();
      const cleanedFile = file.split("?")[0];
      const filteredFindings = existingFindings.filter(
        (f) => f.location.file !== cleanedFile,
      );
      globalReporter.clear();
      globalReporter.addFindings(filteredFindings);

      // 从 processedFiles 中移除，允许重新扫描
      processedFiles.delete(file);
      // 移除可能带查询参数的变体
      for (const key of processedFiles) {
        if (key.split("?")[0] === cleanedFile) {
          processedFiles.delete(key);
        }
      }

      // 读取最新文件内容并重新扫描
      try {
        const code = fs.readFileSync(cleanedFile, "utf-8");
        const findings = scanCode(code, cleanedFile, activeRules);
        if (findings.length > 0) {
          globalReporter.addFindings(findings);
          console.warn(`\n\x1b[35m🔄 [HMR] 重新扫描: ${cleanedFile}\x1b[0m`);
          printFindings(findings);
        } else {
          console.log(`\x1b[32m✅ [HMR] ${cleanedFile} 无安全问题\x1b[0m`);
        }
      } catch (e) {}
    },

    transform(code: string, id: string): any {
      if (isExcluded(id, globalOptions.exclude)) return null;
      if (!isIncluded(id, globalOptions.include)) return null;

      if (processedFiles.has(id)) return null;
      processedFiles.add(id);

      if (id.includes("node_modules")) return null;

      try {
        const findings = scanCode(code, id, activeRules);
        if (findings.length > 0) {
          globalReporter.addFindings(findings);
          printFindings(findings);
        }
      } catch (e) {}

      return null;
    },

    transformIndexHtml(html: string): any {
      // HTML 安全检查
      if (globalOptions.checkHtmlSecurity) {
        try {
          const htmlFindings = checkHtmlSecurity(html);
          if (htmlFindings.length > 0) {
            globalReporter.addFindings(htmlFindings);
            printFindings(htmlFindings);
          }
        } catch (e) {}
      }
      return html;
    },

    writeBundle(outputOptions: any, bundle: any): void {
      // 构建产物安全检查
      if (globalOptions.checkBuildOutput) {
        try {
          const buildFindings = checkBuildOutput(bundle);
          if (buildFindings.length > 0) {
            globalReporter.addFindings(buildFindings);
            printFindings(buildFindings);
          }
        } catch (e) {}
      }
    },

    buildEnd(): void {
      if (globalReporter) {
        globalReporter.report();
        if (globalOptions.failOnError && globalReporter.shouldFail()) {
          throw new Error(
            `Security scan found ${globalOptions.severityThreshold} severity issues. Build failed.`,
          );
        }
      }
    },
  };
}

export default viteSecurityScan;
export type {
  PluginOptions,
  SecurityFinding,
  ScanResult,
  SecurityRule,
} from "./types";
export { Reporter } from "./reporter";
export { getRules, getFilteredRules } from "./rules";
export { scanCode } from "./scanner";
export {
  checkBuildOutput,
  checkHtmlSecurity,
  checkDependencies,
} from "./checkers";
