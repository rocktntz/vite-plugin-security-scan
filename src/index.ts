import type { Plugin } from "vite";
import picomatch from "picomatch";
import {
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

function createMatcher(patterns: string | string[]): (filePath: string) => boolean {
  const patternList = Array.isArray(patterns) ? patterns : [patterns];
  return picomatch(patternList, { dot: true });
}

function viteSecurityScan(options: PluginOptions = {}): Plugin {
  const resolvedOptions: Required<PluginOptions> = {
    include: ["**/*.{js,ts,jsx,tsx,vue}"],
    exclude: ["**/node_modules/**"],
    reporter: "console",
    failOnError: false,
    severityThreshold: "low",
    devMode: false,
    checkBuildOutput: true,
    checkHtmlSecurity: true,
    checkDependencies: true,
    rules: [],
    disableRules: [],
    customRules: [],
    ...options,
  };

  const reporter = new Reporter(resolvedOptions);

  const activeRules: SecurityRule[] = getFilteredRules({
    enableRules: resolvedOptions.rules,
    disableRules: resolvedOptions.disableRules,
    customRules: resolvedOptions.customRules,
  });

  const isExcluded = createMatcher(resolvedOptions.exclude);
  const isIncluded = createMatcher(resolvedOptions.include);

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
        `${color}[${finding.severity.toUpperCase()}${reset}] vite-plugin-security-scan: ${finding.message}`,
      );
      console.warn(
        `  \x1b[36m-> ${finding.location.file}:${finding.location.line}${reset}`,
      );
      if (finding.fix) {
        console.warn(`  ${green}💡 修复建议：${finding.fix}${reset}`);
      }
    }
  }

  function shouldProcessFile(id: string): boolean {
    const cleanId = id.split("?")[0];
    if (cleanId.includes("node_modules")) return false;
    if (isExcluded(cleanId)) return false;
    if (!isIncluded(cleanId)) return false;
    return true;
  }

  return {
    name: "vite-plugin-security-scan",
    enforce: "pre",

    buildStart(): void {
      if (resolvedOptions.checkDependencies) {
        try {
          const rootDir = process.cwd();
          const depFindings = checkDependencies(rootDir);
          if (depFindings.length > 0) {
            reporter.addFindings(depFindings);
            printFindings(depFindings);
          }
        } catch (e) {
          if (resolvedOptions.devMode) {
            console.warn(
              "\x1b[33m[vite-plugin-security-scan] 依赖检查失败:\x1b[0m",
              e instanceof Error ? e.message : e,
            );
          }
        }
      }
    },

    handleHotUpdate(ctx): void {
      const file = ctx.file;
      if (!file) return;
      if (!shouldProcessFile(file)) return;

      const cleanedFile = file.split("?")[0];

      // 清除该文件之前的 findings
      const existingFindings = reporter.getFindings();
      const filteredFindings = existingFindings.filter(
        (f) => f.location.file !== cleanedFile,
      );
      reporter.clear();
      reporter.addFindings(filteredFindings);

      // 从 processedFiles 中移除，允许重新扫描
      processedFiles.delete(cleanedFile);
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
          reporter.addFindings(findings);
          console.warn(`\n\x1b[35m🔄 [HMR] 重新扫描: ${cleanedFile}\x1b[0m`);
          printFindings(findings);
        } else {
          console.log(`\x1b[32m✅ [HMR] ${cleanedFile} 无安全问题\x1b[0m`);
        }
      } catch (e) {
        console.warn(
          `\x1b[33m[vite-plugin-security-scan] [HMR] 读取文件失败: ${cleanedFile}\x1b[0m`,
          e instanceof Error ? e.message : e,
        );
      }
    },

    transform(code, id) {
      if (!shouldProcessFile(id)) return null;

      const cleanId = id.split("?")[0];
      if (processedFiles.has(cleanId)) return null;
      processedFiles.add(cleanId);

      try {
        const findings = scanCode(code, cleanId, activeRules);
        if (findings.length > 0) {
          reporter.addFindings(findings);
          printFindings(findings);
        }
      } catch (e) {
        if (resolvedOptions.devMode) {
          console.warn(
            `\x1b[33m[vite-plugin-security-scan] 扫描失败: ${cleanId}\x1b[0m`,
            e instanceof Error ? e.message : e,
          );
        }
      }

      return null;
    },

    transformIndexHtml(html) {
      if (resolvedOptions.checkHtmlSecurity) {
        try {
          const htmlFindings = checkHtmlSecurity(html);
          if (htmlFindings.length > 0) {
            reporter.addFindings(htmlFindings);
            printFindings(htmlFindings);
          }
        } catch (e) {
          if (resolvedOptions.devMode) {
            console.warn(
              "\x1b[33m[vite-plugin-security-scan] HTML 安全检查失败:\x1b[0m",
              e instanceof Error ? e.message : e,
            );
          }
        }
      }
      return html;
    },

    writeBundle(_outputOptions, bundle) {
      if (resolvedOptions.checkBuildOutput) {
        try {
          const buildFindings = checkBuildOutput(bundle);
          if (buildFindings.length > 0) {
            reporter.addFindings(buildFindings);
            printFindings(buildFindings);
          }
        } catch (e) {
          if (resolvedOptions.devMode) {
            console.warn(
              "\x1b[33m[vite-plugin-security-scan] 构建产物检查失败:\x1b[0m",
              e instanceof Error ? e.message : e,
            );
          }
        }
      }
    },

    buildEnd() {
      reporter.report();
      if (resolvedOptions.failOnError && reporter.shouldFail()) {
        throw new Error(
          `Security scan found ${resolvedOptions.severityThreshold} severity issues. Build failed.`,
        );
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