import type { Plugin } from "vite";
import picomatch from "picomatch";
import * as path from "path";
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

/**
 * 标准化文件路径为相对路径（相对于项目根目录）
 * 确保 dev 模式（绝对路径）和 build 模式（相对路径）输出一致
 */
function normalizeFilePath(filePath: string): string {
  const rootDir = process.cwd();
  if (path.isAbsolute(filePath)) {
    const relative = path.relative(rootDir, filePath);
    return relative.startsWith("..") ? filePath : relative;
  }
  return filePath;
}

function createMatcher(patterns: string | string[]): (filePath: string) => boolean {
  const patternList = Array.isArray(patterns) ? patterns : [patterns];
  return picomatch(patternList, { dot: true });
}

/**
 * 递归查找目录下指定扩展名的文件
 */
function findFilesRecursive(dir: string, extensions: string[]): string[] {
  const results: string[] = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        // 跳过 node_modules 和隐藏目录
        if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
        results.push(...findFilesRecursive(fullPath, extensions));
      } else if (entry.isFile()) {
        if (extensions.some((ext) => entry.name.endsWith(ext))) {
          results.push(fullPath);
        }
      }
    }
  } catch {
    // 目录读取失败静默跳过
  }
  return results;
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
  let isDev = false;

  /** 根据 severityThreshold 过滤 findings */
  function filterByThreshold(findings: SecurityFinding[]): SecurityFinding[] {
    const threshold = resolvedOptions.severityThreshold;
    if (threshold === "high") {
      return findings.filter((f) => f.severity === "high");
    }
    if (threshold === "medium") {
      return findings.filter((f) => f.severity === "high" || f.severity === "medium");
    }
    return findings;
  }

  /** 格式化输出安全发现 */
  function printFindings(findings: SecurityFinding[]): void {
    const filtered = filterByThreshold(findings);
    if (filtered.length === 0) return;

    const severityColors: Record<string, string> = {
      high: "\x1b[31m",
      medium: "\x1b[33m",
      low: "\x1b[36m",
    };
    const reset = "\x1b[0m";
    const green = "\x1b[32m";

    for (const finding of filtered) {
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

  function shouldProcessFile(filePath: string): boolean {
    const cleanPath = filePath.split("?")[0];
    if (cleanPath.includes("node_modules")) return false;
    if (cleanPath.startsWith("\0") || cleanPath.startsWith("vite/") || cleanPath.startsWith("@vite/")) return false;
    if (isExcluded(cleanPath)) return false;
    if (!isIncluded(cleanPath)) return false;
    return true;
  }

  /**
   * 扫描单个文件并收集 findings
   * 仅在 console 模式下即时输出，summary/json 模式仅收集
   */
  function scanAndCollect(
    code: string,
    normalizedId: string,
    originalPath?: string,
  ): void {
    try {
      const findings = scanCode(code, normalizedId, activeRules);
      if (findings.length > 0) {
        reporter.addFindings(findings);
        // 只在 console 模式或 devMode 下即时打印每条 findings
        // summary/json 模式由 reporter.report() 统一输出
        if (resolvedOptions.reporter === "console" || resolvedOptions.devMode) {
          printFindings(findings);
        }
      }
    } catch (e) {
      if (resolvedOptions.devMode) {
        console.warn(
          `\x1b[33m[vite-plugin-security-scan] 扫描失败: ${normalizedId || originalPath}\x1b[0m`,
          e instanceof Error ? e.message : e,
        );
      }
    }
  }

  /**
   * 在 dev 模式下主动从磁盘扫描所有 .vue 文件
   * 完全绕过 Vite 插件管道，确保与 build 模式结果一致
   */
  function scanVueFilesFromDisk(): void {
    const rootDir = process.cwd();
    const vueExtensions = [".vue"];
    const allVueFiles = findFilesRecursive(rootDir, vueExtensions);

    for (const absolutePath of allVueFiles) {
      const normalizedId = normalizeFilePath(absolutePath);
      if (!shouldProcessFile(normalizedId)) continue;
      if (processedFiles.has(normalizedId)) continue;

      processedFiles.add(normalizedId);
      try {
        const code = fs.readFileSync(absolutePath, "utf-8");
        scanAndCollect(code, normalizedId, absolutePath);
      } catch (e) {
        if (resolvedOptions.devMode) {
          console.warn(
            `\x1b[33m[vite-plugin-security-scan] Vue SFC 读取失败: ${absolutePath}\x1b[0m`,
            e instanceof Error ? e.message : e,
          );
        }
      }
    }
  }

  return {
    name: "vite-plugin-security-scan",
    enforce: "pre",

    configResolved(config) {
      isDev = config.command === "serve";
    },

    buildStart(): void {
      // 依赖漏洞检查
      if (resolvedOptions.checkDependencies) {
        try {
          const rootDir = process.cwd();
          const depFindings = checkDependencies(rootDir);
          if (depFindings.length > 0) {
            reporter.addFindings(depFindings);
            if (resolvedOptions.reporter === "console" || resolvedOptions.devMode) {
              printFindings(depFindings);
            }
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

      // dev 模式下主动从磁盘扫描所有 .vue 文件
      // @vitejs/plugin-vue 会在 transform 之前处理 .vue 文件，
      // 通过主动扫描确保 dev 和 build 模式扫描结果完全一致
      if (isDev) {
        scanVueFilesFromDisk();
        // dev 模式下输出 summary 报告（因为 buildEnd 在 dev server 中不会被调用）
        if (resolvedOptions.reporter === "summary" || resolvedOptions.reporter === "json") {
          reporter.report();
        }
      }
    },

    handleHotUpdate(ctx): void {
      const file = ctx.file;
      if (!file) return;
      if (!shouldProcessFile(file)) return;

      const cleanedFile = file.split("?")[0];
      const normalizedFile = normalizeFilePath(cleanedFile);

      // 清除该文件之前的 findings
      const existingFindings = reporter.getFindings();
      const filteredFindings = existingFindings.filter(
        (f) => f.location.file !== normalizedFile,
      );
      reporter.clear();
      reporter.addFindings(filteredFindings);

      // 从 processedFiles 中移除，允许重新扫描
      processedFiles.delete(normalizedFile);

      // 读取最新文件内容并重新扫描
      try {
        const code = fs.readFileSync(cleanedFile, "utf-8");
        const findings = scanCode(code, normalizedFile, activeRules);
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
      const normalizedId = normalizeFilePath(cleanId);

      // dev 模式下 .vue 文件已在 buildStart 中从磁盘扫描，跳过
      if (isDev && cleanId.endsWith(".vue")) return null;

      if (processedFiles.has(normalizedId)) return null;
      processedFiles.add(normalizedId);

      // 始终从磁盘读取原始内容进行扫描，
      // 因为其他插件（如 TypeScript 插件）可能已修改了 transform 传入的 code，
      // 导致 dev 和 build 模式下扫描结果不一致
      let codeToScan = code;
      try {
        codeToScan = fs.readFileSync(cleanId, "utf-8");
      } catch {
        // 读取失败时降级使用传入的 code
      }

      scanAndCollect(codeToScan, normalizedId, cleanId);
      return null;
    },

    transformIndexHtml(html) {
      if (resolvedOptions.checkHtmlSecurity) {
        try {
          const htmlFindings = checkHtmlSecurity(html);
          if (htmlFindings.length > 0) {
            reporter.addFindings(htmlFindings);
            if (resolvedOptions.reporter === "console" || resolvedOptions.devMode) {
              printFindings(htmlFindings);
            }
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
            if (resolvedOptions.reporter === "console" || resolvedOptions.devMode) {
              printFindings(buildFindings);
            }
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