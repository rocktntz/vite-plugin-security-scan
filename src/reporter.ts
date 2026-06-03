import { SecurityFinding, ScanResult, PluginOptions } from "./types";

export class Reporter {
  private findings: SecurityFinding[] = [];
  private options: PluginOptions;

  constructor(options: PluginOptions = {}) {
    this.options = {
      reporter: "console",
      failOnError: false,
      severityThreshold: "low",
      devMode: false,
      ...options,
    };
  }

  addFinding(finding: SecurityFinding): void {
    this.findings.push(finding);
  }

  addFindings(findings: SecurityFinding[]): void {
    this.findings.push(...findings);
  }

  getFindings(): SecurityFinding[] {
    return this.findings;
  }

  clear(): void {
    this.findings = [];
  }

  /**
   * 根据 severityThreshold 过滤 findings
   */
  private filterByThreshold(findings: SecurityFinding[]): SecurityFinding[] {
    const threshold = this.options.severityThreshold || "low";
    if (threshold === "high") {
      return findings.filter((f) => f.severity === "high");
    }
    if (threshold === "medium") {
      return findings.filter((f) => f.severity === "high" || f.severity === "medium");
    }
    // threshold === "low" 返回所有
    return findings;
  }

  getResult(): ScanResult {
    const filtered = this.filterByThreshold(this.findings);
    return {
      total: filtered.length,
      high: filtered.filter((f) => f.severity === "high").length,
      medium: filtered.filter((f) => f.severity === "medium").length,
      low: filtered.filter((f) => f.severity === "low").length,
      findings: filtered,
    };
  }

  report(): void {
    const result = this.getResult();
    const filtered = this.filterByThreshold(this.findings);

    if (this.options.reporter === "json") {
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    if (this.options.reporter === "summary") {
      console.log("\n🔒 Security Scan Summary:");
      console.log(
        `   Total: ${result.total} | High: ${result.high} | Medium: ${result.medium} | Low: ${result.low}`,
      );
      if (result.total > 0) {
        console.log("\n📋 Detailed Findings:");
        this.printFilteredFindings(filtered);
      }
      return;
    }

    if (this.options.devMode || this.options.reporter === "console") {
      this.printFilteredFindings(filtered);
    }
  }

  private printFilteredFindings(findings: SecurityFinding[]): void {
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
        `${color}[${finding.severity.toUpperCase()}]${reset} ${finding.location.file}:${finding.location.line} - ${finding.message}`,
      );
      if (finding.fix) {
        console.warn(`  ${green}💡 修复建议：${finding.fix}${reset}`);
      }
    }
  }

  shouldFail(): boolean {
    if (!this.options.failOnError) return false;
    const result = this.getResult();
    const threshold = this.options.severityThreshold || "low";
    
    if (threshold === "high") {
      return result.high > 0;
    }
    if (threshold === "medium") {
      return result.high > 0 || result.medium > 0;
    }
    // threshold === "low"
    return result.total > 0;
  }
}
