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

  getResult(): ScanResult {
    return {
      total: this.findings.length,
      high: this.findings.filter((f) => f.severity === "high").length,
      medium: this.findings.filter((f) => f.severity === "medium").length,
      low: this.findings.filter((f) => f.severity === "low").length,
      findings: this.findings,
    };
  }

  report(): void {
    const result = this.getResult();

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
        this.printFindings();
      }
      return;
    }

    if (this.options.devMode || this.options.reporter === "console") {
      this.printFindings();
    }
  }

  private printFindings(): void {
    const severityColors: Record<string, string> = {
      high: "\x1b[31m",
      medium: "\x1b[33m",
      low: "\x1b[36m",
    };
    const reset = "\x1b[0m";
    const green = "\x1b[32m";

    for (const finding of this.findings) {
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
    return result.high > 0 || result.medium > 0;
  }
}
