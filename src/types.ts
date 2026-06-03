/** AST 节点基础类型 — 允许规则代码访问任意嵌套属性 */
export interface AstNode {
  type: string;
  [key: string]: unknown;
}

export interface SecurityRule {
  name: string;
  severity: "low" | "medium" | "high";
  match: (node: AstNode, context: RuleContext) => boolean;
  message: string;
  /** 修复建议 */
  fix?: string;
  pattern?: RegExp;
}

export interface RuleContext {
  filename: string;
  code: string;
  results: SecurityFinding[];
}

export interface SecurityFinding {
  rule: string;
  severity: "low" | "medium" | "high";
  message: string;
  /** 修复建议 */
  fix?: string;
  location: {
    file: string;
    line: number;
    column: number;
  };
}

export interface ScanResult {
  total: number;
  high: number;
  medium: number;
  low: number;
  findings: SecurityFinding[];
}

export interface PluginOptions {
  include?: string | string[];
  exclude?: string | string[];
  severityThreshold?: "low" | "medium" | "high";
  failOnError?: boolean;
  devMode?: boolean;
  reporter?: "console" | "json" | "summary";
  /** 需要启用的规则列表（白名单模式），设置后仅运行列表中的规则 */
  rules?: string[];
  /** 需要禁用的规则列表（黑名单模式） */
  disableRules?: string[];
  /** 自定义规则 */
  customRules?: SecurityRule[];
  /** 是否检查构建产物安全（source map 泄露、环境变量暴露） */
  checkBuildOutput?: boolean;
  /** 是否检查 HTML 安全（SRI、CSP） */
  checkHtmlSecurity?: boolean;
  /** 是否检查依赖漏洞 */
  checkDependencies?: boolean;
}