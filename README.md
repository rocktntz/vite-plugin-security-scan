# vite-plugin-security-scan

一个用于前端代码安全风险扫描的 Vite 插件。在开发和构建阶段自动检测代码中的安全隐患，帮助开发者提前发现并修复潜在的安全漏洞。

## 特性

- 🔍 **AST 深度分析** - 基于 Babel 解析器对源码进行抽象语法树分析，精准定位安全问题
- 🛡️ **30 条内置规则** - 覆盖 XSS、开放重定向、敏感数据存储、危险 API 调用、原型链污染等常见安全风险
- ⚡ **无缝集成 Vite** - 作为 Vite 插件零配置接入，不影响构建性能
- 📊 **多种报告格式** - 支持 console、JSON、summary 三种输出格式
- 🚫 **构建拦截** - 可配置在发现高/中级安全问题时阻止构建通过
- 📁 **灵活的文件过滤** - 支持自定义包含/排除文件模式
- ⚙️ **规则可配置** - 支持白名单/黑名单模式，按需启用或禁用规则
- 📦 **构建产物检查** - 检测 source map 泄露、环境变量暴露到客户端
- 🌐 **HTML 安全检查** - 检测 CDN 资源缺少 SRI、缺少 CSP 策略
- 🔗 **依赖漏洞预警** - 自动检查项目依赖中的已知安全漏洞
- 🛠️ **自定义规则** - 可添加自定义规则，对项目进行深度扫描

## 安装

```bash
npm install vite-plugin-security-scan -D
```

```bash
yarn add vite-plugin-security-scan -D
```

```bash
pnpm add vite-plugin-security-scan -D
```

## 快速开始

在 `vite.config.ts` 中引入并使用插件：

```ts
import { defineConfig } from 'vite'
import viteSecurityScan from 'vite-plugin-security-scan'

export default defineConfig({
  plugins: [
    viteSecurityScan()
  ]
})
```

## 配置选项

```ts
viteSecurityScan({
  // 需要扫描的文件模式，默认扫描 js/ts/jsx/tsx/vue 文件
  include: ['**/*.{js,ts,jsx,tsx,vue}'],

  // 排除的文件模式，默认排除 node_modules
  exclude: ['**/node_modules/**'],

  // 报告输出格式：'console' | 'json' | 'summary'
  reporter: 'console',

  // 是否在发现高/中级问题时使构建失败
  failOnError: false,

  // 严重等级阈值：'low' | 'medium' | 'high'
  severityThreshold: 'low',

  // 是否启用开发模式（开发时输出详细信息）
  devMode: false,

  // 白名单模式：仅启用指定的规则（设置后只运行列表中的规则）
  rules: ['xss-innerHTML-assignment', 'dangerous-eval', 'hardcoded-credentials'],

  // 黑名单模式：禁用指定的规则
  disableRules: ['unsafe-math-random', 'console-sensitive-info'],

  // 自定义规则
  customRules: []
})
```

### 配置项说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `include` | `string \| string[]` | `['**/*.{js,ts,jsx,tsx,vue}']` | 需要扫描的文件 glob 模式 |
| `exclude` | `string \| string[]` | `['**/node_modules/**']` | 排除的文件 glob 模式 |
| `reporter` | `'console' \| 'json' \| 'summary'` | `'console'` | 报告输出格式 |
| `failOnError` | `boolean` | `false` | 发现高/中级问题时是否中断构建 |
| `severityThreshold` | `'low' \| 'medium' \| 'high'` | `'low'` | 最低报告的严重等级 |
| `devMode` | `boolean` | `false` | 开发模式，输出更详细的信息 |
| `rules` | `string[]` | `undefined` | 白名单模式，仅启用指定规则 |
| `disableRules` | `string[]` | `undefined` | 黑名单模式，禁用指定规则 |
| `customRules` | `SecurityRule[]` | `undefined` | 自定义安全规则 |
| `checkBuildOutput` | `boolean` | `true` | 是否检查构建产物安全（source map、环境变量泄露） |
| `checkHtmlSecurity` | `boolean` | `true` | 是否检查 HTML 安全（SRI、CSP） |
| `checkDependencies` | `boolean` | `true` | 是否检查依赖漏洞 |

### 规则配置示例

#### 只启用部分规则（白名单模式）

```ts
viteSecurityScan({
  // 只检测 XSS 和硬编码凭证
  rules: [
    'xss-v-html',
    'xss-innerHTML-assignment',
    'xss-dangerously-set-inner-html',
    'xss-document-write',
    'xss-outerhtml-assignment',
    'hardcoded-credentials'
  ]
})
```

#### 禁用部分规则（黑名单模式）

```ts
viteSecurityScan({
  // 项目中 Math.random 仅用于非安全场景，关闭该规则
  // 项目允许 Object.assign 使用
  disableRules: [
    'unsafe-math-random',
    'prototype-pollution',
    'console-sensitive-info'
  ]
})
```

#### 添加自定义规则

```ts
import viteSecurityScan from 'vite-plugin-security-scan'
import type { SecurityRule } from 'vite-plugin-security-scan'

const myRule: SecurityRule = {
  name: 'no-alert',
  severity: 'low',
  message: '不允许使用 alert()，请使用自定义弹窗组件。',
  match: (node) => {
    if (node.type !== 'CallExpression') return false
    return node.callee?.name === 'alert'
  }
}

export default defineConfig({
  plugins: [
    viteSecurityScan({
      customRules: [myRule]
    })
  ]
})
```

## 内置安全规则

### XSS 攻击检测

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `xss-v-html` | 🔴 高 | 检测 Vue 模板中的 `v-html` 指令，用户输入直接插入 HTML 可能导致 XSS |
| `xss-dangerously-set-inner-html` | 🔴 高 | 检测 React 的 `dangerouslySetInnerHTML` 属性 |
| `xss-innerHTML-assignment` | 🔴 高 | 检测对 `innerHTML` 的直接赋值操作 |

### 开放重定向检测

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `unsafe-location-href` | 🟡 中 | 检测 `location.href` 赋值使用不可信输入 |
| `unsafe-window-open` | 🟡 中 | 检测 `window.open` 使用不可信 URL |
| `unsafe-link-target` | 🔵 低 | 检测 `target="_blank"` 链接缺少 `rel="noopener noreferrer"` |

### 敏感数据存储检测

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `sensitive-storage-localStorage` | 🔴 高 | 检测在 localStorage 中存储 token、密码等敏感信息 |
| `sensitive-storage-sessionStorage` | 🔴 高 | 检测在 sessionStorage 中存储 token、密码等敏感信息（需 key 命中敏感关键词） |

### 危险 API 调用检测

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `dangerous-eval` | 🔴 高 | 检测 `eval()` 调用，可执行任意代码 |
| `dangerous-new-function` | 🔴 高 | 检测 `new Function()` 动态创建函数 |
| `dangerous-settimeout-string` | 🟡 中 | 检测 `setTimeout`/`setInterval` 使用字符串参数 |

### 凭证安全检测

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `hardcoded-credentials` | 🔴 高 | 检测代码中硬编码的账号、密码、token 等凭证信息 |
| `hardcoded-internal-ip` | 🔵 低 | 检测硬编码的内网地址/IP，避免暴露内部基础设施 |

### 传输安全检测

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `unsafe-http-url` | 🟡 中 | 检测网络请求中使用 HTTP 明文传输（仅在 fetch/axios/request 调用中触发） |
| `unsafe-cookie-operation` | 🟡 中 | 检测 `document.cookie` 赋值，缺少 secure/httpOnly 保护 |

### 随机数与加密检测

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `unsafe-math-random` | 🟡 中 | 检测 `Math.random()` 用于安全场景，应使用 `crypto.getRandomValues()` |

### DOM 安全检测

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `xss-document-write` | 🔴 高 | 检测 `document.write()` 调用，可被利用进行 XSS |
| `xss-outerhtml-assignment` | 🔴 高 | 检测 `outerHTML` 赋值，与 innerHTML 类似有 XSS 风险 |
| `xss-insertAdjacentHTML` | 🔴 高 | 检测 `insertAdjacentHTML()` 调用，可将未过滤 HTML 插入 DOM |
| `dangerous-dom-script-injection` | 🔴 高 | 检测动态 `document.createElement('script')` 创建脚本元素 |
| `unsafe-iframe-no-sandbox` | 🟡 中 | 检测 iframe 缺少 `sandbox` 属性 |

### 跨域与模块安全检测

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `unsafe-postmessage-handler` | 🟡 中 | 检测 postMessage 监听缺少 origin 来源验证 |
| `unsafe-postmessage-wildcard` | 🔴 高 | 检测 `postMessage()` 使用通配符 `*` 作为目标源，可能泄露敏感数据 |
| `unsafe-dynamic-import` | 🟡 中 | 检测动态 `import()` 使用变量参数，可能加载任意模块 |

### 开放重定向（函数调用）

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `unsafe-url-redirect` | 🔴 高 | 检测 `location.replace()`/`location.assign()` 调用，可能导致开放重定向 |

### 正则与代码质量检测

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `redos-vulnerable-regex` | 🟡 中 | 检测嵌套量词正则，可能导致 ReDoS 灾难性回溯 |
| `unsafe-regexp-constructor` | 🟡 中 | 检测 `new RegExp()` 动态构造正则，参数来自用户输入可导致注入；已排除常量、配置对象访问、转义函数等安全场景 |
| `prototype-pollution` | 🟡 中 | 检测 `Object.assign({}, ...)` 合并不可信对象，存在原型链污染风险 |
| `prototype-pollution-__proto__` | 🔴 高 | 检测直接操作 `__proto__` 属性，可导致原型链污染攻击 |
| `console-sensitive-info` | 🔵 低 | 检测 console 输出中包含 token、密码等敏感关键词 |

## 使用示例

### 基础使用

```ts
// vite.config.ts
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import viteSecurityScan from 'vite-plugin-security-scan'

export default defineConfig({
  plugins: [
    vue(),
    viteSecurityScan()
  ]
})
```

### CI/CD 中强制安全检查

```ts
// vite.config.ts
import { defineConfig } from 'vite'
import viteSecurityScan from 'vite-plugin-security-scan'

export default defineConfig({
  plugins: [
    viteSecurityScan({
      failOnError: true,        // 发现问题时构建失败
      reporter: 'summary',      // 输出统计摘要
      severityThreshold: 'medium' // 只报告中级及以上问题
    })
  ]
})
```

### 生成 JSON 报告

```ts
// vite.config.ts
import { defineConfig } from 'vite'
import viteSecurityScan from 'vite-plugin-security-scan'

export default defineConfig({
  plugins: [
    viteSecurityScan({
      reporter: 'json'  // 输出 JSON 格式，便于工具集成
    })
  ]
})
```

### 自定义扫描范围

```ts
// vite.config.ts
import { defineConfig } from 'vite'
import viteSecurityScan from 'vite-plugin-security-scan'

export default defineConfig({
  plugins: [
    viteSecurityScan({
      include: ['src/**/*.{ts,vue}'],     // 只扫描 src 目录
      exclude: ['**/node_modules/**', '**/test/**']  // 排除测试文件
    })
  ]
})
```

## 输出示例

### Console 模式

```
[HIGH] vite-plugin-security-scan: 潜在的XSS风险：检测到innerHTML赋值。
  -> src/components/Editor.vue:42

[MED] vite-plugin-security-scan: 潜在的开放重定向风险：location.href赋值使用了潜在的不可信输入。
  -> src/utils/redirect.ts:15
```

### Summary 模式

```
🔒 Security Scan Summary:
   Total: 5 | High: 2 | Medium: 2 | Low: 1

📋 Detailed Findings:
[HIGH] src/components/Editor.vue:42 - 潜在的XSS风险：检测到innerHTML赋值。
[MED] src/utils/redirect.ts:15 - 潜在的开放重定向风险：location.href赋值使用了潜在的不可信输入。
...
```

### JSON 模式

```json
{
  "total": 5,
  "high": 2,
  "medium": 2,
  "low": 1,
  "findings": [
    {
      "rule": "xss-innerHTML-assignment",
      "severity": "high",
      "message": "潜在的XSS风险：检测到innerHTML赋值。用户输入的内容直接插入HTML可能导致XSS攻击。",
      "location": {
        "file": "src/components/Editor.vue",
        "line": 42,
        "column": 4
      }
    }
  ]
}
```

## API 导出

插件除了默认导出外，还提供以下具名导出：

```ts
import viteSecurityScan, {
  Reporter,    // 报告生成器类
  getRules,    // 获取所有内置规则
  scanCode     // 独立的代码扫描函数
} from 'vite-plugin-security-scan'

// 类型导出
import type {
  PluginOptions,    // 插件配置选项类型
  SecurityFinding,  // 安全发现记录类型
  ScanResult        // 扫描结果统计类型
} from 'vite-plugin-security-scan'
```

### 独立使用 scanCode

```ts
import { scanCode } from 'vite-plugin-security-scan'

const code = `document.getElementById('app').innerHTML = userInput;`
const findings = scanCode(code, 'example.ts')

console.log(findings)
// [{ rule: 'xss-innerHTML-assignment', severity: 'high', ... }]
```

## 支持的文件类型

- `.js` / `.jsx` - JavaScript
- `.ts` / `.tsx` - TypeScript
- `.vue` - Vue 单文件组件
- `.mjs` / `.cjs` - ES Module / CommonJS

## severityThreshold 配置说明

`severityThreshold` 控制两个行为：

1. **报告输出过滤**：只输出指定级别及以上的问题
2. **构建失败判断**（需配合 `failOnError: true`）：只有指定级别及以上问题才会阻断构建

```ts
viteSecurityScan({
  severityThreshold: 'high', // 只报告和拦截 high 级别问题
  failOnError: true,
  reporter: 'summary'
})
```

| `severityThreshold` 值 | 报告输出 | 构建失败条件 |
|---|---|---|
| `'low'`（默认） | 所有 low + medium + high | 有任何问题即失败 |
| `'medium'` | medium + high | medium 或 high 时失败 |
| `'high'` | 仅 high | high 时失败 |

## 兼容性

- Vite >= 4.0.0
- Node.js >= 18

## 非代码层安全检查

除代码层 AST 分析外，插件还提供以下维度的安全检测：

### 构建产物检查（`checkBuildOutput`）

在 `writeBundle` 阶段自动扫描构建产物：

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `build-sourcemap-exposed` | 🔴 高 | 检测生产构建中是否输出 .map 文件，暴露源码逻辑 |
| `build-env-process-exposed` | 🟡 中 | 检测 bundle 中残留的 `process.env` 引用 |
| `build-secret-key-exposed` | 🔴 高 | 检测 bundle 中是否包含硬编码密钥模式（AWS Key、GitHub Token 等） |

```ts
viteSecurityScan({
  checkBuildOutput: true  // 默认开启
})
```

### HTML 安全检查（`checkHtmlSecurity`）

在 `transformIndexHtml` 阶段检查 index.html：

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `html-missing-sri` | 🟡 中 | 外部 CDN 脚本/样式缺少 `integrity` 属性，可能遭受供应链攻击 |
| `html-missing-csp` | 🔵 低 | 未设置 Content-Security-Policy meta 标签 |
| `html-iframe-no-sandbox` | 🟡 中 | HTML 中 iframe 缺少 sandbox 属性 |

```ts
viteSecurityScan({
  checkHtmlSecurity: true  // 默认开启
})
```

### 依赖漏洞预警（`checkDependencies`）

在 `buildStart` 阶段读取 package.json 检查已知漏洞：

| 规则名 | 严重等级 | 说明 |
|--------|----------|------|
| `dep-known-vulnerability` | 视漏洞而定 | 检测依赖中已知 CVE 漏洞（lodash、axios、jsonwebtoken 等） |
| `dep-deprecated-package` | 🔵 低 | 检测已废弃的不安全包（如 request） |

```ts
viteSecurityScan({
  checkDependencies: true  // 默认开启
})
```

### 跳过特定行的安全检查

使用 `@security-ignore` 注释可以跳过某一行或代码块的安全扫描：

```vue
<template>
  <!-- @security-ignore -->
  <div v-html="trustedContent"></div>
</template>

<script setup>
// @security-ignore
const html = document.createElement('script') // 此行不会被扫描
</script>
```

支持的注释格式：
- `// @security-ignore` — JavaScript 单行注释
- `/* @security-ignore */` — JavaScript 多行注释
- `<!-- @security-ignore -->` — HTML/Vue 模板注释

### 关闭非代码层检查

```ts
viteSecurityScan({
  checkBuildOutput: false,
  checkHtmlSecurity: false,
  checkDependencies: false
})
```



## 开发

```bash
# 安装依赖
npm install

# 开发模式（监听文件变化）
npm run dev

# 构建
npm run build

# 运行测试
npm test
```

## License

MIT
