const { scanCode } = require('../dist/index.js');

console.log('Testing vite-plugin-security-scan...\n');

const testCases = [
  {
    name: 'XSS via dangerouslySetInnerHTML (JSX)',
    code: `const Component = () => <div dangerouslySetInnerHTML={{__html: userInput}} />`,
    expected: 1
  },
  {
    name: 'XSS via innerHTML assignment',
    code: `element.innerHTML = userInput;`,
    expected: 1
  },
  {
    name: 'localStorage token storage',
    code: `localStorage.setItem('auth_token', value);`,
    expected: 1
  },
  {
    name: 'eval usage',
    code: `eval(userInput);`,
    expected: 1
  },
  {
    name: 'new Function usage',
    code: `const fn = new Function('return ' + userInput);`,
    expected: 1
  },
  {
    name: 'setTimeout with string',
    code: `setTimeout('alert(' + userInput + ')', 1000);`,
    expected: 1
  },
  {
    name: 'setTimeout with function (safe)',
    code: `setTimeout(() => alert('hello'), 1000);`,
    expected: 0
  },
  {
    name: 'Safe code',
    code: `const x = 1; console.log('hello');`,
    expected: 0
  },
  {
    name: 'sessionStorage with sensitive key',
    code: `sessionStorage.setItem('api_key', value);`,
    expected: 1
  },
  {
    name: 'window.open',
    code: `window.open(userUrl);`,
    expected: 1
  },
  {
    name: 'location.href assignment',
    code: `location.href = userInput;`,
    expected: 1
  }
];

let passed = 0;
let failed = 0;

for (const test of testCases) {
  const findings = scanCode(test.code, 'test.js');
  const count = findings.length;
  if (count === test.expected) {
    console.log(`✓ ${test.name}: ${count} findings (expected: ${test.expected})`);
    passed++;
  } else {
    console.log(`✗ ${test.name}: ${count} findings (expected: ${test.expected})`);
    if (findings.length > 0) {
      findings.forEach(f => console.log(`  - [${f.severity}] ${f.message}`));
    }
    failed++;
  }
}

console.log(`\nResults: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);