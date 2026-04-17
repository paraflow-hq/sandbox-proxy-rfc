/**
 * Run all test suites sequentially.
 *
 * Each suite creates its own E2B sandbox, so they are fully independent.
 * Requires E2B_API_KEY env var or passed as first CLI argument.
 *
 * Usage:
 *   pnpm test                          # uses E2B_API_KEY env var
 *   pnpm test <api-key>                # pass key as argument
 *   pnpm test:components <api-key>     # run single suite
 */

const { execSync } = require('child_process')
const path = require('path')

const suites = [
  { name: '01-components', file: '01-components.cjs' },
  { name: '02-e2e-lifecycle', file: '02-e2e-lifecycle.cjs' },
  { name: '03-gap-coverage', file: '03-gap-coverage.cjs' },
  { name: '04-adversarial', file: '04-adversarial.cjs' },
  { name: '05-production-reality', file: '05-production-reality.cjs' },
  { name: '06-passthrough-poc', file: '06-passthrough-poc.cjs' },
]

const results = []
const apiKeyArg = process.env.E2B_API_KEY || process.argv[2] || ''

for (const suite of suites) {
  console.log(`\n${'='.repeat(60)}`)
  console.log(`Running: ${suite.name}`)
  console.log('='.repeat(60) + '\n')

  try {
    const cmd = `node ${path.join(__dirname, suite.file)} ${apiKeyArg}`
    execSync(cmd, { stdio: 'inherit', timeout: 10 * 60 * 1000 })
    results.push({ name: suite.name, passed: true })
  } catch (e) {
    results.push({ name: suite.name, passed: false })
  }
}

console.log('\n' + '='.repeat(60))
console.log('OVERALL RESULTS')
console.log('='.repeat(60) + '\n')

for (const r of results) {
  console.log(`  ${r.passed ? '✅' : '❌'} ${r.name}`)
}

const allPassed = results.every(r => r.passed)
console.log(`\n  ${results.filter(r => r.passed).length}/${results.length} suites passed`)
console.log(allPassed ? '\n  ✅ ALL SUITES PASSED' : '\n  ❌ SOME SUITES FAILED')

process.exit(allPassed ? 0 : 1)
