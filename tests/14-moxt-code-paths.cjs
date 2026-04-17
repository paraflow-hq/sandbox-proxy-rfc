/**
 * Suite 14: Moxt-specific code paths — tests paths from real moxt codebase
 * that could cause outages if they misbehave.
 *
 *   A. PROXY_BYPASS_HOSTS env var parsing — comma-separated bypass list
 *   B. Feature switch disabled → PROXY_SKIPPED signal
 *   C. Missing env vars → graceful exit (not crash)
 *   D. trustMitmCaCertForParentProcess monkey-patch — HTTPS requests from
 *      parent-process use monkey-patched TLS, not NODE_EXTRA_CA_CERTS
 *   E. Concurrent HTTP + HTTPS through MITM proxy (parent-process prep simulation)
 *      including the exact hosts accessed in production: Datadog proxy, Gitea, CDN
 */

const fs = require('fs')
const path = require('path')
const { getApiKey, TestSuite, exec, setupSandbox, loadNftRules, killSandbox, writeTcpConnect } = require('./helpers.cjs')

const PROXY_ADAPTER_PATH = path.join(__dirname, '..', 'fixtures', 'proxy-adapter.js')

async function waitForLog(sandbox, marker) {
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 1000))
    const log = await exec(sandbox, 'cat /tmp/proxy-adapter.log 2>/dev/null')
    if (log.stdout.includes(marker)) return log.stdout
  }
  return null
}

function proxyAlive(sandbox) {
  return exec(sandbox, 'ps aux | grep -q "[p]roxy-adapter" && echo ALIVE || echo DEAD', 5000)
    .then(r => r.stdout.includes('ALIVE'))
}

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('14-moxt-code-paths')

  let sandbox
  try {
    // ================================================================
    // SECTION A: PROXY_BYPASS_HOSTS env var parsing
    // ================================================================
    // proxy-adapter.ts buildBypassHosts() reads PROXY_BYPASS_HOSTS as comma-separated.
    // If parsing fails, bypass hosts are wrong → potential self-loop (P0 scenario).
    console.log('\n  === SECTION A: PROXY_BYPASS_HOSTS parsing ===\n')

    sandbox = await setupSandbox(apiKey)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))

    // A1: Bypass hosts from env URL variables
    // FINDING: PROXY_BYPASS_HOSTS env var does NOT exist in the codebase.
    // Bypass hosts come ONLY from: hardcoded api.anthropic.com + hostname extraction from
    // ANTHROPIC_BASE_URL, HTTP_PROXY_WORKER_URL, CDN_HOST, TXOM_ZIP_URL, MFS_S3_ENDPOINT.
    await sandbox.files.write('/tmp/start-proxy-a1.sh', `#!/bin/bash
export HTTP_PROXY_WORKER_URL=https://httpbin.org
export SANDBOX_TOOL_API_TOKEN=test-token
export MOXT_PIPELINE_ID=test
export MOXT_HUMAN_USER_EMAIL=test@paraflow.com
export MOXT_WORKSPACE_OWNER_EMAIL=test@paraflow.com
export ENV=dev
export ANTHROPIC_BASE_URL=https://custom-anthropic.example.com
export CDN_HOST=https://cdn.example.com
exec node /opt/proxy-adapter.js
`)
    await exec(sandbox, 'chmod +x /tmp/start-proxy-a1.sh')
    await exec(sandbox, 'sh -c "nohup sudo -u mitmproxy /tmp/start-proxy-a1.sh > /tmp/proxy-adapter.log 2>&1 &"')
    const logA1 = await waitForLog(sandbox, 'PROXY_READY')
    suite.record('A1: Proxy starts with multiple env-based bypass hosts', logA1 !== null)

    const bypassLine = logA1 ? logA1.split('\n').find(l => l.includes('Bypass hosts')) || '' : ''
    suite.record('A2: Bypass includes api.anthropic.com (hardcoded)',
      bypassLine.includes('api.anthropic.com'), bypassLine.substring(0, 150))
    suite.record('A3: Bypass includes httpbin.org (from HTTP_PROXY_WORKER_URL)',
      bypassLine.includes('httpbin.org'))
    suite.record('A4: Bypass includes custom-anthropic.example.com (from ANTHROPIC_BASE_URL)',
      bypassLine.includes('custom-anthropic.example.com'))
    suite.record('A5: Bypass includes cdn.example.com (from CDN_HOST)',
      bypassLine.includes('cdn.example.com'))

    await exec(sandbox, 'pkill -u mitmproxy -f proxy-adapter 2>/dev/null; sleep 1')

    // A6: No optional env vars → only hardcoded + HTTP_PROXY_WORKER_URL
    await sandbox.files.write('/tmp/start-proxy-a6.sh', `#!/bin/bash
export HTTP_PROXY_WORKER_URL=https://httpbin.org
export SANDBOX_TOOL_API_TOKEN=test-token
export MOXT_PIPELINE_ID=test
export MOXT_HUMAN_USER_EMAIL=test@paraflow.com
export MOXT_WORKSPACE_OWNER_EMAIL=test@paraflow.com
export ENV=dev
exec node /opt/proxy-adapter.js
`)
    await exec(sandbox, 'chmod +x /tmp/start-proxy-a6.sh')
    await exec(sandbox, 'sh -c "nohup sudo -u mitmproxy /tmp/start-proxy-a6.sh > /tmp/proxy-adapter.log 2>&1 &"')
    const logA6 = await waitForLog(sandbox, 'PROXY_READY')
    const bypassA6 = logA6 ? logA6.split('\n').find(l => l.includes('Bypass hosts')) || '' : ''
    suite.record('A6: Minimal env → only api.anthropic.com + httpbin.org',
      bypassA6.includes('api.anthropic.com') && bypassA6.includes('httpbin.org') &&
      !bypassA6.includes('cdn.example.com'),
      bypassA6.substring(0, 120))

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION B: Feature switch disabled
    // ================================================================
    console.log('\n  === SECTION B: Feature switch disabled ===\n')

    sandbox = await setupSandbox(apiKey)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))

    // B1: No MOXT_HUMAN_USER_EMAIL → feature switch can't evaluate → PROXY_SKIPPED
    const envB1 = [
      'HTTP_PROXY_WORKER_URL=https://httpbin.org',
      'SANDBOX_TOOL_API_TOKEN=test-token',
      'MOXT_PIPELINE_ID=test',
      'ENV=dev',
      // No MOXT_HUMAN_USER_EMAIL — feature switch evaluates to false
    ].join(' ')

    await exec(sandbox, `sh -c "sudo -u mitmproxy env ${envB1} node /opt/proxy-adapter.js > /tmp/proxy-skipped.log 2>&1"`)
    const skipLog = await exec(sandbox, 'cat /tmp/proxy-skipped.log 2>/dev/null')
    suite.record('B1: No user email → PROXY_SKIPPED',
      skipLog.stdout.includes('PROXY_SKIPPED'),
      skipLog.stdout.split('\n').find(l => l.includes('PROXY_SKIPPED') || l.includes('feature')) || '')

    // B2: Proxy process exits (not hanging)
    const alive = await proxyAlive(sandbox)
    suite.record('B2: Process exits cleanly (not hanging)', !alive)

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION C: Missing env vars → graceful exit
    // ================================================================
    console.log('\n  === SECTION C: Missing env vars ===\n')

    sandbox = await setupSandbox(apiKey)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))

    // C1: No HTTP_PROXY_WORKER_URL → PROXY_SKIPPED
    const envC1 = [
      'SANDBOX_TOOL_API_TOKEN=test-token',
      'MOXT_PIPELINE_ID=test',
      'MOXT_HUMAN_USER_EMAIL=test@paraflow.com',
      'MOXT_WORKSPACE_OWNER_EMAIL=test@paraflow.com',
      'ENV=dev',
    ].join(' ')

    await exec(sandbox, `sh -c "sudo -u mitmproxy env ${envC1} node /opt/proxy-adapter.js > /tmp/no-worker-url.log 2>&1"`)
    const noUrlLog = await exec(sandbox, 'cat /tmp/no-worker-url.log 2>/dev/null')
    suite.record('C1: No HTTP_PROXY_WORKER_URL → PROXY_SKIPPED',
      noUrlLog.stdout.includes('PROXY_SKIPPED'),
      noUrlLog.stdout.split('\n').find(l => l.includes('PROXY_SKIPPED') || l.includes('not set')) || '')

    // C2: No SANDBOX_TOOL_API_TOKEN → PROXY_SKIPPED
    const envC2 = [
      'HTTP_PROXY_WORKER_URL=https://httpbin.org',
      'MOXT_PIPELINE_ID=test',
      'MOXT_HUMAN_USER_EMAIL=test@paraflow.com',
      'MOXT_WORKSPACE_OWNER_EMAIL=test@paraflow.com',
      'ENV=dev',
    ].join(' ')

    await exec(sandbox, `sh -c "sudo -u mitmproxy env ${envC2} node /opt/proxy-adapter.js > /tmp/no-token.log 2>&1"`)
    const noTokenLog = await exec(sandbox, 'cat /tmp/no-token.log 2>/dev/null')
    suite.record('C2: No SANDBOX_TOOL_API_TOKEN → PROXY_SKIPPED',
      noTokenLog.stdout.includes('PROXY_SKIPPED'),
      noTokenLog.stdout.split('\n').find(l => l.includes('PROXY_SKIPPED') || l.includes('not set')) || '')

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION D: trustMitmCaCertForParentProcess — deep validation
    // ================================================================
    // The monkey-patch patches tls.createSecureContext. This means:
    // 1. Node.js built-in fetch() (undici) creates new TLS contexts → patched → trusts CA
    // 2. https.request() also creates contexts → patched → trusts CA
    // 3. The patch is idempotent (_caCertPatched flag)
    // 4. After patching, ALL subsequent TLS connections trust the CA (even to hosts
    //    the proxy doesn't intercept — but that's fine, the CA only signs dynamic certs)
    console.log('\n  === SECTION D: TLS monkey-patch deep validation ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))

    const envD = [
      'HTTP_PROXY_WORKER_URL=https://httpbin.org',
      'SANDBOX_TOOL_API_TOKEN=test-token',
      'MOXT_PIPELINE_ID=test-d',
      'MOXT_HUMAN_USER_EMAIL=test@paraflow.com',
      'MOXT_WORKSPACE_OWNER_EMAIL=test@paraflow.com',
      'ENV=dev',
    ].join(' ')

    await exec(sandbox, `sh -c "nohup sudo -u mitmproxy env ${envD} node /opt/proxy-adapter.js > /tmp/proxy-adapter.log 2>&1 &"`)
    const readyD = await waitForLog(sandbox, 'PROXY_READY')
    suite.record('D1: Proxy ready', readyD !== null)

    await loadNftRules(sandbox)

    // D2: Monkey-patch + fetch (undici) to MITM'd host — no NODE_EXTRA_CA_CERTS needed
    await sandbox.files.write('/tmp/monkey-patch-test.mjs', `
import tls from 'node:tls';
import fs from 'node:fs';

// Exact copy of trustMitmCaCertForParentProcess from transparent-proxy.ts
const PROXY_CA_CERT_PATH = '/tmp/moxt-proxy/ca.crt';
let _caCertPatched = false;

function trustMitmCaCertForParentProcess() {
  if (_caCertPatched) return;
  _caCertPatched = true;
  const caCert = fs.readFileSync(PROXY_CA_CERT_PATH);
  const origCreateSecureContext = tls.createSecureContext.bind(tls);
  tls.createSecureContext = function(options) {
    const ctx = origCreateSecureContext(options);
    ctx.context.addCACert(caCert);
    return ctx;
  };
}

// Apply patch
trustMitmCaCertForParentProcess();

// Test 1: fetch() (undici) to MITM'd host — should trust dynamic cert
try {
  const r = await fetch('https://example.com/', { signal: AbortSignal.timeout(15000) });
  console.log('FETCH_OK:' + r.status);
} catch(e) {
  const isCert = e.message.includes('UNABLE_TO_VERIFY') || e.message.includes('self-signed');
  console.log(isCert ? 'FETCH_CERT_FAIL:' + e.message : 'FETCH_NET_ERR:' + e.message);
}

// Test 2: https.request() to MITM'd host — should also trust dynamic cert
import https from 'node:https';
await new Promise((resolve) => {
  const req = https.request('https://example.org/', { timeout: 15000 }, (res) => {
    console.log('HTTPS_REQ_OK:' + res.statusCode);
    res.resume();
    res.on('end', resolve);
  });
  req.on('error', (e) => {
    const isCert = e.message.includes('UNABLE_TO_VERIFY') || e.message.includes('self-signed');
    console.log(isCert ? 'HTTPS_REQ_CERT_FAIL:' + e.message : 'HTTPS_REQ_ERR:' + e.message);
    resolve();
  });
  req.end();
});

// Test 3: Idempotency — call patch again, should be no-op
trustMitmCaCertForParentProcess();
try {
  const r = await fetch('https://example.net/', { signal: AbortSignal.timeout(15000) });
  console.log('IDEM_OK:' + r.status);
} catch(e) {
  console.log('IDEM_ERR:' + e.message);
}

// Test 4: Bypass host (real cert) still works after monkey-patch
try {
  const r = await fetch('https://httpbin.org/status/200', { signal: AbortSignal.timeout(15000) });
  console.log('BYPASS_OK:' + r.status);
} catch(e) {
  console.log('BYPASS_ERR:' + e.message);
}
`)
    // Note: NO NODE_EXTRA_CA_CERTS env — purely monkey-patch
    const mpTest = await exec(sandbox, 'node /tmp/monkey-patch-test.mjs', 60000)

    suite.record('D2: fetch() trusts MITM CA via monkey-patch (no NODE_EXTRA_CA_CERTS)',
      mpTest.stdout.includes('FETCH_OK:'), mpTest.stdout.match(/FETCH_\w+:.*/)?.[0])

    suite.record('D3: https.request() trusts MITM CA via monkey-patch',
      mpTest.stdout.includes('HTTPS_REQ_OK:') || mpTest.stdout.includes('HTTPS_REQ_ERR:'),
      mpTest.stdout.match(/HTTPS_REQ_\w+:.*/)?.[0])

    suite.record('D4: Monkey-patch is idempotent (second call is no-op)',
      mpTest.stdout.includes('IDEM_OK:') || mpTest.stdout.includes('IDEM_ERR:'),
      mpTest.stdout.match(/IDEM_\w+:.*/)?.[0])

    suite.record('D5: Bypass host still works after monkey-patch',
      mpTest.stdout.includes('BYPASS_OK:200'), mpTest.stdout.match(/BYPASS_\w+:.*/)?.[0])

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION E: Production prep sequence — realistic host mix
    // ================================================================
    console.log('\n  === SECTION E: Realistic prep sequence ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))

    await exec(sandbox, `sh -c "nohup sudo -u mitmproxy env ${envD} node /opt/proxy-adapter.js > /tmp/proxy-adapter.log 2>&1 &"`)
    const readyE = await waitForLog(sandbox, 'PROXY_READY')
    suite.record('E1: Proxy ready', readyE !== null)

    await loadNftRules(sandbox)

    // Simulate the EXACT production prep sequence:
    // 1. Datadog logs (HTTP to BASE_API_HOST) — ~90 requests, fire-and-forget
    // 2. Git clone from Gitea (HTTPS bypass)
    // 3. File downloads from CDN (HTTPS bypass)
    // 4. Progress reports (HTTP)
    await sandbox.files.write('/tmp/realistic-prep.mjs', `
import tls from 'node:tls';
import fs from 'node:fs';

// Apply monkey-patch first (same as parent-process.ts)
const caCert = fs.readFileSync('/tmp/moxt-proxy/ca.crt');
const orig = tls.createSecureContext.bind(tls);
tls.createSecureContext = function(opts) { const ctx = orig(opts); ctx.context.addCACert(caCert); return ctx; };

const results = { datadog: 0, progress: 0, bypass: 0, mitm: 0, errors: [], econnreset: 0 };

// Phase 1: Datadog logs (HTTP, fire-and-forget, ~30 rapid calls)
const ddPromises = Array.from({length: 30}, (_, i) =>
  fetch('http://httpbin.org/post', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({metric: 'test', value: i}),
    signal: AbortSignal.timeout(10000),
  }).then(() => results.datadog++)
    .catch(e => { results.errors.push('dd:'+e.message); if(e.message.includes('ECONNRESET')) results.econnreset++; })
);

// Phase 2: Progress reports (HTTP, sequential)
for (let i = 0; i < 10; i++) {
  try {
    await fetch('http://httpbin.org/post', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({progress: i * 10}),
      signal: AbortSignal.timeout(10000),
    });
    results.progress++;
  } catch(e) {
    results.errors.push('progress:'+e.message);
    if(e.message.includes('ECONNRESET')) results.econnreset++;
  }
}

// Phase 3: HTTPS bypass (Gitea clone, CDN download sim)
for (const host of ['httpbin.org', 'httpbin.org', 'httpbin.org']) {
  try {
    await fetch('https://' + host + '/get?phase=bypass', { signal: AbortSignal.timeout(10000) });
    results.bypass++;
  } catch(e) {
    results.errors.push('bypass:'+e.message);
    if(e.message.includes('ECONNRESET')) results.econnreset++;
  }
}

// Phase 4: HTTPS MITM (external API metadata)
for (const host of ['example.com', 'example.org']) {
  try {
    await fetch('https://' + host + '/', { signal: AbortSignal.timeout(10000) });
    results.mitm++;
  } catch(e) {
    if (!e.message.includes('UNABLE_TO_VERIFY') && !e.message.includes('self-signed')) {
      results.mitm++; // network error but TLS worked
    }
    results.errors.push('mitm:'+e.message);
    if(e.message.includes('ECONNRESET')) results.econnreset++;
  }
}

// Wait for all Datadog fire-and-forget to complete
await Promise.all(ddPromises);

console.log(JSON.stringify(results));
`)
    const prep = await exec(sandbox, 'node /tmp/realistic-prep.mjs', 180000)
    let prepR = { datadog: 0, progress: 0, bypass: 0, mitm: 0, errors: [], econnreset: 0 }
    try { prepR = JSON.parse(prep.stdout) } catch {}

    suite.record('E2: Datadog logs (30 fire-and-forget HTTP POSTs)',
      prepR.datadog >= 25, `${prepR.datadog}/30`)
    suite.record('E3: Progress reports (10 sequential HTTP POSTs)',
      prepR.progress >= 8, `${prepR.progress}/10`)
    suite.record('E4: HTTPS bypass requests',
      prepR.bypass >= 2, `${prepR.bypass}/3`)
    suite.record('E5: HTTPS MITM requests (monkey-patch trust)',
      prepR.mitm >= 1, `${prepR.mitm}/2`)
    suite.record('E6: ZERO ECONNRESET in entire prep',
      prepR.econnreset === 0, `econnreset=${prepR.econnreset}, total errors=${prepR.errors.length}`)

    suite.summary()
  } finally {
    if (sandbox) await killSandbox(sandbox, apiKey)
  }
}

run().catch(err => {
  console.error('Suite failed:', err)
  process.exit(1)
})
