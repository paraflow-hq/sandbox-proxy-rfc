/**
 * Suite 08: Extended coverage — fills remaining gaps from test audit.
 *
 * Uses REAL proxy-adapter.js. Covers:
 *   1. Root user HTTPS to bypass host → tunnelBypass → receives REAL cert (not MITM)
 *   2. ECONNRESET adversarial with real proxy-adapter (pool build → idle → reuse)
 *   3. Higher concurrency (~50 requests, approaching production ~90)
 *
 * All tests in real E2B sandboxes.
 */

const fs = require('fs')
const path = require('path')
const { getApiKey, TestSuite, exec, setupSandbox, loadNftRules, snapshotRestore, killSandbox, writeTcpConnect } = require('./helpers.cjs')

const PROXY_ADAPTER_PATH = path.join(__dirname, '..', 'fixtures', 'proxy-adapter.js')

const ENV_VARS = [
  'HTTP_PROXY_WORKER_URL=https://httpbin.org',
  'SANDBOX_TOOL_API_TOKEN=test-token-for-rfc-validation',
  'MOXT_PIPELINE_ID=rfc-test-pipeline',
  'MOXT_HUMAN_USER_EMAIL=test@paraflow.com',
  'MOXT_WORKSPACE_OWNER_EMAIL=test@paraflow.com',
  'ENV=dev',
].join(' ')

async function waitForProxy(sandbox) {
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 1000))
    const log = await exec(sandbox, 'cat /tmp/proxy-adapter.log 2>/dev/null')
    if (log.stdout.includes('PROXY_READY')) return true
    if (log.stdout.includes('PROXY_SKIPPED')) return false
  }
  return false
}

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('08-extended-coverage')

  if (!fs.existsSync(PROXY_ADAPTER_PATH)) {
    console.error(`proxy-adapter.js not found at ${PROXY_ADAPTER_PATH}`)
    process.exit(1)
  }

  let sandbox
  try {
    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')

    const proxyJs = fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8')
    await sandbox.files.write('/opt/proxy-adapter.js', proxyJs)

    const startCmd = `sh -c "nohup sudo -u mitmproxy env ${ENV_VARS} node /opt/proxy-adapter.js > /tmp/proxy-adapter.log 2>&1 &"`

    console.log('\n  Starting real proxy-adapter...')
    await exec(sandbox, startCmd)
    const ready = await waitForProxy(sandbox)
    if (!ready) {
      const log = await exec(sandbox, 'cat /tmp/proxy-adapter.log 2>/dev/null')
      console.log('  Log:\n  ' + log.stdout.split('\n').slice(0, 10).join('\n  '))
      suite.record('Setup: proxy starts', false, 'PROXY_READY not found')
      suite.summary()
      return
    }
    console.log('  Proxy ready')

    await loadNftRules(sandbox)
    console.log('  nft rules loaded\n')

    // ==========================================================
    // GAP 1: Root user HTTPS to bypass host → tunnelBypass → real cert
    // ==========================================================
    // In production: root user's Agent code → fetch('https://api.anthropic.com/...')
    // → nft REDIRECT :443 → :18443 → TLS router reads SNI → bypass match
    // → tunnelBypass() → TCP tunnel → client receives REAL cert from upstream
    //
    // This is different from T12 in Suite 07 (which tests mitmproxy user direct,
    // skipping the proxy entirely via UID exemption).
    // Here we test: root user → nft REDIRECT → proxy → tunnelBypass → real cert.

    // T1: Root user HTTPS to bypass host — receives real cert, not MITM
    const rootBypass = await exec(sandbox, `python3 -c "
import ssl, socket
try:
    s = socket.create_connection(('httpbin.org', 443), timeout=20)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(s, server_hostname='httpbin.org')
    cert = ss.getpeercert(binary_form=True)
    # Decode DER cert to check issuer
    import subprocess
    with open('/tmp/bypass-cert.der', 'wb') as f:
        f.write(cert)
    result = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-issuer', '-in', '/tmp/bypass-cert.der'],
                          capture_output=True, text=True)
    issuer = result.stdout.strip()
    is_mitm = 'Moxt' in issuer
    print('ISSUER:' + issuer)
    print('IS_MITM:' + str(is_mitm))
    ss.close()
except Exception as e:
    print('ERROR:' + str(e))
"`, 30000)
    suite.record('T1: Root HTTPS to bypass host → tunnelBypass → real cert (not MITM)',
      rootBypass.stdout.includes('IS_MITM:False'),
      rootBypass.stdout)

    // T2: Root user HTTPS to NON-bypass host — receives MITM cert
    const rootMitm = await exec(sandbox, `python3 -c "
import ssl, socket
try:
    s = socket.create_connection(('example.com', 443), timeout=20)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(s, server_hostname='example.com')
    cert = ss.getpeercert(binary_form=True)
    import subprocess
    with open('/tmp/mitm-cert.der', 'wb') as f:
        f.write(cert)
    result = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-issuer', '-in', '/tmp/mitm-cert.der'],
                          capture_output=True, text=True)
    issuer = result.stdout.strip()
    is_mitm = 'Moxt' in issuer
    print('ISSUER:' + issuer)
    print('IS_MITM:' + str(is_mitm))
    ss.close()
except Exception as e:
    print('ERROR:' + str(e))
"`, 30000)
    suite.record('T2: Root HTTPS to non-bypass host → MITM cert (Moxt CA)',
      rootMitm.stdout.includes('IS_MITM:True'),
      rootMitm.stdout)

    // T3: Verify both certs are different (bypass = real, non-bypass = MITM)
    const certCmp = await exec(sandbox,
      'test -f /tmp/bypass-cert.der && test -f /tmp/mitm-cert.der && ! cmp -s /tmp/bypass-cert.der /tmp/mitm-cert.der && echo DIFFERENT || echo SAME_OR_MISSING')
    suite.record('T3: Bypass cert ≠ MITM cert (different issuers)',
      certCmp.stdout.includes('DIFFERENT'))

    // ==========================================================
    // GAP 2: ECONNRESET adversarial with REAL proxy-adapter
    // ==========================================================
    // Suite 04 tested this with Python simulator. Now test with real proxy-adapter.
    // Build connection pool → idle 6s → reuse. Under RFC architecture, all
    // connections go through proxy from the start, so no stale direct connections.

    // T4: Pool build (10 requests) → 6s idle → pool reuse (10 requests) — zero ECONNRESET
    await sandbox.files.write('/tmp/econnreset-real.mjs', `
const results = { phase1: 0, phase2: 0, errors: [] };

// Phase 1: build connection pool
for (let i = 0; i < 10; i++) {
  try {
    const r = await fetch('http://httpbin.org/get?phase=1&i=' + i, { signal: AbortSignal.timeout(15000) });
    results.phase1++;
  } catch (e) {
    results.errors.push('p1_' + i + ':' + e.message);
  }
}

// Idle — simulate keep-alive timeout window
await new Promise(r => setTimeout(r, 6000));

// Phase 2: reuse pool
for (let i = 0; i < 10; i++) {
  try {
    const r = await fetch('http://httpbin.org/get?phase=2&i=' + i, { signal: AbortSignal.timeout(15000) });
    results.phase2++;
  } catch (e) {
    results.errors.push('p2_' + i + ':' + e.code + ':' + e.message);
  }
}

console.log(JSON.stringify(results));
`)
    const ecrTest = await exec(sandbox, 'node /tmp/econnreset-real.mjs', 120000)
    let ecrResult = { phase1: 0, phase2: 0, errors: [] }
    try { ecrResult = JSON.parse(ecrTest.stdout) } catch {}
    const ecrEconnreset = ecrResult.errors.filter(e => e.includes('ECONNRESET')).length
    suite.record('T4: ECONNRESET adversarial (10+6s+10) — zero ECONNRESET',
      ecrEconnreset === 0 && ecrResult.phase1 > 0 && ecrResult.phase2 > 0,
      `phase1: ${ecrResult.phase1}, phase2: ${ecrResult.phase2}, econnreset: ${ecrEconnreset}, other errors: ${ecrResult.errors.length - ecrEconnreset}`)

    // T5: 3-wave pool health (10 req × 3 waves, 4s gap)
    await sandbox.files.write('/tmp/pool-waves-real.mjs', `
const results = { waves: [], errors: [] };
for (let wave = 0; wave < 3; wave++) {
  const promises = Array.from({length: 10}, (_, i) =>
    fetch('http://httpbin.org/get?w=' + wave + '&i=' + i, { signal: AbortSignal.timeout(15000) })
      .then(r => ({ ok: true, status: r.status }))
      .catch(e => { results.errors.push('w' + wave + '_' + i + ':' + e.message); return { ok: false }; })
  );
  const waveResults = await Promise.all(promises);
  results.waves.push(waveResults.filter(r => r.ok).length);
  if (wave < 2) await new Promise(r => setTimeout(r, 4000));
}
console.log(JSON.stringify(results));
`)
    const waveTest = await exec(sandbox, 'node /tmp/pool-waves-real.mjs', 120000)
    let waveResult = { waves: [], errors: [] }
    try { waveResult = JSON.parse(waveTest.stdout) } catch {}
    const allWavesOk = waveResult.waves.length === 3 && waveResult.waves.every(w => w >= 8) // allow 2 failures per wave (rate limiting)
    suite.record('T5: 3-wave pool health (10×3, 4s gaps) — no ECONNRESET',
      allWavesOk && waveResult.errors.filter(e => e.includes('ECONNRESET')).length === 0,
      `waves: ${JSON.stringify(waveResult.waves)}, econnreset: ${waveResult.errors.filter(e => e.includes('ECONNRESET')).length}`)

    // ==========================================================
    // GAP 3: Higher concurrency (50 requests, approaching production ~90)
    // ==========================================================

    // T6: 50 concurrent requests — all complete (no self-loop, no ECONNRESET)
    await sandbox.files.write('/tmp/concurrent-50.mjs', `
const N = 50;
const results = { ok: 0, errors: [], econnreset: 0 };
const promises = Array.from({length: N}, (_, i) =>
  fetch('http://httpbin.org/get?n=' + i, { signal: AbortSignal.timeout(30000) })
    .then(r => { results.ok++; })
    .catch(e => {
      results.errors.push(i + ':' + e.message);
      if (e.message.includes('ECONNRESET')) results.econnreset++;
    })
);
await Promise.all(promises);
console.log(JSON.stringify(results));
`)
    const conc50 = await exec(sandbox, 'node /tmp/concurrent-50.mjs', 120000)
    let conc50Result = { ok: 0, errors: [], econnreset: 0 }
    try { conc50Result = JSON.parse(conc50.stdout) } catch {}
    suite.record('T6: 50 concurrent requests — all complete',
      conc50Result.ok + conc50Result.errors.length === 50 && conc50Result.econnreset === 0,
      `ok: ${conc50Result.ok}, errors: ${conc50Result.errors.length}, econnreset: ${conc50Result.econnreset}`)

    // T7: 50 concurrent with nft counter verification
    await exec(sandbox, 'nft reset counters')
    await sandbox.files.write('/tmp/concurrent-50-count.mjs', `
const N = 50;
let ok = 0;
const promises = Array.from({length: N}, (_, i) =>
  fetch('http://httpbin.org/get?n=' + i, { signal: AbortSignal.timeout(30000) })
    .then(() => ok++)
    .catch(() => ok++)  // count all completions
);
await Promise.all(promises);
console.log('DONE:' + ok);
`)
    await exec(sandbox, 'node /tmp/concurrent-50-count.mjs', 120000)
    const counters = await exec(sandbox, 'nft list chain ip proxy output')
    const skuidMatch = counters.stdout.match(/skuid.*?packets\s+(\d+)/i)
    const redirectMatch = counters.stdout.match(/dport 80.*?packets\s+(\d+)/i)
    const skuidPkts = skuidMatch ? parseInt(skuidMatch[1]) : 0
    const redirectPkts = redirectMatch ? parseInt(redirectMatch[1]) : 0
    suite.record('T7: 50 concurrent — nft counters (skuid > 0, redirect > 0)',
      skuidPkts > 0 && redirectPkts > 0,
      `skuid: ${skuidPkts}, redirect(80): ${redirectPkts}`)

    // T8: Sequential burst — 20 requests, no delay (stress connection pool)
    await sandbox.files.write('/tmp/burst-20.mjs', `
const results = { ok: 0, errors: [] };
for (let i = 0; i < 20; i++) {
  try {
    await fetch('http://httpbin.org/get?burst=' + i, { signal: AbortSignal.timeout(15000) });
    results.ok++;
  } catch (e) {
    results.errors.push(i + ':' + e.code + ':' + e.message);
  }
}
console.log(JSON.stringify(results));
`)
    const burst = await exec(sandbox, 'node /tmp/burst-20.mjs', 120000)
    let burstResult = { ok: 0, errors: [] }
    try { burstResult = JSON.parse(burst.stdout) } catch {}
    suite.record('T8: 20 sequential burst — zero ECONNRESET',
      burstResult.errors.filter(e => e.includes('ECONNRESET')).length === 0,
      `ok: ${burstResult.ok}, total errors: ${burstResult.errors.length}, econnreset: ${burstResult.errors.filter(e => e.includes('ECONNRESET')).length}`)

    suite.summary()
  } finally {
    if (sandbox) await killSandbox(sandbox, apiKey)
  }
}

run().catch(err => {
  console.error('Suite failed:', err)
  process.exit(1)
})
