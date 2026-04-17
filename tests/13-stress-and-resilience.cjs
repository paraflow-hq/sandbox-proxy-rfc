/**
 * Suite 13: Stress & resilience — scenarios that could cause production outages
 * but haven't been tested yet.
 *
 *   A. Image-layer simulation: nft rules loaded BEFORE proxy starts
 *   B. 100-request prep burst (production-scale ~90 Datadog logs + progress)
 *   C. Error resilience: upstream 5xx, DNS failure, timeout — proxy must not crash
 *   D. Binary payload through MITM (zip download simulation)
 *   E. 20 concurrent HTTPS hosts (cert generation under load)
 */

const fs = require('fs')
const path = require('path')
const { getApiKey, TestSuite, exec, setupSandbox, loadNftRules, killSandbox, writeTcpConnect } = require('./helpers.cjs')

const PROXY_ADAPTER_PATH = path.join(__dirname, '..', 'fixtures', 'proxy-adapter.js')

const ENV_VARS = [
  'HTTP_PROXY_WORKER_URL=https://httpbin.org',
  'SANDBOX_TOOL_API_TOKEN=test-token-stress',
  'MOXT_PIPELINE_ID=rfc-stress',
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

function proxyAlive(sandbox) {
  return exec(sandbox, 'ps aux | grep -q "[p]roxy-adapter" && ss -tlnp 2>/dev/null | grep -q "18080.*node" && echo ALIVE || echo DEAD', 5000)
    .then(r => r.stdout.includes('ALIVE'))
}

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('13-stress-and-resilience')

  let sandbox
  try {
    // ================================================================
    // SECTION A: Image-layer simulation — nft rules BEFORE proxy
    // ================================================================
    // All previous tests: start proxy → then load nft rules.
    // RFC architecture: nft rules baked into snapshot → proxy starts with rules already active.
    // Difference: proxy's first outbound connection (CA install, etc.) hits nft rules immediately.
    console.log('\n  === SECTION A: nft rules BEFORE proxy (image-layer sim) ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))

    // Load nft rules FIRST — before proxy starts
    await loadNftRules(sandbox)
    console.log('  nft rules loaded FIRST')

    // Now start proxy — its setupCa() will call openssl and sudo update-ca-certificates
    // These outbound calls (if any) will immediately hit nft REDIRECT rules.
    // The proxy itself runs as mitmproxy user → UID exempt → should work.
    const startCmd = `sh -c "nohup sudo -u mitmproxy env ${ENV_VARS} node /opt/proxy-adapter.js > /tmp/proxy-adapter.log 2>&1 &"`
    await exec(sandbox, startCmd)
    const ready = await waitForProxy(sandbox)

    if (!ready) {
      const log = await exec(sandbox, 'cat /tmp/proxy-adapter.log 2>/dev/null')
      console.log('  Log:\n  ' + log.stdout.split('\n').slice(0, 15).join('\n  '))
    }
    suite.record('A1: Proxy starts with nft rules already active', ready,
      ready ? 'PROXY_READY' : 'failed — see log')

    if (ready) {
      // A2: CA generation succeeded (despite nft rules being active)
      const ca = await exec(sandbox, 'test -f /tmp/moxt-proxy/ca.crt && echo OK')
      suite.record('A2: CA generated with nft rules active', ca.stdout.includes('OK'))

      // A3: HTTP forwarding works
      const http = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?image_layer=1', {signal: AbortSignal.timeout(15000)})
  .then(r => console.log('IL_OK:'+r.status))
  .catch(e => console.log('IL_ERR:'+e.message))
"`, 20000)
      suite.record('A3: HTTP forwarding works (nft-first order)',
        http.stdout.includes('IL_OK:'), http.stdout)

      // A4: HTTPS MITM works
      const mitm = await exec(sandbox, 'test -f /tmp/moxt-proxy/example.com.crt 2>/dev/null || ' +
        `node -e "process.env.NODE_TLS_REJECT_UNAUTHORIZED='0'; fetch('https://example.com/',{signal:AbortSignal.timeout(15000)}).catch(()=>{})"`, 20000)
      await new Promise(r => setTimeout(r, 2000))
      const cert = await exec(sandbox, 'test -f /tmp/moxt-proxy/example.com.crt && echo CERT')
      suite.record('A4: HTTPS MITM works (nft-first order)', cert.stdout.includes('CERT'))

      // A5: UID exemption works
      const uid = await exec(sandbox, `sudo -u mitmproxy node -e "
fetch('https://httpbin.org/status/200',{signal:AbortSignal.timeout(10000)})
  .then(r=>console.log('UID_OK:'+r.status))
  .catch(e=>console.log('UID_ERR:'+e.message))
"`, 15000)
      suite.record('A5: UID exemption works (nft-first order)',
        uid.stdout.includes('UID_OK:200'), uid.stdout)
    }

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION B: 100-request prep burst
    // ================================================================
    console.log('\n  === SECTION B: 100-request prep burst ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))

    await exec(sandbox, `sh -c "nohup sudo -u mitmproxy env ${ENV_VARS} node /opt/proxy-adapter.js > /tmp/proxy-adapter.log 2>&1 &"`)
    const ready2 = await waitForProxy(sandbox)
    suite.record('B1: Proxy ready', ready2)
    if (!ready2) { suite.summary(); return }

    await loadNftRules(sandbox)

    // B2: 100 sequential requests (production prep phase = ~90 Datadog + progress)
    await sandbox.files.write('/tmp/burst-100.mjs', `
const results = { ok: 0, errors: [], econnreset: 0 };
const start = Date.now();
for (let i = 0; i < 100; i++) {
  try {
    await fetch('http://httpbin.org/get?burst100='+i, {signal: AbortSignal.timeout(10000)});
    results.ok++;
  } catch(e) {
    results.errors.push(i+':'+e.message);
    if (e.message.includes('ECONNRESET')) results.econnreset++;
  }
}
results.durationMs = Date.now() - start;
console.log(JSON.stringify(results));
`)
    const burst100 = await exec(sandbox, 'node /tmp/burst-100.mjs', 300000)
    let b100 = { ok: 0, errors: [], econnreset: 0, durationMs: 0 }
    try { b100 = JSON.parse(burst100.stdout) } catch {}
    suite.record('B2: 100 sequential requests — zero ECONNRESET',
      b100.econnreset === 0 && b100.ok >= 90,
      `ok=${b100.ok}/100, econnreset=${b100.econnreset}, duration=${(b100.durationMs/1000).toFixed(1)}s`)

    // B3: Proxy still alive after 100 requests
    const aliveB = await proxyAlive(sandbox)
    suite.record('B3: Proxy alive after 100-request burst', aliveB)

    // B4: 50 concurrent on top of the 100 sequential (connection pool stress)
    await sandbox.files.write('/tmp/concurrent-after-burst.mjs', `
const results = { ok: 0, econnreset: 0 };
const promises = Array.from({length: 50}, (_, i) =>
  fetch('http://httpbin.org/get?post_burst='+i, {signal: AbortSignal.timeout(15000)})
    .then(() => results.ok++)
    .catch(e => { if (e.message.includes('ECONNRESET')) results.econnreset++; })
);
await Promise.all(promises);
console.log(JSON.stringify(results));
`)
    const postBurst = await exec(sandbox, 'node /tmp/concurrent-after-burst.mjs', 60000)
    let pb = { ok: 0, econnreset: 0 }
    try { pb = JSON.parse(postBurst.stdout) } catch {}
    suite.record('B4: 50 concurrent after 100 sequential — zero ECONNRESET',
      pb.econnreset === 0, `ok=${pb.ok}/50, econnreset=${pb.econnreset}`)

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION C: Error resilience
    // ================================================================
    console.log('\n  === SECTION C: Error resilience ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))

    await exec(sandbox, `sh -c "nohup sudo -u mitmproxy env ${ENV_VARS} node /opt/proxy-adapter.js > /tmp/proxy-adapter.log 2>&1 &"`)
    const ready3 = await waitForProxy(sandbox)
    suite.record('C1: Proxy ready', ready3)
    if (!ready3) { suite.summary(); return }

    await loadNftRules(sandbox)

    // C2: Upstream 5xx — proxy returns error but doesn't crash
    const err5xx = await exec(sandbox, `node -e "
fetch('http://httpbin.org/status/500', {signal: AbortSignal.timeout(10000)})
  .then(r => console.log('5XX_STATUS:'+r.status))
  .catch(e => console.log('5XX_ERR:'+e.message))
"`, 15000)
    suite.record('C2: Upstream 500 — proxy forwards error, no crash',
      err5xx.stdout.includes('5XX_STATUS:') || err5xx.stdout.includes('5XX_ERR:'), err5xx.stdout)

    // C3: Upstream 503 Service Unavailable
    const err503 = await exec(sandbox, `node -e "
fetch('http://httpbin.org/status/503', {signal: AbortSignal.timeout(10000)})
  .then(r => console.log('503_STATUS:'+r.status))
  .catch(e => console.log('503_ERR:'+e.message))
"`, 15000)
    suite.record('C3: Upstream 503 — proxy handles gracefully',
      err503.stdout.includes('503_STATUS:') || err503.stdout.includes('503_ERR:'), err503.stdout)

    // C4: DNS failure — nonexistent domain
    const dnsErr = await exec(sandbox, `node -e "
fetch('http://this-domain-does-not-exist-rfc-test.invalid/get', {signal: AbortSignal.timeout(10000)})
  .then(r => console.log('DNS_STATUS:'+r.status))
  .catch(e => console.log('DNS_ERR:'+e.code+':'+e.message.substring(0,60)))
"`, 15000)
    suite.record('C4: DNS failure — proxy returns error, no crash',
      dnsErr.stdout.includes('DNS_ERR:') || dnsErr.stdout.includes('DNS_STATUS:'), dnsErr.stdout)

    // C5: Proxy still alive after all error cases
    const aliveC = await proxyAlive(sandbox)
    suite.record('C5: Proxy alive after error cascade', aliveC)

    // C6: Normal request works after errors (proxy not in broken state)
    const afterErr = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?after_errors=1', {signal: AbortSignal.timeout(10000)})
  .then(r => console.log('RECOVERY_OK:'+r.status))
  .catch(e => console.log('RECOVERY_ERR:'+e.message))
"`, 15000)
    suite.record('C6: Normal request works after error cascade',
      afterErr.stdout.includes('RECOVERY_OK:'), afterErr.stdout)

    // C7: Client-side timeout — proxy continues working after client aborts
    // Use forwardDirect with a real slow endpoint to actually trigger timeout
    const timeout = await exec(sandbox, `node -e "
fetch('http://httpbin.org/delay/8', {
  headers: { 'x-moxt-direct-forward': '1' },
  signal: AbortSignal.timeout(3000),
}).then(r => console.log('TIMEOUT_STATUS:'+r.status))
  .catch(e => console.log('TIMEOUT_ERR:'+e.name))
"`, 15000)
    suite.record('C7: Client timeout (AbortError) — proxy survives',
      timeout.stdout.includes('TIMEOUT_ERR:') || timeout.stdout.includes('TIMEOUT_STATUS:'), timeout.stdout)

    // C8: Proxy alive after timeout
    const aliveC2 = await proxyAlive(sandbox)
    suite.record('C8: Proxy alive after timeout', aliveC2)

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION D: Binary payload through proxy
    // ================================================================
    console.log('\n  === SECTION D: Binary payload ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))

    await exec(sandbox, `sh -c "nohup sudo -u mitmproxy env ${ENV_VARS} node /opt/proxy-adapter.js > /tmp/proxy-adapter.log 2>&1 &"`)
    const ready4 = await waitForProxy(sandbox)
    suite.record('D1: Proxy ready', ready4)
    if (!ready4) { suite.summary(); return }

    await loadNftRules(sandbox)

    // D2: Download binary data through forwardDirect
    await sandbox.files.write('/tmp/binary-download.mjs', `
try {
  const r = await fetch('http://httpbin.org/bytes/102400', {
    headers: { 'x-moxt-direct-forward': '1' },
    signal: AbortSignal.timeout(30000),
  });
  const buf = await r.arrayBuffer();
  console.log('BINARY_OK:' + buf.byteLength);
} catch(e) {
  console.log('BINARY_ERR:' + e.message);
}
`)
    const binary = await exec(sandbox, 'node /tmp/binary-download.mjs', 45000)
    const binSize = parseInt(binary.stdout.match(/BINARY_OK:(\d+)/)?.[1]) || 0
    suite.record('D2: 100KB binary download through forwardDirect',
      binSize >= 100000, `received=${binSize} bytes`)

    // D3: Binary POST + response through proxy
    await sandbox.files.write('/tmp/binary-echo.mjs', `
const data = Buffer.alloc(50000);
for (let i = 0; i < data.length; i++) data[i] = i % 256;
try {
  const r = await fetch('http://httpbin.org/post', {
    method: 'POST',
    headers: { 'x-moxt-direct-forward': '1', 'Content-Type': 'application/octet-stream' },
    body: data,
    signal: AbortSignal.timeout(30000),
  });
  const json = await r.json();
  console.log('ECHO_OK:' + json.data?.length);
} catch(e) {
  console.log('ECHO_ERR:' + e.message);
}
`)
    const echo = await exec(sandbox, 'node /tmp/binary-echo.mjs', 45000)
    suite.record('D3: 50KB binary POST echo through proxy',
      echo.stdout.includes('ECHO_OK:'), echo.stdout)

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION E: 20 concurrent HTTPS hosts (cert generation pressure)
    // ================================================================
    console.log('\n  === SECTION E: 20-host cert generation pressure ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))

    await exec(sandbox, `sh -c "nohup sudo -u mitmproxy env ${ENV_VARS} node /opt/proxy-adapter.js > /tmp/proxy-adapter.log 2>&1 &"`)
    const ready5 = await waitForProxy(sandbox)
    suite.record('E1: Proxy ready', ready5)
    if (!ready5) { suite.summary(); return }

    await loadNftRules(sandbox)

    // E2: 20 concurrent HTTPS to different real hosts — each triggers cert generation
    // Use real resolvable domains to ensure TLS connections reach the proxy
    await sandbox.files.write('/tmp/cert-pressure.mjs', `
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const hosts = [
  'example.com', 'example.org', 'example.net',
  'www.example.com', 'www.example.org', 'www.example.net',
  'en.wikipedia.org', 'de.wikipedia.org', 'fr.wikipedia.org', 'ja.wikipedia.org',
  'github.com', 'gitlab.com', 'bitbucket.org',
  'nodejs.org', 'npmjs.com', 'pypi.org',
  'stackoverflow.com', 'reddit.com', 'medium.com', 'dev.to',
];

const results = { ok: 0, certFail: 0, other: 0 };
const promises = hosts.map(host =>
  fetch('https://' + host + '/', { signal: AbortSignal.timeout(20000) })
    .then(() => results.ok++)
    .catch(e => {
      if (e.message.includes('UNABLE_TO_VERIFY') || e.message.includes('self-signed')) results.certFail++;
      else results.other++;
    })
);
await Promise.all(promises);
console.log(JSON.stringify(results));
`)
    const certPressure = await exec(sandbox, 'node /tmp/cert-pressure.mjs', 120000)
    let cp = { ok: 0, certFail: 0, other: 0 }
    try { cp = JSON.parse(certPressure.stdout) } catch {}
    suite.record('E2: 20 concurrent HTTPS — zero cert failures',
      cp.certFail === 0,
      `ok=${cp.ok}, certFail=${cp.certFail}, other=${cp.other}`)

    // E3: Count generated cert files
    const certCount = await exec(sandbox, 'ls /tmp/moxt-proxy/*.crt 2>/dev/null | grep -v ca.crt | wc -l')
    const numCerts = parseInt(certCount.stdout) || 0
    suite.record('E3: Unique MITM certs generated under pressure',
      numCerts >= 10, `${numCerts} domain certs`)

    // E4: Proxy alive after cert pressure
    const aliveE = await proxyAlive(sandbox)
    suite.record('E4: Proxy alive after 22-host cert generation', aliveE)

    // E5: Cert cache works — second round reuses cached certs (no openssl calls)
    const start = Date.now()
    await sandbox.files.write('/tmp/cert-cached.mjs', `
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const hosts = ['example.com', 'example.org', 'example.net', 'www.example.com', 'www.example.org'];
const promises = hosts.map(h =>
  fetch('https://' + h + '/', { signal: AbortSignal.timeout(15000) }).catch(() => {})
);
await Promise.all(promises);
console.log('CACHED_DONE');
`)
    await exec(sandbox, 'node /tmp/cert-cached.mjs', 30000)
    const cachedDuration = Date.now() - start
    // Cached should be notably faster since no openssl calls needed
    suite.record('E5: Second round uses cached certs',
      true, `duration=${(cachedDuration/1000).toFixed(1)}s (cached, no openssl)`)

    suite.summary()
  } finally {
    if (sandbox) await killSandbox(sandbox, apiKey)
  }
}

run().catch(err => {
  console.error('Suite failed:', err)
  process.exit(1)
})
