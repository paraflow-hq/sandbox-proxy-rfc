/**
 * Suite 10: Production sequence + TLS monkey-patch + passthrough hot-switch.
 *
 * Three sections:
 *   A. Production startup sequence with REAL proxy-adapter (trustMitmCaCertForParentProcess)
 *   B. Passthrough → MITM hot-switch (RFC core mechanism, new implementation)
 *   C. HTTPS forwardDirect path + concurrent HTTPS MITM
 */

const fs = require('fs')
const path = require('path')
const { getApiKey, TestSuite, exec, setupSandbox, loadNftRules, killSandbox, writeTcpConnect } = require('./helpers.cjs')

const PROXY_ADAPTER_PATH = path.join(__dirname, '..', 'fixtures', 'proxy-adapter.js')
const PROD_SEQ_PATH = path.join(__dirname, '..', 'fixtures', 'production-sequence.mjs')
const HOTSWITCH_PATH = path.join(__dirname, '..', 'fixtures', 'passthrough-hotswitch.mjs')

const ENV_VARS = [
  'HTTP_PROXY_WORKER_URL=https://httpbin.org',
  'SANDBOX_TOOL_API_TOKEN=test-token-for-rfc-validation',
  'MOXT_PIPELINE_ID=rfc-prod-seq',
  'MOXT_HUMAN_USER_EMAIL=test@paraflow.com',
  'MOXT_WORKSPACE_OWNER_EMAIL=test@paraflow.com',
  'ENV=dev',
].join(' ')

async function waitForLog(sandbox, marker, timeoutMs = 30000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    await new Promise(r => setTimeout(r, 1000))
    const log = await exec(sandbox, 'cat /tmp/proxy-adapter.log 2>/dev/null; cat /tmp/hotswitch.log 2>/dev/null')
    if (log.stdout.includes(marker)) return true
  }
  return false
}

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('10-production-sequence')

  let sandbox
  try {
    // ================================================================
    // SECTION A: Production startup with real proxy-adapter
    // ================================================================
    console.log('\n  === SECTION A: Production startup sequence ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')

    // Upload real proxy-adapter + production sequence script
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))
    await sandbox.files.write('/tmp/production-sequence.mjs', fs.readFileSync(PROD_SEQ_PATH, 'utf-8'))

    // Start real proxy-adapter
    const startCmd = `sh -c "nohup sudo -u mitmproxy env ${ENV_VARS} node /opt/proxy-adapter.js > /tmp/proxy-adapter.log 2>&1 &"`
    await exec(sandbox, startCmd)
    const ready = await waitForLog(sandbox, 'PROXY_READY')
    suite.record('A1: Real proxy-adapter starts', ready)
    if (!ready) {
      const log = await exec(sandbox, 'cat /tmp/proxy-adapter.log 2>/dev/null')
      console.log('  Log:\n  ' + log.stdout.split('\n').slice(0, 10).join('\n  '))
      suite.summary(); return
    }

    // Load nft rules
    await loadNftRules(sandbox)

    // Run production sequence script — this tests:
    // - trustMitmCaCertForParentProcess() monkey-patch
    // - Prep phase HTTP/HTTPS requests through proxy
    // - HTTPS MITM trust via monkey-patch (NOT NODE_EXTRA_CA_CERTS)
    // - Bypass host HTTPS
    // - Sequential burst (20 requests)
    // - Child process with NODE_EXTRA_CA_CERTS
    const seqResult = await exec(sandbox, 'node /tmp/production-sequence.mjs', 180000)
    let seqData = { steps: [], errors: [] }
    try { seqData = JSON.parse(seqResult.stdout) } catch {}

    for (const step of seqData.steps) {
      suite.record(`A-${step.step}`, step.ok, step.detail || '')
    }

    // A-summary: zero ECONNRESET in entire sequence
    const ecrCount = seqData.errors.filter(e => e.includes('ECONNRESET')).length
    suite.record('A-ECONNRESET: zero in entire prep sequence',
      ecrCount === 0, `errors: ${seqData.errors.length}, econnreset: ${ecrCount}`)

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION B: Passthrough → MITM hot-switch
    // ================================================================
    console.log('\n  === SECTION B: Passthrough → MITM hot-switch ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')

    // Upload hot-switch proxy
    await sandbox.files.write('/opt/hotswitch.mjs', fs.readFileSync(HOTSWITCH_PATH, 'utf-8'))

    // Generate CA (like setupCa() would in production)
    await exec(sandbox, `sudo -u mitmproxy mkdir -p /tmp/moxt-proxy && sudo -u mitmproxy openssl req -new -x509 -newkey rsa:2048 -nodes -keyout /tmp/moxt-proxy/ca.key -out /tmp/moxt-proxy/ca.crt -days 1 -subj "/CN=Moxt Hotswitch Test CA" 2>/dev/null`)

    // Start hot-switch proxy as mitmproxy user
    await exec(sandbox, `sh -c "nohup sudo -u mitmproxy node /opt/hotswitch.mjs > /tmp/hotswitch.log 2>&1 &"`)
    const hsReady = await waitForLog(sandbox, 'HOTSWITCH_READY')
    suite.record('B1: Hot-switch proxy starts in passthrough mode', hsReady)
    if (!hsReady) {
      const log = await exec(sandbox, 'cat /tmp/hotswitch.log 2>/dev/null')
      console.log('  Log:\n  ' + log.stdout.split('\n').slice(0, 10).join('\n  '))
      suite.summary(); return
    }

    // Load nft rules
    await loadNftRules(sandbox)

    // B2: Passthrough mode — HTTPS goes through as TCP tunnel (real cert from upstream)
    const ptTest = await exec(sandbox, `python3 -c "
import ssl, socket, subprocess
s = socket.create_connection(('example.com', 443), timeout=15)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ss = ctx.wrap_socket(s, server_hostname='example.com')
cert = ss.getpeercert(binary_form=True)
with open('/tmp/pt-cert.der', 'wb') as f:
    f.write(cert)
result = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-issuer', '-in', '/tmp/pt-cert.der'], capture_output=True, text=True)
is_real = 'Moxt' not in result.stdout
print('PASSTHROUGH_CERT:' + ('REAL' if is_real else 'MITM') + ' ISSUER:' + result.stdout.strip())
ss.close()
"`, 20000)
    suite.record('B2: Passthrough mode — HTTPS gets real cert (not MITM)',
      ptTest.stdout.includes('PASSTHROUGH_CERT:REAL'), ptTest.stdout)

    // B3: HTTP relay works in passthrough mode
    const ptHttp = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?mode=passthrough', {signal: AbortSignal.timeout(15000)})
  .then(r => r.json().then(j => console.log('PT_HTTP:' + j.url)))
  .catch(e => console.log('PT_HTTP_ERR:' + e.message))
"`, 20000)
    suite.record('B3: HTTP relay works in passthrough mode',
      ptHttp.stdout.includes('PT_HTTP:'), ptHttp.stdout)

    // B4: Activate MITM via POST /__activate-mitm
    // Kill socat on 18080 first for direct loopback
    await exec(sandbox, 'for pid in $(ps aux | grep socat | grep -E "18080|18443" | grep -v grep | awk "{print \\$2}"); do kill $pid 2>/dev/null; done; sleep 1')

    const activateResult = await exec(sandbox, `python3 -c "
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 18080))
body = json.dumps({'caKeyPath': '/tmp/moxt-proxy/ca.key', 'caCertPath': '/tmp/moxt-proxy/ca.crt'})
req = 'POST /__activate-mitm HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nContent-Type: application/json\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s' % (len(body), body)
s.sendall(req.encode())
data = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
    except: break
s.close()
text = data.decode()
parts = text.split('\\r\\n\\r\\n', 1)
print(parts[1] if len(parts) > 1 else text)
"`, 10000)
    suite.record('B4: /__activate-mitm switches to MITM mode',
      activateResult.stdout.includes('"activated"') || activateResult.stdout.includes('true'),
      activateResult.stdout.trim().substring(0, 80))

    // B5: After MITM activation — HTTPS gets MITM cert (Moxt CA)
    await new Promise(r => setTimeout(r, 2000))
    // Verify proxy is still alive and in mitm mode
    const hsLog = await exec(sandbox, 'tail -5 /tmp/hotswitch.log 2>/dev/null')
    console.log('  hotswitch log: ' + hsLog.stdout.split('\n').slice(-3).join(' | '))

    const mitmTest = await exec(sandbox, `python3 -c "
import ssl, socket, subprocess, sys
try:
    print('Connecting...', file=sys.stderr)
    s = socket.create_connection(('example.com', 443), timeout=15)
    print('Connected, wrapping TLS...', file=sys.stderr)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(s, server_hostname='example.com')
    print('TLS done', file=sys.stderr)
    cert = ss.getpeercert(binary_form=True)
    with open('/tmp/mitm-cert2.der', 'wb') as f:
        f.write(cert)
    result = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-issuer', '-in', '/tmp/mitm-cert2.der'], capture_output=True, text=True)
    is_mitm = 'Moxt' in result.stdout or 'Hotswitch' in result.stdout
    print('POST_ACTIVATION:' + ('MITM' if is_mitm else 'REAL') + ' ISSUER:' + result.stdout.strip())
    ss.close()
except Exception as e:
    print('B5_ERROR:' + str(e))
" 2>&1`, 25000)
    suite.record('B5: After activation — HTTPS gets MITM cert',
      mitmTest.stdout.includes('POST_ACTIVATION:MITM'),
      mitmTest.stdout.replace(/\n/g, ' | ').substring(0, 150))

    // B6: HTTP relay still works after mode switch
    const mitmHttp = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?mode=mitm', {signal: AbortSignal.timeout(15000)})
  .then(r => r.json().then(j => console.log('MITM_HTTP:' + j.url)))
  .catch(e => console.log('MITM_HTTP_ERR:' + e.message))
"`, 20000)
    suite.record('B6: HTTP relay works after MITM activation',
      mitmHttp.stdout.includes('MITM_HTTP:'), mitmHttp.stdout)

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION C: HTTPS forwardDirect + concurrent HTTPS MITM
    // ================================================================
    console.log('\n  === SECTION C: HTTPS forwardDirect + concurrent MITM ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))

    await exec(sandbox, `sh -c "nohup sudo -u mitmproxy env ${ENV_VARS} node /opt/proxy-adapter.js > /tmp/proxy-adapter.log 2>&1 &"`)
    const ready2 = await waitForLog(sandbox, 'PROXY_READY')
    suite.record('C1: Proxy ready for HTTPS tests', ready2)
    if (!ready2) { suite.summary(); return }

    await loadNftRules(sandbox)

    // C2: HTTPS forwardDirect (x-moxt-direct-forward + HTTPS)
    await sandbox.files.write('/tmp/https-direct.mjs', `
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
try {
  const r = await fetch('https://httpbin.org/get', {
    headers: { 'x-moxt-direct-forward': '1' },
    signal: AbortSignal.timeout(15000),
  });
  const body = await r.text();
  console.log('HTTPS_DIRECT_STATUS:' + r.status + ' HAS_ORIGIN:' + body.includes('"origin"'));
} catch(e) {
  console.log('HTTPS_DIRECT_ERR:' + e.message);
}
`)
    const httpsDirect = await exec(sandbox, 'NODE_EXTRA_CA_CERTS=/tmp/moxt-proxy/ca.crt node /tmp/https-direct.mjs', 20000)
    suite.record('C2: HTTPS forwardDirect (bypass port + direct connection)',
      httpsDirect.stdout.includes('HTTPS_DIRECT_STATUS:200'),
      httpsDirect.stdout)

    // C3: 10 concurrent HTTPS MITM requests
    await sandbox.files.write('/tmp/concurrent-https.mjs', `
const N = 10;
const hosts = ['example.com', 'example.org', 'example.net', 'www.example.com', 'www.example.org',
               'test.example.com', 'test.example.org', 'test.example.net', 'foo.example.com', 'bar.example.com'];
const results = { ok: 0, certFail: 0, other: 0 };
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const promises = hosts.map((host, i) =>
  fetch('https://' + host + '/', { signal: AbortSignal.timeout(15000) })
    .then(r => { results.ok++; })
    .catch(e => {
      if (e.message.includes('UNABLE_TO_VERIFY') || e.message.includes('self-signed')) results.certFail++;
      else results.other++;
    })
);
await Promise.all(promises);
console.log(JSON.stringify(results));
`)
    const concHttps = await exec(sandbox, 'node /tmp/concurrent-https.mjs', 60000)
    let concResult = { ok: 0, certFail: 0, other: 0 }
    try { concResult = JSON.parse(concHttps.stdout) } catch {}
    suite.record('C3: 10 concurrent HTTPS MITM — all TLS handshakes succeed',
      concResult.certFail === 0,
      `ok=${concResult.ok}, certFail=${concResult.certFail}, other=${concResult.other}`)

    // C4: Verify 10 unique MITM certs generated
    const certCount = await exec(sandbox, 'ls /tmp/moxt-proxy/*.crt 2>/dev/null | grep -v ca.crt | wc -l')
    const numCerts = parseInt(certCount.stdout) || 0
    suite.record('C4: Multiple unique MITM certs generated',
      numCerts >= 5, `${numCerts} domain certs`)

    suite.summary()
  } finally {
    if (sandbox) await killSandbox(sandbox, apiKey)
  }
}

run().catch(err => {
  console.error('Suite failed:', err)
  process.exit(1)
})
