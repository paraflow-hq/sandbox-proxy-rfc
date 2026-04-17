/**
 * Suite 18: Real proxy-adapter.js with --passthrough + /__activate-mitm
 *
 * This is the final gap: verifying the actual proxy-adapter code (not a
 * Python simulator or independent hotswitch implementation) supports:
 *   1. --passthrough flag: proxy starts without CA, forwards HTTP directly,
 *      tunnels all HTTPS via raw TCP (no MITM)
 *   2. POST /__activate-mitm: switches to MITM mode with provided CA,
 *      subsequent HTTPS connections get MITM certificates
 *
 * All tests run in real E2B sandboxes with nft rules active.
 *
 * Sections:
 *   A. --passthrough startup: proxy starts without CA, health reports passthrough
 *   B. Passthrough behavior: HTTP forwarded directly, HTTPS tunneled (real upstream cert)
 *   C. /__activate-mitm: switch to MITM, verify HTTPS gets proxy cert
 *   D. Post-activation: HTTP via worker, HTTPS MITM, bypass hosts still tunnel
 *   E. Snapshot/restore: passthrough → activate → snapshot → restore → still MITM
 *   F. Idempotent activation: second /__activate-mitm doesn't crash
 */

const fs = require('fs')
const path = require('path')
const {
  getApiKey, TestSuite, exec, setupSandbox, loadNftRules, killSandbox,
  snapshotRestore, writeTcpConnect,
} = require('./helpers.cjs')

const PROXY_ADAPTER_PATH = path.join(__dirname, '..', 'fixtures', 'proxy-adapter.js')

async function waitForProxy(sandbox, logFile = '/tmp/proxy-adapter.log') {
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 1000))
    const log = await exec(sandbox, `cat ${logFile} 2>/dev/null`)
    if (log.stdout.includes('PROXY_READY')) return true
    if (log.stdout.includes('PROXY_SKIPPED')) return false
  }
  return false
}

function proxyAlive(sandbox) {
  return exec(sandbox, 'ps aux | grep -q "[p]roxy-adapter" && ss -tlnp 2>/dev/null | grep -q "18080.*node" && echo ALIVE || echo DEAD', 5000)
    .then(r => r.stdout.includes('ALIVE'))
}

async function healthCheck(sandbox) {
  // Use raw socket to bypass E2B socat
  const r = await exec(sandbox, `python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 18080))
s.sendall(b'GET /__health HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n')
data=b''
while True:
    try:
        c=s.recv(4096)
        if not c:break
        data+=c
    except:break
s.close()
print(data.decode())
"`, 10000)
  return r.stdout
}

async function activateMitm(sandbox, extraFields = '') {
  const r = await exec(sandbox, `python3 -c "
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(('127.0.0.1', 18080))
body = json.dumps({'caKeyPath':'/tmp/moxt-proxy/ca.key','caCertPath':'/tmp/moxt-proxy/ca.crt'${extraFields}})
req = 'POST /__activate-mitm HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nContent-Type: application/json\\r\\nContent-Length: '+str(len(body))+'\\r\\nConnection: close\\r\\n\\r\\n'+body
s.sendall(req.encode())
data=b''
while True:
    try:
        c=s.recv(4096)
        if not c:break
        data+=c
    except:break
s.close()
print(data.decode())
"`, 15000)
  return r.stdout
}

async function getMitmCertIssuer(sandbox, host = 'example.com') {
  const r = await exec(sandbox, `python3 -c "
import ssl, socket
s = socket.create_connection(('${host}', 443), timeout=15)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ss = ctx.wrap_socket(s, server_hostname='${host}')
cert = ss.getpeercert(binary_form=True)
import subprocess
with open('/tmp/cert-check.der', 'wb') as f:
    f.write(cert)
r = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-issuer', '-in', '/tmp/cert-check.der'], capture_output=True, text=True)
print(r.stdout.strip())
ss.close()
"`, 20000)
  return r.stdout.trim()
}

// Minimal passthrough env — no SANDBOX_TOOL_API_TOKEN or HTTP_PROXY_WORKER_URL required
const PASSTHROUGH_ENV = [
  'HTTP_PROXY_WORKER_URL=https://httpbin.org',
  'SANDBOX_TOOL_API_TOKEN=',
  'MOXT_PIPELINE_ID=',
  'MOXT_HUMAN_USER_EMAIL=test@paraflow.com',
  'MOXT_WORKSPACE_OWNER_EMAIL=test@paraflow.com',
  'ENV=dev',
].join(' ')

// Full env for post-activation
const FULL_ENV = [
  'HTTP_PROXY_WORKER_URL=https://httpbin.org',
  'SANDBOX_TOOL_API_TOKEN=test-token-rfc18',
  'MOXT_PIPELINE_ID=rfc-suite18',
  'MOXT_HUMAN_USER_EMAIL=test@paraflow.com',
  'MOXT_WORKSPACE_OWNER_EMAIL=test@paraflow.com',
  'ENV=dev',
].join(' ')

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('18-real-passthrough-activate-mitm')

  let sandbox
  try {
    // ================================================================
    // SECTION A: --passthrough startup
    // ================================================================
    console.log('\n  === SECTION A: --passthrough startup ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))

    // Start with --passthrough flag
    await exec(sandbox, `sh -c "nohup sudo -u mitmproxy env ${FULL_ENV} node /opt/proxy-adapter.js --passthrough > /tmp/proxy-adapter.log 2>&1 &"`)
    const ready = await waitForProxy(sandbox)

    suite.record('A1: Proxy starts with --passthrough flag', ready)

    if (!ready) {
      const log = await exec(sandbox, 'cat /tmp/proxy-adapter.log 2>/dev/null')
      console.log('  Log:\n  ' + log.stdout.split('\n').slice(0, 20).join('\n  '))
      suite.summary()
      return
    }

    // A2: Health reports passthrough mode
    const health = await healthCheck(sandbox)
    suite.record('A2: Health reports passthrough mode',
      health.includes('"passthrough"'),
      health.includes('"passthrough"') ? 'mode=passthrough' : health.substring(0, 150))

    // A3: No CA cert generated in passthrough
    const caCheck = await exec(sandbox, 'test -f /tmp/moxt-proxy/ca.crt && echo EXISTS || echo MISSING')
    suite.record('A3: No CA cert in passthrough mode',
      caCheck.stdout.includes('MISSING'))

    // A4: Proxy runs as mitmproxy user
    const uidCheck = await exec(sandbox, `python3 -c "
import subprocess, pwd
r = subprocess.run(['pgrep', '-f', 'node /opt/proxy-adapter'], capture_output=True, text=True)
for pid in r.stdout.strip().split():
    try:
        uid = open(f'/proc/{pid}/status').read()
        for line in uid.split('\\\\n'):
            if line.startswith('Uid:'):
                real_uid = line.split()[1]
                user = pwd.getpwuid(int(real_uid)).pw_name
                print(f'PID={pid} USER={user}')
    except: pass
"`)
    suite.record('A4: Proxy runs as mitmproxy user',
      uidCheck.stdout.includes('USER=mitmproxy'),
      uidCheck.stdout.trim())

    // ================================================================
    // SECTION B: Passthrough behavior with nft rules
    // ================================================================
    console.log('\n  === SECTION B: Passthrough behavior ===\n')

    await loadNftRules(sandbox)

    // B1: HTTP requests forwarded directly (not via worker)
    let httpOk = false
    let httpDetail = ''
    for (let attempt = 0; attempt < 3 && !httpOk; attempt++) {
      const httpReq = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?suite=18', { signal: AbortSignal.timeout(15000) })
  .then(r => r.text())
  .then(t => console.log('HTTP_OK:' + t.substring(0, 200)))
  .catch(e => console.log('HTTP_ERR:' + e.message))
"`, 20000)
      httpOk = httpReq.stdout.includes('HTTP_OK:')
      httpDetail = httpReq.stdout.substring(0, 100)
      if (!httpOk && attempt < 2) await new Promise(r => setTimeout(r, 2000))
    }
    suite.record('B1: HTTP request works in passthrough mode', httpOk, httpDetail)

    // B2: HTTPS gets real upstream cert (not MITM)
    const certIssuer = await getMitmCertIssuer(sandbox, 'httpbin.org')
    suite.record('B2: HTTPS gets real upstream cert (not Moxt CA)',
      !certIssuer.includes('Moxt') && certIssuer.length > 0,
      certIssuer)

    // B3: Multiple passthrough requests — zero ECONNRESET
    const burstResult = await exec(sandbox, `node -e "
async function burst() {
  const results = [];
  for (let i = 0; i < 10; i++) {
    try {
      const r = await fetch('http://httpbin.org/get?burst=' + i, { signal: AbortSignal.timeout(10000) });
      results.push({ i, status: r.status });
    } catch (e) {
      results.push({ i, error: e.code || e.message });
    }
  }
  console.log(JSON.stringify({ total: results.length, errors: results.filter(r => r.error) }));
}
burst();
"`, 120000)
    let burstParsed
    try { burstParsed = JSON.parse(burstResult.stdout) } catch { burstParsed = null }
    suite.record('B3: 10 passthrough requests — zero errors',
      burstParsed && burstParsed.errors.length === 0,
      burstResult.stdout.substring(0, 100))

    // B4: UID exemption works in passthrough
    const bypass = await exec(sandbox,
      'sudo -u mitmproxy curl -s --max-time 10 http://httpbin.org/get 2>/dev/null', 15000)
    suite.record('B4: mitmproxy user bypasses proxy in passthrough',
      bypass.stdout.includes('"url"') || bypass.stdout.includes('httpbin'))

    // ================================================================
    // SECTION C: /__activate-mitm
    // ================================================================
    console.log('\n  === SECTION C: /__activate-mitm ===\n')

    // C1: Generate CA cert (simulating parent-process setupCa)
    await exec(sandbox, 'sudo -u mitmproxy mkdir -p /tmp/moxt-proxy')
    const caGen = await exec(sandbox, `sudo -u mitmproxy openssl req -new -x509 -newkey rsa:2048 -nodes \
      -keyout /tmp/moxt-proxy/ca.key -out /tmp/moxt-proxy/ca.crt -days 1 \
      -subj "/CN=Moxt Sandbox Proxy CA" 2>/dev/null && echo CA_OK`)
    suite.record('C1: CA generated', caGen.stdout.includes('CA_OK'))

    // C2: Install CA to system trust store
    await exec(sandbox, 'sudo cp /tmp/moxt-proxy/ca.crt /usr/local/share/ca-certificates/moxt-proxy-ca.crt && sudo update-ca-certificates 2>/dev/null')

    // C3: Activate MITM
    const activateResult = await activateMitm(sandbox, ",'sandboxToken':'test-token-rfc18','pipelineId':'rfc-suite18'")
    suite.record('C3: /__activate-mitm returns activated',
      activateResult.includes('activated'),
      activateResult.includes('activated') ? 'activated=true' : activateResult.substring(0, 150))

    // C4: Health now reports mitm mode
    const healthAfter = await healthCheck(sandbox)
    suite.record('C4: Health reports mitm mode after activation',
      healthAfter.includes('"mitm"'),
      healthAfter.includes('"mitm"') ? 'mode=mitm' : healthAfter.substring(0, 150))

    // C5: Proxy still alive after activation
    const aliveC = await proxyAlive(sandbox)
    suite.record('C5: Proxy alive after activation', aliveC)

    // ================================================================
    // SECTION D: Post-activation MITM behavior
    // ================================================================
    console.log('\n  === SECTION D: Post-activation MITM ===\n')

    // D1: HTTPS now gets MITM cert
    const mitmIssuer = await getMitmCertIssuer(sandbox, 'example.com')
    suite.record('D1: HTTPS gets Moxt MITM cert after activation',
      mitmIssuer.includes('Moxt'),
      mitmIssuer)

    // D2: Different host also gets MITM cert
    const mitmIssuer2 = await getMitmCertIssuer(sandbox, 'example.org')
    suite.record('D2: Different host also gets MITM cert',
      mitmIssuer2.includes('Moxt'),
      mitmIssuer2)

    // D3: HTTP still works after activation
    const httpAfter = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?post_activate=1', { signal: AbortSignal.timeout(10000) })
  .then(r => console.log('HTTP_STATUS:' + r.status))
  .catch(e => console.log('HTTP_ERR:' + e.message))
"`, 15000)
    suite.record('D3: HTTP works after MITM activation',
      httpAfter.stdout.includes('HTTP_STATUS:'),
      httpAfter.stdout.trim())

    // D4: Proxy alive after MITM traffic
    const aliveD = await proxyAlive(sandbox)
    suite.record('D4: Proxy alive after MITM traffic', aliveD)

    // ================================================================
    // SECTION E: Snapshot/restore after activation
    // ================================================================
    console.log('\n  === SECTION E: Snapshot/restore ===\n')

    const restored = await snapshotRestore(sandbox, apiKey)
    sandbox = restored

    // E1: Proxy alive after restore (allow brief settling time)
    let aliveE = await proxyAlive(sandbox)
    if (!aliveE) {
      await new Promise(r => setTimeout(r, 3000))
      aliveE = await proxyAlive(sandbox)
    }
    suite.record('E1: Proxy alive after snapshot/restore', aliveE)

    // E2: nft rules survived
    const nftE = await exec(sandbox, 'nft list ruleset 2>/dev/null')
    suite.record('E2: nft rules survived restore',
      nftE.stdout.includes('skuid') && nftE.stdout.includes('redirect'))

    // E3: Health still reports mitm
    const healthE = await healthCheck(sandbox)
    suite.record('E3: Health reports mitm after restore',
      healthE.includes('"mitm"'))

    // E4: HTTPS still gets MITM cert after restore
    const mitmAfterRestore = await getMitmCertIssuer(sandbox, 'www.example.com')
    suite.record('E4: HTTPS gets MITM cert after restore',
      mitmAfterRestore.includes('Moxt'),
      mitmAfterRestore)

    // E5: HTTP works after restore
    const httpE = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?after_restore=1', { signal: AbortSignal.timeout(10000) })
  .then(r => console.log('HTTP_STATUS:' + r.status))
  .catch(e => console.log('HTTP_ERR:' + e.message))
"`, 15000)
    suite.record('E5: HTTP works after restore',
      httpE.stdout.includes('HTTP_STATUS:'))

    // ================================================================
    // SECTION F: Idempotent activation
    // ================================================================
    console.log('\n  === SECTION F: Idempotent activation ===\n')

    // F1: Second activation doesn't crash
    const activate2 = await activateMitm(sandbox)
    suite.record('F1: Second /__activate-mitm succeeds (idempotent)',
      activate2.includes('activated'))

    // F2: Proxy still alive
    const aliveF = await proxyAlive(sandbox)
    suite.record('F2: Proxy alive after double activation', aliveF)

    // F3: MITM still works (use real domain to ensure DNS resolves)
    const mitmF = await getMitmCertIssuer(sandbox, 'example.net')
    suite.record('F3: MITM works after double activation',
      mitmF.includes('Moxt'),
      mitmF || '(empty)')

  } catch (error) {
    console.error(`\n  FATAL: ${error.message}`)
    console.error(error.stack)
    suite.record('FATAL ERROR', false, error.message)
  } finally {
    console.log('\n  === Cleanup ===\n')
    if (sandbox) await killSandbox(sandbox, apiKey)
  }

  const allPassed = suite.summary()
  process.exit(allPassed ? 0 : 1)
}

run().catch(e => {
  console.error(e)
  process.exit(1)
})
