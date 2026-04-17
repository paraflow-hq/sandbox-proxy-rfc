/**
 * Suite 19: Real proxy-adapter.js --passthrough via setStartCmd template build
 *
 * The production path: real proxy-adapter.js with --passthrough flag baked into
 * E2B template via setStartCmd. This is the exact combination that will run in
 * production — Node.js V8 heap, libuv handles, proxy internal state (mitmActive
 * flag, server objects) frozen by Firecracker during first template snapshot.
 *
 * Suite 16 tested setStartCmd with Python proxy.
 * Suite 18 tested real proxy-adapter --passthrough with runtime setup.
 * This suite tests the cross: real proxy-adapter --passthrough + setStartCmd.
 *
 * Sections:
 *   A. Template build with real proxy-adapter.js --passthrough
 *   B. Sandbox from template: passthrough mode from birth, nft rules, UID exemption
 *   C. /__activate-mitm on template-built sandbox
 *   D. Post-activation MITM behavior
 *   E. Snapshot/restore after MITM activation (second snapshot on top of template snapshot)
 *   F. Second sandbox from same template (isolation + independent activation)
 */

const fs = require('fs')
const path = require('path')
const {
  getApiKey, TestSuite, exec, killSandbox, snapshotRestore, writeTcpConnect, Sandbox,
} = require('./helpers.cjs')
const { Template, waitForPort } = require('e2b')

const PROXY_ADAPTER_JS = fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'proxy-adapter.js'), 'utf-8')
const NFT_RULES = fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'nft-rules.conf'), 'utf-8')

const TEMPLATE_ALIAS = `rfc-real-passthrough-${Date.now()}`

async function healthCheck(sandbox) {
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
import ssl, socket, subprocess
s = socket.create_connection(('${host}', 443), timeout=15)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ss = ctx.wrap_socket(s, server_hostname='${host}')
cert = ss.getpeercert(binary_form=True)
with open('/tmp/cert-check.der', 'wb') as f:
    f.write(cert)
r = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-issuer', '-in', '/tmp/cert-check.der'], capture_output=True, text=True)
print(r.stdout.strip())
ss.close()
"`, 20000)
  return r.stdout.trim()
}

function proxyAlive(sandbox) {
  return exec(sandbox, 'ps aux | grep -q "[p]roxy-adapter" && ss -tlnp 2>/dev/null | grep -q "18080.*node" && echo ALIVE || echo DEAD', 5000)
    .then(r => r.stdout.includes('ALIVE'))
}

const ENV_VARS = 'HTTP_PROXY_WORKER_URL=https://httpbin.org SANDBOX_TOOL_API_TOKEN=test-token MOXT_PIPELINE_ID=rfc-19 MOXT_HUMAN_USER_EMAIL=test@paraflow.com MOXT_WORKSPACE_OWNER_EMAIL=test@paraflow.com ENV=dev'

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('19-template-real-passthrough')
  let templateId = null
  const sandboxes = []

  try {
    // ================================================================
    // SECTION A: Template build with real proxy-adapter.js --passthrough
    // ================================================================
    console.log('\n  === SECTION A: Template build ===\n')
    console.log('  Building template with real proxy-adapter.js --passthrough...')

    const template = Template()
      .fromTemplate('base')
      .setUser('root')
      .runCmd('apt-get update -qq && apt-get install -y -qq nftables curl ca-certificates openssl python3 2>/dev/null')
      .runCmd('useradd -r -M -s /usr/sbin/nologin mitmproxy')
      .runCmd('mkdir -p /opt/moxt-proxy')
      .runCmd(`cat > /opt/moxt-proxy/proxy-adapter.js << 'JSEOF'
${PROXY_ADAPTER_JS}
JSEOF`)
      .runCmd(`cat > /opt/moxt-proxy/nft-rules.conf << 'NFTEOF'
${NFT_RULES}
NFTEOF`)
      .runCmd('chmod 644 /opt/moxt-proxy/proxy-adapter.js /opt/moxt-proxy/nft-rules.conf')
      .setStartCmd(
        `sh -c "sudo -u mitmproxy env ${ENV_VARS} node /opt/moxt-proxy/proxy-adapter.js --passthrough & sleep 1 && nft -f /opt/moxt-proxy/nft-rules.conf && wait"`,
        waitForPort(18080)
      )

    const buildStart = Date.now()
    const buildInfo = await Template.build(template, {
      alias: TEMPLATE_ALIAS,
      apiKey,
      onBuildLogs: (log) => {
        if (log.message) {
          const msg = log.message.trim()
          if (msg.includes('start') || msg.includes('ready') || msg.includes('PROXY') ||
              msg.includes('Build') || msg.includes('CACHED') || msg.includes('finalize')) {
            console.log(`    [build] ${msg.substring(0, 120)}`)
          }
        }
      },
    })
    const buildDuration = ((Date.now() - buildStart) / 1000).toFixed(1)
    templateId = buildInfo.templateId

    suite.record('A1: Template built with real proxy-adapter.js --passthrough',
      !!templateId,
      `templateId=${templateId}, ${buildDuration}s`)

    if (!templateId) {
      suite.summary()
      return
    }

    // ================================================================
    // SECTION B: Sandbox from template — passthrough from birth
    // ================================================================
    console.log('\n  === SECTION B: Passthrough from birth ===\n')

    console.log(`  Creating sandbox from template ${templateId}...`)
    const sandbox = await Sandbox.create(templateId, { apiKey, timeoutMs: 5 * 60 * 1000 })
    sandboxes.push(sandbox)
    console.log(`  Sandbox: ${sandbox.sandboxId}`)
    await writeTcpConnect(sandbox)

    // B1: Proxy alive from template snapshot
    let alive = await proxyAlive(sandbox)
    if (!alive) { await new Promise(r => setTimeout(r, 3000)); alive = await proxyAlive(sandbox) }
    suite.record('B1: Proxy alive from template snapshot', alive)

    // B2: Health reports passthrough
    const health = await healthCheck(sandbox)
    suite.record('B2: Health reports passthrough mode',
      health.includes('"passthrough"'),
      health.includes('"passthrough"') ? 'mode=passthrough' : health.substring(0, 150))

    // B3: No CA cert (passthrough skips setupCa)
    const caCheck = await exec(sandbox, 'test -f /tmp/moxt-proxy/ca.crt && echo EXISTS || echo MISSING')
    suite.record('B3: No CA cert in passthrough template', caCheck.stdout.includes('MISSING'))

    // B4: nft rules present from template
    const nft = await exec(sandbox, 'nft list ruleset 2>/dev/null')
    suite.record('B4: nft rules present from template snapshot',
      nft.stdout.includes('skuid') && nft.stdout.includes('redirect'))

    // B5: Proxy runs as mitmproxy user
    const uidCheck = await exec(sandbox, `python3 -c "
import subprocess, pwd
r = subprocess.run(['pgrep', '-f', 'node /opt/moxt-proxy/proxy-adapter'], capture_output=True, text=True)
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
    suite.record('B5: Proxy runs as mitmproxy user',
      uidCheck.stdout.includes('USER=mitmproxy'),
      uidCheck.stdout.trim())

    // B6: HTTP works in passthrough (direct forwarding)
    let httpOk = false
    for (let i = 0; i < 3 && !httpOk; i++) {
      const r = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?s19=1', { signal: AbortSignal.timeout(15000) })
  .then(r => r.text())
  .then(t => console.log('OK:' + t.substring(0, 100)))
  .catch(e => console.log('ERR:' + e.message))
"`, 20000)
      httpOk = r.stdout.includes('OK:')
      if (!httpOk && i < 2) await new Promise(r => setTimeout(r, 2000))
    }
    suite.record('B6: HTTP works in passthrough from template', httpOk)

    // B7: HTTPS gets real upstream cert (not MITM)
    const certIssuer = await getMitmCertIssuer(sandbox, 'httpbin.org')
    suite.record('B7: HTTPS gets real upstream cert (passthrough)',
      !certIssuer.includes('Moxt') && certIssuer.length > 0,
      certIssuer)

    // B8: UID exemption works
    const bypass = await exec(sandbox,
      'sudo -u mitmproxy curl -s --max-time 10 http://httpbin.org/get 2>/dev/null', 15000)
    suite.record('B8: mitmproxy user bypasses proxy',
      bypass.stdout.includes('"url"') || bypass.stdout.includes('httpbin'))

    // B9: 10 requests zero ECONNRESET
    const burst = await exec(sandbox, `node -e "
async function go() {
  const r = [];
  for (let i = 0; i < 10; i++) {
    try {
      const res = await fetch('http://httpbin.org/get?b=' + i, { signal: AbortSignal.timeout(10000) });
      r.push({ ok: true });
    } catch (e) {
      r.push({ err: e.code || e.message });
    }
  }
  console.log(JSON.stringify({ total: r.length, errors: r.filter(x => x.err) }));
}
go();
"`, 120000)
    let burstParsed
    try { burstParsed = JSON.parse(burst.stdout) } catch {}
    suite.record('B9: 10 passthrough requests zero errors',
      burstParsed && burstParsed.errors.length === 0,
      burst.stdout.substring(0, 100))

    // ================================================================
    // SECTION C: /__activate-mitm on template-built sandbox
    // ================================================================
    console.log('\n  === SECTION C: Activate MITM ===\n')

    // C1: Generate CA
    await exec(sandbox, 'sudo -u mitmproxy mkdir -p /tmp/moxt-proxy')
    const caGen = await exec(sandbox, `sudo -u mitmproxy openssl req -new -x509 -newkey rsa:2048 -nodes \
      -keyout /tmp/moxt-proxy/ca.key -out /tmp/moxt-proxy/ca.crt -days 1 \
      -subj "/CN=Moxt Sandbox Proxy CA" 2>/dev/null && echo CA_OK`)
    suite.record('C1: CA generated', caGen.stdout.includes('CA_OK'))

    // C2: Install CA to system trust store
    await exec(sandbox, 'sudo cp /tmp/moxt-proxy/ca.crt /usr/local/share/ca-certificates/moxt-proxy-ca.crt && sudo update-ca-certificates 2>/dev/null')

    // C3: Activate MITM
    const actResult = await activateMitm(sandbox, ",'sandboxToken':'test-token','pipelineId':'rfc-19'")
    suite.record('C3: /__activate-mitm succeeds',
      actResult.includes('activated'))

    // C4: Health reports mitm
    const healthMitm = await healthCheck(sandbox)
    suite.record('C4: Health reports mitm after activation',
      healthMitm.includes('"mitm"'))

    // ================================================================
    // SECTION D: Post-activation MITM behavior
    // ================================================================
    console.log('\n  === SECTION D: Post-activation MITM ===\n')

    // D1: HTTPS gets MITM cert
    const mitmCert = await getMitmCertIssuer(sandbox, 'example.com')
    suite.record('D1: HTTPS gets Moxt MITM cert',
      mitmCert.includes('Moxt'), mitmCert)

    // D2: Different host also gets MITM cert
    const mitmCert2 = await getMitmCertIssuer(sandbox, 'example.org')
    suite.record('D2: Different host also gets MITM cert',
      mitmCert2.includes('Moxt'), mitmCert2)

    // D3: HTTP works post-activation
    const httpPost = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?post=1', { signal: AbortSignal.timeout(10000) })
  .then(r => console.log('STATUS:' + r.status))
  .catch(e => console.log('ERR:' + e.message))
"`, 15000)
    suite.record('D3: HTTP works post-activation',
      httpPost.stdout.includes('STATUS:'))

    // ================================================================
    // SECTION E: Snapshot/restore (second snapshot on template snapshot)
    // ================================================================
    console.log('\n  === SECTION E: Snapshot/restore ===\n')

    const restored = await snapshotRestore(sandbox, apiKey)
    sandboxes.push(restored)

    let aliveE = await proxyAlive(restored)
    if (!aliveE) { await new Promise(r => setTimeout(r, 3000)); aliveE = await proxyAlive(restored) }
    suite.record('E1: Proxy alive after restore', aliveE)

    const nftE = await exec(restored, 'nft list ruleset 2>/dev/null')
    suite.record('E2: nft rules survived', nftE.stdout.includes('skuid'))

    const healthE = await healthCheck(restored)
    suite.record('E3: Still mitm mode after restore', healthE.includes('"mitm"'))

    const mitmE = await getMitmCertIssuer(restored, 'example.com')
    suite.record('E4: MITM cert works after restore',
      mitmE.includes('Moxt'), mitmE || '(empty — cert gen may need real resolvable host)')

    // ================================================================
    // SECTION F: Second sandbox — independent, starts in passthrough
    // ================================================================
    console.log('\n  === SECTION F: Second sandbox (isolation) ===\n')

    console.log('  Creating second sandbox from same template...')
    const sandbox2 = await Sandbox.create(templateId, { apiKey, timeoutMs: 5 * 60 * 1000 })
    sandboxes.push(sandbox2)
    console.log(`  Sandbox 2: ${sandbox2.sandboxId}`)

    // F1: Second sandbox starts in passthrough (not affected by first sandbox's activation)
    await new Promise(r => setTimeout(r, 3000))
    const health2 = await healthCheck(sandbox2)
    suite.record('F1: Second sandbox starts in passthrough (isolated)',
      health2.includes('"passthrough"'),
      health2.includes('passthrough') ? 'mode=passthrough' : health2.substring(0, 150))

    // F2: Second sandbox HTTPS gets real cert (not MITM — still passthrough)
    await writeTcpConnect(sandbox2)
    const cert2 = await getMitmCertIssuer(sandbox2, 'httpbin.org')
    suite.record('F2: Second sandbox HTTPS gets real cert',
      !cert2.includes('Moxt') && cert2.length > 0,
      cert2 || '(empty)')

    // F3: Independently activate second sandbox
    await exec(sandbox2, 'sudo -u mitmproxy mkdir -p /tmp/moxt-proxy && sudo -u mitmproxy openssl req -new -x509 -newkey rsa:2048 -nodes -keyout /tmp/moxt-proxy/ca.key -out /tmp/moxt-proxy/ca.crt -days 1 -subj "/CN=Moxt Sandbox Proxy CA" 2>/dev/null')
    await exec(sandbox2, 'sudo cp /tmp/moxt-proxy/ca.crt /usr/local/share/ca-certificates/moxt-proxy-ca.crt && sudo update-ca-certificates 2>/dev/null')
    const act2 = await activateMitm(sandbox2)
    suite.record('F3: Second sandbox independently activates MITM',
      act2.includes('activated'))

    // F4: Second sandbox now gets MITM cert
    const mitmCert3 = await getMitmCertIssuer(sandbox2, 'example.net')
    suite.record('F4: Second sandbox MITM works',
      mitmCert3.includes('Moxt'), mitmCert3)

  } catch (error) {
    console.error(`\n  FATAL: ${error.message}`)
    console.error(error.stack)
    suite.record('FATAL ERROR', false, error.message)
  } finally {
    console.log('\n  === Cleanup ===\n')
    for (const sb of sandboxes) await killSandbox(sb, apiKey)
    if (templateId) {
      try {
        const resp = await fetch(`https://api.e2b.dev/templates/${templateId}`, {
          method: 'DELETE', headers: { 'X-API-Key': apiKey },
        })
        console.log(`  [cleanup] Template ${templateId} ${resp.ok ? 'deleted' : 'delete failed HTTP ' + resp.status}`)
      } catch (e) {
        console.log(`  [cleanup] Template delete error: ${e.message}`)
      }
    }
  }

  const allPassed = suite.summary()
  process.exit(allPassed ? 0 : 1)
}

run().catch(e => { console.error(e); process.exit(1) })
