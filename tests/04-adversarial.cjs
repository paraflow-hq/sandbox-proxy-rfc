/**
 * Test Suite 4: Adversarial — Try to Break the Design
 *
 * ATTACK 1: Reproduce ECONNRESET (pool build → idle → reuse)
 * ATTACK 2: Reproduce P0 self-loop (mitmproxy user fetch HTTPS)
 * ATTACK 3: Pool health over time (3 waves with gaps)
 * ATTACK 4: Concurrent load
 */

const path = require('path')
const {
  getApiKey, TestSuite, exec, setupSandbox, startProxy,
  loadNftRules, snapshotRestore, killSandbox, writeNodeScript,
} = require('./helpers.cjs')

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('04-adversarial')

  console.log('╔═══════════════════════════════════════════════╗')
  console.log('║  Test 04: Adversarial — Break the Design      ║')
  console.log('╚═══════════════════════════════════════════════╝\n')

  let sandbox
  try {
    sandbox = await setupSandbox(apiKey)
    await startProxy(sandbox)
    await loadNftRules(sandbox)
    sandbox = await snapshotRestore(sandbox, apiKey)

    // Write attack scripts
    const fixturesDir = path.join(__dirname, '..', 'fixtures')
    await writeNodeScript(sandbox, path.join(fixturesDir, 'attack-econnreset.mjs'), '/tmp/attack1.mjs')
    await writeNodeScript(sandbox, path.join(fixturesDir, 'attack-selfloop.mjs'), '/tmp/attack2.mjs')
    await writeNodeScript(sandbox, path.join(fixturesDir, 'attack-pool-waves.mjs'), '/tmp/attack3.mjs')
    await writeNodeScript(sandbox, path.join(fixturesDir, 'attack-concurrent.mjs'), '/tmp/attack4.mjs')

    // ATTACK 1: ECONNRESET
    console.log('\n--- ATTACK 1: Reproduce ECONNRESET ---\n')
    {
      const r = await exec(sandbox, 'node /tmp/attack1.mjs', 30000)
      let res = {}
      try { res = JSON.parse(r.stdout) } catch {
        console.log('  raw:', r.stdout.substring(0, 200))
      }
      suite.record('ATTACK1: 5 req → 6s idle → 5 req pool reuse — no ECONNRESET',
        res.phase1 === 5 && res.phase2 === 5 && (!res.errors || res.errors.length === 0),
        `phase1:${res.phase1} phase2:${res.phase2} errors:${res.errors?.length || 0}`)
    }

    // ATTACK 2: P0 self-loop
    console.log('\n--- ATTACK 2: P0 self-loop ---\n')
    {
      const r = await exec(sandbox, 'sudo -u mitmproxy node /tmp/attack2.mjs', 20000)
      let res = []
      try { res = JSON.parse(r.stdout) } catch {}
      const allDirect = res.length === 3 && res.every(x =>
        x.timeout || x.code === 'ECONNREFUSED' || x.code === 'ETIMEDOUT')
      suite.record('ATTACK2: mitmproxy fetch HTTPS :443 — no self-loop',
        allDirect,
        res.map(x => x.code || x.name).join(', '))
    }

    // ATTACK 3: Pool waves
    console.log('\n--- ATTACK 3: Pool health over time ---\n')
    {
      const r = await exec(sandbox, 'node /tmp/attack3.mjs', 60000)
      let waves = []
      try { waves = JSON.parse(r.stdout) } catch {}
      const allOk = waves.length === 3 && waves.every(w => w.ok === 10 && w.errors.length === 0)
      suite.record('ATTACK3: 3×10 concurrent, 4s gaps — all healthy',
        allOk,
        waves.map(w => `${w.name}:${w.ok}/10`).join(' '))
    }

    // ATTACK 4: Concurrent
    console.log('\n--- ATTACK 4: Concurrent load ---\n')
    {
      const r = await exec(sandbox, 'node /tmp/attack4.mjs', 20000)
      let res = {}
      try { res = JSON.parse(r.stdout) } catch {}
      suite.record('ATTACK4: 10 concurrent requests — all succeed',
        res.ok === 10 && (!res.errors || res.errors.length === 0),
        `${res.ok}/10 ok`)
    }

    // Final proxy health
    console.log('')
    {
      const r = await exec(sandbox, 'curl -s http://127.0.0.1:18080/__health')
      let h = {}
      try { h = JSON.parse(r.stdout) } catch {}
      suite.record('Proxy healthy after all attacks',
        h.ok === true,
        `total requests: ${h.count}`)
    }

  } catch (e) {
    console.error('FATAL:', e.message)
  } finally {
    if (sandbox) await killSandbox(sandbox, apiKey)
  }

  return suite.summary()
}

run().then(ok => process.exit(ok ? 0 : 1))
