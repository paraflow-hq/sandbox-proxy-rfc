/**
 * ATTACK 1: Reproduce ECONNRESET conditions.
 *
 * Phase 1: Build undici connection pool with N sequential requests.
 * Phase 2: Wait 6 seconds (simulates keep-alive timeout window).
 * Phase 3: Reuse pool with N more requests — must ALL succeed.
 *
 * In the OLD architecture: direct connections go stale during iptables
 * setup, subsequent pool reuse hits zombie connections → ECONNRESET.
 *
 * In the RFC architecture: all connections are to local proxy (always up),
 * so keep-alive stays healthy even after idle period.
 */

const N = 5
const IDLE_MS = 6000
const results = { phase1: 0, phase2: 0, errors: [] }

async function req(url) {
  const c = new AbortController()
  const t = setTimeout(() => c.abort(), 5000)
  const r = await fetch(url, { signal: c.signal })
  clearTimeout(t)
  return await r.text()
}

async function main() {
  // Phase 1: build pool
  for (let i = 0; i < N; i++) {
    const t = await req("http://198.18.0.1/pool-build-" + i)
    if (t.includes("OK")) results.phase1++
  }

  // Phase 2: idle wait
  await new Promise(r => setTimeout(r, IDLE_MS))

  // Phase 3: reuse pool
  for (let i = 0; i < N; i++) {
    try {
      const t = await req("http://198.18.0.1/pool-reuse-" + i)
      if (t.includes("OK")) results.phase2++
    } catch (e) {
      results.errors.push({
        i,
        name: e.name,
        code: e.cause ? e.cause.code : null,
      })
    }
  }

  console.log(JSON.stringify(results))
}

main().catch(e => console.error("FATAL:", e))
