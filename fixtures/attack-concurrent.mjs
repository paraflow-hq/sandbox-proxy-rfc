/**
 * ATTACK 5: Concurrent load test.
 *
 * Fire N parallel requests through the proxy.
 * All must succeed — no connection errors, no timeouts.
 */

const N = 10

async function doFetch(url) {
  const c = new AbortController()
  const t = setTimeout(() => c.abort(), 5000)
  const r = await fetch(url, { signal: c.signal })
  clearTimeout(t)
  return await r.text()
}

async function main() {
  const r = { ok: 0, errors: [] }
  const ps = []
  for (let i = 0; i < N; i++) {
    ps.push(
      doFetch("http://198.18.0.1/concurrent-" + i)
        .then(t => { if (t.includes("OK")) r.ok++; else r.errors.push("bad") })
        .catch(e => r.errors.push(e.name))
    )
  }
  await Promise.all(ps)
  console.log(JSON.stringify(r))
}

main().catch(e => console.log(JSON.stringify({ ok: 0, errors: [e.message] })))
