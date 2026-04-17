/**
 * ATTACK 3: Connection pool health over extended time.
 *
 * 3 waves of 10 concurrent requests, 4-second gaps between waves.
 * Tests that undici pool stays healthy across idle periods.
 */

async function doFetch(url) {
  const c = new AbortController()
  const t = setTimeout(() => c.abort(), 5000)
  const r = await fetch(url, { signal: c.signal })
  clearTimeout(t)
  return await r.text()
}

async function wave(name, count) {
  const r = { name, ok: 0, errors: [] }
  const ps = []
  for (let i = 0; i < count; i++) {
    ps.push(
      doFetch("http://198.18.0.1/" + name + "-" + i)
        .then(t => { if (t.includes("OK")) r.ok++; else r.errors.push("bad") })
        .catch(e => r.errors.push(e.name))
    )
  }
  await Promise.all(ps)
  return r
}

async function main() {
  const waves = []
  waves.push(await wave("w1", 10))
  await new Promise(r => setTimeout(r, 4000))
  waves.push(await wave("w2", 10))
  await new Promise(r => setTimeout(r, 4000))
  waves.push(await wave("w3", 10))
  console.log(JSON.stringify(waves))
}

main().catch(e => console.log(JSON.stringify([{ fatal: e.message }])))
