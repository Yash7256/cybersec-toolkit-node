const emptySummary = () => ({ countries: {}, asns: {}, ip_types: {}, cdn: 0, hosting: 0, tor: 0 })

function addSummary(summary, data) {
  if (data.country_code) summary.countries[data.country_code] = (summary.countries[data.country_code] ?? 0) + 1
  if (data.asn) summary.asns[data.asn] = (summary.asns[data.asn] ?? 0) + 1
  if (data.ip_type) summary.ip_types[data.ip_type] = (summary.ip_types[data.ip_type] ?? 0) + 1
  if (data.is_cdn) summary.cdn += 1
  if (data.privacy?.hosting || data.is_hosting) summary.hosting += 1
  if (data.privacy?.tor || data.is_tor) summary.tor += 1
}

export async function runBatch(units, { lookup, lookupAsn, signal, reportProgress } = {}) {
  const rows = new Array(units.length)
  let next = 0
  async function worker() {
    while (next < units.length) {
      if (signal?.aborted) throw Object.assign(new Error('Request failed'), { kind: 'cancelled' })
      const index = next++
      const unit = units[index]
      try {
        const data = unit.kind === 'asn' ? await lookupAsn(unit.canonical, { signal }) : await lookup(unit.canonical, { signal })
        rows[index] = { input: unit.input, kind: unit.kind === 'asn' ? 'asn' : unit.kind === 'host' ? 'host' : 'ip', status: 'ok', ip: data.ip ?? null, country_code: data.country_code ?? data.country ?? null, city: data.city ?? null, asn: data.asn ?? null, org: data.org ?? data.name ?? null, ip_type: data.ip_type ?? null, name: data.name ?? null, prefix_count: data.prefix_count ?? null, data }
      } catch { rows[index] = { input: unit.input, kind: unit.kind === 'asn' ? 'asn' : unit.kind === 'host' ? 'host' : 'ip', status: 'error', error: 'Lookup failed' } }
      reportProgress?.(Math.round(((index + 1) / units.length) * 100))
    }
  }
  await Promise.all(Array.from({ length: Math.min(4, units.length) }, worker))
  const summary = emptySummary()
  const ok = rows.filter((row) => row.status === 'ok')
  ok.forEach((row) => addSummary(summary, row.data))
  return { total: units.length, completed: ok.length, failed: units.length - ok.length, summary, rows, ip_results: ok.flatMap((row) => row.data?.ip_results ?? []), warnings: [...new Set(ok.flatMap((row) => (row.data?.warnings ?? []).map((warning) => warning.source)))].map((source) => ({ source, message: 'Source unavailable' })), error: null }
}
