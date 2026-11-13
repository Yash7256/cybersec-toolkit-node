import { prisma } from '../client.js'
import { Prisma } from '../../generated/prisma/client.ts'
import { env as defaultEnv } from '../../config/env.js'

const VALID_SEVERITY = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/

function severityOrNull(severity) {
  const value = String(severity ?? '').toUpperCase()
  return VALID_SEVERITY.has(value) ? value : null
}

export async function getServiceLookup(cacheKey, { now = new Date(), client = prisma } = {}) {
  const row = await client.serviceCveLookup.findUnique({ where: { cacheKey } })
  if (!row) return null
  if (row.expiresAt.getTime() <= now.getTime()) return null
  return row
}

export async function putServiceLookup({
  service,
  version,
  cveIds,
  cacheKey,
  ttlHours = defaultEnv.NVD_CACHE_TTL_HOURS,
  now = new Date(),
  client = prisma,
}) {
  const key = cacheKey
  const expiresAt = new Date(now.getTime() + ttlHours * 60 * 60 * 1000)
  return client.serviceCveLookup.upsert({
    where: { cacheKey: key },
    create: {
      cacheKey: key,
      service,
      version,
      cveIds: [...new Set(cveIds)].filter((id) => CVE_ID_PATTERN.test(id)).sort(),
      expiresAt,
    },
    update: {
      service,
      version,
      cveIds: [...new Set(cveIds)].filter((id) => CVE_ID_PATTERN.test(id)).sort(),
      fetchedAt: now,
      expiresAt,
    },
  })
}

export async function upsertCves(
  list,
  { ttlHours = defaultEnv.NVD_CACHE_TTL_HOURS, now = new Date(), client = prisma } = {}
) {
  if (!list?.length) return 0

  const expiresAt = new Date(now.getTime() + ttlHours * 60 * 60 * 1000)
  const rows = new Map()
  for (const entry of list) {
    if (!CVE_ID_PATTERN.test(entry?.cve_id ?? entry?.id ?? '')) continue
    const id = entry.cve_id ?? entry.id
    rows.set(id, { ...entry, id })
  }
  const sorted = [...rows.values()].sort((a, b) => a.id.localeCompare(b.id))
  if (!sorted.length) return 0

  const values = sorted.map((entry) => {
    const score = entry.cvss_score ?? entry.cvssScore ?? null
    const severity = severityOrNull(entry.severity)
    const summary = entry.description ?? entry.summary ?? null
    const publishedAt = entry.published_date ?? entry.publishedAt ?? null
    const data = entry.data ?? entry
    return Prisma.sql`(
      ${entry.id},
      ${score}::numeric,
      ${severity}::"Severity",
      ${summary},
      ${JSON.stringify(data)}::jsonb,
      ${publishedAt ? new Date(publishedAt) : null}::timestamptz,
      ${expiresAt}::timestamptz
    )`
  })

  await client.$executeRaw`
    INSERT INTO cves (id, cvss_score, severity, summary, data, published_at, expires_at)
    VALUES ${Prisma.join(values)}
    ON CONFLICT (id) DO UPDATE SET
      cvss_score = EXCLUDED.cvss_score,
      severity = EXCLUDED.severity,
      summary = EXCLUDED.summary,
      data = EXCLUDED.data,
      published_at = EXCLUDED.published_at,
      expires_at = EXCLUDED.expires_at
  `
  return sorted.length
}

export async function findCvesByIds(ids, { client = prisma } = {}) {
  const unique = [...new Set((ids ?? []).filter((id) => CVE_ID_PATTERN.test(id)))]
  if (!unique.length) return []
  const rows = await client.cve.findMany({ where: { id: { in: unique } } })
  return rows.map((row) => ({
    cve_id: row.id,
    description: row.summary ?? '',
    severity: row.severity ?? 'UNKNOWN',
    cvss_score: row.cvssScore == null ? null : Number(row.cvssScore),
    cvss_vector: row.data?.cvss_vector ?? null,
    published_date: row.publishedAt?.toISOString?.() ?? null,
    url: `https://nvd.nist.gov/vuln/detail/${row.id}`,
  }))
}
