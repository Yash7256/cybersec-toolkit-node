import { Prisma } from '../../generated/prisma/client.ts'
import { prisma } from '../client.js'
import * as cveRepo from './cveRepo.js'

const VALID_RISK = new Set(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
const MAX_BANNER_CHARS = 2000

function riskEnum(risk) {
  const value = String(risk ?? '').toUpperCase()
  return VALID_RISK.has(value) ? value : null
}

function bounded(value, max) {
  if (value == null) return null
  const text = String(value)
  return text.length > max ? text.slice(0, max) : text
}

function cveRowsFor(openPorts) {
  const seen = new Map()
  for (const port of openPorts) {
    for (const cve of port.cve_result?.cves ?? []) {
      if (!cve?.cve_id || seen.has(cve.cve_id)) continue
      seen.set(cve.cve_id, cve)
    }
  }
  return [...seen.values()]
}

export async function replaceForRun(tx, runId, openPorts = []) {
  await tx.$executeRaw`DELETE FROM port_findings WHERE run_id = ${runId}::uuid`
  if (!openPorts.length) return 0

  const cves = cveRowsFor(openPorts)
  if (cves.length) {
    await cveRepo.upsertCves(cves, { client: tx })
  }

  const rows = openPorts.map((port) => {
    const portNumber = Number(port.port_number)
    if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
      throw new Error('invalid port number')
    }
    return Prisma.sql`(
      ${runId}::uuid,
      ${portNumber},
      'TCP'::"Protocol",
      'OPEN'::"PortState",
      ${bounded(port.service, 100)},
      ${bounded(port.version, 255)},
      ${bounded(port.raw_banner, MAX_BANNER_CHARS)},
      ${riskEnum(port.risk_level)}::"Severity"
    )`
  })

  const inserted = await tx.$queryRaw`
    INSERT INTO port_findings (run_id, port, protocol, state, service, version, banner, risk)
    VALUES ${Prisma.join(rows)}
    RETURNING id, port
  `

  const links = []
  const idByPort = new Map(inserted.map((row) => [Number(row.port), row.id]))
  for (const port of openPorts) {
    const findingId = idByPort.get(Number(port.port_number))
    if (findingId == null) continue
    for (const cve of port.cve_result?.cves ?? []) {
      if (!cve?.cve_id) continue
      links.push(Prisma.sql`(${findingId}::bigint, ${cve.cve_id})`)
    }
  }

  if (links.length) {
    await tx.$executeRaw`
      INSERT INTO finding_cves (finding_id, cve_id)
      VALUES ${Prisma.join(links)}
      ON CONFLICT (finding_id, cve_id) DO NOTHING
    `
  }

  return inserted.length
}

export async function listForRun({ runId, cursor = null, limit = 50 } = {}) {
  const take = Math.min(200, Math.max(1, Number(limit) || 50))
  return prisma.portFinding.findMany({
    where: {
      runId,
      ...(cursor != null ? { port: { gt: Number(cursor) } } : {}),
    },
    orderBy: { port: 'asc' },
    take,
    include: { cves: { include: { cve: true } } },
  })
}

export function toFinding(row) {
  return {
    port: row.port,
    protocol: row.protocol,
    state: row.state,
    service: row.service,
    version: row.version,
    banner: row.banner,
    risk: row.risk,
    cves: (row.cves ?? []).map((link) => ({
      cve_id: link.cve.id,
      severity: link.cve.severity,
      cvss_score: link.cve.cvssScore == null ? null : Number(link.cve.cvssScore),
      summary: link.cve.summary,
    })),
  }
}
