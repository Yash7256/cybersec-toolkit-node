import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { prisma } from '../../src/db/client.js'
import * as userRepo from '../../src/db/repos/userRepo.js'
import * as runRepo from '../../src/db/repos/runRepo.js'
import * as cveRepo from '../../src/db/repos/cveRepo.js'
import * as findingsRepo from '../../src/db/repos/findingsRepo.js'
import { truncateAll } from './helpers.js'

const cve = {
  cve_id: 'CVE-2024-6387',
  description: 'regreSSHion',
  severity: 'CRITICAL',
  cvss_score: 9.8,
  published_date: '2024-07-01T00:00:00.000Z',
}

function openPort(portNumber, extra = {}) {
  return {
    port_number: portNumber,
    service: 'ssh',
    version: 'OpenSSH 9.6p1',
    raw_banner: 'SSH-2.0-OpenSSH_9.6p1',
    risk_level: 'high',
    cve_result: { cves: [cve] },
    ...extra,
  }
}

async function makeRun(id) {
  const user = await userRepo.upsertFromClerk({
    clerkUserId: id,
    email: `${id}@example.test`,
    tier: 'FREE',
  })
  return runRepo.start({
    userId: user.id,
    tool: 'PORT_SCAN',
    target: 'example.com',
    targetKey: 'example.com',
  })
}

describe('findings repository', () => {
  beforeEach(() => truncateAll())
  afterAll(() => prisma.$disconnect())

  it('upserts CVEs (deduped, sorted, validated) and reads them back', async () => {
    const rows = [
      { ...cve, cve_id: 'CVE-2024-9999' },
      cve,
      { ...cve, cve_id: 'CVE-2024-9999' },
      { ...cve, cve_id: 'not-a-cve' },
    ]
    expect(await cveRepo.upsertCves(rows)).toBe(2)

    const stored = await cveRepo.findCvesByIds(['CVE-2024-6387', 'CVE-2024-9999', 'missing'])
    expect(stored).toHaveLength(2)
    expect(stored[0]).toMatchObject({
      cve_id: 'CVE-2024-6387',
      description: 'regreSSHion',
      severity: 'CRITICAL',
      cvss_score: 9.8,
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-6387',
    })
  })

  it('honors service lookup expiry', async () => {
    const cacheKey = 'a'.repeat(64)
    await cveRepo.putServiceLookup({
      cacheKey,
      service: 'openssh',
      version: '9.6p1',
      cveIds: ['CVE-2024-6387', 'CVE-2024-6387', 'bad'],
      ttlHours: 1,
    })
    const hit = await cveRepo.getServiceLookup(cacheKey)
    expect(hit.cveIds).toEqual(['CVE-2024-6387'])

    const expired = await cveRepo.getServiceLookup(cacheKey, {
      now: new Date(Date.now() + 2 * 60 * 60 * 1000),
    })
    expect(expired).toBeNull()
  })

  it('replaces findings transactionally with bounded banners and CVE links', async () => {
    const run = await makeRun('findings_replace')
    const openPorts = [
      openPort(22),
      openPort(443, {
        service: 'https',
        risk_level: 'CRITICAL',
        raw_banner: 'x'.repeat(5000),
        cve_result: { cves: [{ ...cve, cve_id: 'CVE-2024-1111' }] },
      }),
    ]

    const inserted = await prisma.$transaction((tx) =>
      findingsRepo.replaceForRun(tx, run.id, openPorts)
    )
    expect(inserted).toBe(2)

    const rows = await findingsRepo.listForRun({ runId: run.id, limit: 10 })
    expect(rows.map((row) => row.port)).toEqual([22, 443])
    expect(rows[1].banner).toHaveLength(2000)
    expect(rows[1].risk).toBe('CRITICAL')

    const finding = findingsRepo.toFinding(rows[0])
    expect(finding).toMatchObject({ port: 22, protocol: 'TCP', state: 'OPEN', risk: 'HIGH' })
    expect(finding.cves[0]).toMatchObject({ cve_id: 'CVE-2024-6387', cvss_score: 9.8 })

    await prisma.$transaction((tx) => findingsRepo.replaceForRun(tx, run.id, [openPort(80)]))
    const replaced = await findingsRepo.listForRun({ runId: run.id })
    expect(replaced.map((row) => row.port)).toEqual([80])
  })

  it('paginates by port cursor', async () => {
    const run = await makeRun('findings_pages')
    const ports = [22, 80, 443, 8080, 8443].map((port) => openPort(port))
    await prisma.$transaction((tx) => findingsRepo.replaceForRun(tx, run.id, ports))

    const first = await findingsRepo.listForRun({ runId: run.id, limit: 2 })
    const second = await findingsRepo.listForRun({
      runId: run.id,
      limit: 2,
      cursor: first.at(-1).port,
    })
    const third = await findingsRepo.listForRun({
      runId: run.id,
      limit: 2,
      cursor: second.at(-1).port,
    })
    expect(first.map((row) => row.port)).toEqual([22, 80])
    expect(second.map((row) => row.port)).toEqual([443, 8080])
    expect(third.map((row) => row.port)).toEqual([8443])
  })

  it('clears findings for an empty result', async () => {
    const run = await makeRun('findings_empty')
    await prisma.$transaction((tx) => findingsRepo.replaceForRun(tx, run.id, [openPort(22)]))
    expect(await prisma.$transaction((tx) => findingsRepo.replaceForRun(tx, run.id, []))).toBe(0)
    expect(await findingsRepo.listForRun({ runId: run.id })).toEqual([])
  })
})
