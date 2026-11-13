import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { prisma } from '../../src/db/client.js'
import { parseEnv } from '../../src/config/env.js'
import * as runRepo from '../../src/db/repos/runRepo.js'
import * as findingsRepo from '../../src/db/repos/findingsRepo.js'
import { disconnectRedis } from '../../src/redis/client.js'
import { flushTestRedis } from '../helpers/redis.js'
import { truncateAll } from '../db/helpers.js'
import { asUser, makeTestApp } from '../helpers/auth.js'

const env = parseEnv({ ...process.env, LOG_LEVEL: 'silent' })

function port(number) {
  return {
    port_number: number,
    service: 'ssh',
    version: 'OpenSSH 9.6p1',
    raw_banner: 'SSH-2.0-OpenSSH_9.6p1',
    risk_level: 'medium',
    cve_result: {
      cves: [
        {
          cve_id: 'CVE-2024-6387',
          description: 'regreSSHion',
          severity: 'CRITICAL',
          cvss_score: 9.8,
          published_date: null,
        },
      ],
    },
  }
}

async function seedRun(userId, ports) {
  const run = await runRepo.start({
    userId,
    tool: 'PORT_SCAN',
    target: 'example.com',
    targetKey: 'example.com',
  })
  await prisma.$transaction((tx) => findingsRepo.replaceForRun(tx, run.id, ports.map(port)))
  return run
}

describe('GET /api/runs/:id/findings', () => {
  beforeEach(async () => {
    await truncateAll()
    await flushTestRedis()
  })
  afterAll(() => disconnectRedis())

  it('returns findings with CVE details and a port cursor', async () => {
    const app = makeTestApp({ env })
    const user = await asUser(app, { clerkId: 'findings_owner' })
    const run = await seedRun(user.user.id, [22, 80, 443])

    const first = await user.get(`/api/runs/${run.id}/findings?limit=2`)
    expect(first.status).toBe(200)
    expect(first.headers['cache-control']).toBe('no-store')
    expect(first.body.findings.map((row) => row.port)).toEqual([22, 80])
    expect(first.body.nextCursor).toBe(80)
    expect(first.body.findings[0].cves[0]).toMatchObject({
      cve_id: 'CVE-2024-6387',
      severity: 'CRITICAL',
      cvss_score: 9.8,
    })

    const second = await user.get(`/api/runs/${run.id}/findings?limit=2&cursor=80`)
    expect(second.status).toBe(200)
    expect(second.body.findings.map((row) => row.port)).toEqual([443])
    expect(second.body.nextCursor).toBeNull()
  })

  it('returns 404 for another user run', async () => {
    const app = makeTestApp({ env })
    const owner = await asUser(app, { clerkId: 'findings_run_owner' })
    const other = await asUser(app, { clerkId: 'findings_run_other' })
    const run = await seedRun(owner.user.id, [22])

    expect((await owner.get(`/api/runs/${run.id}/findings`)).status).toBe(200)
    const res = await other.get(`/api/runs/${run.id}/findings`)
    expect(res.status).toBe(404)
    expect(res.body.error.code).toBe('NOT_FOUND')
  })

  it('returns an empty page for runs without findings', async () => {
    const app = makeTestApp({ env })
    const user = await asUser(app, { clerkId: 'findings_empty' })
    const run = await seedRun(user.user.id, [])
    const res = await user.get(`/api/runs/${run.id}/findings`)
    expect(res.status).toBe(200)
    expect(res.body).toEqual({ findings: [], nextCursor: null })
  })

  it('rejects invalid limit and cursor values', async () => {
    const app = makeTestApp({ env })
    const user = await asUser(app, { clerkId: 'findings_validation' })
    const run = await seedRun(user.user.id, [22])

    for (const query of ['limit=0', 'limit=201', 'limit=abc', 'cursor=0', 'cursor=70000', 'cursor=abc']) {
      const res = await user.get(`/api/runs/${run.id}/findings?${query}`)
      expect(res.status).toBe(400)
      expect(res.body.error.code).toBe('VALIDATION_ERROR')
    }
  })
})
