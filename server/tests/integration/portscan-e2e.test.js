import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import net from 'node:net'
import { prisma } from '../../src/db/client.js'
import { parseEnv } from '../../src/config/env.js'
import * as runRepo from '../../src/db/repos/runRepo.js'
import * as cveRepo from '../../src/db/repos/cveRepo.js'
import { cveCacheKey } from '../../src/scanner/cve/detect.js'
import { definition } from '../../src/tools/portScan/index.js'
import { disconnectRedis } from '../../src/redis/client.js'
import { flushTestRedis } from '../helpers/redis.js'
import { truncateAll } from '../db/helpers.js'
import { asUser, makeTestApp } from '../helpers/auth.js'
import {
  closeAsyncQueues,
  obliterateQueues,
  startEmbeddedWorker,
  stopEmbeddedWorker,
  waitFor,
} from '../helpers/asyncTestTool.js'

const baseEnv = {
  ...process.env,
  LOG_LEVEL: 'silent',
  QUEUE_PREFIX: 'cst_phase7a_e2e',
  WORKER_HEARTBEAT_SEC: '1',
  ALLOW_PRIVATE_TARGETS: 'true',
  SCAN_RATE_CONN_PER_SEC: '100',
  SCAN_MAX_CONCURRENCY: '50',
  SCAN_TIMEOUT_MS: '30000',
}
const env = parseEnv(baseEnv)

function listenOn(ports) {
  return new Promise((resolve, reject) => {
    const tryNext = (index) => {
      if (index >= ports.length) { reject(new Error('no free test port')); return }
      const server = net.createServer((socket) => {
        socket.on('error', () => {})
        socket.once('data', () => {
          socket.end(
            'HTTP/1.1 200 OK\r\n' +
              'Server: Apache/2.4.49\r\n' +
              'Content-Type: text/html\r\n' +
              'Content-Length: 2\r\n\r\nOK'
          )
        })
      })
      server.once('error', () => tryNext(index + 1))
      server.listen(ports[index], '127.0.0.1', () => resolve({ server, port: ports[index] }))
    }
    tryNext(0)
  })
}

const cve = {
  cve_id: 'CVE-2021-41773',
  description: 'Path traversal in Apache HTTP Server 2.4.49',
  severity: 'CRITICAL',
  cvss_score: 9.8,
  published_date: '2021-10-05T00:00:00.000Z',
}

describe('port scan async end-to-end', () => {
  let worker
  let app
  let server
  let tarpit
  let httpPort
  let tarpitPort

  beforeAll(async () => {
    worker = await startEmbeddedWorker({ env, definitions: { port_scan: definition } })
    app = makeTestApp({ env })
    const bound = await listenOn([8080, 8000, 8888, 3000, 5000])
    server = bound.server
    httpPort = bound.port
    const stalled = await new Promise((resolve, reject) => {
      const candidates = [3000, 5000, 8000, 8888, 9000, 9080].filter((port) => port !== httpPort)
      const attempt = (index) => {
        if (index >= candidates.length) return reject(new Error('no free tarpit port'))
        const tcp = net.createServer((socket) => {
          socket.on('error', () => {})
          socket.on('data', () => {})
        })
        tcp.once('error', () => attempt(index + 1))
        tcp.listen(candidates[index], '127.0.0.1', () => resolve({ server: tcp, port: candidates[index] }))
      }
      attempt(0)
    })
    tarpit = stalled.server
    tarpitPort = stalled.port
  })

  beforeEach(async () => {
    await truncateAll()
    await flushTestRedis()
    await obliterateQueues(env)
    await cveRepo.upsertCves([cve])
    await cveRepo.putServiceLookup({
      cacheKey: cveCacheKey('apache', '2.4.49'),
      service: 'apache',
      version: '2.4.49',
      cveIds: [cve.cve_id],
    })
  })

  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve))
    await new Promise((resolve) => tarpit.close(resolve))
    await stopEmbeddedWorker(worker)
    await closeAsyncQueues()
    await disconnectRedis()
  })

  it('runs the queue pipeline, persists findings, and serves them over the API', async () => {
    const user = await asUser(app, { clerkId: 'scanner_e2e' })
    const submit = await user
      .post('/api/tools/port_scan')
      .set('Idempotency-Key', 'scanner-e2e-key-1')
      .send({
        target: '127.0.0.1',
        ports: [httpPort],
        timeout: 1,
        max_concurrent: 10,
        include_threat_intel: false,
      })
    expect(submit.status).toBe(202)
    expect(submit.body.runId).toEqual(expect.any(String))

    const finished = await waitFor(async () => {
      const res = await user.get(`/api/runs/${submit.body.runId}`)
      return res.body.status === 'COMPLETED' ? res.body : null
    }, { timeoutMs: 20000, intervalMs: 100 })

    expect(finished.progressPct).toBe(100)
    expect(finished.data.scanned_ip).toBe('127.0.0.1')
    expect(finished.data.open_ports_count).toBe(1)
    const open = finished.data.open_ports[0]
    expect(open.port_number).toBe(httpPort)
    expect(open.version).toBe('Apache 2.4.49')
    expect(open.cve_critical_count).toBe(1)
    expect(open.max_cvss_score).toBe(9.8)
    expect(open.max_cvss_cve).toBe('CVE-2021-41773')
    expect(finished.data.cve_error).toBeNull()
    expect(finished.data.error).toBeNull()

    const rows = await prisma.portFinding.findMany({
      where: { runId: submit.body.runId },
      include: { cves: true },
    })
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ port: httpPort, protocol: 'TCP', state: 'OPEN' })
    expect(rows[0].cves.map((link) => link.cveId)).toEqual(['CVE-2021-41773'])

    const findings = await user.get(`/api/runs/${submit.body.runId}/findings`)
    expect(findings.status).toBe(200)
    expect(findings.body.findings[0].port).toBe(httpPort)
    expect(findings.body.findings[0].service).toMatch(/^HTTP/)
    expect(findings.body.findings[0].risk).toBe('HIGH')
    expect(findings.body.findings[0].cves[0].cve_id).toBe('CVE-2021-41773')
    expect(findings.body.nextCursor).toBeNull()

    const usage = await prisma.usageCounter.findMany({ where: { userId: user.user.id } })
    expect(usage.reduce((sum, row) => sum + row.used, 0)).toBe(1)
  })

  it('cancels a running scan and does not refund quota', async () => {
    const user = await asUser(app, { clerkId: 'scanner_cancel' })
    const submit = await user
      .post('/api/tools/port_scan')
      .set('Idempotency-Key', 'scanner-e2e-cancel-1')
      .send({
        target: '127.0.0.1',
        ports: [tarpitPort],
        timeout: 1,
        max_concurrent: 10,
        include_threat_intel: false,
      })
    expect(submit.status).toBe(202)

    await waitFor(async () => {
      const res = await user.get(`/api/runs/${submit.body.runId}`)
      return res.body.status === 'RUNNING' ? res.body : null
    })

    const cancel = await user.post(`/api/runs/${submit.body.runId}/cancel`)
    expect([200, 202]).toContain(cancel.status)

    const finished = await waitFor(async () => {
      const res = await user.get(`/api/runs/${submit.body.runId}`)
      return ['CANCELLED', 'COMPLETED', 'FAILED', 'TIMED_OUT'].includes(res.body.status) ? res.body : null
    }, { timeoutMs: 15000, intervalMs: 100 })
    expect(finished.status).toBe('CANCELLED')

    const usage = await prisma.usageCounter.findMany({ where: { userId: user.user.id } })
    expect(usage.reduce((sum, row) => sum + row.used, 0)).toBe(1)
    const run = await runRepo.findByIdForUser(submit.body.runId, user.user.id)
    expect(run.quotaRefunded).toBe(false)
  })
})
