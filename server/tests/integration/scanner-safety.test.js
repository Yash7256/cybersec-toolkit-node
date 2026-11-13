import { describe, it, expect, afterEach } from 'vitest'
import net from 'node:net'
import { scanPorts } from '../../src/scanner/engine.js'
import { createSocketSemaphore } from '../../src/scanner/sockets.js'
import { createServiceFarm } from '../helpers/serviceFarm.js'

let farm
afterEach(async () => {
  await farm?.close()
  farm = null
})

function listen(handler) {
  return new Promise((resolve) => {
    const sockets = new Set()
    const server = net.createServer((socket) => {
      sockets.add(socket)
      socket.on('error', () => {})
      socket.on('close', () => sockets.delete(socket))
      handler(socket)
    })
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, sockets }))
  })
}

async function closeAll(servers) {
  await Promise.all(
    servers.map(
      (entry) =>
        new Promise((resolve) => {
          for (const socket of entry.sockets) socket.destroy()
          entry.server.close(() => resolve())
        })
    )
  )
}

describe('scanner safety', () => {
  it('paces connections at or below the configured rate', async () => {
    const acceptedAt = []
    const servers = []
    for (let index = 0; index < 12; index += 1) {
      servers.push(
        await listen((socket) => {
          acceptedAt.push(Date.now())
          socket.end('220 test server\r\n')
        })
      )
    }
    try {
      const result = await scanPorts({
        address: '127.0.0.1',
        family: 4,
        hostname: 'localhost',
        ports: servers.map((entry) => entry.port),
        timeoutMs: 300,
        concurrency: 12,
        ratePerSec: 6,
      })
      expect(result.open_ports_count).toBe(12)

      acceptedAt.sort((a, b) => a - b)
      let peak = 0
      for (let start = 0; start < acceptedAt.length; start += 1) {
        let count = 0
        for (let end = start; end < acceptedAt.length; end += 1) {
          if (acceptedAt[end] - acceptedAt[start] <= 1000) count += 1
          else break
        }
        peak = Math.max(peak, count)
      }
      expect(peak).toBeLessThanOrEqual(6 * 1.25 + 1)
    } finally {
      await closeAll(servers)
    }
  })

  it('never exceeds the shared global socket semaphore across concurrent scans', async () => {
    farm = await createServiceFarm()
    const sockets = createSocketSemaphore({ max: 3, onGauge: () => {} })
    let peak = 0
    const ports = [farm.ports.tarpit, farm.ports.silent, farm.ports.scripted, farm.ports.ssh]

    const run = () =>
      scanPorts({
        address: '127.0.0.1',
        family: 4,
        hostname: 'localhost',
        ports,
        timeoutMs: 400,
        concurrency: 4,
        ratePerSec: 100,
        deps: {
          sockets: {
            acquire: async (signal) => {
              const release = await sockets.acquire(signal)
              peak = Math.max(peak, sockets.active)
              return release
            },
          },
        },
      })

    const results = await Promise.all([run(), run(), run()])
    expect(results.every((result) => result.open_ports_count === 4)).toBe(true)
    expect(peak).toBeLessThanOrEqual(3)
    expect(peak).toBeGreaterThan(1)
  })

  it('bounds hostile services and sanitizes stored banners', async () => {
    farm = await createServiceFarm()
    const started = Date.now()
    const result = await scanPorts({
      address: '127.0.0.1',
      family: 4,
      hostname: 'localhost',
      ports: [farm.ports.tarpit, farm.ports.silent, farm.ports.bannerBomb],
      timeoutMs: 300,
      concurrency: 3,
      ratePerSec: 100,
    })
    expect(Date.now() - started).toBeLessThan(4000)
    expect(result.open_ports_count).toBe(3)

    for (const port of result.open) {
      expect(port.raw_banner?.length ?? 0).toBeLessThanOrEqual(8192)
      // eslint-disable-next-line no-control-regex
      expect(port.raw_banner ?? '').not.toMatch(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/)
    }
  })

  it('aborts every in-flight scan without leaking handles', async () => {
    farm = await createServiceFarm()
    const controller = new AbortController()
    const started = Date.now()
    const scan = scanPorts({
      address: '127.0.0.1',
      family: 4,
      hostname: 'localhost',
      ports: Array.from({ length: 100 }, (_, index) => 40000 + index),
      timeoutMs: 1000,
      concurrency: 20,
      ratePerSec: 200,
      signal: controller.signal,
    })
    setTimeout(() => controller.abort(), 100)
    const result = await scan
    expect(Date.now() - started).toBeLessThan(2500)
    expect(result.aborted).toBe(true)
    expect(result.packets_sent).toBeLessThan(100)
  })
})
