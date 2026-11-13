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

async function closedPort() {
  const server = net.createServer()
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  await new Promise((resolve) => server.close(resolve))
  return port
}

describe('scanner engine', () => {
  it('detects open services and parses banners', async () => {
    farm = await createServiceFarm()
    const result = await scanPorts({
      address: '127.0.0.1',
      family: 4,
      hostname: 'localhost',
      ports: [farm.ports.ssh, farm.ports.ftp, farm.ports.scripted],
      timeoutMs: 500,
      concurrency: 4,
      ratePerSec: 100,
    })

    const byPort = Object.fromEntries(result.open.map((port) => [port.port_number, port]))
    expect(result.open_ports_count).toBe(3)
    expect(byPort[farm.ports.ftp].welcome_message).toContain('vsFTPd')
    expect(byPort[farm.ports.scripted].raw_banner).not.toContain('\u001b')
    expect(result.packets_sent).toBe(3)
    expect(result.closed_count + result.filtered_count).toBe(0)
  })

  it('connects to the pinned address, never the user-supplied hostname', async () => {
    farm = await createServiceFarm()
    const result = await scanPorts({
      address: '127.0.0.1',
      family: 4,
      hostname: 'unresolvable.invalid',
      ports: [farm.ports.ssh, farm.ports.ftp],
      timeoutMs: 500,
      concurrency: 2,
      ratePerSec: 100,
    })
    expect(result.open_ports_count).toBe(2)
  })

  it('distinguishes closed ports and never opens more sockets than the local semaphore', async () => {
    farm = await createServiceFarm()
    const closed = await closedPort()
    const sockets = createSocketSemaphore({ max: 2, onGauge: () => {} })
    let peak = 0
    const result = await scanPorts({
      address: '127.0.0.1',
      family: 4,
      hostname: 'localhost',
      ports: [farm.ports.ssh, closed, farm.ports.ftp],
      timeoutMs: 500,
      concurrency: 4,
      ratePerSec: 200,
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
    expect(peak).toBeLessThanOrEqual(2)
    expect(result.closed_count).toBe(1)
    expect(result.open_ports_count).toBe(2)
  })

  it('aborts promptly and returns partial results', async () => {
    farm = await createServiceFarm()
    const controller = new AbortController()
    const started = Date.now()
    const scan = scanPorts({
      address: '127.0.0.1',
      family: 4,
      hostname: 'localhost',
      ports: Array.from({ length: 40 }, (_, index) => 30000 + index),
      timeoutMs: 1000,
      concurrency: 8,
      ratePerSec: 5,
      signal: controller.signal,
    })
    setTimeout(() => controller.abort(), 120)
    const result = await scan
    expect(Date.now() - started).toBeLessThan(3000)
    expect(result.aborted).toBe(true)
    expect(result.packets_sent).toBeLessThan(40)
  })

  it('reports monotonic progress and reaches completion', async () => {
    farm = await createServiceFarm()
    const values = []
    const result = await scanPorts({
      address: '127.0.0.1',
      family: 4,
      hostname: 'localhost',
      ports: [farm.ports.ssh, farm.ports.ftp, await closedPort()],
      timeoutMs: 400,
      concurrency: 2,
      ratePerSec: 100,
      onProgress: (fraction) => values.push(fraction),
    })
    expect(result.open_ports_count).toBe(2)
    expect(values.length).toBeGreaterThan(0)
    expect(values.at(-1)).toBe(1)
    for (let i = 1; i < values.length; i += 1) {
      expect(values[i]).toBeGreaterThanOrEqual(values[i - 1])
    }
  })
})
