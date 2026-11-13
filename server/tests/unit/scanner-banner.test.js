import { describe, it, expect } from 'vitest'
import net from 'node:net'
import { probeBanner } from '../../src/scanner/bannerProbe.js'
import { detectTechnologies } from '../../src/scanner/techDetect.js'
import { sanitizeBanner } from '../../src/scanner/sanitize.js'

async function withSocket(handler, fn) {
  const server = net.createServer((socket) => {
    socket.on('error', () => {})
    handler(socket)
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const socket = net.connect(server.address().port, '127.0.0.1')
  await new Promise((resolve) => socket.once('connect', resolve))
  try {
    return await fn(socket)
  } finally {
    socket.destroy()
    await new Promise((resolve) => server.close(resolve))
  }
}

describe('banner probing', () => {
  it('sends an HTTP request and parses server versions', async () => {
    const result = await withSocket(
      (socket) =>
        socket.once('data', () =>
          socket.end(
            'HTTP/1.1 200 OK\r\n' +
              'Server: Apache/2.4.49 (Ubuntu)\r\n' +
              'X-Powered-By: PHP/7.4.3\r\n\r\nHello'
          )
        ),
      (socket) =>
        probeBanner({ socket, port: 80, address: '127.0.0.1', hostname: 'localhost', timeoutMs: 500 })
    )
    expect(result.server_response).toContain('Apache/2.4.49')
    expect(result.version).toBe('Apache 2.4.49, PHP 7.4.3')
    expect(result.technologies).toEqual(expect.arrayContaining(['Apache', 'PHP']))
  })

  it('parses SSH banners on the SSH port', async () => {
    const result = await withSocket(
      (socket) => socket.write('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n'),
      (socket) =>
        probeBanner({ socket, port: 22, address: '127.0.0.1', hostname: 'localhost', timeoutMs: 500 })
    )
    expect(result.version).toBe('OpenSSH 9.6p1')
  })

  it('strips terminal escape sequences and truncates long banners', () => {
    const raw = '\u001b]0;title\u0007first\r\n\u001b[31msecond\u001b[0m\r\n'
    expect(sanitizeBanner(raw)).toBe('first\nsecond')

    const long = 'A'.repeat(9000)
    const sanitized = sanitizeBanner(long, { maxBytes: 100, maxLines: 10 })
    expect(sanitized.length).toBeLessThanOrEqual(100)
    expect(sanitized).toContain('[truncated]')
  })

  it('detects technology signatures case-insensitively', () => {
    expect(detectTechnologies('SERVER: NGINX/1.18.0')).toEqual(expect.arrayContaining(['Nginx']))
    expect(detectTechnologies('x-powered-by: express')).toEqual(
      expect.arrayContaining(['Express'])
    )
  })
})
