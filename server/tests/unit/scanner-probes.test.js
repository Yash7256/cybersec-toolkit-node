import { describe, it, expect, afterEach } from 'vitest'
import net from 'node:net'
import { detectMisconfigurations } from '../../src/scanner/probes/index.js'
import { probeAnonymousFtp } from '../../src/scanner/probes/ftpAnon.js'
import { probeOpenProxy } from '../../src/scanner/probes/openProxy.js'
import { detectHttpMisconfigurations } from '../../src/scanner/probes/misconfig.js'
import { detectTlsMisconfiguration } from '../../src/scanner/probes/tlsMisconfig.js'

const servers = []
async function serve(handler) {
  const server = net.createServer((socket) => {
    socket.on('error', () => {})
    handler(socket)
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  servers.push(server)
  return server.address().port
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((server) => new Promise((resolve) => server.close(resolve)))
  )
})

describe('misconfiguration probes', () => {
  it('flags anonymous FTP and open proxies', async () => {
    const ftp = await serve((socket) => {
      socket.write('220 ready\r\n')
      socket.on('data', (chunk) => {
        if (chunk.toString().startsWith('USER')) socket.write('331 password\r\n')
        else socket.write('230 logged in\r\n')
      })
    })
    const proxy = await serve((socket) => {
      socket.once('data', () => socket.end('HTTP/1.1 200 OK\r\n\r\n<title>Example Domain</title>'))
    })

    const ftpFinding = await probeAnonymousFtp({
      address: '127.0.0.1', family: 4, port: ftp, timeoutMs: 500,
    })
    const proxyFinding = await probeOpenProxy({
      address: '127.0.0.1', family: 4, port: proxy, timeoutMs: 500,
    })
    expect(ftpFinding.category).toBe('anonymous_ftp')
    expect(proxyFinding.category).toBe('open_proxy')
  })

  it('does not flag FTP or proxy services that refuse access', async () => {
    const ftp = await serve((socket) => {
      socket.write('220 ready\r\n')
      socket.on('data', () => socket.write('530 Login incorrect.\r\n'))
    })
    const proxy = await serve((socket) => {
      socket.once('data', () => socket.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n'))
    })
    expect(await probeAnonymousFtp({ address: '127.0.0.1', family: 4, port: ftp, timeoutMs: 500 })).toBeNull()
    expect(await probeOpenProxy({ address: '127.0.0.1', family: 4, port: proxy, timeoutMs: 500 })).toBeNull()
  })

  it('detects directory listing and missing security headers', () => {
    const findings = detectHttpMisconfigurations({
      port_number: 80,
      server_response:
        'HTTP/1.1 200 OK\r\nServer: Apache/2.2.15\r\nContent-Type: text/html\r\n\r\n' +
        '<html><title>Index of /backup</title><h1>Index of /backup</h1></html>',
    })
    expect(findings.map((item) => item.category)).toEqual(
      expect.arrayContaining(['directory_listing', 'missing_security_headers'])
    )
  })

  it('detects weak TLS signals from a cached audit result', () => {
    const findings = detectTlsMisconfiguration(
      { port_number: 443 },
      {
        tls_version: 'TLSv1.1',
        cipher_suite: 'RC4-MD5',
        supports_tls12: false,
        is_self_signed: true,
        certificate: { is_expired: true },
      }
    )
    expect(findings.length).toBeGreaterThanOrEqual(3)
    expect(findings.every((item) => item.category === 'weak_ssl')).toBe(true)
  })
})

describe('misconfiguration summary', () => {
  it('returns an empty shape with no open ports', async () => {
    const summary = await detectMisconfigurations({
      address: '127.0.0.1', family: 4, hostname: 'localhost', openPorts: [], timeoutMs: 100,
    })
    expect(summary).toEqual({ total: 0, critical: 0, high: 0, medium: 0, low: 0, categories: [] })
  })
})
