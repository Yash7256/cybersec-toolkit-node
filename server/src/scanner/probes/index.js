import { FTP_PORTS, HTTP_PORTS, HTTPS_PORTS, PROXY_PORTS } from '../constants.js'
import { detectHttpMisconfigurations, misconfigurationSummary } from './misconfig.js'
import { probeAnonymousFtp } from './ftpAnon.js'
import { probeOpenProxy } from './openProxy.js'
import { detectTlsMisconfiguration } from './tlsMisconfig.js'

async function mapLimit(items, limit, fn) {
  let index = 0
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) {
      const current = index
      index += 1
      await fn(items[current])
    }
  })
  await Promise.all(workers)
}

export async function detectMisconfigurations({
  address,
  family,
  hostname,
  openPorts,
  timeoutMs = 2000,
  sslCache = null,
  signal,
  deps = {},
}) {
  if (!openPorts.length) return misconfigurationSummary(openPorts)

  const probeTimeout = Math.min(Math.max(timeoutMs, 2000), 5000)

  await mapLimit(openPorts, 5, async (port) => {
    const findings = []
    if (HTTP_PORTS.has(port.port_number)) {
      findings.push(...detectHttpMisconfigurations(port))
    }
    if (HTTPS_PORTS.has(port.port_number)) {
      const result = sslCache?.get?.(port.port_number) ?? sslCache?.[port.port_number] ?? null
      findings.push(...detectTlsMisconfiguration(port, result))
    }
    if (FTP_PORTS.has(port.port_number)) {
      const finding = await probeAnonymousFtp({
        address,
        family,
        hostname,
        port: port.port_number,
        timeoutMs: probeTimeout,
        signal,
        deps,
      })
      if (finding) findings.push(finding)
    }
    if (PROXY_PORTS.has(port.port_number)) {
      const finding = await probeOpenProxy({
        address,
        family,
        hostname,
        port: port.port_number,
        timeoutMs: probeTimeout,
        signal,
        deps,
      })
      if (finding) findings.push(finding)
    }
    port.misconfigurations = findings
  })

  return misconfigurationSummary(openPorts)
}
