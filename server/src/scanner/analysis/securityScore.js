import { EXPOSED_SERVICE_PORTS, HTTPS_PORTS } from '../constants.js'
import { EXPOSED_SERVICE_PORTS as EXPOSED_WARNINGS } from '../data/portRegistry.js'

export function scoreFactor(category, label, penalty, severity = 'medium') {
  return { category, label, penalty, severity }
}

export function calculateSecurityScore({ openPorts = [], sslCache = null } = {}) {
  const factors = []

  for (const port of openPorts) {
    if (port.risk_level === 'critical') {
      factors.push(scoreFactor('risky_ports', `Critical-risk port ${port.port_number} (${port.service}) is open.`, 18, 'critical'))
    } else if (port.risk_level === 'high') {
      factors.push(scoreFactor('risky_ports', `High-risk port ${port.port_number} (${port.service}) is open.`, 12, 'high'))
    } else if (port.risk_level === 'medium') {
      factors.push(scoreFactor('risky_ports', `Medium-risk port ${port.port_number} (${port.service}) is open.`, 5, 'medium'))
    }

    if (EXPOSED_SERVICE_PORTS.has(port.port_number)) {
      factors.push(
        scoreFactor(
          'exposed_services',
          `Exposed service on port ${port.port_number}: ${EXPOSED_WARNINGS[port.port_number] ?? 'Exposed service.'}`,
          10,
          'high'
        )
      )
    }

    if (port.cve_critical_count) {
      factors.push(
        scoreFactor(
          'outdated_versions',
          `Port ${port.port_number} has ${port.cve_critical_count} critical CVE signal(s).`,
          Math.min(20, port.cve_critical_count * 10),
          'critical'
        )
      )
    }
    if (port.cve_high_count) {
      factors.push(
        scoreFactor(
          'outdated_versions',
          `Port ${port.port_number} has ${port.cve_high_count} high-severity CVE signal(s).`,
          Math.min(15, port.cve_high_count * 6),
          'high'
        )
      )
    } else if (port.cve_count) {
      factors.push(
        scoreFactor(
          'outdated_versions',
          `Port ${port.port_number} has known vulnerability signals for its detected version.`,
          Math.min(8, port.cve_count * 2),
          'medium'
        )
      )
    }
  }

  for (const port of openPorts) {
    if (!HTTPS_PORTS.has(port.port_number)) continue
    const result = sslCache?.get?.(port.port_number) ?? sslCache?.[port.port_number]
    if (!result || result instanceof Error) {
      factors.push(scoreFactor('weak_ssl', `TLS audit failed on port ${port.port_number}.`, 5, 'medium'))
      continue
    }
    if (result.error) {
      factors.push(scoreFactor('weak_ssl', `TLS issue on port ${port.port_number}: ${result.error}`, 6, 'medium'))
      continue
    }
    const certificate = result.certificate ?? result.cert
    if (certificate?.is_expired) {
      factors.push(scoreFactor('weak_ssl', `Expired TLS certificate on port ${port.port_number}.`, 14, 'high'))
    } else if (certificate?.days_remaining != null && certificate.days_remaining < 14) {
      factors.push(scoreFactor('weak_ssl', `TLS certificate on port ${port.port_number} expires soon.`, 5, 'medium'))
    }
    if (result.is_self_signed) {
      factors.push(scoreFactor('weak_ssl', `Self-signed TLS certificate on port ${port.port_number}.`, 8, 'medium'))
    }
    if (result.supports_tls12 === false) {
      factors.push(scoreFactor('weak_ssl', `Port ${port.port_number} does not support TLS 1.2.`, 10, 'high'))
    }
    if (result.tls_version === 'TLSv1' || result.tls_version === 'TLSv1.1') {
      factors.push(scoreFactor('weak_ssl', `Port ${port.port_number} negotiated outdated ${result.tls_version}.`, 12, 'high'))
    }
  }

  const totalPenalty = Math.min(100, factors.reduce((sum, factor) => sum + Number(factor.penalty || 0), 0))
  return { score: Math.max(0, 100 - totalPenalty), factors: factors.slice(0, 12) }
}
