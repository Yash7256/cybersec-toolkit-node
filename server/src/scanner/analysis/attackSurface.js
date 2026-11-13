import {
  ADMIN_SERVICE_PORTS,
  EXPOSED_SERVICE_PORTS,
} from '../constants.js'
import { EXPOSED_SERVICE_PORTS as EXPOSED_WARNINGS } from '../data/portRegistry.js'

export function attackSurfaceLevel(score) {
  if (score >= 70) return 'CRITICAL'
  if (score >= 45) return 'HIGH'
  if (score >= 20) return 'MEDIUM'
  return 'LOW'
}

export function surfaceFactor(category, label, weight, severity = 'medium') {
  return { category, label, weight, severity }
}

export function calculateAttackSurface(openPorts) {
  const publicServices = []
  const factors = []
  const seenServices = new Set()

  for (const port of openPorts) {
    const service = port.service || 'Unknown'
    if (!seenServices.has(service)) {
      seenServices.add(service)
      publicServices.push({
        port: port.port_number,
        service,
        risk_level: port.risk_level,
      })
    }

    if (port.risk_level === 'critical' || port.risk_level === 'high') {
      factors.push(
        surfaceFactor(
          'risky_services',
          `${service} on port ${port.port_number} is classified as ${port.risk_level} risk.`,
          port.risk_level === 'critical' ? 16 : 11,
          port.risk_level
        )
      )
    } else if (port.risk_level === 'medium') {
      factors.push(
        surfaceFactor('risky_services', `${service} on port ${port.port_number} adds moderate exposure.`, 5, 'medium')
      )
    }

    if (EXPOSED_SERVICE_PORTS.has(port.port_number)) {
      factors.push(
        surfaceFactor(
          'exposed_services',
          `${service} is publicly exposed: ${EXPOSED_WARNINGS[port.port_number] ?? 'Exposed service.'}`,
          10,
          'high'
        )
      )
    }

    if (ADMIN_SERVICE_PORTS.has(port.port_number)) {
      factors.push(
        surfaceFactor(
          'admin_services',
          `Administrative or remote-access service ${service} is exposed on port ${port.port_number}.`,
          12,
          'high'
        )
      )
    }

    if (port.cve_critical_count || port.cve_high_count) {
      factors.push(
        surfaceFactor(
          'outdated_versions',
          `${service} on port ${port.port_number} has high-impact vulnerability signals.`,
          port.cve_critical_count ? 15 : 9,
          port.cve_critical_count ? 'critical' : 'high'
        )
      )
    } else if (port.cve_count) {
      factors.push(
        surfaceFactor(
          'outdated_versions',
          `${service} on port ${port.port_number} has known vulnerability signals.`,
          5,
          'medium'
        )
      )
    }
  }

  const portCount = openPorts.length
  if (portCount >= 20) {
    factors.push(surfaceFactor('open_port_count', `${portCount} open ports create a broad attack surface.`, 18, 'high'))
  } else if (portCount >= 8) {
    factors.push(surfaceFactor('open_port_count', `${portCount} open ports create a moderate attack surface.`, 10, 'medium'))
  } else if (portCount >= 4) {
    factors.push(surfaceFactor('open_port_count', `${portCount} open ports increase reachable service exposure.`, 5, 'medium'))
  }

  const score = Math.min(100, factors.reduce((sum, factor) => sum + Number(factor.weight), 0))
  const level = attackSurfaceLevel(score)
  const adminCount = openPorts.filter((port) => ADMIN_SERVICE_PORTS.has(port.port_number)).length
  const vulnerableCount = openPorts.filter((port) => port.cve_count).length

  return {
    level,
    score,
    publicly_exposed_services: publicServices,
    factors: factors.slice(0, 12),
    summary: `${level} attack surface based on ${portCount} open port(s), ${adminCount} admin service(s), and ${vulnerableCount} service(s) with vulnerability signals.`,
  }
}
