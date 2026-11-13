import {
  ADMIN_SERVICE_PORTS,
  DATABASE_PORTS,
  EXPOSURE_SEVERITY_RANK,
  HTTP_PORTS,
  REMOTE_ACCESS_PORTS,
} from '../constants.js'

export function attackPathNode(nodeId, label, nodeType, severity = 'medium', port = null, detail = null) {
  return { id: nodeId, label, type: nodeType, severity, port, detail }
}

export function attackPathEdge(source, target, label, severity = 'medium') {
  return { source, target, label, severity }
}

export function bestWebLabel(port) {
  const techs = (port.technologies ?? []).filter(Boolean)
  if (port.version) return port.version.split(' ')[0].split('/')[0].toUpperCase()
  if (techs.length) return techs[0]
  return port.service || 'Web Service'
}

export function bestPortByScore(ports) {
  if (!ports.length) return null
  let best = ports[0]
  const score = (port) => [
    Number(port.exposure_severity?.score || 0),
    port.cve_critical_count,
    port.cve_high_count,
    port.cve_count,
  ]
  for (const port of ports.slice(1)) {
    const left = score(port)
    const right = score(best)
    for (let i = 0; i < left.length; i += 1) {
      if (left[i] > right[i]) {
        best = port
        break
      }
      if (left[i] < right[i]) break
    }
  }
  return best
}

function pathSummary(nodesById, steps) {
  const labels = []
  for (const step of steps) {
    const node = nodesById[step]
    if (node?.label) labels.push(String(node.label))
  }
  return labels.join(' → ')
}

export function buildAttackPathVisualization(openPorts, exposureSummary = null) {
  if (!openPorts.length) {
    return {
      nodes: [],
      edges: [],
      paths: [],
      summary: 'No attack path could be inferred because no open ports were found.',
    }
  }

  const publicExposure = Boolean(exposureSummary?.public_exposure)
  const webPorts = openPorts.filter((p) => HTTP_PORTS.has(p.port_number))
  const adminPorts = openPorts.filter(
    (p) => ADMIN_SERVICE_PORTS.has(p.port_number) || REMOTE_ACCESS_PORTS.has(p.port_number)
  )
  const databasePorts = openPorts.filter((p) => DATABASE_PORTS.has(p.port_number))
  const vulnerablePorts = openPorts.filter(
    (p) =>
      p.cve_critical_count ||
      p.cve_high_count ||
      p.exploit_availability?.public_exploit_available === true
  )

  const entry = attackPathNode(
    'internet',
    publicExposure ? 'Internet (public IP)' : 'Scanner Network',
    'entry',
    publicExposure ? 'critical' : 'medium',
    null,
    publicExposure
      ? 'Target resolved to a public IP address'
      : 'Target is reachable from the scanner network'
  )
  const nodesById = { internet: entry }
  const edges = []
  const paths = []

  const addNode = (node) => {
    nodesById[node.id] = node
  }
  const addEdge = (edge) => {
    if (!edges.some((existing) => JSON.stringify(existing) === JSON.stringify(edge))) edges.push(edge)
  }

  const primaryWeb = bestPortByScore(webPorts)
  const primaryAdmin = bestPortByScore(adminPorts)
  const primaryDb = bestPortByScore(databasePorts)
  const primaryVuln = bestPortByScore(vulnerablePorts)

  if (primaryWeb) {
    const webId = `web-${primaryWeb.port_number}`
    addNode(
      attackPathNode(
        webId,
        bestWebLabel(primaryWeb),
        'web',
        primaryWeb.risk_level,
        primaryWeb.port_number,
        primaryWeb.version || primaryWeb.service
      )
    )
    addEdge(attackPathEdge('internet', webId, `HTTP/S exposed on ${primaryWeb.port_number}`, primaryWeb.risk_level))

    let previousId = webId
    const steps = ['internet', webId]

    if (
      primaryWeb.misconfigurations?.length ||
      primaryWeb.cve_count ||
      primaryWeb.exploit_availability?.public_exploit_available
    ) {
      const appId = 'admin-panel'
      const reasons = []
      if (primaryWeb.misconfigurations?.length) reasons.push('observed web misconfiguration')
      if (primaryWeb.cve_count) reasons.push(`${primaryWeb.cve_count} CVE signal(s)`)
      if (primaryWeb.exploit_availability?.public_exploit_available) reasons.push('curated public-exploit signal')
      addNode(
        attackPathNode(
          appId,
          'Inferred Admin Surface',
          'application',
          primaryWeb.risk_level !== 'critical' ? 'high' : 'critical',
          null,
          reasons.join(', ') || 'Inferred from exposed web service'
        )
      )
      addEdge(attackPathEdge(previousId, appId, 'Potential web-to-admin pivot', 'high'))
      previousId = appId
      steps.push(appId)
    }

    if (primaryDb) {
      const dbId = `db-${primaryDb.port_number}`
      addNode(
        attackPathNode(
          dbId,
          primaryDb.service || 'Database',
          'database',
          primaryDb.risk_level,
          primaryDb.port_number,
          primaryDb.version || 'Exposed database service'
        )
      )
      addEdge(
        attackPathEdge(
          previousId,
          dbId,
          'Potential backend data-service pivot',
          primaryDb.risk_level === 'critical' ? 'critical' : 'high'
        )
      )
      steps.push(dbId)
    }

    paths.push({
      id: 'web-to-data',
      title: 'Web-to-Data Attack Path',
      severity: primaryDb && publicExposure ? 'critical' : 'high',
      steps,
      summary: pathSummary(nodesById, steps),
    })
  } else if (primaryAdmin) {
    const adminId = `admin-${primaryAdmin.port_number}`
    addNode(
      attackPathNode(
        adminId,
        primaryAdmin.service || 'Admin Service',
        'admin',
        primaryAdmin.risk_level,
        primaryAdmin.port_number,
        primaryAdmin.exposure_severity?.finding || primaryAdmin.service_security_concern
      )
    )
    addEdge(attackPathEdge('internet', adminId, 'Direct remote-access exposure', primaryAdmin.risk_level))
    paths.push({
      id: 'direct-admin',
      title: 'Direct Admin Access Path',
      severity: primaryAdmin.risk_level,
      steps: ['internet', adminId],
      summary: pathSummary(nodesById, ['internet', adminId]),
    })
  }

  if (primaryVuln && (!primaryWeb || primaryVuln.port_number !== primaryWeb.port_number)) {
    const vulnId = `vuln-${primaryVuln.port_number}`
    addNode(
      attackPathNode(
        vulnId,
        primaryVuln.service || 'Vulnerable Service',
        'vulnerability',
        primaryVuln.cve_critical_count ? 'critical' : 'high',
        primaryVuln.port_number,
        primaryVuln.max_cvss_cve || 'Public exploit or high-impact CVE signal'
      )
    )
    addEdge(
      attackPathEdge(
        'internet',
        vulnId,
        'Potential exploit path from exposed service',
        primaryVuln.cve_critical_count ? 'critical' : 'high'
      )
    )
    paths.push({
      id: 'exploit-service',
      title: 'Exploit-to-Service Path',
      severity: primaryVuln.cve_critical_count ? 'critical' : 'high',
      steps: ['internet', vulnId],
      summary: pathSummary(nodesById, ['internet', vulnId]),
    })
  }

  if (!paths.length) {
    const safest = bestPortByScore(openPorts)
    if (safest) {
      const serviceId = `service-${safest.port_number}`
      addNode(
        attackPathNode(
          serviceId,
          safest.service || 'Open Service',
          'service',
          safest.risk_level,
          safest.port_number,
          safest.service_security_concern
        )
      )
      addEdge(
        attackPathEdge('internet', serviceId, 'Reachable open service observed', safest.risk_level)
      )
      paths.push({
        id: 'reachable-service',
        title: 'Reachable Service Path',
        severity: safest.risk_level,
        steps: ['internet', serviceId],
        summary: pathSummary(nodesById, ['internet', serviceId]),
      })
    }
  }

  let highestPath = null
  for (const path of paths) {
    const rank = EXPOSURE_SEVERITY_RANK[String(path.severity || 'medium').toLowerCase()] ?? 2
    const bestRank = highestPath
      ? EXPOSURE_SEVERITY_RANK[String(highestPath.severity || 'medium').toLowerCase()] ?? 2
      : -1
    if (rank > bestRank) highestPath = path
  }

  return {
    nodes: Object.values(nodesById),
    edges,
    paths,
    summary: highestPath ? highestPath.summary : 'No attack path inferred.',
    highest_severity: highestPath ? highestPath.severity : 'low',
  }
}
