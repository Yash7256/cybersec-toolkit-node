export function buildRouteIntelligence(target, hops, destinationIp) {
  const visible = hops.filter((hop) => hop.rtt_ms != null)
  const hiddenHops = hops.filter((hop) => hop.is_hidden).length
  const packetLossHops = hops.filter((hop) => hop.packet_loss_pct > 0).length
  const bottlenecks = hops
    .filter((hop) => hop.latency_added_ms != null && hop.latency_added_ms >= 40)
    .map((hop) => ({
      hop: hop.hop,
      ip: hop.ip,
      latency_added_ms: hop.latency_added_ms,
      reason: 'Large per-hop latency increase',
    }))

  const countries = hops.map((hop) => hop.country_code).filter(Boolean)
  const internationalRoute = new Set(countries).size > 1
  const cdnDetected = hops.find((hop) => hop.cdn_provider)?.cdn_provider ?? null

  const ownershipChain = []
  for (const hop of hops) {
    const owner = hop.cdn_provider || hop.provider || hop.asn
    if (owner && !ownershipChain.includes(owner)) ownershipChain.push(owner)
  }

  const autonomousSystemPath = []
  for (const hop of hops) {
    const asn = hop.asn || hop.provider
    if (asn && !autonomousSystemPath.includes(asn)) autonomousSystemPath.push(asn)
  }

  const rtts = visible.map((hop) => hop.rtt_ms)
  let variance = 0
  if (rtts.length > 0) {
    const average = rtts.reduce((sum, value) => sum + value, 0) / rtts.length
    variance = rtts.reduce((sum, value) => sum + (value - average) ** 2, 0) / rtts.length
  }

  const stabilityScore = Math.max(0, Math.min(100, Math.round(
    100
    - Math.min(35, hiddenHops * 7)
    - Math.min(25, packetLossHops * 6)
    - Math.min(25, Math.sqrt(variance) / 3)
    - Math.min(20, bottlenecks.length * 10)
  )))

  let routeEfficiency = 'Poor'
  if (stabilityScore >= 88) routeEfficiency = 'Excellent'
  else if (stabilityScore >= 72) routeEfficiency = 'Good'
  else if (stabilityScore >= 50) routeEfficiency = 'Moderate'

  const routingIntelligence = []
  const securityInsights = []
  const riskFactors = []

  if (cdnDetected) {
    routingIntelligence.push(`Traffic appears to traverse ${cdnDetected} edge or cloud infrastructure.`)
  }
  if (hiddenHops) {
    securityInsights.push(`${hiddenHops} intermediate hop(s) suppress ICMP replies.`)
    riskFactors.push('Filtered intermediate routers reduce route visibility.')
  }
  if (bottlenecks.length > 0) {
    routingIntelligence.push(`Possible bottleneck detected at hop ${bottlenecks[0].hop}.`)
    riskFactors.push('A large latency jump indicates congestion or long-distance transit.')
  }
  if (internationalRoute) {
    routingIntelligence.push('Cross-border routing detected.')
    riskFactors.push('Traffic crosses multiple geographic regions.')
  }
  if (routingIntelligence.length === 0) {
    routingIntelligence.push('Route appears direct with no major inferred transit anomaly.')
  }
  if (securityInsights.length === 0) {
    securityInsights.push('No obvious traceroute security anomaly detected.')
  }

  const healthIndicators = [
    stabilityScore >= 80 ? 'HEALTHY' : 'WATCH',
    bottlenecks.length === 0 ? 'LOW CONGESTION' : 'CONGESTION SIGNAL',
    ['Excellent', 'Good'].includes(routeEfficiency) ? 'OPTIMAL ROUTE' : 'SUBOPTIMAL ROUTE',
  ]

  let routeRisk = 'Low'
  if (riskFactors.length >= 2 || stabilityScore < 55) routeRisk = 'High'
  else if (riskFactors.length > 0) routeRisk = 'Medium'

  const finalRtt = visible.length > 0 ? visible[visible.length - 1].rtt_ms : null
  const summaryParts = [
    `Traceroute to ${target} reached ${visible.length} visible hop(s)`
      + (finalRtt != null ? ` with final observed latency near ${finalRtt.toFixed(1)}ms.` : '.'),
  ]
  if (bottlenecks.length > 0) {
    summaryParts.push(`A notable latency increase occurs around hop ${bottlenecks[0].hop}.`)
  }
  if (hiddenHops) {
    summaryParts.push(`${hiddenHops} hop(s) are hidden or filtered, which is common on hardened network paths.`)
  }
  if (cdnDetected) {
    summaryParts.push(`The route likely uses ${cdnDetected} infrastructure.`)
  }

  return {
    destination_ip: destinationIp,
    route_stability_score: stabilityScore,
    route_efficiency: routeEfficiency,
    health_indicators: healthIndicators,
    autonomous_system_path: autonomousSystemPath,
    ownership_chain: ownershipChain,
    bottlenecks,
    hidden_hops: hiddenHops,
    packet_loss_hops: packetLossHops,
    international_route: internationalRoute,
    cdn_detected: cdnDetected,
    route_risk: routeRisk,
    route_risk_factors: riskFactors,
    routing_intelligence: routingIntelligence,
    ai_summary: summaryParts.join(' '),
    security_insights: securityInsights,
  }
}
