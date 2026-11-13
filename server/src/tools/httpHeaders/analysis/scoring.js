export function scoreResult({ securityHeaders = [], hsts = {}, csp = {}, clickjacking = {}, cookies = [], disclosure = {} } = {}) {
  let score = 100 - securityHeaders.filter((x) => !x.present).length * 10
  if (!hsts.strong) score -= 10
  if (csp.weak) score -= 10
  if (!clickjacking.protected) score -= 10
  score -= Math.min(20, cookies.filter((x) => x.issues?.length).length * 5)
  if (disclosure.issues?.length) score -= 5
  score = Math.max(0, Math.min(100, score))
  return { securityScore: score, riskLevel: score >= 80 ? 'low' : score >= 50 ? 'medium' : 'high' }
}
