const tokenRe = /[^\s,;]+/g

export function classifyGeoipInput(value = '') {
  const tokens = value.match(tokenRe) ?? []
  const counts = { hosts: 0, ips: 0, cidrs: 0, asns: 0, invalid: 0 }
  for (const token of tokens) {
    if (/^AS\d{1,10}$/i.test(token)) counts.asns += 1
    else if (/^\d+(?:\.\d+){3}$/.test(token) || token.includes(':')) counts.ips += 1
    else if (/^\S+\/\d+$/.test(token)) counts.cidrs += 1
    else if (/^[a-z0-9.-]+$/i.test(token) || /^https?:\/\//i.test(token)) counts.hosts += 1
    else counts.invalid += 1
  }
  return { tokens, counts, total: tokens.length }
}
