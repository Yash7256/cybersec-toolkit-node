import { queryAll, TYPE_NUMBERS } from '../../net/dohClient.js'
import { MEDIUM, LOW } from './constants.js'
import { vulnerability, baseDomain } from './result.js'

function txtValue(data) {
  const text = String(data ?? '').trim()
  const quoted = text.match(/^"([\s\S]*)"$/)
  const unquoted = quoted ? quoted[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\') : text
  return unquoted.replace(/"\s+"/g, '')
}

export async function txtRecords(name, { query = queryAll, env } = {}) {
  try {
    const [result] = await query(name, ['TXT'], { overallMs: env?.WEBAPP_REQUEST_TIMEOUT_MS ?? 5000 })
    if (result?.error || Number(result?.data?.Status ?? 0) !== 0) return []
    const answers = Array.isArray(result.data?.Answer) ? result.data.Answer : []
    return answers
      .filter((answer) => Number(answer?.type) === TYPE_NUMBERS.TXT)
      .map((answer) => txtValue(answer.data))
  } catch {
    return []
  }
}

export async function checkDnsEmailSecurity(baseUrl, { query, env } = {}) {
  const vulnerabilities = []
  const domain = baseDomain(baseUrl)
  if (!domain) return vulnerabilities

  const txts = await txtRecords(domain, { query, env })
  const spf = txts.filter((record) => record.toLowerCase().startsWith('v=spf1'))
  if (spf.length === 0) {
    vulnerabilities.push(vulnerability({
      vulnType: 'MISSING_SPF',
      severity: MEDIUM,
      url: baseUrl,
      parameter: 'SPF',
      evidence: `No SPF TXT record found for '${domain}'.`,
      recommendation: "Add an SPF record to prevent email spoofing: 'v=spf1 include:... -all'.",
      category: 'dns',
    }))
  } else {
    for (const record of spf) {
      const normalized = record.trim().toLowerCase()
      if (normalized.endsWith('+all') || normalized.endsWith('?all')) {
        vulnerabilities.push(vulnerability({
          vulnType: 'WEAK_SPF',
          severity: MEDIUM,
          url: baseUrl,
          parameter: 'SPF',
          evidence: `SPF record ends with permissive qualifier: ${record.slice(0, 80)}`,
          recommendation: "Use '-all' (fail) or '~all' (softfail) instead of '+all' or '?all'.",
          category: 'dns',
        }))
      }
    }
  }

  const dmarcTxts = await txtRecords(`_dmarc.${domain}`, { query, env })
  const dmarc = dmarcTxts.filter((record) => record.toLowerCase().startsWith('v=dmarc1'))
  if (dmarc.length === 0) {
    vulnerabilities.push(vulnerability({
      vulnType: 'MISSING_DMARC',
      severity: MEDIUM,
      url: baseUrl,
      parameter: 'DMARC',
      evidence: `No DMARC TXT record found for '_dmarc.${domain}'.`,
      recommendation: "Add a DMARC record: 'v=DMARC1; p=reject; rua=mailto:...'.",
      category: 'dns',
    }))
  } else if (/\bp=none\b/i.test(dmarc[0])) {
    vulnerabilities.push(vulnerability({
      vulnType: 'WEAK_DMARC',
      severity: LOW,
      url: baseUrl,
      parameter: 'DMARC',
      evidence: `DMARC policy is 'none' (monitoring only): ${dmarc[0].slice(0, 80)}`,
      recommendation: "Upgrade DMARC policy to 'quarantine' or 'reject'.",
      category: 'dns',
    }))
  }

  return vulnerabilities
}
