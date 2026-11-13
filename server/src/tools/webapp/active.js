import {
  SQLI_PAYLOADS, XSS_PAYLOADS, SSTI_PAYLOADS, TRAVERSAL_PAYLOADS, SQL_ERRORS,
  CRITICAL, HIGH, MEDIUM,
} from './constants.js'
import { withQuery, encodeForm } from './client.js'
import { vulnerability } from './result.js'

function formRequest(client, form, data) {
  if (form.method === 'POST') {
    return client.request(form.action, {
      method: 'POST',
      body: encodeForm(data),
      followRedirects: false,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    })
  }
  return client.request(withQuery(form.action, data))
}

export async function checkSqli(url, forms, { client }) {
  const vulnerabilities = []
  for (const form of forms) {
    for (const name of form.inputs) {
      for (const payload of SQLI_PAYLOADS.slice(0, 3)) {
        try {
          const data = Object.fromEntries(form.inputs.map((input) => [input, 'test']))
          data[name] = payload
          const response = await formRequest(client, form, data)
          let matched = false
          for (const error of SQL_ERRORS) {
            const lower = response.text.toLowerCase()
            if (!lower.includes(error.toLowerCase())) continue
            const index = lower.indexOf(error.toLowerCase())
            vulnerabilities.push(vulnerability({
              vulnType: 'SQL_INJECTION',
              severity: CRITICAL,
              url,
              parameter: name,
              evidence: response.text.slice(Math.max(0, index - 20), index + 80).slice(0, 120),
              recommendation: 'Use parameterized queries / prepared statements; never interpolate user input into SQL.',
              category: 'injection',
            }))
            matched = true
            break
          }
          if (matched) break
        } catch {}
      }
    }
  }
  return vulnerabilities
}

export async function checkXss(url, forms, { client }) {
  const urlParams = url.includes('?')
    ? url.split('?', 1)[1].split('&').filter((pair) => pair.includes('=')).map((pair) => pair.split('=')[0])
    : []

  const probes = []
  for (const form of forms) {
    for (const name of form.inputs) {
      for (const payload of XSS_PAYLOADS.slice(0, 2)) {
        probes.push((async () => {
          try {
            const data = Object.fromEntries(form.inputs.map((input) => [input, 'test']))
            data[name] = payload
            const response = await formRequest(client, form, data)
            if (!response.text.includes(payload)) return null
            return vulnerability({
              vulnType: 'XSS',
              severity: HIGH,
              url,
              parameter: name,
              evidence: `Payload reflected: ${payload.slice(0, 60)}`,
              recommendation: 'HTML-encode all user output; implement a strict Content-Security-Policy.',
              category: 'injection',
            })
          } catch {
            return null
          }
        })())
      }
    }
  }

  for (const param of urlParams) {
    for (const payload of XSS_PAYLOADS.slice(0, 2)) {
      probes.push((async () => {
        try {
          const candidate = new URL(url)
          candidate.searchParams.set(param, payload)
          const response = await client.request(candidate.toString())
          if (!response.text.includes(payload)) return null
          return vulnerability({
            vulnType: 'XSS',
            severity: HIGH,
            url,
            parameter: param,
            evidence: `URL param reflected: ${payload.slice(0, 60)}`,
            recommendation: 'HTML-encode all user output; implement a strict Content-Security-Policy.',
            category: 'injection',
          })
        } catch {
          return null
        }
      })())
    }
  }

  return (await Promise.all(probes)).filter(Boolean)
}

export function checkCsrf(url, forms) {
  const vulnerabilities = []
  for (const form of forms) {
    if (form.method !== 'POST') continue
    const tokenMarkers = ['csrf', 'token', '_token', 'authenticity_token', 'nonce', 'xsrf']
    const hasToken = form.inputs.some((input) => tokenMarkers.some((marker) => input.toLowerCase().includes(marker)))
    if (!hasToken) {
      vulnerabilities.push(vulnerability({
        vulnType: 'CSRF',
        severity: MEDIUM,
        url,
        evidence: `POST form at '${form.action}' has no CSRF token.`,
        recommendation: 'Add an unpredictable, per-session CSRF token to all state-changing forms.',
        category: 'injection',
      }))
    }
  }
  return vulnerabilities
}

export async function checkSsti(url, forms, { client }) {
  const vulnerabilities = []
  for (const form of forms) {
    for (const name of form.inputs) {
      for (const payload of SSTI_PAYLOADS) {
        try {
          const data = Object.fromEntries(form.inputs.map((input) => [input, 'test']))
          data[name] = payload
          const response = await formRequest(client, form, data)
          if (response.text.includes('49') && ['{{7*7}}', '${7*7}', '#{7*7}'].includes(payload)) {
            vulnerabilities.push(vulnerability({
              vulnType: 'SSTI',
              severity: CRITICAL,
              url,
              parameter: name,
              evidence: `Template expression '${payload}' evaluated to 49.`,
              recommendation: 'Never pass user input to template engines unsanitised; use sandboxed evaluation.',
              category: 'injection',
            }))
            break
          }
        } catch {}
      }
    }
  }
  return vulnerabilities
}

export async function checkPathTraversal(baseUrl, { client }) {
  const params = ['file', 'path', 'page', 'include', 'template', 'load', 'doc']
  for (const payload of TRAVERSAL_PAYLOADS) {
    for (const param of params) {
      const url = `${baseUrl.replace(/\/+$/, '')}/?${param}=${encodeURIComponent(payload)}`
      try {
        const response = await client.request(url)
        if (response.status === 200 && (
          response.text.includes('root:') || response.text.includes('[fonts]') || response.text.includes('daemon:')
        )) {
          return [vulnerability({
            vulnType: 'PATH_TRAVERSAL',
            severity: CRITICAL,
            url,
            parameter: param,
            evidence: `Traversal payload '${payload}' returned file contents.`,
            recommendation: 'Validate and canonicalise file paths; use an allowlist of permitted files.',
            category: 'injection',
          })]
        }
      } catch {}
    }
  }
  return []
}
