import { absoluteUrl, baseDomain, sameSite } from './result.js'
import { classifyIp } from '../../security/ipPolicy.js'
import net from 'node:net'

const HREF = /href=["'](https?:\/\/[^"'<>\s]+|\/[^"'<>\s]*)["']/gi
const ACTION = /action=["']([^"']*)["']/i
const METHOD = /method=["']([^"']*)["']/i
const NAMED_INPUT = /<(?:input|select|textarea)[^>]*name=["']([^"']+)["']/gi

export function extractForms(text, pageUrl) {
  const forms = []
  const chunks = String(text).split(/<form/i).slice(1)
  for (const chunk of chunks) {
    const tagEnd = chunk.indexOf('>')
    if (tagEnd === -1) continue
    const opening = chunk.slice(0, tagEnd)
    const actionMatch = ACTION.exec(opening)
    const methodMatch = METHOD.exec(opening)
    const action = absoluteUrl(pageUrl, actionMatch?.[1] || pageUrl)
    if (!action) continue
    const body = chunk.split(/<\/form>/i)[0]
    const names = []
    let match
    NAMED_INPUT.lastIndex = 0
    while ((match = NAMED_INPUT.exec(body)) !== null) {
      if (!names.includes(match[1])) names.push(match[1])
    }
    if (names.length === 0) continue
    let actionHost
    try { actionHost = new URL(action).hostname } catch { continue }
    // A literal private/metadata form action is discarded before any active
    // check sees it. Hostnames are deliberately retained: safeHttp performs
    // the independent DNS pinning and redirect validation at request time.
    if (net.isIP(actionHost) && !classifyIp(actionHost).allowed) continue
    forms.push({
      action,
      method: (methodMatch?.[1] || 'GET').toUpperCase(),
      inputs: names,
    })
  }
  return forms
}

export function extractLinks(text, pageUrl) {
  const links = []
  let match
  HREF.lastIndex = 0
  while ((match = HREF.exec(text)) !== null) {
    const link = absoluteUrl(pageUrl, match[1])
    if (link && sameSite(pageUrl, link) && !links.includes(link)) links.push(link)
  }
  return links
}

export async function crawlSite(baseUrl, {
  client,
  maxPages = 20,
  signal,
  onProgress = () => {},
} = {}) {
  const queue = [baseUrl]
  const visited = new Set()
  const results = []
  const host = baseDomain(baseUrl)

  while (queue.length > 0 && visited.size < maxPages) {
    if (signal?.aborted) throw new Error('aborted')
    const url = queue.shift()
    if (visited.has(url)) continue
    visited.add(url)

    try {
      const response = await client.request(url)
      const text = response.text
      const links = extractLinks(text, url)
      for (const link of links) {
        if (!visited.has(link) && !queue.includes(link) && baseDomain(link) === host) queue.push(link)
      }
      results.push({
        url,
        status_code: response.status,
        content_type: response.headers['content-type'] ?? null,
        forms: extractForms(text, url),
        links,
        response_headers: response.headers,
        body_snippet: text.slice(0, 4096),
      })
      onProgress(results.length)
    } catch {
      continue
    }
  }

  return results
}
