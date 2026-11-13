import { MAX_BANNER_BYTES } from './constants.js'
import { sanitizeBanner } from './sanitize.js'

function firstLine(text) {
  for (const line of text.replace(/\r\n/g, '\n').split('\n')) {
    const value = line.trim()
    if (value) return value
  }
  return null
}

export function fromBytes(data, { serverResponse = null, maxBytes = MAX_BANNER_BYTES } = {}) {
  if (!data || data.length === 0) {
    return { raw_banner: null, welcome_message: null, server_response: serverResponse || null }
  }
  const text = sanitizeBanner(data, { maxBytes })
  if (!text) {
    return { raw_banner: null, welcome_message: null, server_response: serverResponse || null }
  }
  return {
    raw_banner: text,
    welcome_message: firstLine(text),
    server_response: serverResponse || null,
  }
}

export function fromHttpResponse(data, { maxBytes = MAX_BANNER_BYTES } = {}) {
  if (!data || data.length === 0) {
    return { raw_banner: null, welcome_message: null, server_response: null }
  }
  const text = sanitizeBanner(data, { maxBytes })
  if (!text) {
    return { raw_banner: null, welcome_message: null, server_response: null }
  }
  const headerBlock = text.split(/\n\s*\n/, 1)[0]
  return {
    raw_banner: text,
    welcome_message: firstLine(text),
    server_response: headerBlock || text || null,
  }
}
