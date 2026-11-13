import { MAX_BANNER_BYTES, MAX_BANNER_LINES } from './constants.js'

export const TRUNCATION_MARKER = '\n… [truncated]'

// OSC sequences (window title injection), CSI sequences (colour/cursor), and
// any remaining two-byte ESC sequences. Order matters: OSC/CSI first.
const OSC = /\u001B\][^\u0007\u001B]*(?:\u0007|\u001B\\)/g
const CSI = /\u001B\[[0-?]*[ -/]*[@-~]/g
const ESC = /\u001B[@-_]?/g

// C0 except \n and \t, DEL, and C1 controls.
const CONTROLS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g

export function stripControlCharacters(text) {
  return String(text)
    .replace(OSC, '')
    .replace(CSI, '')
    .replace(ESC, '')
    .replace(CONTROLS, '')
}

export function sanitizeBanner(input, { maxBytes = MAX_BANNER_BYTES, maxLines = MAX_BANNER_LINES } = {}) {
  if (input == null) return ''

  const text = Buffer.isBuffer(input)
    ? input.toString('utf8')
    : typeof input === 'string'
      ? input
      : Buffer.from(input).toString('utf8')

  let cleaned = stripControlCharacters(text)
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/\u0000/g, '')
    .replace(/[ \t]+\n/g, '\n')
    .trimEnd()

  if (!cleaned) return ''

  let truncated = false
  const lines = cleaned.split('\n')
  if (maxLines > 0 && lines.length > maxLines) {
    cleaned = lines.slice(0, maxLines).join('\n')
    truncated = true
  }

  if (maxBytes > 0 && cleaned.length > maxBytes) {
    const room = Math.max(0, maxBytes - TRUNCATION_MARKER.length)
    cleaned = cleaned.slice(0, room)
    truncated = true
  }

  if (truncated) cleaned += TRUNCATION_MARKER
  return cleaned
}

export function sanitizeText(input, options) {
  return sanitizeBanner(input, options)
}
