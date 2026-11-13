import { misconfiguration } from './misconfig.js'
import { readSome, withProbeSocket, writeText } from './util.js'

// The canary target is a fixed constant, never user-controlled.
const CANARY_URL = 'http://example.com/'

export async function probeOpenProxy({
  address,
  family,
  port,
  timeoutMs = 2000,
  signal,
  deps = {},
}) {
  return withProbeSocket(
    { address, family, port, timeoutMs, signal, deps },
    async (socket) => {
      const request =
        `GET ${CANARY_URL} HTTP/1.1\r\n` +
        `Host: example.com\r\n` +
        `User-Agent: CyberSecPortScanner/1.0\r\n` +
        `Connection: close\r\n\r\n`
      if (!writeText(socket, request)) return null

      const data = await readSome(socket, {
        maxBytes: 2048,
        timeoutMs: Math.max(timeoutMs, 3000),
        signal,
      })
      const text = data.toString('utf8')
      const head = text.split('\r\n\r\n', 1)[0]
      if (
        text.includes('Example Domain') ||
        (/HTTP\/\d(?:\.\d)?\s+20\d/.test(head) &&
          !head.includes('407 Proxy Authentication Required') &&
          !head.includes('403 Forbidden'))
      ) {
        return misconfiguration(
          'open_proxy',
          'Open proxy detected',
          'critical',
          'The service accepted an absolute-form HTTP proxy request.',
          'Disable unauthenticated proxying or restrict proxy access to trusted networks only.'
        )
      }
      return null
    }
  )
}
