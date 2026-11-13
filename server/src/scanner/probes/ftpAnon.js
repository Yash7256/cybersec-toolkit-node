import { misconfiguration } from './misconfig.js'
import { readSome, withProbeSocket, writeText } from './util.js'

export async function probeAnonymousFtp({
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
      await readSome(socket, { maxBytes: 256, timeoutMs, signal })
      if (!writeText(socket, 'USER anonymous\r\n')) return null
      const userReply = await readSome(socket, { maxBytes: 256, timeoutMs, signal })
      if (!writeText(socket, 'PASS anonymous@\r\n')) return null
      const passReply = await readSome(socket, { maxBytes: 512, timeoutMs, signal })

      const combined = Buffer.concat([userReply, passReply]).toString('utf8')
      if (combined.includes('230')) {
        return misconfiguration(
          'anonymous_ftp',
          'Anonymous FTP login enabled',
          'critical',
          'FTP accepted USER anonymous with an anonymous password.',
          'Disable anonymous FTP access or restrict it to a hardened read-only drop zone.'
        )
      }
      return null
    }
  )
}
