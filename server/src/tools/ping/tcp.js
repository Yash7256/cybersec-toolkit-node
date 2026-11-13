import net from 'node:net'

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export function tcpAttempt({ address, port, timeoutMs = 2000, signal } = {}) {
  return new Promise((resolve) => {
    const started = Date.now()
    let settled = false
    const socket = net.connect({ host: address, port, timeout: timeoutMs })

    const finish = (value) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(value)
    }

    socket.once('connect', () => finish(Date.now() - started))
    socket.once('error', () => finish(null))
    socket.once('timeout', () => finish(null))
    if (signal) signal.addEventListener('abort', () => finish(null), { once: true })
  })
}

export async function tcpPing({
  address,
  count,
  ports = [443, 80],
  intervalMs = 200,
  timeoutMs = 2000,
  signal,
} = {}) {
  let port = null
  for (const candidate of ports) {
    const first = await tcpAttempt({ address, port: candidate, timeoutMs, signal })
    if (first !== null) {
      port = candidate
      const values = [first]
      for (let index = 1; index < count; index += 1) {
        await sleep(intervalMs)
        values.push(await tcpAttempt({ address, port, timeoutMs, signal }))
      }
      const received = values.filter((value) => value !== null).length
      return { method: 'tcp', port, values, sent: count, received, loss_pct: ((count - received) / count) * 100 }
    }
  }

  return { method: 'tcp', port: null, values: [], sent: count, received: 0, loss_pct: 100 }
}
