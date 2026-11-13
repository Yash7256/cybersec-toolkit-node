import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { ToolError } from '../_shared/errors.js'
const run = promisify(execFile)

export function parsePingOutput(output, count = 4) {
  const samples = []
  for (const line of String(output).split('\n')) {
    const match = line.match(/time[=<]([0-9.]+)\s*ms/i)
    if (match) samples.push(Number(match[1]))
  }
  const summary = output.match(/(\d+) packets transmitted, (\d+) (?:packets )?received.*?([0-9.]+)% packet loss/i)
  const transmitted = Number(summary?.[1] ?? count)
  const received = Number(summary?.[2] ?? samples.length)
  return { samples, transmitted, received, loss_pct: Number(summary?.[3] ?? ((transmitted - received) / Math.max(transmitted, 1)) * 100) }
}

export async function pingIp(ip, { count = 4, family = 4, signal } = {}) {
  if (!/^([0-9a-f:.]+)$/i.test(ip)) throw new ToolError('target', 'Host not reachable')
  const args = ['-n', '-c', String(count), '-i', '0.5', '-W', '2', family === 6 ? '-6' : '-4', '--', ip]
  try {
    const { stdout, stderr } = await run('ping', args, { env: { LC_ALL: 'C', PATH: '/usr/bin:/bin' }, timeout: count * 500 + 5000, maxBuffer: 64 * 1024, signal })
    return parsePingOutput(`${stdout}\n${stderr}`, count)
  } catch (err) {
    if (err.stdout || err.stderr) return parsePingOutput(`${err.stdout ?? ''}\n${err.stderr ?? ''}`, count)
    throw new ToolError('target', 'Host not reachable', err)
  }
}
