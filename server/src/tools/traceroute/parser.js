const HOP_IP = /^\s*(\d+)\s+([0-9a-fA-F:.]+|\*)/
const RTT = /(\d+(?:\.\d+)?)\s*ms/g

export function parseTracerouteOutput(output) {
  const rawHops = []
  let destinationIp = null

  for (const sourceLine of String(output ?? '').split(/\r?\n/)) {
    const line = sourceLine.trim()
    if (!line || !/^\d/.test(line)) continue

    if (line.includes('* * *')) {
      rawHops.push({ hop: Number(line.split(/\s+/)[0]), ip: null, samples: [] })
      continue
    }

    const match = HOP_IP.exec(line)
    if (!match) continue
    const hop = Number(match[1])
    const ip = match[2]
    if (ip === '*') {
      rawHops.push({ hop, ip: null, samples: [] })
      continue
    }

    const samples = []
    let rtt
    RTT.lastIndex = 0
    while ((rtt = RTT.exec(line)) !== null) {
      const value = Number(rtt[1])
      if (Number.isFinite(value)) samples.push(value)
    }
    rawHops.push({ hop, ip, samples })
    destinationIp = ip
  }

  return { rawHops, destinationIp }
}
