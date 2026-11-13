import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { globSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../../src/tools/', import.meta.url))
const files = globSync('**/*.js', { cwd: root })
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/
const STACK = /\bat\s+\S+:\d+:\d+|\bError:\s|\bENOTFOUND\b|\bECONNREFUSED\b/

describe('tool error vocabulary', () => {
  it('never embeds IP literals or stack traces in ToolError messages', () => {
    const offenders = []
    for (const file of files) {
      const source = readFileSync(`${root}${file}`, 'utf8')
      const pattern = /new ToolError\(\s*['"][^'"]+['"]\s*,\s*(['"])(.*?)\1/g
      for (const match of source.matchAll(pattern)) {
        const message = match[2]
        if (IPV4.test(message) || STACK.test(message)) offenders.push(`${file}: ${message}`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('does not import child_process outside the ICMP probe', () => {
    const offenders = files.filter((file) => {
      if (file === 'ping/icmp.js') return false
      return readFileSync(`${root}${file}`, 'utf8').includes('child_process')
    })
    expect(offenders).toEqual([])
  })
})
