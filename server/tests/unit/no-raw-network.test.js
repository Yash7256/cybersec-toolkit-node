import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { resolve, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const allowlist = JSON.parse(
  readFileSync(new URL('./network-allowlist.json', import.meta.url), 'utf8')
)
const exemptDirs = new Set(['security', 'net', 'redis', 'db'])

describe('raw network guard', () => {
  it('keeps raw network primitives in approved modules', () => {
    const root = resolve(fileURLToPath(new URL('../../src', import.meta.url)))
    const forbidden =
      /fetch\(|https?\.request|net\.connect|tls\.connect|dns\.lookup|dns\.promises|execFile\(|spawn\(/g
    const files = []
    const walk = (dir) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = resolve(dir, entry.name)
        if (entry.isDirectory()) walk(full)
        else if (entry.name.endsWith('.js')) files.push(full)
      }
    }
    walk(root)

    for (const [entry, reason] of Object.entries(allowlist)) {
      expect(reason.length, `${entry} needs a reason`).toBeGreaterThan(10)
      expect(existsSync(resolve(root, entry)), `${entry} is allow-listed but missing`).toBe(true)
    }

    for (const file of files) {
      const rel = relative(root, file)
      if (exemptDirs.has(rel.split('/')[0])) continue
      if (allowlist[rel]) continue
      const hits = readFileSync(file, 'utf8').match(forbidden)
      expect(hits, `${rel} contains raw network code`).toBeNull()
    }
  })
})
