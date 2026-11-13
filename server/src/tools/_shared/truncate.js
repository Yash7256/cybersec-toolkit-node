export function capResult(value, maxBytes = 512 * 1024) {
  const size = (input) => Buffer.byteLength(JSON.stringify(input))
  if (size(value) <= maxBytes) return value
  const copy = structuredClone(value)
  const strings = []
  const walk = (node, parent, key) => {
    if (typeof node === 'string') strings.push({ parent, key, value: node })
    else if (node && typeof node === 'object') Object.entries(node).forEach(([k, v]) => walk(v, node, k))
  }
  walk(copy, null, null)
  strings.sort((a, b) => b.value.length - a.value.length)
  for (const item of strings) {
    const current = item.value
    item.parent[item.key] = current.slice(0, Math.max(0, Math.floor(current.length * 0.75))) + '…'
    if (size(copy) <= maxBytes) break
  }
  if (copy && typeof copy === 'object') copy.truncated = true
  return copy
}
