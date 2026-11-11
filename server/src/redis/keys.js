const MAX_PART_LENGTH = 200

function cleanPart(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`redis key part "${label}" must be a non-empty string`)
  }
  const sanitized = value.replaceAll(':', '_')
  if (sanitized.length > MAX_PART_LENGTH) {
    throw new Error(`redis key part "${label}" exceeds ${MAX_PART_LENGTH} characters`)
  }
  return sanitized
}

// All keys are built here: cst:<area>:<name>:<id>. No ioredis keyPrefix.
export function key(area, name, id) {
  return `cst:${cleanPart(area, 'area')}:${cleanPart(name, 'name')}:${cleanPart(id, 'id')}`
}
