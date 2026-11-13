export const MAX_TECH_SCAN_BYTES = 8192

const TECH_PATTERNS = [
  ['Cloudflare', /cloudflare|cf-ray|cf-cache-status|__cf_bm/i],
  ['WordPress', /wordpress|wp-content|wp-includes|\/xmlrpc\.php/i],
  ['Drupal', /drupal|x-drupal-|\/sites\/default\//i],
  ['Joomla', /joomla|\/components\/com_/i],
  ['Shopify', /shopify|x-shopid|cdn\.shopify/i],
  ['Apache', /apache[/\s]|apache-coyote|mod_ssl|mod_php/i],
  ['Nginx', /nginx[/\s]/i],
  ['IIS', /microsoft-iis|asp\.net/i],
  ['LiteSpeed', /litespeed/i],
  ['Caddy', /\bcaddy\b/i],
  ['Tomcat', /apache-coyote|tomcat|servlet/i],
  ['Jetty', /jetty/i],
  ['PHP', /\bphp[/\s\d]|x-powered-by:\s*php/i],
  ['Node.js', /node\.?js[/\s\da-z.]*|x-powered-by:\s*node/i],
  ['Express', /\bexpress\b|x-powered-by:\s*express/i],
  ['Django', /django|csrftoken=|wsgi/i],
  ['Laravel', /laravel|x-powered-by:\s*laravel/i],
  ['Ruby on Rails', /ruby on rails|rails|x-runtime:.*rails/i],
  ['React', /react-dom|__react|data-reactroot|\/_next\/static/i],
  ['Vue.js', /vue\.js|__vue__|data-v-[a-f0-9]/i],
  ['Angular', /angular|ng-version=/i],
  ['jQuery', /jquery[./-]\d|jquery\.min\.js/i],
  ['Bootstrap', /bootstrap[./-]\d|bootstrap\.min/i],
  ['AWS', /amazonaws|x-amz-|awselb/i],
  ['Google Cloud', /google frontend|gfe|x-cloud-trace/i],
  ['Azure', /microsoft-azure|x-azure-ref/i],
  ['Varnish', /varnish|x-varnish/i],
  ['HAProxy', /haproxy/i],
  ['OpenSSH', /openssh[_\s]/i],
  ['MySQL', /\bmysql\b|mariadb/i],
  ['PostgreSQL', /\bpostgresql\b/i],
  ['Redis', /\bredis\b/i],
  ['MongoDB', /\bmongodb\b/i],
  ['Elasticsearch', /elasticsearch|kibana/i],
]

export function detectTechnologies(raw, { extraText = null } = {}) {
  let text
  if (raw == null) text = ''
  else if (Buffer.isBuffer(raw)) text = raw.toString('utf8')
  else text = String(raw)

  if (extraText) text = `${text}\n${extraText}`
  if (!text.trim()) return []
  if (text.length > MAX_TECH_SCAN_BYTES) text = text.slice(0, MAX_TECH_SCAN_BYTES)

  const found = []
  for (const [name, pattern] of TECH_PATTERNS) {
    if (pattern.test(text)) found.push(name)
  }
  return found
}

export function mergeTechnologies(...lists) {
  const merged = []
  const seen = new Set()
  for (const items of lists) {
    for (const name of items ?? []) {
      if (seen.has(name)) continue
      seen.add(name)
      merged.push(name)
    }
  }
  return merged
}
