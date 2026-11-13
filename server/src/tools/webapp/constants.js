export const CRITICAL = 'critical'
export const HIGH = 'high'
export const MEDIUM = 'medium'
export const LOW = 'low'
export const INFO = 'info'

export const SEVERITY_RANK = Object.freeze({
  [CRITICAL]: 0,
  [HIGH]: 1,
  [MEDIUM]: 2,
  [LOW]: 3,
  [INFO]: 4,
})

export const SENSITIVE_FILES = Object.freeze([
  '.env', '.env.local', '.env.production',
  '.git/config', '.git/HEAD',
  'robots.txt', 'sitemap.xml',
  'wp-config.php', 'wp-login.php', 'wp-admin/',
  'config.php', 'configuration.php', 'settings.php',
  '.htaccess', 'web.config',
  'phpinfo.php', 'info.php', 'test.php',
  'admin/', 'administrator/', 'phpmyadmin/', 'pma/',
  'backup.zip', 'backup.tar.gz', 'dump.sql', 'database.sql', 'db.sql',
  '.DS_Store', 'package.json', 'yarn.lock', 'composer.json',
  'Dockerfile', 'docker-compose.yml',
  'server-status', 'server-info',
  'actuator/', 'actuator/env', 'actuator/health',
  'api/swagger.json', 'api/openapi.json', 'swagger-ui.html',
  'graphql', 'graphiql',
])

export const ADMIN_PATHS = Object.freeze([
  '/admin', '/admin/', '/administrator/', '/wp-admin/',
  '/phpmyadmin/', '/pma/', '/cpanel/', '/webmail/',
  '/manager/html', '/jmx-console/', '/admin-console/',
  '/login', '/login.php', '/signin', '/auth/login',
  '/user/login', '/account/login', '/panel/',
  '/dashboard', '/console/', '/control/',
])

export const SQLI_PAYLOADS = Object.freeze(["'", "''", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"])
export const XSS_PAYLOADS = Object.freeze([
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  "'><svg onload=alert(1)>",
])
export const SSTI_PAYLOADS = Object.freeze(['{{7*7}}', '${7*7}', '#{7*7}', '<%= 7*7 %>', '{{config}}'])
export const TRAVERSAL_PAYLOADS = Object.freeze([
  '../etc/passwd', '../../etc/passwd', '../../../etc/passwd',
  '....//....//etc/passwd', '%2e%2e%2fetc%2fpasswd',
])

export const SQL_ERRORS = Object.freeze([
  'sql syntax', 'mysql_fetch', 'ORA-', 'syntax error',
  'unclosed quotation', 'quoted string not properly terminated',
  'pg_query()', 'sqlite_', 'Microsoft OLE DB', 'Warning: mysql',
  'You have an error in your SQL syntax', 'SQLSTATE',
  'PDOException', 'psycopg2',
])

export const SECURITY_HEADERS = Object.freeze({
  'Strict-Transport-Security': [HIGH, 'Prevents protocol downgrade / MITM attacks'],
  'Content-Security-Policy': [HIGH, 'Mitigates XSS and data injection'],
  'X-Frame-Options': [MEDIUM, 'Prevents clickjacking via iframe'],
  'X-Content-Type-Options': [MEDIUM, 'Prevents MIME-type sniffing'],
  'Referrer-Policy': [LOW, 'Controls referrer leakage'],
  'Permissions-Policy': [LOW, 'Restricts browser feature access'],
})

export const FINGERPRINTS = Object.freeze([
  ['wp-content|wp-includes|wordpress', 'WordPress', 'cms'],
  ['Joomla!|/components/com_', 'Joomla', 'cms'],
  ['Drupal|sites/default/files', 'Drupal', 'cms'],
  ['Magento|mage/|Mage\\.', 'Magento', 'cms'],
  ['TYPO3', 'TYPO3', 'cms'],
  ['Django|csrfmiddlewaretoken|__admin__', 'Django', 'framework'],
  ['Rails|X-Powered-By: Phusion Passenger|_rails_', 'Ruby on Rails', 'framework'],
  ['Laravel|laravel_session', 'Laravel', 'framework'],
  ['ASP\\.NET|__VIEWSTATE|__EVENTVALIDATION', 'ASP.NET', 'framework'],
  ['Spring Boot|Whitelabel Error Page', 'Spring Boot', 'framework'],
  ['jquery[./\\-](\\d+\\.\\d+\\.\\d+)', 'jQuery', 'library'],
  ['react\\.development|react\\.production|__REACT', 'React', 'library'],
  ['angular(?:\\.min)?\\.js|ng-version', 'Angular', 'library'],
  ['vue\\.(?:min\\.)?js|__vue__', 'Vue.js', 'library'],
  ['bootstrap(?:\\.min)?\\.(?:js|css)', 'Bootstrap', 'library'],
])

export const LANGUAGE_PATTERNS = Object.freeze([
  ['PHP', ['\\.php', 'x-powered-by: php', 'phpsessid']],
  ['Python', ['python|django|flask|wsgi', '\\.py']],
  ['Java', ['jsessionid|\\.jsp|\\.do\\b|java|tomcat']],
  ['Ruby', ['rack|passenger|_rails|\\.rb\\b']],
  ['Node.js', ['express|node\\.js|connect\\.']],
  ['.NET', ['asp\\.net|__viewstate|x-aspnet']],
])

export const LOGIN_KEYWORDS = Object.freeze(['/login', '/signin', '/auth', '/wp-login'])
export const EVIL_ORIGIN = 'https://evil.com'
export const EXTERNAL_SENTINEL = 'https://example.com/'
