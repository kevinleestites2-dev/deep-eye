"""
Directory Bruteforce Scanner
Discovers hidden files and directories via wordlist-based probing
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from utils.logger import get_logger

logger = get_logger(__name__)


class DirectoryBruteforcer:
    """Bruteforce common directories and files."""

    DEFAULT_WORDLIST = [
        '/admin', '/administrator', '/admin/login', '/login', '/dashboard',
        '/api', '/api/v1', '/api/v2', '/api/docs', '/api/swagger',
        '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger.json',
        '/graphql', '/graphiql', '/playground',
        '/.git', '/.git/config', '/.git/HEAD', '/.gitignore',
        '/.env', '/.env.local', '/.env.production', '/.env.backup',
        '/.htaccess', '/.htpasswd', '/.DS_Store',
        '/wp-admin', '/wp-login.php', '/wp-config.php', '/wp-content',
        '/phpmyadmin', '/pma', '/adminer', '/adminer.php',
        '/phpinfo.php', '/info.php', '/test.php',
        '/server-status', '/server-info', '/.well-known',
        '/actuator', '/actuator/health', '/actuator/env', '/actuator/beans',
        '/console', '/debug', '/trace', '/metrics', '/health',
        '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/security.txt',
        '/backup', '/backup.zip', '/backup.tar.gz', '/backup.sql',
        '/db.sql', '/dump.sql', '/database.sql',
        '/config.php', '/config.yml', '/config.json', '/config.xml',
        '/package.json', '/composer.json', '/Gemfile', '/requirements.txt',
        '/.dockerenv', '/Dockerfile', '/docker-compose.yml',
        '/.aws/credentials', '/.ssh/id_rsa',
        '/web.config', '/elmah.axd', '/error_log', '/access.log',
        '/tmp', '/temp', '/upload', '/uploads', '/files', '/media',
        '/cgi-bin', '/cgi-bin/test', '/bin', '/includes',
        '/old', '/new', '/test', '/dev', '/staging', '/beta',
        '/install', '/setup', '/config', '/conf',
        '/status', '/monitor', '/stats', '/info',
        '/node_modules', '/vendor', '/bower_components',
        '/xmlrpc.php', '/readme.html', '/license.txt', '/changelog.txt',
        '/.svn', '/.svn/entries', '/.hg', '/.bzr',
        '/WEB-INF/web.xml', '/META-INF/MANIFEST.MF',
        '/solr', '/jenkins', '/manager', '/jmx-console',
        '/invoker/JMXInvokerServlet', '/web-console',
        '/telescope', '/horizon', '/nova', '/pulse',
        '/graphql/console', '/_debug', '/__debug__',
        '/spring', '/spring/health', '/env', '/configprops',
        '/trace.axd', '/errorlog.txt',
    ]

    SEVERITY_MAP = {
        '/.git': 'critical', '/.git/config': 'critical', '/.git/HEAD': 'critical',
        '/.env': 'critical', '/.env.local': 'critical', '/.env.production': 'critical',
        '/.aws/credentials': 'critical', '/.ssh/id_rsa': 'critical',
        '/backup.sql': 'critical', '/db.sql': 'critical', '/dump.sql': 'critical',
        '/wp-config.php': 'critical', '/web.config': 'high',
        '/actuator/env': 'high', '/actuator/beans': 'high',
        '/phpinfo.php': 'high', '/server-status': 'high',
        '/admin': 'high', '/phpmyadmin': 'high', '/console': 'high',
        '/swagger': 'medium', '/graphql': 'medium', '/api/docs': 'medium',
        '/robots.txt': 'info', '/sitemap.xml': 'info', '/security.txt': 'info',
    }

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config
        dirb_config = config.get('directory_bruteforce', {})
        self.max_workers = dirb_config.get('threads', 10)
        self.wordlist = self.DEFAULT_WORDLIST

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """Scan for hidden directories and files."""
        vulnerabilities = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        logger.info(f"[DirBrute] Scanning {base_url} with {len(self.wordlist)} paths")

        def check_path(path):
            target = urljoin(base_url, path)
            try:
                response = self.http_client.get(target)
                if not response:
                    return None
                if response.status_code in (200, 201, 301, 302, 307, 401, 403):
                    return (path, response.status_code, len(response.text))
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = executor.map(check_path, self.wordlist)

        for result in results:
            if result:
                path, status, size = result
                severity = self.SEVERITY_MAP.get(path, 'medium' if status in (200, 301) else 'low')
                target_url = urljoin(base_url, path)

                vulnerabilities.append({
                    'type': 'Directory/File Discovery',
                    'severity': severity,
                    'url': target_url,
                    'parameter': 'path',
                    'payload': path,
                    'evidence': f'HTTP {status} (size: {size} bytes)',
                    'description': f'Hidden path discovered: {path} (status {status})',
                    'remediation': 'Remove unnecessary files from production. Restrict access to sensitive paths. Configure web server to deny access to dotfiles and backups.'
                })

        logger.info(f"[DirBrute] Found {len(vulnerabilities)} paths on {base_url}")
        return vulnerabilities
