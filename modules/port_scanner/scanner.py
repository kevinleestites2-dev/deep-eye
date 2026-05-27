"""
Port Scanner
TCP connect scan with banner grabbing
"""

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
from urllib.parse import urlparse
from utils.logger import get_logger

logger = get_logger(__name__)


class PortScanner:
    """TCP port scanner with banner grabbing."""

    DEFAULT_PORTS = [
        21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995,
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
        8888, 9200, 9300, 27017
    ]

    HIGH_RISK_PORTS = {
        6379: 'Redis (often no auth)',
        27017: 'MongoDB (often no auth)',
        9200: 'Elasticsearch (often no auth)',
        9300: 'Elasticsearch transport',
        11211: 'Memcached (no auth)',
        2375: 'Docker API (unencrypted)',
        5900: 'VNC',
    }

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config
        port_config = config.get('port_scanner', {})
        self.ports = port_config.get('ports', self.DEFAULT_PORTS)
        self.timeout = port_config.get('timeout', 2)
        self.max_workers = port_config.get('threads', 20)

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """Scan target host for open ports."""
        vulnerabilities = []
        parsed = urlparse(url)
        host = parsed.hostname

        if not host:
            return vulnerabilities

        logger.info(f"[PortScan] Scanning {host} ({len(self.ports)} ports)")

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    banner = self._grab_banner(sock)
                    sock.close()
                    return (port, banner)
                sock.close()
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = list(executor.map(scan_port, self.ports))

        for result in results:
            if result:
                port, banner = result
                severity = 'high' if port in self.HIGH_RISK_PORTS else 'info'
                service = self.HIGH_RISK_PORTS.get(port, self._guess_service(port))

                vulnerabilities.append({
                    'type': 'Open Port',
                    'severity': severity,
                    'url': f"{host}:{port}",
                    'parameter': 'TCP port',
                    'payload': str(port),
                    'evidence': f'Port {port} open. Banner: {banner or "N/A"}. Service: {service}',
                    'description': f'Open TCP port {port} ({service}) detected on {host}',
                    'remediation': 'Close unnecessary ports. Implement firewall rules. Ensure services require authentication.'
                })

        logger.info(f"[PortScan] Found {len(vulnerabilities)} open ports on {host}")
        return vulnerabilities

    def _grab_banner(self, sock) -> Optional[str]:
        """Attempt to grab service banner."""
        try:
            sock.send(b'\r\n')
            sock.settimeout(1)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200] if banner else None
        except Exception:
            return None

    def _guess_service(self, port: int) -> str:
        """Guess service name from port number."""
        services = {
            21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt',
        }
        return services.get(port, 'Unknown')
