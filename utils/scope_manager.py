"""
Scope Manager
Controls which URLs/hosts are in-scope for scanning
"""

import re
import fnmatch
from typing import Dict, List
from urllib.parse import urlparse
from utils.logger import get_logger

logger = get_logger(__name__)


class ScopeManager:
    """Manage scan scope - allowed hosts, excluded paths, port restrictions."""

    def __init__(self, config: Dict):
        scope_config = config.get('scope', {})
        self.enabled = scope_config.get('enabled', False)
        self.allowed_hosts = scope_config.get('allowed_hosts', [])
        self.excluded_paths = [re.compile(p) for p in scope_config.get('excluded_paths', [])]
        self.allowed_ports = scope_config.get('allowed_ports', [80, 443])

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is within configured scope."""
        if not self.enabled:
            return True

        parsed = urlparse(url)
        host = parsed.hostname or ''
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        path = parsed.path or '/'

        # Check host
        if self.allowed_hosts:
            host_match = False
            for pattern in self.allowed_hosts:
                if fnmatch.fnmatch(host, pattern):
                    host_match = True
                    break
            if not host_match:
                logger.debug(f"[Scope] Host {host} not in allowed list")
                return False

        # Check port
        if self.allowed_ports and port not in self.allowed_ports:
            logger.debug(f"[Scope] Port {port} not allowed")
            return False

        # Check excluded paths
        for pattern in self.excluded_paths:
            if pattern.search(path):
                logger.debug(f"[Scope] Path {path} excluded by pattern")
                return False

        return True
