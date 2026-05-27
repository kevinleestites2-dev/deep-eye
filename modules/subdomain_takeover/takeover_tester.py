"""
Subdomain Takeover Tester

Checks for dangling CNAME records pointing to unclaimed services.
"""

from typing import Dict, List, Optional
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger(__name__)

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not installed. Subdomain takeover checks will be limited.")


class SubdomainTakeoverTester:
    """Tests for subdomain takeover vulnerabilities via dangling CNAMEs."""

    # Known fingerprints for vulnerable services
    FINGERPRINTS = {
        'github': {
            'cnames': ['.github.io'],
            'fingerprint': "There isn't a GitHub Pages site here",
            'service': 'GitHub Pages',
        },
        'heroku': {
            'cnames': ['.herokuapp.com', '.herokussl.com'],
            'fingerprint': 'No such app',
            'service': 'Heroku',
        },
        'aws_s3': {
            'cnames': ['.s3.amazonaws.com', '.s3-website'],
            'fingerprint': 'NoSuchBucket',
            'service': 'AWS S3',
        },
        'azure': {
            'cnames': ['.azurewebsites.net', '.cloudapp.net', '.azure-api.net',
                       '.azurefd.net', '.blob.core.windows.net', '.trafficmanager.net'],
            'fingerprint': 'NXDOMAIN',
            'service': 'Microsoft Azure',
        },
        'shopify': {
            'cnames': ['.myshopify.com'],
            'fingerprint': 'Sorry, this shop is currently unavailable',
            'service': 'Shopify',
        },
        'fastly': {
            'cnames': ['.fastly.net'],
            'fingerprint': 'Fastly error: unknown domain',
            'service': 'Fastly',
        },
        'pantheon': {
            'cnames': ['.pantheonsite.io'],
            'fingerprint': '404 error unknown site',
            'service': 'Pantheon',
        },
        'tumblr': {
            'cnames': ['.tumblr.com'],
            'fingerprint': "There's nothing here.",
            'service': 'Tumblr',
        },
        'wordpress': {
            'cnames': ['.wordpress.com'],
            'fingerprint': "Do you want to register",
            'service': 'WordPress.com',
        },
        'ghost': {
            'cnames': ['.ghost.io'],
            'fingerprint': "The thing you were looking for is no longer here",
            'service': 'Ghost',
        },
        'surge': {
            'cnames': ['.surge.sh'],
            'fingerprint': 'project not found',
            'service': 'Surge.sh',
        },
        'bitbucket': {
            'cnames': ['.bitbucket.io'],
            'fingerprint': 'Repository not found',
            'service': 'Bitbucket',
        },
        'zendesk': {
            'cnames': ['.zendesk.com'],
            'fingerprint': 'Help Center Closed',
            'service': 'Zendesk',
        },
        'unbounce': {
            'cnames': ['.unbouncepages.com'],
            'fingerprint': 'The requested URL was not found on this server',
            'service': 'Unbounce',
        },
        'cargo': {
            'cnames': ['.cargocollective.com'],
            'fingerprint': '404 Not Found',
            'service': 'Cargo Collective',
        },
    }

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config
        self.timeout = config.get('scanner', {}).get('timeout', 5)

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """
        Run subdomain takeover tests against the target URL.

        Args:
            url: Target URL to test
            context: Optional context (may contain 'subdomains' list)

        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        logger.info(f"Starting subdomain takeover tests for {url}")

        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return vulnerabilities

        # Test the main hostname
        vuln = self._check_takeover(hostname)
        if vuln:
            vulnerabilities.append(vuln)

        # If context provides subdomains, test those too
        if context and 'subdomains' in context:
            for subdomain in context['subdomains']:
                vuln = self._check_takeover(subdomain)
                if vuln:
                    vulnerabilities.append(vuln)

        logger.info(f"Subdomain takeover tests complete. Found {len(vulnerabilities)} issues.")
        return vulnerabilities

    def _check_takeover(self, hostname: str) -> Optional[Dict]:
        """Check a single hostname for subdomain takeover vulnerability."""
        if not DNS_AVAILABLE:
            return self._check_takeover_http_only(hostname)

        try:
            # Resolve CNAME records
            cname_target = self._get_cname(hostname)
            if not cname_target:
                return None

            logger.debug(f"{hostname} has CNAME -> {cname_target}")

            # Check if CNAME points to a known vulnerable service
            for service_key, service_info in self.FINGERPRINTS.items():
                for cname_pattern in service_info['cnames']:
                    if cname_pattern in cname_target.lower():
                        # Check if the CNAME target resolves (NXDOMAIN = dangling)
                        if service_info['fingerprint'] == 'NXDOMAIN':
                            if self._is_nxdomain(cname_target):
                                return {
                                    'type': 'subdomain_takeover',
                                    'severity': 'high',
                                    'url': f"https://{hostname}",
                                    'parameter': 'CNAME',
                                    'payload': f"{hostname} -> {cname_target}",
                                    'evidence': f"CNAME points to {cname_target} which "
                                                f"returns NXDOMAIN (unclaimed {service_info['service']})",
                                    'description': f"Subdomain {hostname} has a dangling CNAME "
                                                   f"record pointing to an unclaimed "
                                                   f"{service_info['service']} resource. An attacker "
                                                   f"can claim this resource and serve content "
                                                   f"on the victim's subdomain.",
                                    'remediation': "Remove the dangling CNAME record or claim "
                                                   "the resource on the target service.",
                                }
                        else:
                            # Check HTTP response for fingerprint
                            vuln = self._check_http_fingerprint(
                                hostname, cname_target, service_info
                            )
                            if vuln:
                                return vuln

        except Exception as e:
            logger.debug(f"Error checking takeover for {hostname}: {e}")

        return None

    def _get_cname(self, hostname: str) -> Optional[str]:
        """Resolve CNAME record for a hostname."""
        try:
            answers = dns.resolver.resolve(hostname, 'CNAME')
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.exception.DNSException):
            pass
        return None

    def _is_nxdomain(self, hostname: str) -> bool:
        """Check if a hostname returns NXDOMAIN."""
        try:
            dns.resolver.resolve(hostname, 'A')
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except dns.exception.DNSException:
            return False

    def _check_http_fingerprint(self, hostname: str, cname_target: str,
                                service_info: Dict) -> Optional[Dict]:
        """Check HTTP response for takeover fingerprint."""
        for scheme in ['https', 'http']:
            try:
                response = self.http_client.get(f"{scheme}://{hostname}")
                if response and service_info['fingerprint'] in response.text:
                    return {
                        'type': 'subdomain_takeover',
                        'severity': 'high',
                        'url': f"{scheme}://{hostname}",
                        'parameter': 'CNAME',
                        'payload': f"{hostname} -> {cname_target}",
                        'evidence': f"Response contains fingerprint: "
                                    f"'{service_info['fingerprint']}' "
                                    f"(Service: {service_info['service']})",
                        'description': f"Subdomain {hostname} has a CNAME pointing to "
                                       f"{cname_target} ({service_info['service']}) which "
                                       f"appears to be unclaimed. An attacker can register "
                                       f"this resource and serve arbitrary content.",
                        'remediation': "Remove the dangling CNAME record or reclaim the "
                                       "resource on the target service.",
                    }
            except Exception:
                continue

        return None

    def _check_takeover_http_only(self, hostname: str) -> Optional[Dict]:
        """Fallback: check for takeover indicators via HTTP when DNS library unavailable."""
        for scheme in ['https', 'http']:
            try:
                response = self.http_client.get(f"{scheme}://{hostname}")
                if not response:
                    continue

                body = response.text
                for service_key, service_info in self.FINGERPRINTS.items():
                    if service_info['fingerprint'] == 'NXDOMAIN':
                        continue
                    if service_info['fingerprint'] in body:
                        return {
                            'type': 'subdomain_takeover',
                            'severity': 'medium',
                            'url': f"{scheme}://{hostname}",
                            'parameter': 'HTTP response',
                            'payload': hostname,
                            'evidence': f"Response contains takeover fingerprint: "
                                        f"'{service_info['fingerprint']}' "
                                        f"(Service: {service_info['service']})",
                            'description': f"Subdomain {hostname} shows indicators of a "
                                           f"potential takeover via {service_info['service']}. "
                                           f"DNS verification unavailable (install dnspython).",
                            'remediation': "Verify CNAME records and remove dangling entries. "
                                           "Install dnspython for full DNS-based verification.",
                        }
            except Exception:
                continue

        return None
