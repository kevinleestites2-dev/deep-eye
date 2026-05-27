"""
OAuth Security Tester Module for Deep Eye.

Tests for OAuth 2.0 implementation vulnerabilities including redirect_uri manipulation,
missing state parameter, scope escalation, and token leakage.
"""

from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.logger import get_logger

logger = get_logger(__name__)


class OAuthTester:
    """Tests for OAuth 2.0 security vulnerabilities."""

    OAUTH_ENDPOINT_PATTERNS = [
        "/authorize",
        "/oauth/authorize",
        "/oauth2/authorize",
        "/auth/authorize",
        "/login/oauth",
        "/oauth/token",
        "/oauth2/token",
        "/callback",
        "/oauth/callback",
        "/auth/callback",
    ]

    REDIRECT_URI_BYPASSES = [
        "https://evil.com",
        "https://evil.com@legitimate.com",
        "https://legitimate.com.evil.com",
        "https://legitimate.com%40evil.com",
        "https://legitimate.com/.evil.com",
        "https://legitimate.com%2F.evil.com",
        "http://localhost",
        "https://legitimate.com/../evil.com",
        "https://legitimate.com/callback?next=https://evil.com",
        "https://legitimate.com/callback#@evil.com",
    ]

    ESCALATION_SCOPES = [
        "admin",
        "write",
        "read write",
        "openid profile email admin",
        "user:admin",
        "repo",
        "all",
        "root",
        "superuser",
    ]

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config
        self.timeout = config.get("scanner", {}).get("timeout", 10)

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """
        Scan a URL for OAuth security vulnerabilities.

        Args:
            url: Target URL to test.
            context: Optional context with OAuth endpoint info.

        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities = []
        context = context or {}

        logger.info(f"[OAuth] Testing: {url}")

        # Detect OAuth endpoints
        oauth_endpoints = self._detect_oauth_endpoints(url, context)

        for endpoint in oauth_endpoints:
            # Test redirect_uri manipulation
            vulns = self._test_redirect_uri(endpoint)
            vulnerabilities.extend(vulns)

            # Test missing state parameter
            vulns = self._test_missing_state(endpoint)
            vulnerabilities.extend(vulns)

            # Test scope escalation
            vulns = self._test_scope_escalation(endpoint)
            vulnerabilities.extend(vulns)

        # Test token leakage in URL
        vulns = self._test_token_leakage(url)
        vulnerabilities.extend(vulns)

        logger.info(f"[OAuth] Found {len(vulnerabilities)} potential issues on {url}")
        return vulnerabilities

    def _detect_oauth_endpoints(self, url: str, context: Dict) -> List[str]:
        """Detect OAuth-related endpoints from the target URL."""
        endpoints = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Check if the URL itself is an OAuth endpoint
        for pattern in self.OAUTH_ENDPOINT_PATTERNS:
            if pattern in parsed.path:
                endpoints.append(url)
                break

        # Probe common OAuth paths
        for pattern in self.OAUTH_ENDPOINT_PATTERNS:
            probe_url = f"{base_url}{pattern}"
            try:
                response = self.http_client.get(probe_url, timeout=self.timeout, allow_redirects=False)
                if response is not None and response.status_code in (200, 302, 400, 401):
                    endpoints.append(probe_url)
            except Exception:
                pass

        # Include endpoints from context
        if "oauth_endpoints" in context:
            endpoints.extend(context["oauth_endpoints"])

        return list(set(endpoints))

    def _test_redirect_uri(self, endpoint: str) -> List[Dict]:
        """Test redirect_uri parameter for open redirect vulnerabilities."""
        vulnerabilities = []
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)

        # Extract legitimate redirect_uri if present
        legit_redirect = None
        if "redirect_uri" in params:
            legit_redirect = params["redirect_uri"][0]

        for malicious_uri in self.REDIRECT_URI_BYPASSES:
            # If we know the legitimate domain, craft targeted bypasses
            if legit_redirect:
                legit_parsed = urlparse(legit_redirect)
                malicious_uri = malicious_uri.replace("legitimate.com", legit_parsed.netloc)

            test_url = self._inject_param(endpoint, "redirect_uri", malicious_uri)

            try:
                response = self.http_client.get(test_url, timeout=self.timeout, allow_redirects=False)
                if response is None:
                    continue

                # Check if the server accepted the malicious redirect_uri
                if response.status_code in (302, 301, 303, 307):
                    location = response.headers.get("Location", "")
                    if "evil.com" in location or malicious_uri in location:
                        vulnerabilities.append({
                            "type": "oauth_redirect_uri_manipulation",
                            "severity": "high",
                            "url": endpoint,
                            "parameter": "redirect_uri",
                            "payload": malicious_uri,
                            "evidence": f"Server redirected to attacker-controlled URI: {location}",
                            "description": (
                                "OAuth redirect_uri validation is insufficient. The authorization server "
                                "accepted a manipulated redirect_uri, allowing an attacker to steal "
                                "authorization codes or tokens via open redirect."
                            ),
                            "remediation": (
                                "Implement strict redirect_uri validation using exact string matching. "
                                "Do not allow partial matches, subdomain wildcards, or path traversal. "
                                "Pre-register all valid redirect URIs."
                            ),
                        })
                        return vulnerabilities  # One finding is enough

                # Server accepted without error (200) - may indicate weak validation
                if response.status_code == 200 and "error" not in response.text.lower():
                    vulnerabilities.append({
                        "type": "oauth_redirect_uri_manipulation",
                        "severity": "medium",
                        "url": endpoint,
                        "parameter": "redirect_uri",
                        "payload": malicious_uri,
                        "evidence": (
                            f"Server returned 200 without error for manipulated redirect_uri. "
                            f"Response length: {len(response.text)} bytes"
                        ),
                        "description": (
                            "OAuth endpoint accepted a potentially malicious redirect_uri without "
                            "returning an error. This may indicate weak URI validation."
                        ),
                        "remediation": (
                            "Validate redirect_uri against a strict allowlist of pre-registered URIs. "
                            "Return an error for any unrecognized redirect_uri values."
                        ),
                    })
                    return vulnerabilities

            except Exception as e:
                logger.debug(f"[OAuth] redirect_uri test error: {e}")

        return vulnerabilities

    def _test_missing_state(self, endpoint: str) -> List[Dict]:
        """Test if the OAuth flow works without a state parameter (CSRF protection)."""
        vulnerabilities = []

        # Remove state parameter if present
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)

        if "state" in params:
            del params["state"]

        # Build URL without state
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        # Also ensure required OAuth params are present
        if "response_type" not in params:
            params["response_type"] = ["code"]
        if "client_id" not in params:
            params["client_id"] = ["test_client"]

        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            response = self.http_client.get(test_url, timeout=self.timeout, allow_redirects=False)
            if response is None:
                return vulnerabilities

            # If the server proceeds without state, it's vulnerable to CSRF
            if response.status_code in (200, 302) and "state" not in response.text.lower():
                # Check if the response is a login page or redirect (not an error)
                if "error" not in response.text.lower()[:500]:
                    vulnerabilities.append({
                        "type": "oauth_missing_state",
                        "severity": "medium",
                        "url": endpoint,
                        "parameter": "state",
                        "payload": "OAuth request without state parameter",
                        "evidence": (
                            f"Server returned {response.status_code} without requiring state parameter. "
                            f"No error about missing state in response."
                        ),
                        "description": (
                            "The OAuth authorization endpoint does not enforce the state parameter. "
                            "This makes the OAuth flow vulnerable to CSRF attacks, where an attacker "
                            "can force a victim to authorize the attacker's account."
                        ),
                        "remediation": (
                            "Require and validate the state parameter on all OAuth authorization requests. "
                            "Generate a cryptographically random state value tied to the user's session. "
                            "Reject requests with missing or invalid state values."
                        ),
                    })

        except Exception as e:
            logger.debug(f"[OAuth] state test error: {e}")

        return vulnerabilities

    def _test_scope_escalation(self, endpoint: str) -> List[Dict]:
        """Test if additional scopes can be requested beyond what's authorized."""
        vulnerabilities = []
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)

        original_scope = params.get("scope", [""])[0]

        for escalated_scope in self.ESCALATION_SCOPES:
            params["scope"] = [escalated_scope]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                response = self.http_client.get(test_url, timeout=self.timeout, allow_redirects=False)
                if response is None:
                    continue

                # If server accepts elevated scope without error
                if response.status_code in (200, 302):
                    response_text = response.text.lower()
                    if "invalid_scope" not in response_text and "error" not in response_text[:200]:
                        vulnerabilities.append({
                            "type": "oauth_scope_escalation",
                            "severity": "high",
                            "url": endpoint,
                            "parameter": "scope",
                            "payload": escalated_scope,
                            "evidence": (
                                f"Server accepted elevated scope '{escalated_scope}' "
                                f"(original: '{original_scope}'). Status: {response.status_code}"
                            ),
                            "description": (
                                "OAuth scope escalation possible. The authorization server accepted "
                                "a higher-privilege scope than originally granted, potentially allowing "
                                "unauthorized access to protected resources."
                            ),
                            "remediation": (
                                "Validate requested scopes against the client's registered allowed scopes. "
                                "Reject requests for scopes not pre-approved for the client application. "
                                "Implement scope consent screens for elevated permissions."
                            ),
                        })
                        return vulnerabilities  # One finding is enough

            except Exception as e:
                logger.debug(f"[OAuth] scope test error: {e}")

        return vulnerabilities

    def _test_token_leakage(self, url: str) -> List[Dict]:
        """Check for token leakage in URL fragments or query parameters."""
        vulnerabilities = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Check if tokens are exposed in query parameters
        sensitive_params = ["access_token", "token", "id_token", "refresh_token", "code"]
        leaked_params = [p for p in sensitive_params if p in params]

        if leaked_params:
            vulnerabilities.append({
                "type": "oauth_token_leakage",
                "severity": "high",
                "url": url,
                "parameter": ", ".join(leaked_params),
                "payload": "Token exposed in URL query parameters",
                "evidence": (
                    f"Sensitive OAuth parameters found in URL: {leaked_params}. "
                    f"These may be logged in server logs, browser history, and referrer headers."
                ),
                "description": (
                    "OAuth tokens or authorization codes are exposed in URL query parameters. "
                    "This leads to token leakage via browser history, server logs, referrer headers, "
                    "and proxy logs."
                ),
                "remediation": (
                    "Use response_type=code with PKCE instead of implicit flow. "
                    "Transmit tokens in response body or HTTP-only cookies, never in URLs. "
                    "Implement short-lived tokens and token binding."
                ),
            })

        # Check if the endpoint uses implicit flow (response_type=token)
        if params.get("response_type", [""])[0] == "token":
            vulnerabilities.append({
                "type": "oauth_implicit_flow",
                "severity": "medium",
                "url": url,
                "parameter": "response_type",
                "payload": "response_type=token (implicit flow)",
                "evidence": "OAuth implicit flow detected. Tokens returned in URL fragment.",
                "description": (
                    "The OAuth endpoint uses the implicit flow (response_type=token), which is "
                    "deprecated due to token exposure in URL fragments and susceptibility to "
                    "token interception attacks."
                ),
                "remediation": (
                    "Migrate to Authorization Code flow with PKCE (response_type=code). "
                    "The implicit flow is deprecated in OAuth 2.1 due to security concerns."
                ),
            })

        return vulnerabilities

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject or replace a query parameter in a URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
