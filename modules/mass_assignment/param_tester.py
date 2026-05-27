"""
Mass Assignment and HTTP Parameter Pollution Tester Module for Deep Eye.

Tests for mass assignment vulnerabilities and HTTP parameter pollution.
"""

import json
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.logger import get_logger

logger = get_logger(__name__)


class MassAssignmentTester:
    """Tests for mass assignment and HTTP parameter pollution vulnerabilities."""

    # Common privileged fields that should not be user-controllable
    PRIVILEGED_FIELDS = [
        ("role", "admin"),
        ("is_admin", "true"),
        ("isAdmin", "true"),
        ("admin", "true"),
        ("verified", "true"),
        ("is_verified", "true"),
        ("email_verified", "true"),
        ("active", "true"),
        ("is_active", "true"),
        ("permissions", "admin"),
        ("user_type", "admin"),
        ("userType", "administrator"),
        ("privilege", "superuser"),
        ("level", "9999"),
        ("credits", "99999"),
        ("balance", "99999"),
        ("is_staff", "true"),
        ("is_superuser", "true"),
        ("approved", "true"),
        ("disabled", "false"),
        ("banned", "false"),
    ]

    # Fields for JSON body mass assignment
    JSON_PRIVILEGED_PAYLOADS = [
        {"role": "admin", "is_admin": True},
        {"verified": True, "email_verified": True},
        {"permissions": ["admin", "write", "delete"]},
        {"user_type": "administrator", "level": 9999},
        {"balance": 99999, "credits": 99999},
        {"is_staff": True, "is_superuser": True},
    ]

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config
        self.timeout = config.get("scanner", {}).get("timeout", 10)

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """
        Scan a URL for mass assignment and parameter pollution vulnerabilities.

        Args:
            url: Target URL to test.
            context: Optional context with form fields, method info.

        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities = []
        context = context or {}

        logger.info(f"[MassAssignment] Testing: {url}")

        # Test HTTP Parameter Pollution
        vulns = self._test_parameter_pollution(url)
        vulnerabilities.extend(vulns)

        # Test mass assignment via query string
        vulns = self._test_query_mass_assignment(url)
        vulnerabilities.extend(vulns)

        # Test mass assignment via JSON body
        vulns = self._test_json_mass_assignment(url, context)
        vulnerabilities.extend(vulns)

        # Test mass assignment via form data
        vulns = self._test_form_mass_assignment(url, context)
        vulnerabilities.extend(vulns)

        logger.info(f"[MassAssignment] Found {len(vulnerabilities)} potential issues on {url}")
        return vulnerabilities

    def _test_parameter_pollution(self, url: str) -> List[Dict]:
        """Test HTTP Parameter Pollution with duplicate parameters."""
        vulnerabilities = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulnerabilities

        for param_name, values in params.items():
            original_value = values[0] if values else ""

            # Inject duplicate parameter with different value
            polluted_values = [
                (original_value, "injected_hpp"),
                ("injected_hpp", original_value),
            ]

            for val1, val2 in polluted_values:
                # Manually construct query with duplicate params
                polluted_query = f"{param_name}={val1}&{param_name}={val2}"
                # Preserve other params
                other_params = {k: v[0] for k, v in params.items() if k != param_name}
                if other_params:
                    polluted_query += "&" + urlencode(other_params)

                test_url = urlunparse(parsed._replace(query=polluted_query))

                try:
                    response = self.http_client.get(test_url, timeout=self.timeout)
                    if response is None:
                        continue

                    # Check if the injected value appears in response
                    if "injected_hpp" in response.text:
                        vulnerabilities.append({
                            "type": "http_parameter_pollution",
                            "severity": "medium",
                            "url": url,
                            "parameter": param_name,
                            "payload": f"{param_name}={val1}&{param_name}={val2}",
                            "evidence": (
                                f"Injected HPP value 'injected_hpp' reflected in response. "
                                f"Server processes duplicate parameters, potentially bypassing "
                                f"input validation or WAF rules."
                            ),
                            "description": (
                                f"HTTP Parameter Pollution detected on parameter '{param_name}'. "
                                f"The application processes duplicate parameters, which can be exploited "
                                f"to bypass security controls, WAFs, or input validation."
                            ),
                            "remediation": (
                                "Explicitly handle duplicate parameters by accepting only the first "
                                "or last occurrence. Implement server-side validation that accounts for "
                                "parameter arrays. Normalize parameters before processing."
                            ),
                        })
                        break

                except Exception as e:
                    logger.debug(f"[MassAssignment] HPP test error: {e}")

        return vulnerabilities

    def _test_query_mass_assignment(self, url: str) -> List[Dict]:
        """Test mass assignment by injecting privileged fields in query string."""
        vulnerabilities = []

        # Get baseline
        baseline_response = self._get_baseline(url)
        if baseline_response is None:
            return vulnerabilities

        for field_name, field_value in self.PRIVILEGED_FIELDS:
            test_url = self._inject_param(url, field_name, field_value)

            try:
                response = self.http_client.get(test_url, timeout=self.timeout)
                if response is None:
                    continue

                evidence = self._detect_mass_assignment(response, baseline_response, field_name, field_value)
                if evidence:
                    vulnerabilities.append({
                        "type": "mass_assignment",
                        "severity": "high",
                        "url": url,
                        "parameter": field_name,
                        "payload": f"{field_name}={field_value} (query string)",
                        "evidence": evidence,
                        "description": (
                            f"Mass assignment vulnerability detected. Injecting '{field_name}={field_value}' "
                            f"in the query string affected the response, indicating the server binds "
                            f"request parameters directly to internal objects without filtering."
                        ),
                        "remediation": (
                            "Implement allowlists for bindable parameters. Use DTOs (Data Transfer Objects) "
                            "that only include user-modifiable fields. Never bind request parameters "
                            "directly to database models. Apply role-based field access control."
                        ),
                    })
                    break  # One finding is enough for query string

            except Exception as e:
                logger.debug(f"[MassAssignment] Query test error: {e}")

        return vulnerabilities

    def _test_json_mass_assignment(self, url: str, context: Dict) -> List[Dict]:
        """Test mass assignment via JSON body with privileged fields."""
        vulnerabilities = []

        # Get baseline POST response
        baseline_body = context.get("body", {"test": "value"})
        baseline_response = self._post_baseline(url, baseline_body)
        if baseline_response is None:
            return vulnerabilities

        for payload in self.JSON_PRIVILEGED_PAYLOADS:
            # Merge privileged fields with legitimate body
            injected_body = {**baseline_body, **payload}

            try:
                response = self.http_client.post(
                    url, json=injected_body, timeout=self.timeout
                )
                if response is None:
                    continue

                # Check if any privileged field value appears in response
                injected_fields = []
                for field, value in payload.items():
                    str_value = json.dumps(value) if isinstance(value, (list, dict, bool)) else str(value)
                    if str_value.lower() in response.text.lower():
                        injected_fields.append(f"{field}={str_value}")

                if injected_fields:
                    vulnerabilities.append({
                        "type": "mass_assignment",
                        "severity": "high",
                        "url": url,
                        "parameter": ", ".join(payload.keys()),
                        "payload": json.dumps(payload),
                        "evidence": (
                            f"Injected privileged fields reflected in response: {', '.join(injected_fields)}. "
                            f"Status: {response.status_code}"
                        ),
                        "description": (
                            "Mass assignment vulnerability via JSON body. The server accepted and processed "
                            "privileged fields that should not be user-controllable, potentially allowing "
                            "privilege escalation or unauthorized state modification."
                        ),
                        "remediation": (
                            "Use explicit allowlists for accepted JSON fields. Implement separate DTOs "
                            "for user input that exclude privileged attributes. Apply schema validation "
                            "to reject unexpected fields in request bodies."
                        ),
                    })
                    return vulnerabilities  # One finding is enough

            except Exception as e:
                logger.debug(f"[MassAssignment] JSON test error: {e}")

        return vulnerabilities

    def _test_form_mass_assignment(self, url: str, context: Dict) -> List[Dict]:
        """Test mass assignment via form-encoded POST data."""
        vulnerabilities = []

        for field_name, field_value in self.PRIVILEGED_FIELDS[:10]:  # Test top 10
            form_data = {field_name: field_value}

            # Add any known legitimate fields from context
            if "form_fields" in context:
                for f in context["form_fields"]:
                    form_data[f] = "test"

            try:
                response = self.http_client.post(url, data=form_data, timeout=self.timeout)
                if response is None:
                    continue

                # Check for acceptance indicators
                if response.status_code in (200, 201, 204):
                    if field_value in response.text or field_name in response.text:
                        vulnerabilities.append({
                            "type": "mass_assignment",
                            "severity": "high",
                            "url": url,
                            "parameter": field_name,
                            "payload": f"{field_name}={field_value} (form data)",
                            "evidence": (
                                f"Privileged field '{field_name}' accepted via form POST. "
                                f"Value or field name reflected in {response.status_code} response."
                            ),
                            "description": (
                                f"Mass assignment via form data. The field '{field_name}' was accepted "
                                f"by the server, potentially allowing privilege escalation."
                            ),
                            "remediation": (
                                "Filter incoming form fields against an allowlist. Use strong typing "
                                "and explicit field mapping. Never auto-bind form data to models."
                            ),
                        })
                        return vulnerabilities

            except Exception as e:
                logger.debug(f"[MassAssignment] Form test error: {e}")

        return vulnerabilities

    def _get_baseline(self, url: str) -> Optional[Dict]:
        """Get baseline GET response."""
        try:
            response = self.http_client.get(url, timeout=self.timeout)
            if response is None:
                return None
            return {
                "status_code": response.status_code,
                "content_length": len(response.text),
                "text": response.text,
            }
        except Exception:
            return None

    def _post_baseline(self, url: str, body: Dict) -> Optional[Dict]:
        """Get baseline POST response."""
        try:
            response = self.http_client.post(url, json=body, timeout=self.timeout)
            if response is None:
                return None
            return {
                "status_code": response.status_code,
                "content_length": len(response.text),
                "text": response.text,
            }
        except Exception:
            return None

    def _detect_mass_assignment(
        self, response, baseline: Dict, field_name: str, field_value: str
    ) -> Optional[str]:
        """Detect if mass assignment was successful."""
        indicators = []

        # Field value reflected in response
        if field_value.lower() in response.text.lower():
            indicators.append(f"Injected value '{field_value}' reflected in response")

        # Status code changed favorably
        if baseline["status_code"] in (401, 403) and response.status_code == 200:
            indicators.append(
                f"Status changed from {baseline['status_code']} to {response.status_code}"
            )

        # Significant content change
        current_length = len(response.text)
        if baseline["content_length"] > 0:
            diff = abs(current_length - baseline["content_length"]) / baseline["content_length"]
            if diff > 0.3:
                indicators.append(
                    f"Response size changed significantly: {baseline['content_length']} -> {current_length}"
                )

        if indicators:
            return "; ".join(indicators)
        return None

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject a parameter into the URL query string."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
