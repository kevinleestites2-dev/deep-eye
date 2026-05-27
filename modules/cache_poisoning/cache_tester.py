"""
Web Cache Poisoning Tester

Tests for web cache poisoning vulnerabilities via unkeyed headers
and cache deception attacks.
"""

import time
import hashlib
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin

from utils.logger import get_logger

logger = get_logger(__name__)


class CachePoisoningTester:
    """Tests for web cache poisoning and cache deception vulnerabilities."""

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config

        # Unkeyed headers commonly used in cache poisoning
        self.poison_headers = [
            'X-Forwarded-Host',
            'X-Original-URL',
            'X-Rewrite-URL',
            'X-Forwarded-Scheme',
            'X-Forwarded-Proto',
            'X-Host',
            'X-Forwarded-Server',
            'X-HTTP-Method-Override',
            'X-Original-Host',
        ]

        # Cache deception suffixes
        self.deception_suffixes = [
            '/nonexistent.css',
            '/nonexistent.js',
            '/nonexistent.png',
            '/nonexistent.gif',
            '/style.css',
            '/logo.png',
        ]

        # Cache buster parameter name
        self.cache_buster_param = 'cb'

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """
        Run all cache poisoning tests against the target URL.

        Args:
            url: Target URL to test
            context: Optional context with additional scan info

        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        logger.info(f"Starting cache poisoning tests on {url}")

        vulnerabilities.extend(self._test_unkeyed_headers(url))
        vulnerabilities.extend(self._test_cache_deception(url))
        vulnerabilities.extend(self._test_header_injection(url))

        logger.info(f"Cache poisoning tests complete. Found {len(vulnerabilities)} issues.")
        return vulnerabilities

    def _generate_cache_buster(self) -> str:
        """Generate a unique cache buster value."""
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

    def _test_unkeyed_headers(self, url: str) -> List[Dict]:
        """Test for cache poisoning via unkeyed headers."""
        vulnerabilities = []

        for header in self.poison_headers:
            try:
                # First request: get baseline response
                cb = self._generate_cache_buster()
                baseline_url = f"{url}{'&' if '?' in url else '?'}{self.cache_buster_param}={cb}"
                baseline_response = self.http_client.get(baseline_url)
                if not baseline_response:
                    continue

                baseline_body = baseline_response.text

                # Second request: inject poison header with unique canary
                canary = f"evil-{self._generate_cache_buster()}.example.com"
                cb = self._generate_cache_buster()
                poison_url = f"{url}{'&' if '?' in url else '?'}{self.cache_buster_param}={cb}"
                poison_headers = {header: canary}
                poison_response = self.http_client.get(poison_url, headers=poison_headers)
                if not poison_response:
                    continue

                poison_body = poison_response.text

                # Check if canary appears in response (header reflected)
                if canary in poison_body:
                    # Third request: verify the poisoned response is cached
                    time.sleep(0.5)
                    verify_response = self.http_client.get(poison_url)
                    if verify_response and canary in verify_response.text:
                        vulnerabilities.append({
                            'type': 'cache_poisoning',
                            'severity': 'high',
                            'url': url,
                            'parameter': header,
                            'payload': f"{header}: {canary}",
                            'evidence': f"Injected value '{canary}' via {header} header "
                                        f"was reflected and cached in response",
                            'description': f"Web cache poisoning via unkeyed header '{header}'. "
                                           f"The server reflects the header value in the response "
                                           f"and the cache stores the poisoned response.",
                            'remediation': "Include the header in the cache key, or strip "
                                           "unrecognized headers before processing. Configure "
                                           "the cache to vary on relevant headers.",
                        })
                    else:
                        # Header reflected but not cached - lower severity
                        vulnerabilities.append({
                            'type': 'cache_poisoning',
                            'severity': 'medium',
                            'url': url,
                            'parameter': header,
                            'payload': f"{header}: {canary}",
                            'evidence': f"Injected value '{canary}' via {header} header "
                                        f"was reflected in response (not confirmed cached)",
                            'description': f"The server reflects the unkeyed header '{header}' "
                                           f"in its response. This may be exploitable for cache "
                                           f"poisoning if a caching layer is present.",
                            'remediation': "Strip or ignore unrecognized headers. Avoid "
                                           "reflecting header values in responses.",
                        })

            except Exception as e:
                logger.debug(f"Error testing header {header} on {url}: {e}")

        return vulnerabilities

    def _test_cache_deception(self, url: str) -> List[Dict]:
        """Test for web cache deception attacks."""
        vulnerabilities = []

        # Get baseline response
        baseline_response = self.http_client.get(url)
        if not baseline_response:
            return vulnerabilities

        baseline_body = baseline_response.text
        baseline_length = len(baseline_body)

        for suffix in self.deception_suffixes:
            try:
                # Append static file extension to the URL
                deception_url = url.rstrip('/') + suffix

                response = self.http_client.get(deception_url)
                if not response:
                    continue

                response_body = response.text

                # If the response with static suffix returns similar content
                # as the original page, it may be vulnerable to cache deception
                if response.status_code == 200 and len(response_body) > 0:
                    # Check similarity - if the deception URL returns the same
                    # dynamic content as the original URL
                    similarity = self._calculate_similarity(baseline_body, response_body)

                    if similarity > 0.8 and baseline_length > 100:
                        # Check cache headers to see if response would be cached
                        cache_headers = self._get_cache_indicators(response)

                        if cache_headers:
                            vulnerabilities.append({
                                'type': 'cache_deception',
                                'severity': 'high',
                                'url': url,
                                'parameter': 'path',
                                'payload': deception_url,
                                'evidence': f"URL '{deception_url}' returns dynamic content "
                                            f"(similarity: {similarity:.0%}) with cache indicators: "
                                            f"{cache_headers}",
                                'description': "Web cache deception vulnerability. Appending a "
                                               "static file extension to a dynamic URL causes the "
                                               "cache to store sensitive dynamic content as if it "
                                               "were a static resource.",
                                'remediation': "Configure the cache to respect the origin "
                                               "server's caching directives. Use Cache-Control: "
                                               "no-store for dynamic/authenticated pages. "
                                               "Implement path-based cache rules carefully.",
                            })
                            break  # One finding is sufficient

            except Exception as e:
                logger.debug(f"Error testing cache deception with {suffix} on {url}: {e}")

        return vulnerabilities

    def _test_header_injection(self, url: str) -> List[Dict]:
        """Test for cache poisoning via multiple host headers or port injection."""
        vulnerabilities = []

        try:
            parsed = urlparse(url)
            host = parsed.hostname

            # Test X-Forwarded-Port injection
            cb = self._generate_cache_buster()
            test_url = f"{url}{'&' if '?' in url else '?'}{self.cache_buster_param}={cb}"
            response = self.http_client.get(
                test_url,
                headers={'X-Forwarded-Port': '1337'}
            )
            if response and ':1337' in response.text:
                vulnerabilities.append({
                    'type': 'cache_poisoning',
                    'severity': 'medium',
                    'url': url,
                    'parameter': 'X-Forwarded-Port',
                    'payload': 'X-Forwarded-Port: 1337',
                    'evidence': "Port value '1337' from X-Forwarded-Port header "
                                "reflected in response body",
                    'description': "The server reflects the X-Forwarded-Port header "
                                   "value in its response, which may enable cache "
                                   "poisoning if the header is not part of the cache key.",
                    'remediation': "Do not reflect X-Forwarded-Port in responses, or "
                                   "include it in the cache key.",
                })

        except Exception as e:
            logger.debug(f"Error testing header injection on {url}: {e}")

        return vulnerabilities

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate rough similarity ratio between two texts."""
        if not text1 or not text2:
            return 0.0
        len1, len2 = len(text1), len(text2)
        if len1 == 0 and len2 == 0:
            return 1.0
        max_len = max(len1, len2)
        diff = abs(len1 - len2)
        # Simple length-based similarity as a fast heuristic
        length_similarity = 1.0 - (diff / max_len)

        # Check for shared content at the start
        common_prefix = 0
        check_len = min(len1, len2, 500)
        for i in range(check_len):
            if text1[i] == text2[i]:
                common_prefix += 1
        prefix_similarity = common_prefix / check_len if check_len > 0 else 0

        return (length_similarity + prefix_similarity) / 2

    def _get_cache_indicators(self, response) -> str:
        """Check response headers for caching indicators."""
        indicators = []
        headers = response.headers

        if 'X-Cache' in headers:
            indicators.append(f"X-Cache: {headers['X-Cache']}")
        if 'CF-Cache-Status' in headers:
            indicators.append(f"CF-Cache-Status: {headers['CF-Cache-Status']}")
        if 'Age' in headers:
            indicators.append(f"Age: {headers['Age']}")
        if 'X-Varnish' in headers:
            indicators.append("X-Varnish present")
        if 'Via' in headers:
            indicators.append(f"Via: {headers['Via']}")

        cache_control = headers.get('Cache-Control', '')
        if 'public' in cache_control or 'max-age' in cache_control:
            if 'no-store' not in cache_control and 'private' not in cache_control:
                indicators.append(f"Cache-Control: {cache_control}")

        return ', '.join(indicators) if indicators else ''
