"""
Secrets and Credentials Detector
Scans for leaked secrets, API keys, database credentials, etc.
"""

import re
import math
from typing import Dict, List, Set, Tuple
from collections import Counter
from utils.logger import get_logger

logger = get_logger(__name__)


class SecretsDetector:
    """Detect secrets and credentials in responses, headers, and JavaScript."""

    def __init__(self, config: Dict):
        """Initialize secrets detector."""
        self.config = config
        self.secrets_config = config.get('secrets_scanner', {})
        self.enabled = self.secrets_config.get('enabled', True)
        self.min_entropy = self.secrets_config.get('min_entropy', 4.5)
        self.check_entropy = self.secrets_config.get('check_entropy', True)

        # Whitelist for suppressing false positives
        whitelist_config = self.secrets_config.get('whitelist', {})
        self.whitelisted_emails = [e.lower() for e in whitelist_config.get('emails', [])]
        self.whitelisted_domains = [d.lower() for d in whitelist_config.get('domains', [])]

        # Initialize patterns
        self.patterns = self._initialize_patterns()

        # Track found secrets to avoid duplicates
        self.found_secrets: Set[str] = set()

    def _is_whitelisted(self, value: str) -> bool:
        """Check if a matched value contains a whitelisted email or domain."""
        value_lower = value.lower()
        # Check exact email matches
        for email in self.whitelisted_emails:
            if email in value_lower:
                return True
        # Check domain matches (any email @domain)
        for domain in self.whitelisted_domains:
            if f"@{domain}" in value_lower:
                return True
        return False

    def _initialize_patterns(self) -> Dict[str, Dict]:
        """Initialize regex patterns for various secret types."""
        return {
            # AWS Credentials
            'aws_access_key': {
                'pattern': r'(?:AWS|aws|Aws)?_?(?:ACCESS|access|Access)?_?(?:KEY|key|Key)?_?(?:ID|id|Id)?\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})["\']?',
                'severity': 'critical',
                'description': 'AWS Access Key ID',
                'example': 'AKIAIOSFODNN7EXAMPLE'
            },
            'aws_secret_key': {
                'pattern': r'(?:AWS|aws|Aws)?_?(?:SECRET|secret|Secret)?_?(?:ACCESS|access|Access)?_?(?:KEY|key|Key)?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
                'severity': 'critical',
                'description': 'AWS Secret Access Key',
                'example': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
            },
            'aws_session_token': {
                'pattern': r'(?:AWS|aws)?_?(?:SESSION|session)?_?(?:TOKEN|token)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?',
                'severity': 'high',
                'description': 'AWS Session Token'
            },

            # Google Cloud
            'gcp_api_key': {
                'pattern': r'AIza[0-9A-Za-z\-_]{35}',
                'severity': 'critical',
                'description': 'Google Cloud Platform API Key'
            },
            'gcp_service_account': {
                'pattern': r'"type":\s*"service_account"',
                'severity': 'critical',
                'description': 'GCP Service Account JSON',
                'context': True  # Need to extract entire JSON
            },

            # Azure
            'azure_storage_key': {
                'pattern': r'(?:DefaultEndpointsProtocol|AccountName|AccountKey)\s*=',
                'severity': 'critical',
                'description': 'Azure Storage Account Connection String'
            },

            # API Keys (Generic)
            'generic_api_key': {
                'pattern': r'(?i)(?:api|app|application)[-_]?key\s*[:=]\s*["\']?([a-z0-9]{32,})["\']?',
                'severity': 'high',
                'description': 'Generic API Key'
            },
            'generic_secret': {
                'pattern': r'(?i)(?:api|app|application)[-_]?secret\s*[:=]\s*["\']?([a-z0-9]{32,})["\']?',
                'severity': 'high',
                'description': 'Generic API Secret'
            },
            'generic_token': {
                'pattern': r'(?i)(?:api|app|bearer|auth)[-_]?token\s*[:=]\s*["\']?([a-z0-9]{32,})["\']?',
                'severity': 'high',
                'description': 'Generic API Token'
            },

            # Database Credentials
            'database_url': {
                'pattern': r'(?i)(?:mysql|postgresql|mongodb|postgres|mssql|oracle)://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/([^\s"\']+)',
                'severity': 'critical',
                'description': 'Database Connection String with Credentials'
            },
            'jdbc_url': {
                'pattern': r'jdbc:(?:mysql|postgresql|oracle|sqlserver)://[^;]+;.*(?:user|username|password)=',
                'severity': 'critical',
                'description': 'JDBC Connection String with Credentials'
            },
            'mongodb_url': {
                'pattern': r'mongodb(?:\+srv)?://([^:]+):([^@]+)@',
                'severity': 'critical',
                'description': 'MongoDB Connection String with Credentials'
            },

            # Private Keys
            'rsa_private_key': {
                'pattern': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
                'severity': 'critical',
                'description': 'Private Key (RSA/EC/OpenSSH)'
            },
            'dsa_private_key': {
                'pattern': r'-----BEGIN DSA PRIVATE KEY-----',
                'severity': 'critical',
                'description': 'DSA Private Key'
            },
            'pgp_private_key': {
                'pattern': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                'severity': 'critical',
                'description': 'PGP Private Key'
            },

            # OAuth & JWT
            'oauth_token': {
                'pattern': r'(?i)(?:oauth|bearer)[-_]?token\s*[:=]\s*["\']?([a-z0-9\-_.]{20,})["\']?',
                'severity': 'high',
                'description': 'OAuth/Bearer Token'
            },
            'jwt_token': {
                'pattern': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
                'severity': 'medium',
                'description': 'JWT Token (may be expired)'
            },

            # GitHub
            'github_token': {
                'pattern': r'(?i)github[-_]?(?:token|pat|key)\s*[:=]\s*["\']?(ghp_[a-zA-Z0-9]{36})["\']?',
                'severity': 'critical',
                'description': 'GitHub Personal Access Token'
            },
            'github_oauth': {
                'pattern': r'gho_[a-zA-Z0-9]{36}',
                'severity': 'critical',
                'description': 'GitHub OAuth Token'
            },
            'github_app_token': {
                'pattern': r'(?:ghu|ghs)_[a-zA-Z0-9]{36}',
                'severity': 'critical',
                'description': 'GitHub App Token'
            },

            # GitLab
            'gitlab_token': {
                'pattern': r'glpat-[a-zA-Z0-9\-_]{20}',
                'severity': 'critical',
                'description': 'GitLab Personal Access Token'
            },

            # Slack
            'slack_token': {
                'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
                'severity': 'high',
                'description': 'Slack Token'
            },
            'slack_webhook': {
                'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
                'severity': 'high',
                'description': 'Slack Webhook URL'
            },

            # Stripe
            'stripe_secret_key': {
                'pattern': r'sk_live_[0-9a-zA-Z]{24,}',
                'severity': 'critical',
                'description': 'Stripe Secret Key (Live)'
            },
            'stripe_test_key': {
                'pattern': r'sk_test_[0-9a-zA-Z]{24,}',
                'severity': 'medium',
                'description': 'Stripe Test Key'
            },

            # Twilio
            'twilio_api_key': {
                'pattern': r'SK[a-z0-9]{32}',
                'severity': 'high',
                'description': 'Twilio API Key'
            },

            # SendGrid
            'sendgrid_api_key': {
                'pattern': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
                'severity': 'high',
                'description': 'SendGrid API Key'
            },

            # Mailgun
            'mailgun_api_key': {
                'pattern': r'key-[a-z0-9]{32}',
                'severity': 'high',
                'description': 'Mailgun API Key'
            },

            # Passwords in Code
            'password_assignment': {
                'pattern': r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']',
                'severity': 'high',
                'description': 'Password in Code'
            },
            'db_password': {
                'pattern': r'(?i)(?:db|database)[-_]?(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']',
                'severity': 'critical',
                'description': 'Database Password'
            },

            # SMTP Credentials
            'smtp_credentials': {
                'pattern': r'smtp://([^:]+):([^@]+)@',
                'severity': 'high',
                'description': 'SMTP Credentials'
            },

            # API Endpoints with Keys
            'url_with_key': {
                'pattern': r'(?:https?://[^\s"\']+)(?:[?&](?:api_key|apikey|key|token)=)([a-zA-Z0-9_-]{16,})',
                'severity': 'high',
                'description': 'URL with API Key Parameter'
            },

            # Generic High-Entropy Strings
            'high_entropy_string': {
                'pattern': r'(?:["\']|^)([a-zA-Z0-9+/]{32,})(?:["\']|$)',
                'severity': 'low',
                'description': 'High Entropy String (Potential Secret)',
                'entropy_check': True
            },
        }

    def scan_response(self, url: str, response, context: Dict = None) -> List[Dict]:
        """
        Scan HTTP response for secrets.

        Args:
            url: URL being scanned
            response: HTTP response object
            context: Additional context (headers, etc.)

        Returns:
            List of detected secrets
        """
        if not self.enabled:
            return []

        secrets = []

        try:
            # Scan response body
            if response and hasattr(response, 'text'):
                content = response.text
                secrets.extend(self._scan_content(url, content, 'response_body'))

            # Scan response headers
            if response and hasattr(response, 'headers'):
                headers_str = '\n'.join([f"{k}: {v}" for k, v in response.headers.items()])
                secrets.extend(self._scan_content(url, headers_str, 'response_headers'))

            # Scan JavaScript files separately (if URL ends with .js)
            if url.endswith('.js') and response and hasattr(response, 'text'):
                secrets.extend(self._scan_javascript(url, response.text))

        except Exception as e:
            logger.error(f"Error scanning for secrets in {url}: {e}")

        return secrets

    def _scan_content(self, url: str, content: str, location: str) -> List[Dict]:
        """Scan content for secrets using regex patterns."""
        secrets = []

        for secret_type, pattern_info in self.patterns.items():
            try:
                pattern = pattern_info['pattern']
                regex = re.compile(pattern, re.MULTILINE)

                for match in regex.finditer(content):
                    # Extract the secret value
                    if match.groups():
                        secret_value = match.group(1) if len(match.groups()) >= 1 else match.group(0)
                    else:
                        secret_value = match.group(0)

                    # Skip if empty or too short
                    if not secret_value or len(secret_value) < 4:
                        continue

                    # Skip whitelisted emails/domains
                    if self._is_whitelisted(secret_value) or self._is_whitelisted(match.group(0)):
                        continue

                    # Check entropy if required
                    if pattern_info.get('entropy_check') and self.check_entropy:
                        entropy = self._calculate_entropy(secret_value)
                        if entropy < self.min_entropy:
                            continue

                    # Avoid duplicates
                    secret_hash = f"{url}:{secret_type}:{secret_value[:20]}"
                    if secret_hash in self.found_secrets:
                        continue
                    self.found_secrets.add(secret_hash)

                    # Extract context (surrounding text)
                    context_start = max(0, match.start() - 50)
                    context_end = min(len(content), match.end() + 50)
                    context_text = content[context_start:context_end]

                    # Create secret finding
                    secret = {
                        'type': 'Secret Exposure',
                        'secret_type': secret_type,
                        'severity': pattern_info['severity'],
                        'url': url,
                        'location': location,
                        'description': pattern_info['description'],
                        'evidence': self._mask_secret(secret_value),
                        'full_match': self._mask_secret(match.group(0)),
                        'context': self._mask_secret(context_text),
                        'remediation': self._get_remediation(secret_type),
                        'line_number': content[:match.start()].count('\n') + 1
                    }

                    secrets.append(secret)
                    logger.warning(f"🔐 Found {pattern_info['description']} in {url} ({location})")

            except re.error as e:
                logger.error(f"Invalid regex pattern for {secret_type}: {e}")
            except Exception as e:
                logger.debug(f"Error scanning for {secret_type}: {e}")

        return secrets

    def _scan_javascript(self, url: str, js_content: str) -> List[Dict]:
        """Scan JavaScript files with additional patterns."""
        secrets = []

        # Additional JS-specific patterns
        js_patterns = {
            'js_config_object': r'(?i)(?:config|settings|credentials)\s*=\s*\{[^}]{20,}\}',
            'js_api_endpoint': r'(?:https?://[^\s"\']+/api/[^\s"\']+)',
            'js_base64': r'(?:["\']|^)([A-Za-z0-9+/]{40,}={0,2})(?:["\']|$)',
        }

        for pattern_name, pattern in js_patterns.items():
            try:
                for match in re.finditer(pattern, js_content):
                    matched_text = match.group(0)

                    # Check if it contains sensitive keywords
                    if any(keyword in matched_text.lower() for keyword in
                           ['password', 'secret', 'key', 'token', 'credential', 'api']):

                        secret_hash = f"{url}:{pattern_name}:{matched_text[:20]}"
                        if secret_hash not in self.found_secrets:
                            self.found_secrets.add(secret_hash)

                            secrets.append({
                                'type': 'Secret Exposure',
                                'secret_type': f'javascript_{pattern_name}',
                                'severity': 'medium',
                                'url': url,
                                'location': 'javascript',
                                'description': f'Potential secret in JavaScript: {pattern_name}',
                                'evidence': self._mask_secret(matched_text[:200]),
                                'remediation': 'Remove hardcoded secrets from JavaScript. Use environment variables or secure configuration management.',
                                'line_number': js_content[:match.start()].count('\n') + 1
                            })

            except Exception as e:
                logger.debug(f"Error scanning JS pattern {pattern_name}: {e}")

        return secrets

    def _calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Args:
            string: Input string

        Returns:
            Entropy value (higher = more random)
        """
        if not string:
            return 0.0

        # Count character frequencies
        char_counts = Counter(string)
        total = len(string)

        # Calculate Shannon entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)

        return entropy

    def _mask_secret(self, secret: str, visible_chars: int = 4) -> str:
        """
        Mask secret value for safe logging/reporting.

        Args:
            secret: Secret string to mask
            visible_chars: Number of characters to show at start/end

        Returns:
            Masked secret string
        """
        if not secret or len(secret) <= visible_chars * 2:
            return '*' * len(secret) if secret else ''

        start = secret[:visible_chars]
        end = secret[-visible_chars:]
        masked_length = len(secret) - (visible_chars * 2)

        return f"{start}{'*' * min(masked_length, 20)}{end}"

    def _get_remediation(self, secret_type: str) -> str:
        """Get remediation advice for specific secret type."""
        remediations = {
            'aws_access_key': 'Immediately rotate AWS credentials. Use AWS IAM roles instead of hardcoded keys. Enable AWS CloudTrail for audit logging.',
            'aws_secret_key': 'Immediately rotate AWS credentials. Never commit secrets to code. Use AWS Secrets Manager or Parameter Store.',
            'gcp_api_key': 'Rotate GCP API key immediately. Restrict API key usage by IP, referrer, or API. Use service accounts with minimal permissions.',
            'gcp_service_account': 'Rotate service account key immediately. Use Workload Identity or service account impersonation when possible.',
            'github_token': 'Revoke GitHub token immediately at github.com/settings/tokens. Use encrypted secrets in CI/CD. Enable token expiration.',
            'database_url': 'Change database password immediately. Never expose connection strings. Use environment variables and secret management.',
            'rsa_private_key': 'Revoke and regenerate keypair immediately. Never commit private keys. Use secret management systems. Audit all systems that used this key.',
            'slack_token': 'Revoke Slack token at api.slack.com/apps. Rotate workspace tokens. Use OAuth scopes with minimal permissions.',
            'stripe_secret_key': 'Rotate Stripe key at dashboard.stripe.com/apikeys. Check for unauthorized transactions. Enable webhook signatures.',
        }

        return remediations.get(
            secret_type,
            'Rotate/revoke this credential immediately. Remove from code. Use environment variables or secret management systems. Audit access logs.'
        )

    def scan_git_files(self, url: str, response) -> List[Dict]:
        """Scan for exposed .git files and git metadata."""
        secrets = []

        git_patterns = [
            '.git/config',
            '.git/HEAD',
            '.git/index',
            '.git/logs/',
            '.env',
            '.env.local',
            '.env.production',
            'config.json',
            'credentials.json',
            'secrets.json',
        ]

        # Check if any git-related files are exposed
        if response and hasattr(response, 'text'):
            content = response.text.lower()

            for pattern in git_patterns:
                if pattern.lower() in url.lower() or pattern.lower() in content:
                    secrets.append({
                        'type': 'Secret Exposure',
                        'secret_type': 'git_exposure',
                        'severity': 'high',
                        'url': url,
                        'location': 'file_path',
                        'description': f'Exposed Git/Config File: {pattern}',
                        'evidence': f'File or reference to {pattern} detected',
                        'remediation': 'Remove .git directory and config files from web root. Add to .gitignore. Configure web server to deny access to these files.',
                    })

        return secrets
