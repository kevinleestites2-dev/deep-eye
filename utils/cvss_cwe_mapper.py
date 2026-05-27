"""
CVSS/CWE Mapping Utility
Maps vulnerability types to CVSS 3.1 scores and CWE identifiers
"""

# Vulnerability type -> (CVSS 3.1 base score, CWE ID, CWE name, OWASP Top 10 2021 category)
VULN_MAPPING = {
    'sql_injection': (9.8, 'CWE-89', 'SQL Injection', 'A03:2021-Injection'),
    'SQL Injection': (9.8, 'CWE-89', 'SQL Injection', 'A03:2021-Injection'),
    'xss': (6.1, 'CWE-79', 'Cross-site Scripting', 'A03:2021-Injection'),
    'Cross-Site Scripting (XSS)': (6.1, 'CWE-79', 'Cross-site Scripting', 'A03:2021-Injection'),
    'command_injection': (9.8, 'CWE-78', 'OS Command Injection', 'A03:2021-Injection'),
    'Command Injection': (9.8, 'CWE-78', 'OS Command Injection', 'A03:2021-Injection'),
    'ssrf': (9.1, 'CWE-918', 'Server-Side Request Forgery', 'A10:2021-SSRF'),
    'Server-Side Request Forgery (SSRF)': (9.1, 'CWE-918', 'Server-Side Request Forgery', 'A10:2021-SSRF'),
    'xxe': (7.5, 'CWE-611', 'XML External Entity', 'A05:2021-Security Misconfiguration'),
    'XML External Entity (XXE)': (7.5, 'CWE-611', 'XML External Entity', 'A05:2021-Security Misconfiguration'),
    'path_traversal': (7.5, 'CWE-22', 'Path Traversal', 'A01:2021-Broken Access Control'),
    'Path Traversal': (7.5, 'CWE-22', 'Path Traversal', 'A01:2021-Broken Access Control'),
    'csrf': (8.8, 'CWE-352', 'Cross-Site Request Forgery', 'A01:2021-Broken Access Control'),
    'CSRF': (8.8, 'CWE-352', 'Cross-Site Request Forgery', 'A01:2021-Broken Access Control'),
    'open_redirect': (6.1, 'CWE-601', 'Open Redirect', 'A01:2021-Broken Access Control'),
    'Open Redirect': (6.1, 'CWE-601', 'Open Redirect', 'A01:2021-Broken Access Control'),
    'cors_misconfiguration': (7.5, 'CWE-942', 'CORS Misconfiguration', 'A05:2021-Security Misconfiguration'),
    'lfi': (7.5, 'CWE-98', 'Local File Inclusion', 'A03:2021-Injection'),
    'rfi': (9.8, 'CWE-98', 'Remote File Inclusion', 'A03:2021-Injection'),
    'ssti': (9.8, 'CWE-1336', 'Server-Side Template Injection', 'A03:2021-Injection'),
    'crlf_injection': (6.1, 'CWE-93', 'CRLF Injection', 'A03:2021-Injection'),
    'host_header_injection': (6.1, 'CWE-644', 'Host Header Injection', 'A05:2021-Security Misconfiguration'),
    'ldap_injection': (9.8, 'CWE-90', 'LDAP Injection', 'A03:2021-Injection'),
    'xml_injection': (7.5, 'CWE-91', 'XML Injection', 'A03:2021-Injection'),
    'insecure_deserialization': (9.8, 'CWE-502', 'Insecure Deserialization', 'A08:2021-Software and Data Integrity Failures'),
    'jwt_vulnerabilities': (7.5, 'CWE-347', 'JWT Verification Bypass', 'A02:2021-Cryptographic Failures'),
    'broken_authentication': (7.5, 'CWE-287', 'Broken Authentication', 'A07:2021-Identification and Authentication Failures'),
    'sensitive_data_exposure': (7.5, 'CWE-200', 'Sensitive Data Exposure', 'A02:2021-Cryptographic Failures'),
    'information_disclosure': (5.3, 'CWE-200', 'Information Disclosure', 'A01:2021-Broken Access Control'),
    'security_misconfiguration': (5.3, 'CWE-16', 'Security Misconfiguration', 'A05:2021-Security Misconfiguration'),
    'nosql_injection': (9.8, 'CWE-943', 'NoSQL Injection', 'A03:2021-Injection'),
    'http_smuggling': (9.8, 'CWE-444', 'HTTP Request Smuggling', 'A05:2021-Security Misconfiguration'),
    'race_condition': (8.1, 'CWE-362', 'Race Condition', 'A04:2021-Insecure Design'),
    'log4shell': (10.0, 'CWE-917', 'JNDI Injection (Log4Shell)', 'A03:2021-Injection'),
    'oauth_testing': (8.1, 'CWE-346', 'OAuth Flow Bypass', 'A07:2021-Identification and Authentication Failures'),
    'mass_assignment': (6.5, 'CWE-915', 'Mass Assignment', 'A04:2021-Insecure Design'),
    'prototype_pollution': (9.8, 'CWE-1321', 'Prototype Pollution', 'A03:2021-Injection'),
    'Secret Exposure': (7.5, 'CWE-798', 'Hardcoded Credentials', 'A02:2021-Cryptographic Failures'),
    'Secret Leak': (7.5, 'CWE-798', 'Hardcoded Credentials', 'A02:2021-Cryptographic Failures'),
    'cache_poisoning': (7.5, 'CWE-349', 'Cache Poisoning', 'A05:2021-Security Misconfiguration'),
    'subdomain_takeover': (7.5, 'CWE-284', 'Subdomain Takeover', 'A05:2021-Security Misconfiguration'),
    'saml_attack': (9.8, 'CWE-347', 'SAML Signature Bypass', 'A07:2021-Identification and Authentication Failures'),
}


def enrich_vulnerability(vuln: dict) -> dict:
    """Add CVSS score, CWE ID, and OWASP category to a vulnerability dict."""
    vuln_type = vuln.get('type', '')
    mapping = VULN_MAPPING.get(vuln_type)

    if not mapping:
        for key, val in VULN_MAPPING.items():
            if key.lower() in vuln_type.lower():
                mapping = val
                break

    if mapping:
        cvss_score, cwe_id, cwe_name, owasp_category = mapping
        vuln['cvss_score'] = cvss_score
        vuln['cwe_id'] = cwe_id
        vuln['cwe_name'] = cwe_name
        vuln['owasp_category'] = owasp_category
    else:
        severity_cvss = {'critical': 9.5, 'high': 7.5, 'medium': 5.0, 'low': 3.0, 'info': 0.0}
        vuln['cvss_score'] = severity_cvss.get(vuln.get('severity', 'info'), 0.0)
        vuln['cwe_id'] = 'CWE-Unknown'
        vuln['cwe_name'] = vuln_type
        vuln['owasp_category'] = 'Uncategorized'

    return vuln


def enrich_all(vulnerabilities: list) -> list:
    """Enrich all vulnerabilities with CVSS/CWE/OWASP data."""
    return [enrich_vulnerability(v) for v in vulnerabilities]
