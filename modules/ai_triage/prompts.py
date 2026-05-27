"""Prompt templates for AI triage and bounty writing."""

TRIAGE_PROMPT = """You are a security expert reviewing a vulnerability finding.

Finding:
  Type: {type}
  URL: {url}
  Parameter: {parameter}
  Severity: {severity}
  Payload: {payload}
  Evidence: {evidence}
  Description: {description}

Determine if this is a TRUE POSITIVE or FALSE POSITIVE.

Common false positives:
- Reflected input without script execution context
- Error messages that don't reveal stack traces or DB schema
- Open redirect to same-origin URL
- "Sensitive" headers that are actually standard

Return ONLY a JSON object with these keys (no markdown fence):
  confidence: float between 0.0 and 1.0
  false_positive: boolean
  reason: brief one-line explanation

Example:
{{"confidence": 0.85, "false_positive": false, "reason": "Payload reflected unencoded in HTML body"}}
"""


BOUNTY_PROMPT = """Generate a bug bounty submission report in Markdown.

Format: {format}

Vulnerability:
  Type: {type}
  Severity: {severity}
  CVSS: {cvss_score}
  URL: {url}
  Parameter: {parameter}
  Payload: {payload}
  Evidence: {evidence}
  Description: {description}
  Remediation: {remediation}

Required sections:
  ## Summary
  ## Steps to Reproduce
  ## Impact
  ## Proof of Concept (payload in code block)
  ## Suggested Fix
  ## Severity Justification

Clear, concise. No marketing fluff. Output Markdown only.
"""
