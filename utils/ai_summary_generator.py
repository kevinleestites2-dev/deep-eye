"""
AI Executive Summary Generator
Uses configured AI provider to generate executive summaries from scan results
"""

from typing import Dict, List, Optional
from utils.logger import get_logger

logger = get_logger(__name__)


class AISummaryGenerator:
    """Generate AI-powered executive summaries from scan results."""

    def __init__(self, ai_provider_manager):
        """
        Args:
            ai_provider_manager: AIProviderManager instance with active provider
        """
        self.ai = ai_provider_manager

    def generate_executive_summary(self, results: Dict) -> str:
        """Generate an executive summary of scan findings using AI."""
        vulns = results.get('vulnerabilities', [])
        target = results.get('target', 'Unknown')
        duration = results.get('duration', 'Unknown')

        if not vulns:
            return f"Security scan of {target} completed with no vulnerabilities detected."

        # Build context for AI
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        vuln_types = set()
        for v in vulns:
            sev = v.get('severity', 'info').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            vuln_types.add(v.get('type', 'Unknown'))

        # Top 5 most critical findings
        critical_findings = sorted(vulns, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x.get('severity', 'info'), 5))[:5]

        findings_text = "\n".join([
            f"- [{v.get('severity', 'info').upper()}] {v.get('type', 'Unknown')} at {v.get('url', 'N/A')}"
            for v in critical_findings
        ])

        prompt = f"""Generate a professional executive summary for a security assessment report.

Target: {target}
Scan Duration: {duration}
Total Vulnerabilities: {len(vulns)}
Breakdown: {severity_counts['critical']} Critical, {severity_counts['high']} High, {severity_counts['medium']} Medium, {severity_counts['low']} Low, {severity_counts['info']} Info
Vulnerability Types Found: {', '.join(list(vuln_types)[:10])}

Top Findings:
{findings_text}

Write a 3-4 paragraph executive summary that:
1. States the overall security posture (critical/poor/moderate/good)
2. Highlights the most impactful findings and their business risk
3. Provides high-level remediation priorities
4. Is suitable for C-level executives (non-technical language)

Do not use markdown formatting. Write in plain professional prose."""

        try:
            summary = self.ai.generate(prompt)
            if summary:
                logger.info("AI executive summary generated successfully")
                return summary
            else:
                logger.warning("AI provider returned empty summary, using fallback")
                return self._fallback_summary(target, vulns, severity_counts)
        except Exception as e:
            logger.error(f"AI summary generation failed: {e}")
            return self._fallback_summary(target, vulns, severity_counts)

    def _fallback_summary(self, target: str, vulns: List[Dict], severity_counts: Dict) -> str:
        """Generate a basic summary without AI."""
        total = len(vulns)
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)

        if critical > 0:
            posture = "CRITICAL"
        elif high > 0:
            posture = "HIGH RISK"
        elif severity_counts.get('medium', 0) > 0:
            posture = "MODERATE RISK"
        else:
            posture = "LOW RISK"

        return (
            f"Security Assessment Summary for {target}\n\n"
            f"Overall Security Posture: {posture}\n\n"
            f"The scan identified {total} vulnerabilities: "
            f"{critical} critical, {high} high, {severity_counts.get('medium', 0)} medium, "
            f"{severity_counts.get('low', 0)} low, and {severity_counts.get('info', 0)} informational findings.\n\n"
            f"Immediate action is required for all critical and high severity findings. "
            f"Prioritize remediation based on exploitability and business impact."
        )
