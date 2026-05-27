"""Bug bounty report writer — generates Markdown reports per finding."""
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

from modules.ai_triage.prompts import BOUNTY_PROMPT
from modules.ai_triage.triage import SEVERITY_RANK

logger = logging.getLogger(__name__)


def _slugify(text: str, max_len: int = 60) -> str:
    """Make a filesystem-safe slug from arbitrary text."""
    s = re.sub(r"[^a-zA-Z0-9_-]+", "_", text or "")
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:max_len] or "vuln"


class BountyWriter:
    """Generate per-vuln bug bounty Markdown reports."""

    def __init__(self, ai_manager, config: Optional[Dict] = None):
        self.ai_manager = ai_manager
        config = config or {}
        bb_cfg = config.get("bug_bounty", {}) if isinstance(config.get("bug_bounty"), dict) else {}
        self.enabled = bool(bb_cfg.get("enabled", False))
        self.format = str(bb_cfg.get("format", "hackerone")).lower()
        self.min_severity = str(bb_cfg.get("min_severity", "high")).lower()
        self._min_rank = SEVERITY_RANK.get(self.min_severity, 3)
        self.output_dir = Path(bb_cfg.get("output_directory", "reports/bounty"))
        self.one_file_per_vuln = bool(bb_cfg.get("one_file_per_vuln", True))

    def is_enabled(self) -> bool:
        return self.enabled and self.ai_manager is not None

    def _should_generate(self, vuln: Dict) -> bool:
        if vuln.get("false_positive"):
            return False
        sev = str(vuln.get("severity", "info")).lower()
        return SEVERITY_RANK.get(sev, 0) >= self._min_rank

    def _generate_one(self, vuln: Dict) -> Optional[str]:
        prompt = BOUNTY_PROMPT.format(
            format=self.format,
            type=vuln.get("type", ""),
            severity=vuln.get("severity", ""),
            cvss_score=vuln.get("cvss_score", "N/A"),
            url=vuln.get("url", ""),
            parameter=vuln.get("parameter", ""),
            payload=str(vuln.get("payload", ""))[:500],
            evidence=str(vuln.get("evidence", ""))[:500],
            description=vuln.get("description", ""),
            remediation=vuln.get("remediation", ""),
        )
        try:
            md = self.ai_manager.generate(prompt)
        except Exception as e:
            logger.warning(f"Bounty writer AI call failed: {e}")
            return None
        return md

    def generate_reports(self, vulnerabilities: List[Dict]) -> None:
        """Generate bounty reports for eligible vulns; write to disk if configured."""
        if not self.is_enabled():
            return

        if self.one_file_per_vuln:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        for idx, vuln in enumerate(vulnerabilities):
            if not self._should_generate(vuln):
                continue

            md = self._generate_one(vuln)
            if not md:
                continue

            vuln["bounty_report"] = md

            if self.one_file_per_vuln:
                stem = f"{idx:03d}_{_slugify(vuln.get('type', ''))}_{_slugify(vuln.get('parameter', '') or 'noparam', 30)}"
                path = self.output_dir / f"{stem}.md"
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(md)
                    logger.info(f"Bounty report saved: {path}")
                except OSError as e:
                    logger.error(f"Failed to write bounty report {path}: {e}")
