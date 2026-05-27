"""AI-based triage for vulnerability findings.

Reviews each finding via AI provider, returning confidence + FP flag.
Optionally drops high-confidence false positives.
"""
import json
import logging
import re
from typing import Dict, List, Optional

from modules.ai_triage.prompts import TRIAGE_PROMPT

logger = logging.getLogger(__name__)


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _parse_ai_json(raw: str) -> Optional[Dict]:
    """Extract JSON object from AI response. Tolerates code fences and prose."""
    if not raw:
        return None
    text = raw.strip()
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1)
    else:
        brace_match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
        if brace_match:
            text = brace_match.group(0)

    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


class AITriage:
    """Triage findings via AI provider."""

    def __init__(self, ai_manager, config: Optional[Dict] = None):
        self.ai_manager = ai_manager
        config = config or {}
        triage_cfg = config.get("ai_triage", {}) if isinstance(config.get("ai_triage"), dict) else {}
        self.enabled = bool(triage_cfg.get("enabled", False))
        self.drop_fps = bool(triage_cfg.get("drop_false_positives", False))
        self.drop_threshold = float(triage_cfg.get("drop_threshold", 0.8))
        self.min_severity = str(triage_cfg.get("min_severity", "high")).lower()
        self._min_rank = SEVERITY_RANK.get(self.min_severity, 3)

    def is_enabled(self) -> bool:
        return self.enabled and self.ai_manager is not None

    def _should_triage(self, vuln: Dict) -> bool:
        sev = str(vuln.get("severity", "info")).lower()
        return SEVERITY_RANK.get(sev, 0) >= self._min_rank

    def _triage_one(self, vuln: Dict) -> None:
        prompt = TRIAGE_PROMPT.format(
            type=vuln.get("type", ""),
            url=vuln.get("url", ""),
            parameter=vuln.get("parameter", ""),
            severity=vuln.get("severity", ""),
            payload=str(vuln.get("payload", ""))[:500],
            evidence=str(vuln.get("evidence", ""))[:500],
            description=vuln.get("description", ""),
        )
        try:
            raw = self.ai_manager.generate(prompt)
        except Exception as e:
            logger.warning(f"AI triage call failed for {vuln.get('type')}: {e}")
            vuln["confidence"] = 0.5
            vuln["false_positive"] = False
            vuln["triage_reason"] = "AI unavailable"
            return

        parsed = _parse_ai_json(raw)
        if not parsed or not isinstance(parsed, dict):
            vuln["confidence"] = 0.4
            vuln["false_positive"] = False
            vuln["triage_reason"] = "Malformed AI response"
            return

        try:
            confidence = float(parsed.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))

        vuln["confidence"] = confidence
        vuln["false_positive"] = bool(parsed.get("false_positive", False))
        vuln["triage_reason"] = str(parsed.get("reason", ""))

    def triage_vulnerabilities(self, vulnerabilities: List[Dict]) -> None:
        """Triage all eligible vulns in-place. Optionally drop FPs."""
        if not self.is_enabled():
            return

        for vuln in vulnerabilities:
            if self._should_triage(vuln):
                self._triage_one(vuln)

        if self.drop_fps:
            kept = []
            for v in vulnerabilities:
                if v.get("false_positive") and v.get("confidence", 0) >= self.drop_threshold:
                    logger.info(
                        f"Dropped FP: {v.get('type')} @ {v.get('url')} "
                        f"(confidence={v.get('confidence')}, reason={v.get('triage_reason')})"
                    )
                    continue
                kept.append(v)
            vulnerabilities[:] = kept
