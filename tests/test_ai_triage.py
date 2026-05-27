"""Tests for AI triage + bounty writer (Group C)."""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from modules.ai_triage import AITriage, BountyWriter


class MockAI:
    """Mock AI provider returning pre-configured responses."""

    def __init__(self, responses=None, raise_on_call=False):
        self.responses = responses or []
        self.raise_on_call = raise_on_call
        self.calls = []
        self._idx = 0

    def generate(self, prompt, **kwargs):
        self.calls.append(prompt)
        if self.raise_on_call:
            raise RuntimeError("AI provider unavailable")
        if self._idx < len(self.responses):
            response = self.responses[self._idx]
            self._idx += 1
            return response
        return self.responses[-1] if self.responses else ""


def _vuln(type_="XSS", severity="high", url="https://example.com/x", parameter="q"):
    return {
        "type": type_,
        "severity": severity,
        "url": url,
        "parameter": parameter,
        "payload": "<script>",
        "evidence": "reflected",
        "description": "test vuln",
        "remediation": "encode",
        "cvss_score": 7.5,
    }


class TestTriage:
    def test_attaches_fields(self):
        ai = MockAI(['{"confidence": 0.9, "false_positive": false, "reason": "valid XSS"}'])
        triage = AITriage(ai, {"ai_triage": {"enabled": True, "min_severity": "low"}})
        vulns = [_vuln()]
        triage.triage_vulnerabilities(vulns)
        assert vulns[0]["confidence"] == 0.9
        assert vulns[0]["false_positive"] is False
        assert "valid" in vulns[0]["triage_reason"]

    def test_drops_fp_above_threshold(self):
        ai = MockAI(['{"confidence": 0.95, "false_positive": true, "reason": "harmless"}'])
        triage = AITriage(ai, {"ai_triage": {
            "enabled": True, "drop_false_positives": True,
            "drop_threshold": 0.8, "min_severity": "low",
        }})
        vulns = [_vuln()]
        triage.triage_vulnerabilities(vulns)
        assert vulns == []

    def test_keeps_fp_below_threshold(self):
        ai = MockAI(['{"confidence": 0.5, "false_positive": true, "reason": "uncertain"}'])
        triage = AITriage(ai, {"ai_triage": {
            "enabled": True, "drop_false_positives": True,
            "drop_threshold": 0.8, "min_severity": "low",
        }})
        vulns = [_vuln()]
        triage.triage_vulnerabilities(vulns)
        assert len(vulns) == 1
        assert vulns[0]["false_positive"] is True

    def test_min_severity_filter(self):
        ai = MockAI(['{"confidence": 0.9, "false_positive": false, "reason": "x"}'])
        triage = AITriage(ai, {"ai_triage": {"enabled": True, "min_severity": "critical"}})
        vulns = [_vuln(severity="high")]
        triage.triage_vulnerabilities(vulns)
        assert "confidence" not in vulns[0]
        assert ai.calls == []

    def test_handles_malformed_json(self):
        ai = MockAI(["this is not json at all"])
        triage = AITriage(ai, {"ai_triage": {"enabled": True, "min_severity": "low"}})
        vulns = [_vuln()]
        triage.triage_vulnerabilities(vulns)
        assert vulns[0]["false_positive"] is False
        assert vulns[0]["confidence"] < 0.5
        assert "Malformed" in vulns[0]["triage_reason"]

    def test_handles_fenced_json(self):
        ai = MockAI([
            '```json\n{"confidence": 0.7, "false_positive": false, "reason": "ok"}\n```'
        ])
        triage = AITriage(ai, {"ai_triage": {"enabled": True, "min_severity": "low"}})
        vulns = [_vuln()]
        triage.triage_vulnerabilities(vulns)
        assert vulns[0]["confidence"] == 0.7

    def test_provider_unavailable(self):
        ai = MockAI(raise_on_call=True)
        triage = AITriage(ai, {"ai_triage": {"enabled": True, "min_severity": "low"}})
        vulns = [_vuln()]
        triage.triage_vulnerabilities(vulns)
        assert vulns[0]["false_positive"] is False
        assert "unavailable" in vulns[0]["triage_reason"].lower()

    def test_disabled_does_nothing(self):
        ai = MockAI(['{"confidence": 0.9, "false_positive": true, "reason": "x"}'])
        triage = AITriage(ai, {"ai_triage": {"enabled": False}})
        vulns = [_vuln()]
        triage.triage_vulnerabilities(vulns)
        assert "confidence" not in vulns[0]
        assert ai.calls == []

    def test_confidence_clamped(self):
        ai = MockAI(['{"confidence": 5.0, "false_positive": false, "reason": "x"}'])
        triage = AITriage(ai, {"ai_triage": {"enabled": True, "min_severity": "low"}})
        vulns = [_vuln()]
        triage.triage_vulnerabilities(vulns)
        assert vulns[0]["confidence"] <= 1.0


class TestBountyWriter:
    def test_generates_markdown(self, tmp_path):
        ai = MockAI(["## Summary\nTest vuln\n## Steps to Reproduce\n1. visit URL\n## Impact\nbad"])
        cfg = {"bug_bounty": {
            "enabled": True, "min_severity": "low",
            "output_directory": str(tmp_path / "bounty"),
            "one_file_per_vuln": True,
        }}
        writer = BountyWriter(ai, cfg)
        vulns = [_vuln(severity="critical")]
        writer.generate_reports(vulns)
        assert "bounty_report" in vulns[0]
        assert "## Summary" in vulns[0]["bounty_report"]
        files = list((tmp_path / "bounty").glob("*.md"))
        assert len(files) == 1

    def test_min_severity_filter(self, tmp_path):
        ai = MockAI(["## Summary\nx"])
        cfg = {"bug_bounty": {
            "enabled": True, "min_severity": "critical",
            "output_directory": str(tmp_path / "bounty"),
        }}
        writer = BountyWriter(ai, cfg)
        vulns = [_vuln(severity="high")]
        writer.generate_reports(vulns)
        assert "bounty_report" not in vulns[0]
        assert ai.calls == []

    def test_skips_false_positives(self, tmp_path):
        ai = MockAI(["## Summary\nx"])
        cfg = {"bug_bounty": {
            "enabled": True, "min_severity": "low",
            "output_directory": str(tmp_path / "bounty"),
        }}
        writer = BountyWriter(ai, cfg)
        v = _vuln(severity="critical")
        v["false_positive"] = True
        vulns = [v]
        writer.generate_reports(vulns)
        assert "bounty_report" not in vulns[0]
        assert ai.calls == []

    def test_disabled_does_nothing(self, tmp_path):
        ai = MockAI(["## Summary"])
        cfg = {"bug_bounty": {"enabled": False, "output_directory": str(tmp_path / "bounty")}}
        writer = BountyWriter(ai, cfg)
        vulns = [_vuln(severity="critical")]
        writer.generate_reports(vulns)
        assert "bounty_report" not in vulns[0]
        assert ai.calls == []

    def test_one_file_per_vuln_disabled(self, tmp_path):
        ai = MockAI(["## Summary\nx"])
        cfg = {"bug_bounty": {
            "enabled": True, "min_severity": "low",
            "output_directory": str(tmp_path / "bounty"),
            "one_file_per_vuln": False,
        }}
        writer = BountyWriter(ai, cfg)
        vulns = [_vuln(severity="critical")]
        writer.generate_reports(vulns)
        assert "bounty_report" in vulns[0]
        bounty_dir = tmp_path / "bounty"
        if bounty_dir.exists():
            assert list(bounty_dir.glob("*.md")) == []

    def test_provider_failure_no_crash(self, tmp_path):
        ai = MockAI(raise_on_call=True)
        cfg = {"bug_bounty": {
            "enabled": True, "min_severity": "low",
            "output_directory": str(tmp_path / "bounty"),
        }}
        writer = BountyWriter(ai, cfg)
        vulns = [_vuln(severity="critical")]
        writer.generate_reports(vulns)
        assert "bounty_report" not in vulns[0]
