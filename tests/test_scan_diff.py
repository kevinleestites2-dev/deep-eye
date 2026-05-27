"""Tests for scan diff (Group E)."""
import csv
import io
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core.scan_diff import diff_scans, normalize_url, load_scan_json
from utils.exports.diff_renderer import render_html, render_json, render_csv


def _vuln(type_, url, parameter="", severity="high", payload="x", evidence="e"):
    return {
        "type": type_,
        "url": url,
        "parameter": parameter,
        "severity": severity,
        "payload": payload,
        "evidence": evidence,
        "description": "",
        "remediation": "",
    }


def _scan(target, vulns, scan_time="2026-05-28T10:00:00Z"):
    return {
        "target": target,
        "vulnerabilities": vulns,
        "end_time": scan_time,
    }


class TestURLNormalization:
    def test_trailing_slash(self):
        assert normalize_url("https://example.com/path/") == normalize_url("https://example.com/path")

    def test_query_param_order(self):
        a = normalize_url("https://example.com/?a=1&b=2")
        b = normalize_url("https://example.com/?b=2&a=1")
        assert a == b

    def test_case_insensitive_host(self):
        assert normalize_url("HTTPS://EXAMPLE.COM/x") == normalize_url("https://example.com/x")

    def test_empty(self):
        assert normalize_url("") == ""


class TestDiffScans:
    def test_new_only(self):
        baseline = _scan("https://example.com", [])
        current = _scan("https://example.com", [_vuln("XSS", "https://example.com/x")])
        diff = diff_scans(baseline, current)
        assert diff["summary"]["new"] == 1
        assert diff["summary"]["fixed"] == 0
        assert diff["summary"]["unchanged"] == 0

    def test_fixed_only(self):
        baseline = _scan("https://example.com", [_vuln("XSS", "https://example.com/x")])
        current = _scan("https://example.com", [])
        diff = diff_scans(baseline, current)
        assert diff["summary"]["new"] == 0
        assert diff["summary"]["fixed"] == 1

    def test_unchanged(self):
        v = _vuln("SQL Injection", "https://example.com/login", "user", "critical")
        baseline = _scan("https://example.com", [dict(v)])
        current = _scan("https://example.com", [dict(v)])
        diff = diff_scans(baseline, current)
        assert diff["summary"]["unchanged"] == 1
        assert diff["summary"]["new"] == 0
        assert diff["summary"]["fixed"] == 0

    def test_severity_changed(self):
        v_low = _vuln("SQL Injection", "https://example.com/x", "id", "low")
        v_high = _vuln("SQL Injection", "https://example.com/x", "id", "high")
        baseline = _scan("x", [v_low])
        current = _scan("x", [v_high])
        diff = diff_scans(baseline, current)
        assert diff["summary"]["severity_changed"] == 1
        assert diff["summary"]["new"] == 0
        assert diff["summary"]["fixed"] == 0

    def test_url_normalization_keeps_unchanged(self):
        baseline = _scan("x", [_vuln("XSS", "https://example.com/path/")])
        current = _scan("x", [_vuln("XSS", "https://example.com/path")])
        diff = diff_scans(baseline, current)
        assert diff["summary"]["unchanged"] == 1

    def test_summary_counts(self):
        baseline = _scan("x", [
            _vuln("XSS", "https://example.com/a"),
            _vuln("SQL Injection", "https://example.com/b"),
            _vuln("CSRF", "https://example.com/c"),
        ])
        current = _scan("x", [
            _vuln("XSS", "https://example.com/a"),
            _vuln("SSRF", "https://example.com/d"),
        ])
        diff = diff_scans(baseline, current)
        assert diff["summary"] == {
            "new": 1,
            "fixed": 2,
            "unchanged": 1,
            "severity_changed": 0,
            "net_delta": -1,
        }

    def test_skip_invalid_vulns(self):
        baseline = _scan("x", [{"type": "XSS"}])
        current = _scan("x", [_vuln("XSS", "https://example.com/x")])
        diff = diff_scans(baseline, current)
        assert diff["summary"]["new"] == 1
        assert diff["baseline"]["vuln_count"] == 0


class TestRenderers:
    def _diff_fixture(self):
        baseline = _scan("https://example.com", [
            _vuln("XSS", "https://example.com/old", severity="high"),
        ])
        current = _scan("https://example.com", [
            _vuln("SQL Injection", "https://example.com/new", "id", "critical"),
        ])
        return diff_scans(baseline, current)

    def test_render_json(self):
        diff = self._diff_fixture()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tf:
            path = tf.name
        render_json(diff, path)
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["summary"]["new"] == 1
        assert loaded["summary"]["fixed"] == 1
        os.unlink(path)

    def test_render_csv(self):
        diff = self._diff_fixture()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as tf:
            path = tf.name
        render_csv(diff, path)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        body = text.lstrip("\ufeff")
        reader = csv.reader(io.StringIO(body))
        header = next(reader)
        assert "status" in header
        rows = list(reader)
        statuses = {r[0] for r in rows}
        assert "new" in statuses
        assert "fixed" in statuses
        os.unlink(path)

    def test_render_html(self):
        diff = self._diff_fixture()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8") as tf:
            path = tf.name
        render_html(diff, path)
        with open(path, encoding="utf-8") as f:
            html = f.read()
        assert "Deep Eye Scan Diff" in html
        assert "New Vulnerabilities" in html
        assert "Fixed Vulnerabilities" in html
        os.unlink(path)

    def test_render_html_xss_safe(self):
        baseline = _scan("x", [])
        current = _scan("x", [_vuln("<script>alert(1)</script>", "https://example.com/x")])
        diff = diff_scans(baseline, current)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8") as tf:
            path = tf.name
        render_html(diff, path)
        with open(path, encoding="utf-8") as f:
            html = f.read()
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html
        os.unlink(path)


class TestLoadJSON:
    def test_load_valid(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tf:
            json.dump({"target": "x", "vulnerabilities": []}, tf)
            path = tf.name
        loaded = load_scan_json(path)
        assert loaded["target"] == "x"
        os.unlink(path)
