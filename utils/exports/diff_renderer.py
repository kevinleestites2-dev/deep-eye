"""Renderers for scan diff reports (JSON, CSV, HTML)."""
import csv
import json
from typing import Dict, List


def render_json(diff: Dict, output_path: str) -> None:
    """Write diff dict as pretty JSON."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(diff, f, indent=2, ensure_ascii=False)


def render_csv(diff: Dict, output_path: str) -> None:
    """Write diff as flat CSV."""
    rows = []
    for v in diff.get("new", []):
        rows.append(_row("new", v, baseline_sev="", current_sev=v.get("severity", "")))
    for v in diff.get("fixed", []):
        rows.append(_row("fixed", v, baseline_sev=v.get("severity", ""), current_sev=""))
    for v in diff.get("unchanged", []):
        rows.append(
            _row("unchanged", v, baseline_sev=v.get("severity", ""), current_sev=v.get("severity", ""))
        )
    for pair in diff.get("severity_changed", []):
        b, c = pair["baseline"], pair["current"]
        rows.append(_row("severity_changed", c, baseline_sev=b.get("severity", ""), current_sev=c.get("severity", "")))

    columns = [
        "status", "type", "severity", "url", "parameter",
        "baseline_severity", "current_severity", "payload", "evidence",
    ]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        f.write("\ufeff")
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
        writer.writerow(columns)
        for r in rows:
            writer.writerow([r[c] for c in columns])


def _row(status: str, vuln: Dict, baseline_sev: str = "", current_sev: str = "") -> Dict:
    return {
        "status": status,
        "type": str(vuln.get("type", "")),
        "severity": str(vuln.get("severity", "")),
        "url": str(vuln.get("url", "")),
        "parameter": str(vuln.get("parameter", "")),
        "baseline_severity": str(baseline_sev),
        "current_severity": str(current_sev),
        "payload": str(vuln.get("payload", "")),
        "evidence": str(vuln.get("evidence", ""))[:500],
    }


def render_html(diff: Dict, output_path: str) -> None:
    """Write diff as standalone HTML page."""
    summary = diff.get("summary", {})
    base = diff.get("baseline", {})
    curr = diff.get("current", {})

    def _vuln_table(vulns: List[Dict], title: str, color: str) -> str:
        if not vulns:
            return ""
        rows = []
        for v in vulns:
            rows.append(
                f"<tr><td>{_esc(v.get('type', ''))}</td>"
                f"<td>{_esc(v.get('severity', ''))}</td>"
                f"<td>{_esc(v.get('url', ''))}</td>"
                f"<td>{_esc(v.get('parameter', ''))}</td></tr>"
            )
        return (
            f'<details open><summary style="border-left:4px solid {color};padding:8px;'
            f'font-size:1.1em;font-weight:bold;cursor:pointer;">'
            f"{title} ({len(vulns)})</summary>"
            f'<table style="border-collapse:collapse;width:100%;margin-top:8px;">'
            f"<thead><tr><th>Type</th><th>Severity</th><th>URL</th><th>Parameter</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></details>"
        )

    def _sev_changed_table(pairs: List[Dict]) -> str:
        if not pairs:
            return ""
        rows = []
        for pair in pairs:
            b, c = pair["baseline"], pair["current"]
            rows.append(
                f"<tr><td>{_esc(c.get('type', ''))}</td>"
                f"<td>{_esc(b.get('severity', ''))} &rarr; {_esc(c.get('severity', ''))}</td>"
                f"<td>{_esc(c.get('url', ''))}</td>"
                f"<td>{_esc(c.get('parameter', ''))}</td></tr>"
            )
        return (
            '<details open><summary style="border-left:4px solid orange;padding:8px;'
            'font-size:1.1em;font-weight:bold;cursor:pointer;">'
            f"Severity Changed ({len(pairs)})</summary>"
            '<table style="border-collapse:collapse;width:100%;margin-top:8px;">'
            "<thead><tr><th>Type</th><th>Baseline &rarr; Current</th><th>URL</th><th>Parameter</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></details>"
        )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Deep Eye Scan Diff</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; max-width: 1200px; margin: 30px auto; padding: 20px; color: #333; }}
h1 {{ color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 8px; }}
.meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
.meta-card {{ background: #f5f5f5; padding: 12px; border-radius: 6px; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin: 20px 0; }}
.stat {{ padding: 14px; border-radius: 6px; text-align: center; color: white; }}
.stat-new {{ background: #d9534f; }}
.stat-fixed {{ background: #5cb85c; }}
.stat-sevch {{ background: #f0ad4e; }}
.stat-unchanged {{ background: #888; }}
table {{ font-size: 0.9em; }}
th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; word-break: break-all; }}
th {{ background: #667eea; color: white; }}
details {{ margin-bottom: 14px; }}
</style></head><body>
<h1>Deep Eye Scan Diff</h1>
<div class="meta">
  <div class="meta-card"><strong>Baseline</strong><br/>{_esc(base.get('target', ''))}<br/><small>{_esc(base.get('scan_time', ''))}</small><br/>{base.get('vuln_count', 0)} vulns</div>
  <div class="meta-card"><strong>Current</strong><br/>{_esc(curr.get('target', ''))}<br/><small>{_esc(curr.get('scan_time', ''))}</small><br/>{curr.get('vuln_count', 0)} vulns</div>
</div>
<div class="summary">
  <div class="stat stat-new">New<br/><strong>{summary.get('new', 0)}</strong></div>
  <div class="stat stat-fixed">Fixed<br/><strong>{summary.get('fixed', 0)}</strong></div>
  <div class="stat stat-sevch">Severity Changed<br/><strong>{summary.get('severity_changed', 0)}</strong></div>
  <div class="stat stat-unchanged">Unchanged<br/><strong>{summary.get('unchanged', 0)}</strong></div>
</div>
<p><strong>Net Delta:</strong> {summary.get('net_delta', 0)} (negative = improvement)</p>
{_vuln_table(diff.get('new', []), 'New Vulnerabilities', '#d9534f')}
{_vuln_table(diff.get('fixed', []), 'Fixed Vulnerabilities', '#5cb85c')}
{_sev_changed_table(diff.get('severity_changed', []))}
<p><em>Unchanged: {summary.get('unchanged', 0)} findings present in both scans (omitted from detail tables).</em></p>
</body></html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def _esc(s) -> str:
    """Minimal HTML escape."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
