"""Scan diff engine — compare two scan JSONs, classify findings."""
import json
import logging
from typing import Dict, List, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

logger = logging.getLogger(__name__)


def normalize_url(url: str) -> str:
    """Lowercase scheme+host, strip trailing slash, sort query params."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        netloc = (parsed.netloc or "").lower()
        path = parsed.path or ""
        if path.endswith("/") and len(path) > 1:
            path = path.rstrip("/")
        if parsed.query:
            params = sorted(parse_qsl(parsed.query, keep_blank_values=True))
            query = urlencode(params)
        else:
            query = ""
        return urlunparse((scheme, netloc, path, parsed.params, query, ""))
    except Exception:
        return url


def _identity(vuln: Dict) -> Tuple[str, str, str, str]:
    """Identity tuple including severity."""
    return (
        str(vuln.get("type", "")),
        normalize_url(vuln.get("url", "")),
        str(vuln.get("parameter", "")),
        str(vuln.get("severity", "")),
    )


def _identity_no_sev(vuln: Dict) -> Tuple[str, str, str]:
    """Identity tuple WITHOUT severity, for severity_changed detection."""
    return (
        str(vuln.get("type", "")),
        normalize_url(vuln.get("url", "")),
        str(vuln.get("parameter", "")),
    )


def load_scan_json(path: str) -> Dict:
    """Load and parse a scan result JSON."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def diff_scans(baseline: Dict, current: Dict) -> Dict:
    """Compute diff between baseline and current scan results."""
    base_vulns = baseline.get("vulnerabilities", [])
    curr_vulns = current.get("vulnerabilities", [])

    base_vulns = [v for v in base_vulns if v.get("type") and v.get("url")]
    curr_vulns = [v for v in curr_vulns if v.get("type") and v.get("url")]

    base_by_id = {_identity(v): v for v in base_vulns}
    curr_by_id = {_identity(v): v for v in curr_vulns}

    base_ids = set(base_by_id.keys())
    curr_ids = set(curr_by_id.keys())

    base_by_id_no_sev = {_identity_no_sev(v): v for v in base_vulns}
    curr_by_id_no_sev = {_identity_no_sev(v): v for v in curr_vulns}

    severity_changed = []
    sev_changed_no_sev_keys = set()
    for k_no_sev, base_v in base_by_id_no_sev.items():
        curr_v = curr_by_id_no_sev.get(k_no_sev)
        if curr_v and base_v.get("severity") != curr_v.get("severity"):
            severity_changed.append({"baseline": base_v, "current": curr_v})
            sev_changed_no_sev_keys.add(k_no_sev)

    new_list = []
    for cid in curr_ids - base_ids:
        v = curr_by_id[cid]
        if _identity_no_sev(v) in sev_changed_no_sev_keys:
            continue
        new_list.append(v)

    fixed_list = []
    for bid in base_ids - curr_ids:
        v = base_by_id[bid]
        if _identity_no_sev(v) in sev_changed_no_sev_keys:
            continue
        fixed_list.append(v)

    unchanged_list = [curr_by_id[cid] for cid in curr_ids & base_ids]

    summary = {
        "new": len(new_list),
        "fixed": len(fixed_list),
        "unchanged": len(unchanged_list),
        "severity_changed": len(severity_changed),
        "net_delta": len(new_list) - len(fixed_list),
    }

    return {
        "baseline": {
            "target": baseline.get("target", "unknown"),
            "scan_time": baseline.get("end_time", baseline.get("start_time", "")),
            "vuln_count": len(base_vulns),
        },
        "current": {
            "target": current.get("target", "unknown"),
            "scan_time": current.get("end_time", current.get("start_time", "")),
            "vuln_count": len(curr_vulns),
        },
        "summary": summary,
        "new": new_list,
        "fixed": fixed_list,
        "unchanged": unchanged_list,
        "severity_changed": severity_changed,
    }
