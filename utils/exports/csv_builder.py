"""CSV builder for spreadsheet export.

UTF-8 BOM for Excel compatibility, RFC 4180 quoting.
"""
import csv
import io
from datetime import datetime, timezone
from typing import Dict


BASE_COLUMNS = [
    "type",
    "severity",
    "url",
    "parameter",
    "payload",
    "evidence",
    "description",
    "remediation",
    "cve_references",
    "cvss_score",
    "timestamp",
]

COMPLIANCE_COLUMNS = [
    "compliance_pci_dss",
    "compliance_soc2",
    "compliance_iso_27001",
]

# Backward-compat alias for tests
COLUMNS = BASE_COLUMNS

_EVIDENCE_LIMIT = 1000
_UTF8_BOM = "\ufeff"

_COMPLIANCE_KEY_MAP = {
    "compliance_pci_dss": "PCI-DSS",
    "compliance_soc2": "SOC 2",
    "compliance_iso_27001": "ISO 27001",
}


def _flatten_cve(refs) -> str:
    if not refs:
        return ""
    if isinstance(refs, list):
        return "; ".join(str(r) for r in refs)
    return str(refs)


def _flatten_compliance(compliance: Dict, framework_display: str) -> str:
    if not compliance:
        return ""
    controls = compliance.get(framework_display, [])
    return "; ".join(c.get("control_id", "") for c in controls)


def _has_compliance(vulnerabilities) -> bool:
    return any(v.get("compliance") for v in vulnerabilities)


def build_csv(results: Dict) -> str:
    """Build CSV string from scan results.

    Args:
        results: Scan result dict with 'vulnerabilities' list.

    Returns:
        CSV string with UTF-8 BOM prefix.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    vulnerabilities = results.get("vulnerabilities", [])
    include_compliance = _has_compliance(vulnerabilities)

    columns = list(BASE_COLUMNS)
    if include_compliance:
        columns += COMPLIANCE_COLUMNS

    buf = io.StringIO()
    buf.write(_UTF8_BOM)
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(columns)

    for vuln in vulnerabilities:
        evidence = str(vuln.get("evidence", ""))[:_EVIDENCE_LIMIT]
        row = [
            str(vuln.get("type", "")),
            str(vuln.get("severity", "")),
            str(vuln.get("url", "")),
            str(vuln.get("parameter", "")),
            str(vuln.get("payload", "")),
            evidence,
            str(vuln.get("description", "")),
            str(vuln.get("remediation", "")),
            _flatten_cve(vuln.get("cve_references", [])),
            str(vuln.get("cvss_score", "")),
            timestamp,
        ]
        if include_compliance:
            compliance = vuln.get("compliance", {})
            for col in COMPLIANCE_COLUMNS:
                row.append(_flatten_compliance(compliance, _COMPLIANCE_KEY_MAP[col]))
        writer.writerow(row)

    return buf.getvalue()
