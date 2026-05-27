# Group B — Compliance Framework Mapping (PCI-DSS, SOC 2, ISO 27001)

**Date:** 2026-05-28
**Status:** Design — pending approval
**Scope:** Tag each vulnerability with the compliance controls it violates across PCI-DSS v4.0, SOC 2, and ISO/IEC 27001:2022. Render mappings in HTML/PDF/JSON/SARIF/CSV/Excel reports.

---

## Goals

- Map each vuln type to control IDs from PCI-DSS v4.0, SOC 2 (Common Criteria), ISO 27001:2022 (Annex A).
- Surface mappings in every report format (HTML new section, PDF table, JSON field, CSV columns, xlsx Compliance sheet populated).
- Support config opt-in to enable / disable per framework.
- Auditor-friendly export: list of failing controls per framework.

## Non-Goals

- Auto-attestation generation (requires evidence collection beyond scan scope).
- HIPAA, FedRAMP, NIST CSF (out of scope; future cycle).
- Per-org control customization (use defaults; framework JSON files editable post-install).

---

## Architecture

### New module

```
utils/compliance/
  __init__.py
  mapper.py
  frameworks/
    pci_dss_v4.json
    soc2_cc.json
    iso_27001_2022.json
```

### Mapping data shape

Each framework JSON:
```json
{
  "framework": "PCI-DSS",
  "version": "4.0",
  "controls": {
    "6.2.4": {"title": "Engineering practices prevent common vulns", "category": "Develop secure software"},
    "6.4.1": {"title": "Public-facing web apps protected against attacks", "category": "WAF"}
  },
  "vuln_mappings": {
    "SQL Injection": ["6.2.4", "6.4.1"],
    "XSS": ["6.2.4", "6.4.1"]
  }
}
```

### Mapping function

```python
def map_vuln(vuln_type: str, frameworks: List[str] = None) -> Dict[str, List[Dict]]:
    """
    Returns: {
      "PCI-DSS": [{"control_id": "6.2.4", "title": "...", "category": "..."}, ...],
      "SOC 2":   [...],
      "ISO 27001": [...]
    }
    """
```

### Integration

Post-scan enrichment in `ScannerEngine.scan()` adds to each vuln:

```python
vuln["compliance"] = {
    "PCI-DSS": [{"control_id": "6.2.4", ...}, ...],
    "SOC 2": [...],
    "ISO 27001": [...]
}
```

### Config

```yaml
compliance:
  enabled: true
  frameworks: [pci_dss, soc2, iso_27001]
```

---

## Vuln-Type → Control Mappings (initial set)

Sample:

| Vuln Type | PCI-DSS v4.0 | SOC 2 CC | ISO 27001:2022 |
|-----------|--------------|----------|----------------|
| SQL Injection | 6.2.4, 6.4.1 | CC6.6, CC7.1 | A.8.28, A.8.29 |
| XSS | 6.2.4, 6.4.1 | CC6.6 | A.8.28 |
| Command Injection | 6.2.4 | CC6.6 | A.8.28 |
| Path Traversal | 6.2.4, 6.4.1 | CC6.6, CC6.1 | A.8.28, A.5.15 |
| SSRF | 6.4.1 | CC6.6, CC6.7 | A.8.20 |
| XXE | 6.2.4 | CC6.6 | A.8.28 |
| Authentication Bypass | 8.3.1, 8.3.4 | CC6.1 | A.8.5, A.5.16 |
| Insecure Deserialization | 6.2.4 | CC6.6 | A.8.28 |
| CSRF | 6.4.1 | CC6.7 | A.8.23 |
| Open Redirect | 6.2.4 | CC6.6 | A.8.28 |
| Sensitive Data Exposure | 3.5.1, 3.5.1.2 | CC6.1, CC6.7 | A.8.10, A.8.24 |
| IDOR | 8.3.1 | CC6.1 | A.5.15 |
| Security Misconfiguration | 2.2.1 | CC6.1 | A.8.9 |
| Weak Cryptography | 4.2.1 | CC6.1 | A.8.24 |
| TLS Issues | 4.2.1 | CC6.7 | A.8.24 |
| Information Disclosure | 1.4.4 | CC6.1 | A.5.10 |
| Subdomain Takeover | 2.2.1 | CC6.6 | A.8.9 |
| Mass Assignment | 6.2.4 | CC6.6 | A.8.28 |
| NoSQL Injection | 6.2.4 | CC6.6 | A.8.28 |
| Race Condition | 6.2.4 | CC6.6 | A.8.28 |
| Log4Shell / RCE | 6.3.1, 6.3.3 | CC7.1 | A.8.8 |
| Cache Poisoning | 6.4.1 | CC6.6 | A.8.23 |
| HTTP Smuggling | 6.4.1 | CC6.6 | A.8.23 |
| Prototype Pollution | 6.2.4 | CC6.6 | A.8.28 |
| OAuth Issues | 8.3.1 | CC6.1 | A.5.16 |
| SAML Issues | 8.3.1 | CC6.1 | A.5.16 |
| Secret Leak | 8.3.4, 3.5.1 | CC6.1 | A.5.10, A.8.10 |

Unknown vuln types map to empty lists (legitimate state).

---

## Report Rendering

- **JSON:** `vuln["compliance"]` embedded as-is.
- **SARIF:** rule `properties.compliance` carries framework→control_ids.
- **CSV:** 3 extra columns when compliance enabled: `compliance_pci_dss, compliance_soc2, compliance_iso_27001` (`"; "`-joined IDs).
- **xlsx:** populates Compliance sheet (one row per framework×control×vuln). Adds Control Summary sheet with pivot counts.
- **HTML:** new "Compliance Mapping" section with stats cards + collapsible table per framework.
- **PDF:** ReportLab table per framework: control_id | title | violation_count | max_severity.

---

## Components

```
utils/compliance/                # new package
core/scanner_engine.py           # + _enrich_compliance(results) post-scan
core/report_generator.py         # + HTML/PDF compliance sections, SARIF properties
utils/exports/csv_builder.py     # optional 3 columns when present
utils/exports/xlsx_builder.py    # populate Compliance + Control Summary sheets
config/config.example.yaml       # compliance:{enabled,frameworks}
```

---

## Error Handling

| Failure | Behavior |
|---------|----------|
| Framework JSON missing/malformed | Log warn/error, skip that framework |
| Vuln type not in mapping | Empty list (no error) |
| Compliance disabled | Skip enrichment, reports omit sections |

---

## Testing

`tests/test_compliance_mapping.py`:

- `test_load_frameworks` — all 3 JSONs parse
- `test_map_known_vuln` — SQL Injection returns non-empty for all 3 frameworks
- `test_map_unknown_vuln` — unknown returns empty, no crash
- `test_framework_filter` — `frameworks=["pci_dss"]` returns only PCI-DSS
- `test_enrich_results` — `_enrich_compliance` adds `compliance` key to each vuln
- `test_csv_with_compliance` — CSV has 3 extra columns
- `test_xlsx_compliance_sheet_populated` — body rows present
- `test_xlsx_control_summary_sheet` — pivot sheet exists
- `test_compliance_disabled` — vuln dict unchanged

---

## Migration / Compat

- Vuln dict gains optional `compliance` field. All renderers treat it as optional.
- Group A xlsx placeholder Compliance sheet becomes populated.
- No breaking changes.

---

## Open Questions

None. Locked.

---

## Out of Scope

- HIPAA, FedRAMP, NIST CSF
- Auto-attestation evidence
- Custom catalogs (edit JSON to customize)
