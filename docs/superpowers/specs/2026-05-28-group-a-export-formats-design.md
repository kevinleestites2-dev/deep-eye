# Group A — Export Formats (JUnit XML, CSV, Excel)

**Date:** 2026-05-28
**Status:** Design — pending approval
**Scope:** Add three new report output formats to `core/report_generator.py` without rewriting existing HTML/PDF/JSON/SARIF paths.

---

## Goals

- CI-friendly JUnit XML for build gates (Jenkins, GitLab, Azure DevOps test reporters).
- Flat CSV for spreadsheet pivots, BI ingestion, and ad-hoc grep.
- Multi-sheet Excel workbook for executive distribution.
- Multi-format emit in one scan run.
- Zero impact on existing HTML/PDF/JSON/SARIF output.

## Non-Goals

- Compliance tagging in exports (deferred to Group B; Excel reserves a placeholder sheet).
- CSV severity filtering (export everything; let consumer filter).
- Streaming export for very large scans (current scans fit in memory).

---

## Architecture

### Current state

`ReportGenerator.generate(results, output_path, format)` dispatches on `format` string to one of `_generate_html|_generate_pdf|_generate_json|_generate_sarif`. Each method writes one file at `output_path`.

### Change shape

Three new dispatch branches, three new private methods:

| Format key | Method | Extension |
|------------|--------|-----------|
| `junit` | `_generate_junit(results, output_path)` | `.xml` |
| `csv` | `_generate_csv(results, output_path)` | `.csv` |
| `xlsx` | `_generate_xlsx(results, output_path)` | `.xlsx` |

Existing dispatch keeps current behavior. New keys are additive.

### Multi-format dispatch

`deep_eye.py` currently honors single `reporting.default_format` from config. Add CLI flag `--formats` (comma-separated) and config key `reporting.formats` (list). Resolution precedence:

1. CLI `--formats junit,csv,xlsx` → emit each as sibling files
2. config `reporting.formats: [junit, csv, xlsx]` → same
3. fallback: existing `reporting.default_format` (single)

When multi-format is active, `output_filename` (if set) is treated as a stem; extensions are appended per format. When unset, generated stem is reused across formats.

Example:
```
reports/
  deep_eye_example.com_20260528_184400.junit.xml
  deep_eye_example.com_20260528_184400.csv
  deep_eye_example.com_20260528_184400.xlsx
```

### Lazy install for openpyxl

`openpyxl` is **not** added to `requirements.txt`. `_generate_xlsx` imports lazily; on `ImportError`:

```
[!] xlsx export needs openpyxl. Install now? [y/N]:
```

- Yes → `subprocess.run([sys.executable, "-m", "pip", "install", "openpyxl"])`, then retry import.
- No → log warning, skip xlsx (other formats still emit), exit code unchanged.

Non-interactive runs (no TTY): skip prompt, log warning, skip xlsx.

---

## Format Specs

### JUnit XML

One `<testsuite>` per scan. One `<testcase>` per vulnerability. Vulnerability = test failure.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="Deep Eye" tests="42" failures="42" errors="0" time="123.45">
  <testsuite name="https://example.com" tests="42" failures="42" timestamp="2026-05-28T18:44:00Z">
    <testcase classname="SQL Injection" name="https://example.com/login?user=admin" time="0">
      <failure type="critical" message="SQL Injection on parameter 'user'">
        Payload: ' OR 1=1--
        Evidence: MySQL syntax error in response
        Remediation: Use parameterized queries
        CVE: CVE-2021-XXXX (if present)
      </failure>
    </testcase>
    ...
  </testsuite>
</testsuites>
```

Mapping rules:
- `testsuite.name` = scan target URL
- `testcase.classname` = vuln `type`
- `testcase.name` = vuln `url` (with parameter if present: `url [param]`)
- `failure.type` = vuln `severity`
- `failure.message` = `"{type} on parameter '{parameter}'"` (or just type)
- `failure` body = multiline: payload, evidence (truncated to 500 chars), remediation, CVE refs
- `tests` and `failures` counts equal vuln count (no passing testcases — informational design choice)
- `time` = scan duration in seconds when available, else `0`

Library: stdlib `xml.etree.ElementTree`. Escape via `ElementTree`'s built-in handling.

### CSV

Single sheet, comma-delimited, UTF-8 BOM (Excel friendly), RFC 4180 quoting.

Columns (fixed order):
```
type, severity, url, parameter, payload, evidence, description, remediation, cve_references, cvss_score, timestamp
```

- `evidence` truncated to 1000 chars (CSV cell sanity)
- `cve_references` joined with `;` if list
- `cvss_score` from `vuln.get('cvss_score', '')`
- `timestamp` = scan timestamp (same value all rows)
- All values pass through `csv.writer` (handles quoting)
- No header customization, no severity filter

Library: stdlib `csv`.

### Excel (xlsx)

Workbook with five sheets in order:

| Sheet | Contents |
|-------|----------|
| **Summary** | Target, scan duration, URL count, severity counts, generation date. Single column-pair table. |
| **Vulnerabilities** | Same columns as CSV + severity-colored row fill. Frozen header. Auto-filter on. |
| **Reconnaissance** | DNS records (record_type, value), OSINT (emails, subdomains, github_leaks, breaches), technologies. One section per category, blank-row separated. |
| **CVEs** | Pivot of `cve_references` field. Columns: cve_id, vuln_type, url, severity, cvss_score. Empty if none found. |
| **Compliance** | Headers only: `framework, control_id, vulnerability_type, severity, status`. Empty body. Populated when Group B lands. |

Severity colors (cell fill on Vulnerabilities sheet):
- critical: `#8B0000` (white text)
- high: `#FF4500` (white text)
- medium: `#FFA500` (black text)
- low: `#FFD700` (black text)
- info: `#87CEEB` (black text)

Library: `openpyxl` (lazy install).

---

## Components

```
core/report_generator.py
  ReportGenerator
    + generate(results, output_path, format)         # extended dispatch
    + _generate_junit(results, output_path)          # new
    + _generate_csv(results, output_path)            # new
    + _generate_xlsx(results, output_path)           # new
    + _ensure_openpyxl()                             # new — lazy install helper

utils/exports/  (new package)
  junit_builder.py     # ElementTree assembly, kept out of generator for testability
  csv_builder.py       # row flattening logic
  xlsx_builder.py      # workbook construction, sheet builders

deep_eye.py
  + --formats CLI flag
  + multi-format emission loop in main()

config/config.example.yaml
  reporting:
    formats: [html]              # NEW — list form, default keeps current behavior
    default_format: html         # kept for back-compat
```

`utils/exports/` keeps each builder ≤200 lines, isolates stdlib XML/csv/openpyxl details from `report_generator.py`. Generator stays a thin dispatcher.

---

## Data Flow

```
ScannerEngine.scan() -> results dict
                          |
                          v
              ReportGenerator.generate(results, path, fmt)
                          |
            +-------------+-------------+--------+--------+--------+
            v             v             v        v        v        v
        _generate_    _generate_    _generate_ _gen_   _gen_    _gen_
        html         pdf          json/sarif  junit   csv      xlsx
                                                |       |        |
                                                v       v        v
                                         junit_builder csv_   xlsx_
                                                       builder builder
```

`deep_eye.py` loops over resolved formats list, calling `report_gen.generate()` once per format with adjusted output path.

---

## Error Handling

| Failure | Behavior |
|---------|----------|
| `openpyxl` missing, user declines install | Log warning, skip xlsx, continue other formats |
| `openpyxl` missing, non-interactive | Log warning, skip xlsx |
| Vuln dict missing fields | Use `.get(key, '')` defaults — never crash |
| Disk write error | Log error, continue to next format |
| Empty vuln list | Still emit valid empty file (testsuite with 0 tests, CSV header only, xlsx with sheets but empty Vulns/CVEs) |

No format failure aborts other formats. CLI exit code reflects scanner success, not export success.

---

## Testing

`tests/test_export_formats.py`:

| Test | Assertion |
|------|-----------|
| `test_junit_basic` | Valid XML, testcase count = vuln count, failure type matches severity |
| `test_junit_empty` | Empty vuln list → testsuite with 0 tests, parses |
| `test_junit_xml_escaping` | Vuln with `<script>` in evidence → properly escaped |
| `test_csv_columns` | Header row matches spec, row count = vuln count |
| `test_csv_quoting` | Evidence with commas/newlines → properly quoted |
| `test_csv_utf8_bom` | First bytes = `\xef\xbb\xbf` |
| `test_xlsx_sheets` | All 5 sheets present, in order |
| `test_xlsx_severity_colors` | Vulnerability rows have expected fill colors |
| `test_xlsx_compliance_placeholder` | Compliance sheet exists, header-only |
| `test_xlsx_lazy_install_missing` | `openpyxl` mocked-missing → log warning, no crash |
| `test_multi_format_dispatch` | `--formats junit,csv,xlsx` → 3 sibling files |

Use `pytest` + `tempfile.TemporaryDirectory`. Mock `openpyxl` import for the missing-dep test via `sys.modules`.

---

## Migration / Compat

- `reporting.default_format` continues working (single format). `reporting.formats` list takes precedence when present.
- Existing `--config` workflows unchanged.
- No changes to vuln dict shape (Group B will add `compliance` field later — this design tolerates absent field).

---

## Open Questions

None. All decisions locked:
- Q1: 1 testcase per vuln
- Q2: no severity filter on CSV
- Q3: sheets = Summary, Vulns, Recon, CVEs, Compliance placeholder
- Q4: `--formats` CLI list + config `reporting.formats`
- Q5: lazy install prompt for openpyxl

---

## Out of Scope (Future Groups)

- B: populate Compliance sheet
- C: AI triage column in CSV/xlsx
- E: scan diff exports (will be its own format)
- I: async safety of file writes (current sync writes are fine)
