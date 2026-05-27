# Group E — Scan Diff / Baseline Comparison

**Date:** 2026-05-28
**Status:** Design — pending approval
**Scope:** Compare two scan result JSONs and produce a diff classifying each finding as new, fixed, or unchanged. Render diff reports in HTML/JSON/CSV.

---

## Goals

- Determine if a fix actually shipped (regression detection).
- Compare last-week vs this-week scans during pen-test engagements.
- Track posture trend across CI runs.
- Output a portable diff JSON + human HTML.

## Non-Goals

- Continuous historical timeline (out of scope; users keep their own JSON archives).
- DB-backed history (no schema, no migration burden).
- Severity drift across CVE re-scoring (treat severity as snapshot at scan time).

---

## Architecture

### CLI

```bash
python deep_eye.py --diff baseline.json current.json
python deep_eye.py --diff baseline.json current.json --diff-output report.html --diff-format html
```

`--diff` path1 path2:
- path1 = baseline (older scan)
- path2 = current (newer scan)
- Both must be JSON-format Deep Eye reports

`--diff-output`: where diff report goes. Defaults to `reports/diff_<timestamp>.html`.
`--diff-format`: `html`, `json`, `csv`. Default `html`.

When `--diff` is set, no scan runs — exits after diff.

### New module

```
core/scan_diff.py
  diff_scans(baseline: Dict, current: Dict) -> Dict
  load_scan_json(path: str) -> Dict
  normalize_url(url: str) -> str

utils/exports/diff_renderer.py
  render_html(diff: Dict, path: str)
  render_json(diff: Dict, path: str)
  render_csv(diff: Dict, path: str)
```

---

## Vuln Identity

A vuln "is the same" across scans when its **identity tuple** matches:

```python
(type, url_normalized, parameter, severity)
```

`url_normalized` strips trailing `/`, lowercases scheme+host, sorts query params alphabetically.

### Diff classification

| Class | Definition |
|-------|-----------|
| `new` | Identity in current, not in baseline |
| `fixed` | Identity in baseline, not in current |
| `unchanged` | Identity in both |
| `severity_changed` | Same (type, url, parameter), different severity |

### Diff result shape

```json
{
  "baseline": {"target": "...", "scan_time": "...", "vuln_count": N},
  "current":  {"target": "...", "scan_time": "...", "vuln_count": M},
  "summary": {
    "new": 3, "fixed": 5, "unchanged": 12, "severity_changed": 1, "net_delta": -2
  },
  "new":              [<vuln dicts>],
  "fixed":            [<vuln dicts from baseline>],
  "unchanged":        [<vuln dicts from current>],
  "severity_changed": [{"baseline": <vuln>, "current": <vuln>}]
}
```

---

## Components

```
core/scan_diff.py
utils/exports/diff_renderer.py

deep_eye.py
  + --diff path1 path2
  + --diff-output, --diff-format
  + main(): if args.diff -> run diff -> exit
```

### Renderer formats

**JSON:** dump diff dict.

**CSV:** flat — `status, type, severity, url, parameter, baseline_severity, current_severity, payload, evidence`. `status` ∈ {new, fixed, unchanged, severity_changed}.

**HTML:** standalone page. Three collapsible sections (New, Fixed, Severity Changed) + Unchanged summary count. Color-coded borders. Vanilla CSS, no external JS.

---

## Error Handling

| Failure | Behavior |
|---------|----------|
| JSON missing/malformed | Exit 2, error message |
| Different targets | Warn, continue |
| Vuln missing `type`/`url` | Skip, log warning |

---

## Testing

`tests/test_scan_diff.py`:

- `test_identity_normalization` — trailing slash equivalence
- `test_query_param_order` — ordering invariance
- `test_diff_new_only`
- `test_diff_fixed_only`
- `test_diff_unchanged`
- `test_severity_changed`
- `test_diff_summary_counts`
- `test_render_json`
- `test_render_csv`
- `test_render_html`

---

## Open Questions

None. Locked.

---

## Out of Scope

- Trend graphs across N scans
- DB-backed history
- Auto-baseline retention
