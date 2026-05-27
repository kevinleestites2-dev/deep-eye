# Group C — AI Auto-Triage, FP Reduction, Bug Bounty Writer

**Date:** 2026-05-28
**Status:** Design — pending approval
**Scope:** Use AI providers (already wired in `ai_providers/`) to: (1) re-validate findings and flag likely false positives, (2) score confidence, (3) generate bug bounty submission markdown for high-severity findings.

---

## Goals

- Reduce noise: drop or down-rank findings the AI judges as likely false positive.
- Add `confidence` and `triage_reason` fields per vuln.
- For each critical/high finding, optionally generate a Markdown bug bounty report.
- Strict opt-in via config; never enabled by default.

## Non-Goals

- Replace human review.
- Re-test exploits.
- Multi-provider voting.

---

## Architecture

### New module

```
modules/ai_triage/
  __init__.py
  triage.py
  bounty_writer.py
  prompts.py
```

### Triage flow

```
ScannerEngine.scan()
  -> existing scan loop produces self.vulnerabilities
  -> RAG enrichment (Group F)
  -> Compliance enrichment (Group B)
  -> AI Triage (Group C)
       -> per vuln: build prompt → AI returns JSON {confidence, false_positive, reason}
       -> attach fields; optionally drop FPs
  -> Bug bounty writer (Group C)
       -> per high/critical surviving vuln: generate markdown
       -> attach as vuln['bounty_report']
```

### Triage prompt

```
You are a security expert reviewing a vulnerability finding.

Finding:
  Type: {type}
  URL: {url}
  Parameter: {parameter}
  Severity: {severity}
  Payload: {payload}
  Evidence: {evidence}
  Description: {description}

Determine if TRUE POSITIVE or FALSE POSITIVE.

Common false positives:
- Reflected input without script execution context
- Error messages without stack traces or DB schema
- Open redirect to same-origin
- Standard headers misflagged as sensitive

Return ONLY JSON:
  confidence: float 0.0-1.0
  false_positive: boolean
  reason: brief explanation
```

### Bug bounty writer prompt

```
Generate a HackerOne-format Markdown bug report.

Vulnerability:
  Type: {type}
  Severity: {severity}
  CVSS: {cvss_score}
  URL: {url}
  Parameter: {parameter}
  Payload: {payload}
  Evidence: {evidence}
  Description: {description}
  Remediation: {remediation}

Required sections:
  ## Summary
  ## Steps to Reproduce
  ## Impact
  ## Proof of Concept (payload in code block)
  ## Suggested Fix
  ## Severity Justification

Clear, concise. No marketing fluff.
```

### API

```python
class AITriage:
    def __init__(self, ai_manager, config: Dict)
    def triage_vulnerabilities(self, vulnerabilities: List[Dict]) -> None
    def is_enabled(self) -> bool

class BountyWriter:
    def __init__(self, ai_manager, config: Dict)
    def generate_reports(self, vulnerabilities: List[Dict]) -> None
```

### Config

```yaml
ai_triage:
  enabled: false
  drop_false_positives: false
  drop_threshold: 0.8
  min_severity: "high"

bug_bounty:
  enabled: false
  format: "hackerone"
  min_severity: "high"
  output_directory: "reports/bounty"
  one_file_per_vuln: true
```

### Vuln dict additions

```python
vuln["confidence"]: float
vuln["false_positive"]: bool
vuln["triage_reason"]: str
vuln["bounty_report"]: str
```

---

## Components

```
modules/ai_triage/__init__.py
modules/ai_triage/triage.py
modules/ai_triage/bounty_writer.py
modules/ai_triage/prompts.py

core/scanner_engine.py
  + invoke AITriage after RAG/compliance
  + invoke BountyWriter and write per-vuln markdown

config/config.example.yaml
  + ai_triage: {...}
  + bug_bounty: {...}
```

---

## Error Handling

| Failure | Behavior |
|---------|----------|
| AI provider unavailable | Skip triage, log warning |
| Malformed JSON from AI | Default safe: low confidence, true positive |
| Rate limit/timeout | Skip remaining triage |
| Bounty per-vuln failure | Log, continue |

Triage/bounty never block scan completion.

---

## Testing

Mock AI provider with canned JSON.

- `test_triage_attaches_fields`
- `test_triage_drops_fp_above_threshold`
- `test_triage_keeps_fp_below_threshold`
- `test_triage_min_severity_filter`
- `test_triage_handles_malformed_json`
- `test_triage_provider_unavailable`
- `test_bounty_writer_generates_markdown`
- `test_bounty_writer_min_severity_filter`
- `test_bounty_writer_one_file_per_vuln`

---

## Migration / Compat

- All fields optional.
- Default config off — zero impact.
- No AI provider interface change.

---

## Open Questions

None. Locked.

---

## Out of Scope

- Multi-provider voting
- Browser-based re-testing
- Auto-submit to HackerOne/Bugcrowd
- Triage queues
