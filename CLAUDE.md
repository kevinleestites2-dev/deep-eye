# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Deep Eye is an AI-driven penetration testing tool. It orchestrates multiple AI providers for payload generation, scans targets for 45+ vulnerability types, and produces professional reports. Python 3.8+, MIT license, v1.4.0 (Code Name: Hanzou).

## Commands

```bash
# Setup
pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml

# Browser automation (optional)
pip install playwright && playwright install chromium

# Run
python deep_eye.py -u https://example.com
python deep_eye.py -c config/config.yaml
python deep_eye.py -u https://example.com -v        # verbose
python deep_eye.py -u https://example.com --no-banner

# CVE database update
python scripts/update_cve_database.py

# Tests
pytest
pytest tests/test_litellm_provider.py -v   # unit tests
python tests/e2e_litellm.py                # e2e test
```

## Architecture

**Scan Flow**: CLI → `ScannerEngine` → Web Crawler → URL Discovery → `AIPayloadGenerator` → `VulnerabilityScanner` → `ReportGenerator`

### Layers

| Layer | Purpose |
|-------|---------|
| `core/` | Orchestration: scanner engine, vuln scanner, AI payload gen, report gen, state manager, subdomain scanner, plugin manager |
| `ai_providers/` | Unified interface to OpenAI, Claude, Grok, OLLAMA, Gemini, Groq, Mistral, OpenRouter, LiteLLM, LM Studio. All implement `generate(prompt, **kwargs) -> str` |
| `modules/` | Specialized testers: api_security, authentication, browser_automation, business_logic, cve_intelligence, file_upload, ml_detection, payload_obfuscation, reconnaissance, reporting, secrets_scanner, websocket, collaboration |
| `utils/` | http_client, config_loader, parser, logger, notification_manager |
| `scripts/` | CVE database updater, notification tester |

### Key Design Decisions

- **Config-driven**: Almost all behavior controlled via `config/config.yaml`. CLI is intentionally minimal (target URL, config path, verbose flag).
- **Multi-threaded scanning**: `ScannerEngine` uses `ThreadPoolExecutor` for concurrent URL scanning. Thread count configurable 1-50.
- **Browser automation is hybrid**: Playwright handles deterministic tests (SQLi, DOM XSS, clickjacking). Browser Use AI (experimental, disabled by default) handles intelligent tests (XSS, hidden elements). Automatic fallback to Playwright when AI unavailable.
- **AI provider abstraction**: All providers share `generate()` interface. `provider_manager.py` handles failover/retry.
- **State tracking**: `PentestStateManager` tracks phases (RECON → CRAWLING → VULNERABILITY_SCAN → REPORTING) with per-attack progress.

### Vulnerability Result Format

All scanners return dicts with: `type`, `severity` (critical/high/medium/low/info), `url`, `parameter`, `payload`, `evidence`, `remediation`, optional `cve_references`.

## Development Patterns

### Adding a vulnerability check
1. Add `_check_new_vuln(self, url, payloads)` method to `core/vulnerability_scanner.py`
2. Register in `scan()` with state manager start/end calls
3. Add to `config.example.yaml` `enabled_checks` list

### Adding an AI provider
1. Create class in `ai_providers/` with `generate(prompt, **kwargs) -> str`
2. Register in `provider_manager.py` `_initialize_providers()`
3. Add config section to `config.example.yaml`

### Adding a plugin
Create class in `plugins/` with `__init__(self, http_client, config)` and `scan(self, url) -> List[Dict]`. Enable via `plugin_manager.enabled: true` in config.

## Important Context

- **Authorized testing only** — never scan without explicit permission
- **Windows primary dev environment** — uses ReportLab (not WeasyPrint) for PDF, `pathlib.Path` for cross-platform paths
- **Tests exist** in `tests/` — LiteLLM provider unit + e2e tests
- **Virtual env** at `.deep-venv/` (gitignored)
- **SQLite databases**: `data/deep_eye.db` (scan results), `data/cve_intelligence.db` (CVE data)
- **Experimental features** gated behind `experimental.*` config flags: CVE matching, subdomain scanning
- **Notifications** (v1.3.0): Email/Slack/Discord via `utils/notification_manager.py`
