# Deep Eye — Pantheon Integration
**Forked for the Pantheon | 2026-05-31**
**Source:** https://github.com/zakirkun/deep-eye
**Version:** v1.4.0 (codename: Hestia)
**Status:** FORKED ✅ | Deploy Target: Termux (now) + The Nexus (full power)

---

## Pantheon Role: SentinelPrime — Offensive & Defensive Security Layer

Deep Eye serves the Pantheon on two fronts:

### Offensive (Revenue)
- Scan targets for 45+ vuln types with AI-generated payloads
- Auto-generate HackerOne-format bug bounty reports
- CVE RAG index finds real exploits for detected tech stacks
- Bug bounty = passive revenue stream requiring zero capital

### Defensive (Protection)
- Audit every Pantheon asset before going live
- Scan GhostPrime faucet sites, PropPilot landing page, Nexus Relay
- Know your own holes before someone else does
- Compliance reports (PCI-DSS, SOC2, ISO 27001) for PropPilot clients

---

## GhostPrime Synergy — Cloudflare Bypass Module

Deep Eye's `challenge_solver` module solves the exact problem GhostPrime
fights every cycle: Cloudflare/Akamai challenge bypass.

**Extract and wire into GhostPrime:**
```python
from modules.challenge_solver import ChallengeSolver
# Gets cf_clearance + _abck cookies
# Injects into aiohttp session
# Per-domain TTL cache — no re-solving same domain
```

This is a direct upgrade to GhostPrime stealth. Priority integration.

---

## Quick Start (Termux — works now)

```bash
git clone https://github.com/kevinleestites2-dev/deep-eye
cd deep-eye
chmod +x scripts/install.sh && ./scripts/install.sh
# OR manual:
pip install -r requirements.txt

# Configure AI provider (free — Ollama)
# Edit config/config.yaml:
# ai_providers:
#   ollama:
#     base_url: "[Ollama tunnel from TOOLS.md]"
#     model: "llama3"

# Basic scan
python deep_eye.py -u https://target.com

# Full scan with verbose output
python deep_eye.py -u https://target.com -v

# Generate compliance report
python deep_eye.py -u https://target.com --formats html,json,pdf
```

## Quick Start (Nexus — full power)

```bash
# Same as above but with local Ollama (no tunnel latency)
# ai_providers.ollama.base_url: "http://localhost:11434"
# + playwright install for CF bypass
pip install playwright && playwright install chromium
```

---

## Pantheon Asset Audit Queue

Run Deep Eye against every Pantheon asset before launch:

| Target | Priority | Status |
|---|---|---|
| https://kevinleestites2-dev.github.io/faucet-master/ | HIGH | QUEUED |
| https://nexus-relay-production.up.railway.app | HIGH | QUEUED |
| PropPilot landing page (prop_clone) | MEDIUM | QUEUED |
| OpenAgora API endpoints | MEDIUM | QUEUED |

---

## Bug Bounty Pipeline

1. Find target on HackerOne/Bugcrowd with active program
2. Run Deep Eye: `python deep_eye.py -u https://target.com -v`
3. AI triage auto-filters false positives
4. Bug bounty writer auto-generates HackerOne Markdown report
5. Submit → collect bounty → War Chest

**CVE database update (run monthly):**
```bash
python scripts/update_cve_database.py
python scripts/build_cve_rag_index.py
```

---

## LLM Config (Free Options)

```yaml
# Ollama (local, free)
ai_providers:
  ollama:
    base_url: "[tunnel URL from TOOLS.md]"
    model: "llama3"

# OpenRouter (free tier)
ai_providers:
  openrouter:
    api_key: "[key from TOOLS.md]"
    model: "meta-llama/llama-3-70b-instruct"

# Groq (free tier, fast)
ai_providers:
  groq:
    api_key: "[groq key if obtained]"
    model: "llama3-70b-8192"
```

---

## Integration Queue
- [ ] Extract CF/Akamai bypass module → wire into GhostPrime stealth layer
- [ ] Audit all Pantheon assets (see queue above)
- [ ] Set up bug bounty pipeline on HackerOne
- [ ] Update CVE database (NVD/MITRE/Exploit-DB)
- [ ] Build RAG index: `python scripts/build_cve_rag_index.py`
- [ ] Full Nexus deploy with Playwright for CF bypass
