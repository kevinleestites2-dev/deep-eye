# SentinelPrime — Security Operations Protocol

## Mission
Protect the Pantheon. Generate revenue via bug bounties.
Two modes: Defensive (audit Pantheon assets) and Offensive (bug bounty hunting).

## Defensive Mode — Pantheon Asset Hardening

### Before ANY Pantheon asset goes live:
```bash
cd ~/deep-eye

# Quick scan (5-10 min)
python deep_eye.py -u https://[target] --formats json

# Full scan with compliance (30-60 min)
python deep_eye.py -u https://[target] -v --formats html,json,pdf
```

### What to look for:
- CRITICAL/HIGH findings → fix before launch
- Secrets exposed in headers or responses → rotate immediately
- Misconfigurations → patch config
- Subdomain takeover → claim or remove DNS records

## Offensive Mode — Bug Bounty Hunting

### Target Selection
1. Browse HackerOne: https://hackerone.com/programs
2. Filter: active programs, web targets, scope includes subdomains
3. Pick targets running known vuln stacks (PHP, older Django, etc.)
4. Start with smaller programs (less competition, faster triage)

### Execution
```bash
# Recon first
python deep_eye.py -u https://target.com --enable-recon -v

# Full offensive scan
python deep_eye.py -u https://target.com -v --formats json,html

# AI triage auto-generates bounty report
# Find it in: reports/bounty/
```

### Submission
- Reports auto-formatted for HackerOne Markdown
- Include: vuln type, CVSS score, reproduction steps, impact, remediation
- Submit → typical response 3-14 days
- Payouts: $150 (low) → $500 (medium) → $2,000 (high) → $10,000+ (critical)

## GhostPrime CF Bypass Integration

The `modules/challenge_solver/` directory contains Playwright-based
Cloudflare/Akamai solvers. Extract and integrate:

```python
# In GhostPrime swarm_commander_v2.py
from deep_eye.modules.challenge_solver.detector import detect_challenge
from deep_eye.modules.challenge_solver.solver import ChallengeSolver

async def get_cf_cookies(url, session):
    challenge = await detect_challenge(url)
    if challenge:
        solver = ChallengeSolver()
        cookies = await solver.solve(url)
        session.cookie_jar.update_cookies(cookies)
    return session
```

## Reporting Schedule
- Weekly: run audit on all Pantheon assets
- Monthly: update CVE database + rebuild RAG index
- On new asset launch: full scan before public

## War Chest Contribution Target
- 2 medium bugs/month = ~$1,000 → War Chest
- 1 high bug/month = ~$2,000 → War Chest
- Realistic starting target: $500-$1,000/month from bug bounties
