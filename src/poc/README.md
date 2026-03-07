# Wazuh Agentic SOC — Proof of Concept

A self-contained demo showing how AI agents can triage, enrich, investigate, and make decisions on security alerts — the same way an agentic SOC would operate on top of Wazuh.

## What This Demonstrates

**The pipeline processes each alert through 4 stages:**

```
  Wazuh Alert
       │
       ▼
  ┌─────────────┐
  │ TRIAGE AGENT│  Claude Haiku (fast, cheap)
  │             │  Classifies severity, identifies FPs,
  │             │  decides if enrichment/investigation needed
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │ ENRICHMENT  │  Deterministic (no LLM)
  │             │  VirusTotal, AbuseIPDB, MISP lookups
  │             │  MITRE ATT&CK context
  └──────┬──────┘
         │
         ▼
  ┌──────────────────┐
  │ INVESTIGATION    │  Claude Sonnet (stronger reasoning)
  │ AGENT            │  Attack narrative, IOC correlation,
  │                  │  MITRE chain, affected assets
  └──────┬───────────┘
         │
         ▼
  ┌─────────────┐
  │ DECISION    │  Claude Haiku
  │ AGENT       │  Auto-close noise, auto-block IPs,
  │             │  escalate critical to humans
  └─────────────┘
```

## Setup

```bash
# 1. Install the only dependency
pip install anthropic

# 2. Set your API key
export ANTHROPIC_API_KEY=sk-ant-...

# 3. Run from the repo root
python -m src.poc
```

## Usage

```bash
# Run all 5 scenarios (brute force, malware, C2, privesc, false positive)
python -m src.poc

# Run a single scenario
python -m src.poc c2_beacon

# Run specific scenarios
python -m src.poc brute_force malware
```

## Scenarios

| Scenario | What Happens | Expected AI Decision |
|----------|-------------|---------------------|
| `brute_force` | SSH brute force from Tor exit node (185.220.101.34) | Block IP + monitor |
| `malware` | Known Emotet/AgentTesla hash dropped on endpoint | Isolate host (needs human approval) + quarantine |
| `c2_beacon` | Outbound Cobalt Strike beacon to C2 server | Isolate host + block IP + escalate to IR team |
| `privesc` | User runs `sudo /bin/bash` (suspicious root shell) | Investigate + alert SOC |
| `false_positive` | Web scanner 404s on `/.env` (routine noise) | Auto-close |

## What to Show Your SOC Team

1. **AI Triage is instant** — Each alert is classified in ~1 second vs. 15-30 minutes for a human analyst
2. **Enrichment adds context** — IP reputation, malware family, MITRE ATT&CK mapping happen automatically
3. **Investigation produces narratives** — The AI writes the kind of analysis a Tier 2 analyst would
4. **Human-in-the-loop is built in** — High-impact actions (host isolation, account disable) always require human approval
5. **False positives are auto-closed** — Low-severity scanner noise is closed without wasting analyst time

## Cost Estimate

For a demo run of all 5 scenarios:
- ~13 API calls (5 triage + 4 investigation + 4 decision, skipping investigation on FPs)
- Estimated cost: ~$0.02-0.05 per full run
- In production with caching: ~$0.005 per alert

## Architecture Notes

- **No Wazuh instance required** — Alerts are simulated with realistic structure
- **No external APIs required** — Threat intel enrichment is simulated
- **Only dependency is `anthropic`** — Minimal setup friction
- **Structured JSON output** — Every agent returns parseable JSON for downstream automation

In production, you'd replace the simulated alerts with the Wazuh MCP Server or Indexer API, and the simulated enrichment with real VirusTotal/MISP/AbuseIPDB calls.
