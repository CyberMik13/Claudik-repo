# Wazuh Agentic SOC — Proof of Concept

A self-contained demo showing how a Master AI Agent (Opus) orchestrates specialized sub-agents to triage, enrich, investigate, and make decisions on security alerts — the same way an agentic SOC would operate on top of Wazuh.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  MASTER AGENT (Claude Opus) — "SOC Director"         │
│                                                      │
│  Receives raw alert, decides which agents to invoke, │
│  reviews their output, can re-run agents with extra  │
│  guidance, skips unnecessary steps, and produces an  │
│  executive briefing when done.                       │
│                                                      │
│  Available tools (invoked via Claude tool_use):      │
│  ┌────────────┐ ┌────────────┐ ┌───────┐ ┌────────┐ │
│  │  Triage    │ │  Enrich    │ │Invest-│ │Decision│ │
│  │  Agent     │ │  (TI)      │ │igate  │ │ Agent  │ │
│  │  (Haiku)   │ │(determin.) │ │Agent  │ │(Haiku) │ │
│  │            │ │            │ │(Sonnet)│ │        │ │
│  └────────────┘ └────────────┘ └───────┘ └────────┘ │
└──────────────────────────────────────────────────────┘
```

### What Makes This "Agentic"

The Master Agent doesn't follow a hardcoded pipeline. It **decides dynamically**:

- **Skip investigation** for obvious false positives (saves cost + time)
- **Re-run triage** with guidance if confidence is low
- **Re-run investigation** with follow-up questions if the first pass misses details
- **Add extra steps** for complex multi-stage attacks
- **Produce executive briefings** that synthesize all findings

This is the difference between automation (fixed scripts) and agentic AI (adaptive reasoning).

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
# Run all 5 scenarios
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

1. **Master Agent orchestration** — Opus decides which sub-agents to call and when, not a hardcoded script
2. **Dynamic routing** — False positives may skip investigation entirely; critical alerts get full treatment
3. **AI Triage is instant** — Each alert classified in ~1 second vs. 15-30 minutes for a human
4. **Enrichment adds context** — IP reputation, malware family, MITRE ATT&CK mapping
5. **Investigation produces narratives** — The AI writes Tier 2-quality analysis
6. **Human-in-the-loop** — High-impact actions always require human approval
7. **Executive briefings** — The Master Agent summarizes everything for management

## Model Tiers & Cost

| Agent | Model | Role | Cost/call |
|-------|-------|------|-----------|
| Master Agent | Claude Opus | Orchestration, executive briefing | ~$0.02-0.05 |
| Triage Agent | Claude Haiku | Fast classification | ~$0.001 |
| Investigation Agent | Claude Sonnet | Deep analysis | ~$0.005-0.01 |
| Decision Agent | Claude Haiku | Response determination | ~$0.001 |
| Enrichment | N/A (deterministic) | Threat intel lookup | Free |

Total per alert: ~$0.03-0.07 (with Master Agent overhead)

## Architecture Notes

- **No Wazuh instance required** — Alerts are simulated with realistic structure
- **No external APIs required** — Threat intel enrichment is simulated
- **Only dependency is `anthropic`** — Minimal setup friction
- **Tool-use pattern** — Master Agent uses Claude's native tool_use to invoke sub-agents
- **Structured JSON output** — Sub-agents return parseable JSON; Master Agent returns prose briefing

In production, replace simulated alerts with the Wazuh MCP Server or Indexer API, and simulated enrichment with real VirusTotal/MISP/AbuseIPDB calls.
