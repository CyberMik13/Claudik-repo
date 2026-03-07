# SOC AI Copilot — Full Architecture

> System architecture showing the AI Copilot joined to real SOC data sources,
> with the Master Agent (Opus) orchestrating specialized sub-agents.

## High-Level Architecture

```
 ┌─────────────────────────── SOC DATA SOURCES ────────────────────────────┐
 │                                                                          │
 │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌─────────┐ ┌─────────┐  │
 │  │ Wazuh      │ │ Wazuh      │ │ Wazuh      │ │  Cloud  │ │ Network │  │
 │  │ Agents     │ │ Agents     │ │ Agents     │ │  Trail  │ │ Sensors │  │
 │  │ (Windows)  │ │ (Linux)    │ │ (macOS)    │ │  Logs   │ │ (IDS)   │  │
 │  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └────┬────┘ └────┬────┘  │
 │        └───────────────┴───────────────┴─────────────┴──────────┘       │
 │                                    │                                     │
 │                         ┌──────────▼──────────┐                          │
 │                         │   WAZUH MANAGER     │                          │
 │                         │                     │                          │
 │                         │  • Rule Engine       │                          │
 │                         │  • FIM / Syscheck    │                          │
 │                         │  • Vuln Detection    │                          │
 │                         │  • SCA / Compliance  │                          │
 │                         │  • Active Response   │◄──── Response Actions    │
 │                         │  • Syscollector      │      (block, isolate)    │
 │                         └────┬────────────┬────┘                          │
 │                              │            │                               │
 │                  ┌───────────▼─┐    ┌─────▼──────────┐                    │
 │                  │ Wazuh API   │    │ Wazuh Indexer  │                    │
 │                  │ (REST:55000)│    │ (OpenSearch    │                    │
 │                  │             │    │  :9200)        │                    │
 │                  └──────┬──────┘    └───────┬────────┘                    │
 │                         │                   │                             │
 └─────────────────────────┼───────────────────┼─────────────────────────────┘
                           │                   │
          Webhooks / Syslog / API Polling / Filebeat
                           │                   │
 ══════════════════════════╪═══════════════════╪═════════════════════════════
                           │                   │
 ┌─────────────────────────▼───────────────────▼─────────────────────────────┐
 │                                                                           │
 │                    I N G E S T I O N   L A Y E R                          │
 │                                                                           │
 │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
 │  │ Wazuh MCP    │  │  Webhook     │  │  Indexer     │  │  Filebeat →  │  │
 │  │ Server       │  │  Receiver    │  │  Poller      │  │  Kafka/Redis │  │
 │  │ (48 tools)   │  │  (push)      │  │  (pull)      │  │  (stream)    │  │
 │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
 │         └─────────────────┴─────────────────┴─────────────────┘          │
 │                                    │                                      │
 │                       ┌────────────▼────────────┐                         │
 │                       │   Alert Normalizer &    │                         │
 │                       │   Multi-Tenant Router   │                         │
 │                       └────────────┬────────────┘                         │
 │                                    │                                      │
 └────────────────────────────────────┼──────────────────────────────────────┘
                                      │
 ═════════════════════════════════════╪══════════════════════════════════════
                                      │
 ┌────────────────────────────────────▼──────────────────────────────────────┐
 │                                                                           │
 │         M A S T E R   A G E N T   ( C l a u d e   O p u s )              │
 │                        "SOC Director"                                     │
 │                                                                           │
 │   Receives alerts → Reasons about context → Decides which sub-agents     │
 │   to invoke → Reviews their output → Can re-run with guidance →          │
 │   Produces executive briefings                                            │
 │                                                                           │
 │   ┌─────────────────────────────────────────────────────────────────┐     │
 │   │                    TOOL CALLS (tool_use)                        │     │
 │   │                                                                 │     │
 │   │  ┌───────────────┐   ┌───────────────┐   ┌───────────────┐     │     │
 │   │  │ TRIAGE AGENT  │   │ INVESTIGATION │   │ DECISION      │     │     │
 │   │  │ (Claude Haiku)│   │ AGENT         │   │ AGENT         │     │     │
 │   │  │               │   │ (Claude       │   │ (Claude Haiku)│     │     │
 │   │  │ • Classify    │   │  Sonnet)      │   │               │     │     │
 │   │  │ • Severity    │   │               │   │ • Verdict     │     │     │
 │   │  │ • TP/FP       │   │ • Narrative   │   │ • Auto actions│     │     │
 │   │  │ • Confidence  │   │ • MITRE chain │   │ • Human       │     │     │
 │   │  │ • Route       │   │ • IOCs        │   │   approvals   │     │     │
 │   │  │               │   │ • Escalation  │   │ • Case mgmt   │     │     │
 │   │  └───────┬───────┘   └───────┬───────┘   └───────┬───────┘     │     │
 │   │          │                   │                    │             │     │
 │   │  ┌───────▼──────────────────────────────────────────────┐      │     │
 │   │  │                ENRICHMENT (Deterministic)            │      │     │
 │   │  │                                                      │      │     │
 │   │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │      │     │
 │   │  │  │ VirusTotal│ │AbuseIPDB │ │  MISP /  │ │ MITRE  │  │      │     │
 │   │  │  │ IP + Hash│ │ IP Abuse │ │  Cortex  │ │ ATT&CK │  │      │     │
 │   │  │  │ Lookup   │ │ Score    │ │  IOC DB  │ │ Context│  │      │     │
 │   │  │  └──────────┘ └──────────┘ └──────────┘ └────────┘  │      │     │
 │   │  └──────────────────────────────────────────────────────┘      │     │
 │   │                                                                 │     │
 │   └─────────────────────────────────────────────────────────────────┘     │
 │                                                                           │
 │   Outputs:                                                                │
 │   • Per-alert executive briefing (prose)                                  │
 │   • Structured triage / investigation / decision JSON                     │
 │   • Response action commands (auto + pending approval)                    │
 │                                                                           │
 └──────────────┬──────────────────────┬─────────────────────┬───────────────┘
                │                      │                     │
                ▼                      ▼                     ▼
 ┌──────────────────────┐ ┌───────────────────────┐ ┌───────────────────────┐
 │  RESPONSE ACTIONS    │ │  HUMAN-IN-THE-LOOP    │ │  CASE MANAGEMENT      │
 │                      │ │                       │ │  & PERSISTENCE        │
 │  Wazuh Active Resp.  │ │  ┌─────────────────┐  │ │                       │
 │  ┌────────────────┐  │ │  │   Dashboard     │  │ │  ┌─────────────────┐  │
 │  │ • Block IP     │  │ │  │  (SvelteKit)    │  │ │  │  TheHive        │  │
 │  │ • Isolate host │  │ │  │                 │  │ │  │  Case Mgmt      │  │
 │  │ • Kill process │  │ │  │  • Live alert   │  │ │  └─────────────────┘  │
 │  │ • Quarantine   │  │ │  │    feed         │  │ │  ┌─────────────────┐  │
 │  │   file         │  │ │  │  • Approve/deny │  │ │  │  PostgreSQL     │  │
 │  │ • Disable acct │  │ │  │    actions      │  │ │  │  Audit Trail    │  │
 │  └────────────────┘  │ │  │  • Briefings    │  │ │  └─────────────────┘  │
 │                      │ │  └─────────────────┘  │ │  ┌─────────────────┐  │
 │  External Firewalls  │ │                       │ │  │  ChromaDB /     │  │
 │  ┌────────────────┐  │ │  ┌─────────────────┐  │ │  │  Qdrant         │  │
 │  │ • Cloud WAF    │  │ │  │  Notifications  │  │ │  │  (Vector RAG)   │  │
 │  │ • EDR (Crowd-  │  │ │  │  ┌───┐ ┌─────┐ │  │ │  └─────────────────┘  │
 │  │   Strike etc)  │  │ │  │  │   │ │     │ │  │ │  ┌─────────────────┐  │
 │  │ • Firewall API │  │ │  │  │ S │ │PD/  │ │  │ │  │  Grafana        │  │
 │  └────────────────┘  │ │  │  │ l │ │Teams│ │  │ │  │  Dashboards     │  │
 │                      │ │  │  │ a │ │Email│ │  │ │  └─────────────────┘  │
 │  SOAR Playbooks      │ │  │  │ c │ │     │ │  │ │                       │
 │  ┌────────────────┐  │ │  │  │ k │ │     │ │  │ │  Compliance Reports  │
 │  │ Shuffle / n8n  │  │ │  │  └───┘ └─────┘ │  │ │  ┌─────────────────┐  │
 │  │ Custom scripts │  │ │  └─────────────────┘  │ │  │ PCI-DSS, HIPAA  │  │
 │  └────────────────┘  │ │                       │ │  │ SOC2, GDPR      │  │
 │                      │ │  Approval Workflow:   │ │  └─────────────────┘  │
 └──────────────────────┘ │  [AUTO] → execute     │ └───────────────────────┘
                          │  [HUMAN] → wait for   │
                          │   analyst approval    │
                          └───────────────────────┘
```

## Data Flow — Single Alert Lifecycle

```
    ┌─────────┐
    │  Wazuh  │ 1. Raw alert generated
    │  Alert  │    (e.g., SSH brute force from 185.220.101.34)
    └────┬────┘
         │
         ▼
    ┌─────────────────┐
    │  Ingestion      │ 2. Normalized, tagged with tenant ID,
    │  Layer          │    queued for processing
    └────┬────────────┘
         │
         ▼
    ┌─────────────────────────────────────────────────────┐
    │  MASTER AGENT (Opus)                                │
    │                                                     │
    │  3. Reads alert, decides first action               │
    │     "This is a level 10 brute force from an         │
    │      external IP — I need triage first"             │
    │                                                     │
    │     ──── tool_use: triage_alert ────►               │
    │                                                     │
    │  4. Reviews triage: severity=high, confidence=0.92  │
    │     "High confidence TP — I need enrichment"        │
    │                                                     │
    │     ──── tool_use: enrich_alert ────►               │
    │                                                     │
    │  5. Reviews enrichment: IP is Tor exit node,        │
    │     abuse score 100%, known for brute force         │
    │     "Confirmed malicious — full investigation"      │
    │                                                     │
    │     ──── tool_use: investigate_alert ────►           │
    │                                                     │
    │  6. Reviews investigation: T1110.001, 347 attempts, │
    │     no successful auth. Asks for decision.          │
    │                                                     │
    │     ──── tool_use: decide_response ────►             │
    │                                                     │
    │  7. Produces EXECUTIVE BRIEFING:                    │
    │     "SSH brute force from Tor exit node.            │
    │      Auto-blocked IP. No breach detected.           │
    │      Recommend enabling MFA on SSH."                │
    │                                                     │
    └─────────┬───────────────────────────────────────────┘
              │
     ┌────────┴────────┐
     ▼                 ▼
 ┌────────┐    ┌────────────┐
 │ [AUTO] │    │  [HUMAN]   │
 │Block IP│    │  Review    │
 │via     │    │  briefing  │
 │Wazuh   │    │  in Slack  │
 │Active  │    │  or        │
 │Response│    │  dashboard │
 └────────┘    └────────────┘
```

## Adaptive Routing — Master Agent Decisions

```
                              ┌──────────────────┐
                              │   Incoming Alert  │
                              └────────┬─────────┘
                                       │
                                       ▼
                              ┌──────────────────┐
                              │  MASTER AGENT    │
                              │  (Opus)          │
                              │  "What is this?" │
                              └────────┬─────────┘
                                       │
                                       ▼
                              ┌──────────────────┐
                              │  Triage Agent    │
                              │  (always first)  │
                              └────────┬─────────┘
                                       │
                       ┌───────────────┼───────────────┐
                       │               │               │
                       ▼               ▼               ▼
              ┌────────────┐  ┌────────────┐  ┌────────────────┐
              │ FALSE POS  │  │ MEDIUM     │  │ HIGH/CRITICAL  │
              │ confidence │  │ needs more │  │ confirmed      │
              │ > 0.9      │  │ context    │  │ threat         │
              └─────┬──────┘  └─────┬──────┘  └───────┬────────┘
                    │               │                  │
                    ▼               ▼                  ▼
            ┌──────────┐   ┌──────────────┐   ┌──────────────┐
            │ AUTO-    │   │ Enrich       │   │ Enrich       │
            │ CLOSE    │   │ ────────►    │   │ ────────►    │
            │          │   │ Investigate  │   │ Investigate  │
            │ (skip    │   │ ────────►    │   │ ────────►    │
            │ enrich + │   │ Decide       │   │ Decide       │
            │ invest.) │   │              │   │ ────────►    │
            │          │   │              │   │ Re-run?      │
            └──────────┘   └──────────────┘   │ ────────►    │
                                              │ Escalate     │
              Saves $$                        └──────────────┘
              and time
                                                Full pipeline
                                                + possible re-runs
```

## External Data Source Integration Map

```
 ┌──────────────────── THREAT INTELLIGENCE ─────────────────────┐
 │                                                               │
 │   ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
 │   │ VirusTotal  │  │ AbuseIPDB   │  │ MISP                │  │
 │   │             │  │             │  │ (Malware Info       │  │
 │   │ • IP reputa-│  │ • IP abuse  │  │  Sharing Platform)  │  │
 │   │   tion      │  │   score     │  │                     │  │
 │   │ • File hash │  │ • Country   │  │ • IOC correlation   │  │
 │   │   analysis  │  │ • Reports   │  │ • Threat feeds      │  │
 │   │ • Domain    │  │ • ISP/Org   │  │ • Community intel   │  │
 │   │   lookup    │  │             │  │                     │  │
 │   └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
 │          └────────────────┴─────────────────────┘             │
 │                            │                                  │
 └────────────────────────────┼──────────────────────────────────┘
                              │
               ┌──────────────▼──────────────┐
               │      ENRICHMENT LAYER       │
               │   (called by Master Agent   │
               │    via enrich_alert tool)    │
               └──────────────┬──────────────┘
                              │
 ┌────────────────────────────┼──────────────────────────────────┐
 │                            │                                  │
 │   ┌─────────────┐  ┌──────▼──────┐  ┌─────────────────────┐  │
 │   │ Wazuh       │  │ MITRE       │  │ Cortex              │  │
 │   │ Indexer     │  │ ATT&CK      │  │ (IOC analysis       │  │
 │   │             │  │             │  │  engine)             │  │
 │   │ • Historical│  │ • Technique │  │                     │  │
 │   │   alerts    │  │   mapping   │  │ • Automated IOC     │  │
 │   │ • Correlated│  │ • Tactic    │  │   enrichment        │  │
 │   │   events    │  │   context   │  │ • Multi-source      │  │
 │   │ • Vuln data │  │ • Mitiga-   │  │   analysis          │  │
 │   │             │  │   tions     │  │                     │  │
 │   └─────────────┘  └─────────────┘  └─────────────────────┘  │
 │                                                               │
 └──────────────── KNOWLEDGE SOURCES ────────────────────────────┘
```

## Model Tier Strategy

```
   Cost per alert ──────────────────────────────────────────►

   $0.001          $0.005           $0.02            $0.05
   │                │                │                │
   ▼                ▼                ▼                ▼

   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
   │ HAIKU    │    │ HAIKU    │    │ SONNET   │    │ OPUS     │
   │          │    │          │    │          │    │          │
   │ Triage   │    │ Decision │    │ Investi- │    │ Master   │
   │ Agent    │    │ Agent    │    │ gation   │    │ Agent    │
   │          │    │          │    │ Agent    │    │          │
   │ Fast     │    │ Rule-    │    │ Deep     │    │ Orches-  │
   │ classify │    │ based    │    │ analysis │    │ tration  │
   │ ~90% of  │    │ action   │    │ ~30% of  │    │ ~100%    │
   │ calls    │    │ routing  │    │ alerts   │    │ of alerts│
   └──────────┘    └──────────┘    └──────────┘    └──────────┘

   Blended cost per alert: ~$0.03–0.07
   (vs. $0.001–0.01 without Master Agent)
   (vs. $15–50 per alert for human analyst @ 15-30 min)
```
