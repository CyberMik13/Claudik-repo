# Wazuh Agentic SOC — Service Design & Feasibility Study

**Date:** 2026-03-04
**Status:** Research / Proposal
**Author:** Claude (AI Assistant) for CyberMik13

---

## Executive Summary

Building a "vibe-coded" agentic SOC service layer on top of Wazuh is **highly feasible in 2026**. The open-source ecosystem has matured significantly — there are production-quality building blocks available on GitHub, Wazuh itself is investing in agentic AI integration, and the commercial market validates strong customer demand. This document covers the landscape, architecture, cost model, and a build plan we can execute together.

---

## 1. GitHub Project Landscape — What Already Exists

### Tier 1: Production-Ready Building Blocks

| Project | Stars | What It Does | Tech Stack | License |
|---------|-------|-------------|------------|---------|
| [**Wazuh-MCP-Server** (GenSecAI)](https://github.com/gensecaihq/Wazuh-MCP-Server) | 133 | 48 specialized MCP tools for querying Wazuh via natural language — alerts, agents, vulnerabilities, compliance, active response. Production-ready with OAuth 2.0, circuit breakers, rate limiting, Prometheus metrics. | Python 3.13+, FastAPI, Docker | MIT |
| [**SocTalk**](https://github.com/gbrigandi/soctalk) | 25 | Full agentic SOC: autonomous triage → investigation → escalation → response. Supervisor + worker architecture across Wazuh, Cortex, MISP, TheHive. Dual-LLM (fast router + reasoning engine). | Python, LangGraph, FastAPI, SvelteKit, PostgreSQL | MIT |
| [**AI_SOC**](https://github.com/zhadyz/AI_SOC) | 62 | Research-grade AI-augmented SOC. ML-based intrusion detection (99.28% accuracy), alert triage service, RAG-based threat intelligence. 15-min Docker deployment. | Python 3.10+, scikit-learn, XGBoost, Wazuh, Docker, Grafana | Apache 2.0 |

### Tier 2: SOAR Automation Labs

| Project | What It Does |
|---------|-------------|
| [**SOC-Automation-Lab**](https://github.com/uruc/SOC-Automation-Lab) | Wazuh + Shuffle SOAR + TheHive. Complete automated workflow: alert → enrichment (VirusTotal) → case creation → analyst notification → response. |
| [**SOAR-Flow**](https://github.com/malwarekid/SOAR-Flow) | Shuffle + Wazuh + TheHive with VirusTotal/AbuseIPDB enrichment and Discord notifications. |
| [**Wazuh-Artificial-Intelligence**](https://github.com/marcus-ar/Wazuh-Artificial-Intelligence) | Claude Haiku integration directly into Wazuh Dashboard (tested on Wazuh 4.9.1). |

### Tier 3: Official Wazuh Direction

Wazuh is officially investing in agentic AI (blog post from January 2026). Their demonstrated use cases include:
- AI agents that generate decoders, deploy them, test via logtest, and self-correct errors
- Agents interacting through Wazuh's REST API with proper permissions
- "Coordination, not autonomy" — human-in-the-loop by design

**Source:** [A Sneak Peak at Agentic AI in Wazuh](https://wazuh.com/blog/a-sneak-peak-at-agentic-ai-in-wazuh/)

---

## 2. Recommended Architecture

### Design Philosophy: "Vibe-Coded" = Low-Config, High-Autonomy, Human-in-the-Loop

```
┌─────────────────────────────────────────────────────────────────┐
│                     CUSTOMER ENVIRONMENTS                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Wazuh    │  │ Wazuh    │  │ Wazuh    │  │ Wazuh    │       │
│  │ Agent    │  │ Agent    │  │ Agent    │  │ Agent    │       │
│  │ (Win/Lin)│  │ (Win/Lin)│  │ (Mac)    │  │ (Cloud)  │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│       └──────────────┴──────────────┴──────────────┘            │
│                              │                                   │
│                    ┌─────────▼──────────┐                       │
│                    │  Wazuh Manager     │                       │
│                    │  (Per Customer or  │                       │
│                    │   Multi-Tenant)    │                       │
│                    └─────────┬──────────┘                       │
└──────────────────────────────┼───────────────────────────────────┘
                               │ Wazuh API / Webhook / Syslog
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   YOUR AGENTIC SOC SERVICE LAYER                │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    INGESTION LAYER                        │   │
│  │  • Wazuh MCP Server (GenSecAI) — 48 tools               │   │
│  │  • Alert Poller (continuous Wazuh API polling)            │   │
│  │  • Webhook Receiver (real-time push)                      │   │
│  │  • Multi-tenant Router                                    │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                         │                                        │
│  ┌──────────────────────▼───────────────────────────────────┐   │
│  │                    AGENT ORCHESTRATOR                      │   │
│  │  (LangGraph / Claude Agent SDK)                           │   │
│  │                                                            │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐ │   │
│  │  │ Triage      │ │ Investigation│ │ Response            │ │   │
│  │  │ Agent       │ │ Agent        │ │ Agent               │ │   │
│  │  │             │ │              │ │                     │ │   │
│  │  │ • Classify  │ │ • Correlate  │ │ • Block IP         │ │   │
│  │  │ • Prioritize│ │ • Enrich IOC │ │ • Isolate host     │ │   │
│  │  │ • Deduplicate│ │ • MITRE map │ │ • Disable account  │ │   │
│  │  │ • Auto-close│ │ • Timeline   │ │ • Custom playbook  │ │   │
│  │  │   noise     │ │              │ │                     │ │   │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘ │   │
│  │                                                            │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐ │   │
│  │  │ Compliance  │ │ Threat Intel│ │ Reporting            │ │   │
│  │  │ Agent       │ │ Agent (RAG) │ │ Agent               │ │   │
│  │  │ PCI/HIPAA/  │ │ MISP/OTX/   │ │ Daily/weekly        │ │   │
│  │  │ SOC2/GDPR   │ │ VirusTotal  │ │ summaries           │ │   │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘ │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                         │                                        │
│  ┌──────────────────────▼───────────────────────────────────┐   │
│  │                    HUMAN-IN-THE-LOOP                       │   │
│  │  • Dashboard (SvelteKit / Next.js)                        │   │
│  │  • Slack / Teams / Discord Notifications                  │   │
│  │  • Approval Workflows (critical actions need human OK)    │   │
│  │  • Customer Portal (tenant-specific views)                │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                         │                                        │
│  ┌──────────────────────▼───────────────────────────────────┐   │
│  │                    CASE MANAGEMENT & PERSISTENCE           │   │
│  │  • TheHive (case management)                              │   │
│  │  • PostgreSQL (event sourcing, audit trail)               │   │
│  │  • ChromaDB / Qdrant (vector store for RAG)               │   │
│  │  • Grafana (operational dashboards)                       │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Core Technology Choices

| Component | Recommended Choice | Why |
|-----------|-------------------|-----|
| **Agent Framework** | LangGraph + Claude API | SocTalk already proves this works. LangGraph gives stateful multi-agent orchestration with human-in-the-loop. Claude provides strong reasoning for security analysis. |
| **Wazuh Integration** | Wazuh MCP Server (GenSecAI) | 133 stars, 48 tools, production-ready, MIT license. Best foundation. |
| **SOAR Backbone** | Shuffle (open-source) or n8n | Proven Wazuh integration, visual workflow builder for "vibe-coded" playbooks. |
| **Case Management** | TheHive | Industry standard open-source, deep Wazuh ecosystem integration. |
| **Threat Intel** | MISP + Cortex | IOC correlation, VirusTotal/AbuseIPDB enrichment. |
| **LLM Provider** | Claude API (Anthropic) | Best reasoning for security analysis. Haiku for triage (fast/cheap), Sonnet for investigation, Opus for complex incident response. |
| **Vector Store / RAG** | ChromaDB or Qdrant | Threat intelligence retrieval, log summarization, historical context. |
| **Dashboard** | SvelteKit or Next.js | Real-time SSE, multi-tenant, customer-facing portal. |
| **Infrastructure** | Docker Compose → Kubernetes | Start containerized, scale to K8s as customer count grows. |

---

## 3. Cost Estimates

### A. Development Costs (Build Phase)

| Phase | Effort | Cost Range (if outsourced) | With Claude |
|-------|--------|--------------------------|-------------|
| **Phase 1: MVP** — Wazuh MCP + single triage agent + Slack notifications | 2–4 weeks | $15K–$30K | ~$2K–$5K (mostly infra + your time) |
| **Phase 2: Full Agent Pipeline** — Triage + Investigation + Response agents, TheHive, dashboard | 4–8 weeks | $30K–$60K | ~$5K–$10K |
| **Phase 3: Multi-Tenant** — Customer portal, tenant isolation, billing, compliance reporting | 4–6 weeks | $25K–$50K | ~$5K–$10K |
| **Phase 4: Hardening** — Security audit, rate limiting, monitoring, SLAs | 2–4 weeks | $15K–$30K | ~$3K–$5K |
| **Total** | **12–22 weeks** | **$85K–$170K** | **~$15K–$30K** |

> "With Claude" assumes you're the developer and I'm pair-programming with you. Costs are primarily infrastructure, API usage during dev/test, and your time investment.

### B. Monthly Operating Costs (Per Customer)

| Cost Item | Small Customer (≤50 agents) | Medium (≤250 agents) | Large (≤500 agents) |
|-----------|---------------------------|---------------------|---------------------|
| **Wazuh Cloud** (if using managed) | $571/mo | $923/mo | $1,467/mo |
| **Wazuh Self-Hosted** (if you host) | $100–$200/mo (VPS) | $200–$500/mo | $500–$1,000/mo |
| **LLM API Costs** (Claude) | $200–$500/mo | $500–$1,500/mo | $1,000–$3,000/mo |
| **Infrastructure** (Docker/K8s, DBs) | $100–$200/mo | $200–$400/mo | $400–$800/mo |
| **Threat Intel Feeds** | $0–$100/mo (MISP free) | $0–$200/mo | $0–$500/mo |
| **Total COGS** | **$400–$1,000/mo** | **$900–$2,600/mo** | **$1,900–$5,300/mo** |

### C. What You Can Charge Customers

For context, the managed SOC market charges:

| Service Tier | Market Rate |
|-------------|-------------|
| Basic SIEM monitoring (no AI) | $2,000–$5,000/mo |
| Managed SOC (Tier 1 + Tier 2) | $5,000–$15,000/mo |
| Full MDR / AI-Enhanced SOC | $10,000–$30,000/mo |
| Enterprise SOC-as-a-Service | $25,000–$100,000+/mo |

**Your competitive positioning:** An AI-powered agentic SOC at $3,000–$10,000/mo per customer — significantly cheaper than traditional managed SOC, with faster response times (seconds vs. hours for Tier 1 triage).

### D. LLM Cost Optimization

| Strategy | Impact |
|----------|--------|
| Use **Haiku** for alert triage (90%+ of calls) | 10x cheaper than Sonnet |
| Use **Sonnet** for investigation correlation | Balance of cost/quality |
| Use **Opus** only for complex incident analysis | <1% of calls |
| Cache common alert patterns | 40–60% reduction in API calls |
| Batch low-priority alerts | Reduce API call frequency |
| Fine-tune open-source model (Llama 3) for triage | Eliminate API costs for Tier 1 |

---

## 4. Revenue Model & Unit Economics

### Example: 10 Customers, Average $5,000/mo

| Item | Monthly |
|------|---------|
| **Revenue** (10 × $5,000) | $50,000 |
| **COGS** (10 × ~$1,500 avg) | ($15,000) |
| **Your Time** (ops/support) | ($5,000–$10,000) |
| **Gross Margin** | **$25,000–$30,000/mo** |
| **Gross Margin %** | **50–60%** |

This scales well — adding customer 11 is mostly incremental COGS with minimal additional effort if the platform is properly automated.

---

## 5. Build Plan — What We Can Do Together

### Phase 1: MVP (Weeks 1–3) — "Prove It Works"

I (Claude) can help you build this step by step:

1. **Set up Wazuh** — Deploy Wazuh Manager (Docker) with test agents
2. **Deploy Wazuh MCP Server** — Fork GenSecAI's MCP server, customize for your needs
3. **Build Triage Agent** — LangGraph agent that:
   - Polls Wazuh for new alerts
   - Classifies severity using Claude Haiku
   - Auto-closes known false positives
   - Escalates true positives to Slack/Teams
4. **Basic Dashboard** — Simple web UI showing alert pipeline status
5. **Demo to first customer** — Show the value proposition

### Phase 2: Full Pipeline (Weeks 4–8)

6. **Investigation Agent** — Correlates alerts, enriches IOCs via VirusTotal/MISP, maps to MITRE ATT&CK
7. **Response Agent** — Executes pre-approved playbooks (block IP, isolate host) via Wazuh Active Response
8. **TheHive Integration** — Auto-create cases for confirmed incidents
9. **Reporting Agent** — Generate daily/weekly security summaries per customer

### Phase 3: Multi-Tenant Service (Weeks 9–14)

10. **Tenant Isolation** — Per-customer Wazuh manager or multi-tenant indexer
11. **Customer Portal** — Branded dashboard with customer-specific views
12. **Compliance Reporting** — PCI DSS, HIPAA, SOC 2 automated compliance checks
13. **Billing Integration** — Usage tracking and invoicing

### Phase 4: Hardening & Launch (Weeks 15–18)

14. **Security Audit** — Harden the platform itself
15. **Monitoring & Alerting** — Grafana + Prometheus for platform health
16. **SLA Framework** — Define response time commitments
17. **Documentation & Onboarding** — Customer onboarding playbook

---

## 6. Key Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| **LLM hallucinations in security context** | Human-in-the-loop for all response actions. Confidence scoring. Never auto-execute high-impact responses without approval. |
| **LLM API costs spike** | Tiered model usage (Haiku/Sonnet/Opus). Caching. Option to run local Llama 3 for triage. |
| **Customer data privacy** | Process alerts metadata only — no raw log forwarding unless customer opts in. SOC 2 compliance. |
| **Wazuh API changes** | Pin to supported versions. MCP Server abstracts API layer. |
| **False negatives (missed threats)** | AI augments, never replaces. Traditional rules still run. AI adds correlation layer on top. |
| **Multi-tenant data leakage** | Strict tenant isolation. Separate vector stores per customer. Row-level security on all queries. |

---

## 7. Competitive Advantages of This Approach

1. **Open-source foundation** — No vendor lock-in. Wazuh, TheHive, MISP are all open-source.
2. **AI-native from day one** — Not bolting AI onto a legacy SIEM. Designed for autonomous operation.
3. **"Vibe-coded" playbooks** — Customers describe what they want in natural language, agents execute.
4. **Seconds, not hours** — AI triage in seconds vs. traditional SOC analyst hours.
5. **Cost advantage** — 50–70% cheaper than traditional managed SOC services.
6. **Scales without headcount** — Adding customers doesn't require hiring more analysts.

---

## 8. Can We Build This Together?

**Yes, absolutely.** Here's what the collaboration looks like:

| You (Human) | Me (Claude) |
|-------------|-------------|
| Business decisions, customer relationships, contracts | Architecture design, code generation, debugging |
| Infrastructure provisioning (cloud accounts, servers) | Docker configs, deployment scripts, CI/CD pipelines |
| Security domain expertise, playbook design | Agent logic, LLM prompt engineering, MCP integration |
| Customer onboarding, support | Documentation, runbooks, automated reporting |
| Testing in real customer environments | Unit tests, integration tests, mock alert generators |

### What I Can Do Right Now

1. **Scaffold the project** — Set up the repo structure, Docker configs, CI/CD
2. **Fork and customize** the Wazuh MCP Server for your use case
3. **Build the LangGraph agent pipeline** — Triage → Investigate → Respond
4. **Create the dashboard** — SvelteKit or Next.js multi-tenant UI
5. **Write playbooks** — Automated response playbooks as code
6. **Build the customer portal** — Tenant-isolated views and reporting

Just say the word on which phase to start with.

---

## Sources & References

### GitHub Projects
- [Wazuh-MCP-Server (GenSecAI)](https://github.com/gensecaihq/Wazuh-MCP-Server) — 133 stars, production-ready MCP server
- [SocTalk](https://github.com/gbrigandi/soctalk) — AI-powered SOC automation with LangGraph
- [AI_SOC](https://github.com/zhadyz/AI_SOC) — Research-grade AI-augmented SOC
- [SOC-Automation-Lab](https://github.com/uruc/SOC-Automation-Lab) — Wazuh + Shuffle + TheHive lab
- [SOAR-Flow](https://github.com/malwarekid/SOAR-Flow) — Shuffle SOAR + Wazuh automation
- [Wazuh-Artificial-Intelligence](https://github.com/marcus-ar/Wazuh-Artificial-Intelligence) — Claude on Wazuh Dashboard
- [SOCFortress Wazuh MCP Server](https://socfortress.medium.com/introducing-wazuh-mcp-server-bridging-siem-and-ai-for-smarter-security-operations-ea9b5441dbba)

### Market & Industry
- [Wazuh Blog: Agentic AI in Wazuh (Jan 2026)](https://wazuh.com/blog/a-sneak-peak-at-agentic-ai-in-wazuh/)
- [Wazuh Cloud Pricing](https://wazuh.com/cloud/)
- [Top 10 Agentic SOC Platforms 2025 — Stellar Cyber](https://stellarcyber.ai/learn/top-10-agentic-soc-platforms/)
- [Omdia: Agentic SOC Market Landscape 2025](https://omdia.tech.informa.com/om139309/market-landscape-agentic-security-operations-center-soc--2025)
- [Elastic: Why 2026 is the Year for Agentic AI SOC](https://www.elastic.co/security-labs/why-2026-is-the-year-to-upgrade-to-an-agentic-ai-soc)
- [Gartner Hype Cycle: AI SOC Agents](https://www.prophetsecurity.ai/blog/ai-soc-agents-in-gartner-hype-cycle-for-security-operations)
- [AI Agent Development Cost Guide 2026](https://www.cleveroad.com/blog/ai-agent-development-cost/)
- [Wazuh Cost Analysis — Sirius Open Source](https://www.siriusopensource.com/en-us/blog/how-much-does-wazuh-cost)

---

*Generated 2026-03-04 by Claude for CyberMik13/Claudik-repo*
