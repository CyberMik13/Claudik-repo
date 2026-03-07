"""
Multi-agent pipeline for the Agentic SOC POC.

Architecture:
    Master Agent (Opus) orchestrates everything via tool calls:
    ┌──────────────────────────────────────────────┐
    │  MASTER AGENT (Claude Opus)                  │
    │  "SOC Director" — decides what to do         │
    │                                              │
    │  Available tools:                            │
    │    ├── triage_alert()     → Haiku            │
    │    ├── enrich_alert()     → Deterministic    │
    │    ├── investigate_alert() → Sonnet          │
    │    ├── decide_response()  → Haiku            │
    │    └── (can call any tool multiple times,    │
    │        skip tools, or re-run with guidance)  │
    │                                              │
    │  Final output: Executive briefing            │
    └──────────────────────────────────────────────┘

Each sub-agent is a focused Claude API call with a specific system prompt
and structured JSON output. The Master Agent sees all their results and
makes the orchestration decisions a SOC Director would.
"""

import json
import os

from anthropic import Anthropic

from .enrichment import enrich_alert as _enrich_alert_impl

# --- Configuration ---

DEFAULT_MODEL = "claude-haiku-4-5-20251001"  # Fast + cheap for triage/decision
INVESTIGATION_MODEL = "claude-sonnet-4-6"    # Stronger reasoning for investigation
MASTER_MODEL = "claude-opus-4-6"             # Top-tier reasoning for orchestration

client: Anthropic | None = None


def _get_client() -> Anthropic:
    global client
    if client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY environment variable is required.\n"
                "Export it before running: export ANTHROPIC_API_KEY=sk-ant-..."
            )
        client = Anthropic(api_key=api_key)
    return client


def _call_agent(system_prompt: str, user_message: str, model: str = DEFAULT_MODEL) -> str:
    """Make a single Claude API call representing one sub-agent's work."""
    response = _get_client().messages.create(
        model=model,
        max_tokens=2048,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
    )
    return response.content[0].text


def _parse_json(raw: str) -> dict:
    """Parse JSON from an agent response, handling markdown code blocks."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        if "```" in raw:
            json_str = raw.split("```")[1]
            if json_str.startswith("json"):
                json_str = json_str[4:]
            return json.loads(json_str.strip())
        return {"error": "Failed to parse agent output", "raw": raw}


# ═══════════════════════════════════════════════════════════════
#  SUB-AGENT SYSTEM PROMPTS
# ═══════════════════════════════════════════════════════════════

TRIAGE_SYSTEM = """\
You are a SOC Tier 1 Triage Agent. Your job is to rapidly assess incoming \
Wazuh security alerts and classify them.

For each alert, output a JSON object (and nothing else) with these fields:
- "severity": one of "critical", "high", "medium", "low", "informational"
- "confidence": 0.0 to 1.0 — how confident you are in your assessment
- "category": one of "true_positive", "likely_true_positive", "suspicious", \
"likely_false_positive", "false_positive"
- "needs_enrichment": true/false — whether threat intel lookups would help
- "needs_investigation": true/false — whether a deeper investigation is needed
- "summary": 1-2 sentence assessment of the alert
- "reasoning": brief explanation of your classification logic

Consider:
- The Wazuh rule level (0-15 scale, 10+ is significant)
- MITRE ATT&CK mapping
- Source IP reputation indicators in the alert
- Whether this looks like automated scanning vs. targeted attack
- Time of day and target system context
"""

INVESTIGATION_SYSTEM = """\
You are a SOC Tier 2 Investigation Agent. You receive triaged alerts along with \
threat intelligence enrichment data. Your job is to conduct a thorough \
investigation and produce an investigation report.

Output a JSON object (and nothing else) with these fields:
- "investigation_id": generate a short ID like "INV-XXXX"
- "title": concise title for this investigation
- "severity_adjusted": reassess severity with enrichment data ("critical"/"high"/"medium"/"low")
- "attack_narrative": 3-5 sentence narrative of what happened, written for a SOC manager
- "mitre_attack_chain": list of MITRE technique IDs with brief context on how they apply
- "indicators_of_compromise": list of IOCs found (IPs, hashes, domains, etc.)
- "affected_assets": list of affected hosts/users with their risk level
- "correlated_evidence": what evidence supports this being a real attack vs. noise
- "gaps": what information is missing that would help confirm/deny
- "recommended_actions": ordered list of specific response actions
- "escalation_required": true/false
- "escalation_reason": why escalation is/isn't needed

Think like an experienced threat analyst. Connect the dots between the alert, \
the enrichment data, and known attack patterns.
"""

DECISION_SYSTEM = """\
You are a SOC Decision Agent. Based on the investigation report, you determine \
the response actions to take. You operate under a "human-in-the-loop" policy: \
high-impact actions require human approval.

Output a JSON object (and nothing else) with these fields:
- "decision_id": generate a short ID like "DEC-XXXX"
- "verdict": one of "auto_close", "monitor", "respond", "escalate_to_human"
- "auto_actions": list of actions to execute automatically (low-risk only), each with:
  - "action": the action name (e.g., "block_ip", "add_to_watchlist", "create_ticket")
  - "target": what to act on
  - "reason": why this is safe to auto-execute
- "human_approval_required": list of actions needing human sign-off, each with:
  - "action": the action name (e.g., "isolate_host", "disable_account", "kill_process")
  - "target": what to act on
  - "risk": why this needs human approval
  - "urgency": "immediate", "within_1_hour", "within_24_hours"
- "notification": who to notify and how ("slack_channel", "pagerduty", "email")
- "follow_up": what to monitor after response actions
- "case_management": {"create_case": true/false, "priority": "P1"/"P2"/"P3"/"P4", \
"assigned_to": "soc_team"/"ir_team"/"management"}

Decision guidelines:
- NEVER auto-execute host isolation or account disabling — always require human approval
- Auto-blocking known-malicious external IPs is acceptable
- Auto-creating tickets and watchlist entries is acceptable
- When in doubt, escalate to human
- Critical severity = PagerDuty + Slack + case creation
- Medium/Low = Slack notification + optional ticket
"""


# ═══════════════════════════════════════════════════════════════
#  SUB-AGENT EXECUTION FUNCTIONS (called by Master Agent tools)
# ═══════════════════════════════════════════════════════════════

def _run_triage(alert_json: str, guidance: str = "") -> dict:
    """Run the Triage sub-agent."""
    prompt = f"Triage the following Wazuh alert:\n\n{alert_json}"
    if guidance:
        prompt += f"\n\nAdditional guidance from the SOC Director:\n{guidance}"
    return _parse_json(_call_agent(TRIAGE_SYSTEM, prompt))


def _run_enrichment(alert_json: str) -> dict:
    """Run deterministic threat intelligence enrichment."""
    alert = json.loads(alert_json)
    return _enrich_alert_impl(alert)


def _run_investigation(context_json: str, guidance: str = "") -> dict:
    """Run the Investigation sub-agent."""
    prompt = f"Investigate the following triaged alert with enrichment data:\n\n{context_json}"
    if guidance:
        prompt += f"\n\nAdditional guidance from the SOC Director:\n{guidance}"
    return _parse_json(_call_agent(INVESTIGATION_SYSTEM, prompt, model=INVESTIGATION_MODEL))


def _run_decision(context_json: str, guidance: str = "") -> dict:
    """Run the Decision sub-agent."""
    prompt = f"Determine the response for this investigated alert:\n\n{context_json}"
    if guidance:
        prompt += f"\n\nAdditional guidance from the SOC Director:\n{guidance}"
    return _parse_json(_call_agent(DECISION_SYSTEM, prompt))


# ═══════════════════════════════════════════════════════════════
#  MASTER AGENT — OPUS ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

MASTER_SYSTEM = """\
You are the SOC Director — the master orchestrator of an AI-powered Security \
Operations Center. You have a team of specialized sub-agents at your disposal, \
each accessible as a tool.

Your job:
1. Receive a raw Wazuh security alert
2. Decide which agents to invoke and in what order
3. Review each agent's output — if the results are insufficient, you can \
re-run an agent with additional guidance
4. Coordinate the flow: typically Triage → Enrich → Investigate → Decide, \
but you can skip steps for obvious false positives or add extra steps for \
complex incidents
5. After all agents have reported, produce your EXECUTIVE BRIEFING as your \
final text response

Your orchestration principles:
- For obvious noise (level <= 6, known scanner patterns), you may triage and \
auto-close without full investigation — save resources
- For critical alerts (C2 beacons, active malware), run the full pipeline and \
consider re-running investigation with extra guidance if the first pass misses \
something
- Always enrich before investigating — investigators need threat intel context
- If triage confidence is low (< 0.7), consider providing guidance to the \
triage agent and re-running it
- If investigation is missing key details, re-run it with specific questions

When you have gathered enough information from your agents, write your final \
EXECUTIVE BRIEFING directly (not as a tool call). Structure it as:

## Executive Briefing — [short title]
**Classification:** [critical/high/medium/low/false_positive]
**Verdict:** [what to do]

**What happened:** [2-3 sentence narrative]

**Key findings:**
- [bullet points of important findings]

**Response actions:**
- [AUTO] actions taken automatically
- [PENDING APPROVAL] actions requiring human sign-off

**Risk assessment:** [what's the ongoing risk if we don't act]

**Recommendations:** [strategic recommendations beyond immediate response]
"""

# Tool definitions for the Master Agent
MASTER_TOOLS = [
    {
        "name": "triage_alert",
        "description": (
            "Run the Tier 1 Triage Agent (Claude Haiku) to classify an alert's "
            "severity, determine if it's a true/false positive, and decide if "
            "enrichment and investigation are needed. Fast and cheap — use this first. "
            "You can re-run this with guidance if the first result has low confidence."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_json": {
                    "type": "string",
                    "description": "The raw Wazuh alert as a JSON string.",
                },
                "guidance": {
                    "type": "string",
                    "description": "Optional guidance to steer the triage agent (e.g., 'pay special attention to the source IP' or 'consider that this host is a honeypot'). Leave empty for default behavior.",
                    "default": "",
                },
            },
            "required": ["alert_json"],
        },
    },
    {
        "name": "enrich_alert",
        "description": (
            "Run threat intelligence enrichment on the alert. Looks up IPs in "
            "VirusTotal/AbuseIPDB, checks file hashes against malware databases, "
            "and retrieves MITRE ATT&CK context. This is deterministic (no LLM) "
            "and very fast. Always run this before investigation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_json": {
                    "type": "string",
                    "description": "The raw Wazuh alert as a JSON string.",
                },
            },
            "required": ["alert_json"],
        },
    },
    {
        "name": "investigate_alert",
        "description": (
            "Run the Tier 2 Investigation Agent (Claude Sonnet) for deep analysis. "
            "Produces an attack narrative, MITRE chain mapping, IOC list, affected "
            "assets, and escalation recommendation. Needs triage + enrichment results "
            "as context. More expensive — only use when triage indicates it's needed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "context_json": {
                    "type": "string",
                    "description": "JSON string containing the original alert, triage results, and enrichment data.",
                },
                "guidance": {
                    "type": "string",
                    "description": "Optional guidance for the investigator (e.g., 'focus on lateral movement indicators' or 'check if the hash matches any known APT campaigns'). Leave empty for default behavior.",
                    "default": "",
                },
            },
            "required": ["context_json"],
        },
    },
    {
        "name": "decide_response",
        "description": (
            "Run the Decision Agent (Claude Haiku) to determine response actions. "
            "Separates actions into auto-execute (safe) vs. human-approval-required "
            "(risky). Sets notification channels and case management. Run this last."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "context_json": {
                    "type": "string",
                    "description": "JSON string containing the original alert and investigation report.",
                },
                "guidance": {
                    "type": "string",
                    "description": "Optional guidance for the decision agent (e.g., 'this is a VIP host, escalate immediately' or 'we have a maintenance window, defer non-critical actions'). Leave empty for default behavior.",
                    "default": "",
                },
            },
            "required": ["context_json"],
        },
    },
]

# Map tool names to implementations
TOOL_DISPATCH = {
    "triage_alert": _run_triage,
    "enrich_alert": _run_enrichment,
    "investigate_alert": _run_investigation,
    "decide_response": _run_decision,
}


def run_pipeline(alert: dict, on_step=None) -> dict:
    """
    Run the Master Agent-orchestrated pipeline on a single alert.

    The Master Agent (Opus) decides which tools to call and in what order.
    The on_step callback is called for each step so the display layer can
    render progress in real-time.

    Args:
        alert: Raw Wazuh alert dict.
        on_step: Optional callback(step_name, step_data) for live display.

    Returns:
        Dict with all intermediate results and the master's executive briefing.
    """
    result = {
        "alert": alert,
        "scenario": alert.get("_scenario", "Unknown"),
        "expected_decision": alert.get("_expected", "Unknown"),
        "steps": [],       # Ordered list of (tool_name, tool_input, tool_output)
        "briefing": None,  # Master Agent's final executive briefing
    }

    alert_json = json.dumps(alert, indent=2)

    # Start the Master Agent conversation
    messages = [
        {
            "role": "user",
            "content": (
                f"A new Wazuh security alert has arrived. Analyze it using your "
                f"team of sub-agents and produce an executive briefing.\n\n"
                f"Raw alert:\n```json\n{alert_json}\n```"
            ),
        }
    ]

    if on_step:
        on_step("master_start", {"alert": alert})

    # Agentic loop — Master Agent calls tools until it produces a final text response
    max_iterations = 10  # Safety limit
    for _ in range(max_iterations):
        response = _get_client().messages.create(
            model=MASTER_MODEL,
            max_tokens=4096,
            system=MASTER_SYSTEM,
            tools=MASTER_TOOLS,
            messages=messages,
        )

        # Check if the Master Agent is done (end_turn with text, no tool calls)
        if response.stop_reason == "end_turn":
            # Extract the final text (executive briefing)
            text_parts = [
                block.text for block in response.content if block.type == "text"
            ]
            if text_parts:
                result["briefing"] = "\n".join(text_parts)
                if on_step:
                    on_step("briefing", {"text": result["briefing"]})
            break

        # Process tool calls
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                tool_name = block.name
                tool_input = block.input

                if on_step:
                    on_step("tool_call", {"tool": tool_name, "input": tool_input})

                # Execute the sub-agent
                dispatch_fn = TOOL_DISPATCH.get(tool_name)
                if dispatch_fn:
                    try:
                        tool_output = dispatch_fn(**tool_input)
                    except Exception as e:
                        tool_output = {"error": str(e)}
                else:
                    tool_output = {"error": f"Unknown tool: {tool_name}"}

                # Record the step
                step = {
                    "tool": tool_name,
                    "input": tool_input,
                    "output": tool_output,
                }
                result["steps"].append(step)

                if on_step:
                    on_step("tool_result", {
                        "tool": tool_name,
                        "output": tool_output,
                    })

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(tool_output, indent=2),
                })

        # Feed results back to the Master Agent
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    # Extract key outputs from steps for backward compatibility
    for step in result["steps"]:
        if step["tool"] == "triage_alert":
            result.setdefault("triage", step["output"])
        elif step["tool"] == "enrich_alert":
            result.setdefault("enrichments", step["output"])
        elif step["tool"] == "investigate_alert":
            result.setdefault("investigation", step["output"])
        elif step["tool"] == "decide_response":
            result.setdefault("decision", step["output"])

    return result
