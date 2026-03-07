"""
Multi-agent pipeline for the Agentic SOC POC.

Pipeline: Alert → Triage Agent → Enrichment → Investigation Agent → Decision Agent

Each agent is a focused Claude API call with a specific system prompt and
structured output. This demonstrates how agentic orchestration works —
each agent has a narrow role, clear inputs/outputs, and the orchestrator
chains them together.
"""

import json
import os

from anthropic import Anthropic

from .enrichment import enrich_alert

# --- Configuration ---

DEFAULT_MODEL = "claude-haiku-4-5-20251001"  # Fast + cheap for triage
INVESTIGATION_MODEL = "claude-sonnet-4-6"  # Stronger reasoning for investigation

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
    """Make a single Claude API call representing one agent's work."""
    response = _get_client().messages.create(
        model=model,
        max_tokens=2048,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
    )
    return response.content[0].text


# --- Agent 1: Triage ---

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


def triage_alert(alert: dict) -> dict:
    """Run the triage agent on a raw alert."""
    alert_json = json.dumps(alert, indent=2)
    result = _call_agent(
        TRIAGE_SYSTEM,
        f"Triage the following Wazuh alert:\n\n{alert_json}",
    )
    try:
        return json.loads(result)
    except json.JSONDecodeError:
        # Try to extract JSON from markdown code blocks
        if "```" in result:
            json_str = result.split("```")[1]
            if json_str.startswith("json"):
                json_str = json_str[4:]
            return json.loads(json_str.strip())
        return {"error": "Failed to parse triage output", "raw": result}


# --- Agent 2: Investigation ---

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


def investigate_alert(alert: dict, triage: dict, enrichments: dict) -> dict:
    """Run the investigation agent with full context."""
    context = json.dumps(
        {
            "original_alert": alert,
            "triage_assessment": triage,
            "threat_intelligence": enrichments,
        },
        indent=2,
    )
    result = _call_agent(
        INVESTIGATION_SYSTEM,
        f"Investigate the following triaged alert with enrichment data:\n\n{context}",
        model=INVESTIGATION_MODEL,
    )
    try:
        return json.loads(result)
    except json.JSONDecodeError:
        if "```" in result:
            json_str = result.split("```")[1]
            if json_str.startswith("json"):
                json_str = json_str[4:]
            return json.loads(json_str.strip())
        return {"error": "Failed to parse investigation output", "raw": result}


# --- Agent 3: Decision ---

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


def decide_response(alert: dict, investigation: dict) -> dict:
    """Run the decision agent on an investigation report."""
    context = json.dumps(
        {
            "original_alert": alert,
            "investigation_report": investigation,
        },
        indent=2,
    )
    result = _call_agent(
        DECISION_SYSTEM,
        f"Determine the response for this investigated alert:\n\n{context}",
        model=DEFAULT_MODEL,
    )
    try:
        return json.loads(result)
    except json.JSONDecodeError:
        if "```" in result:
            json_str = result.split("```")[1]
            if json_str.startswith("json"):
                json_str = json_str[4:]
            return json.loads(json_str.strip())
        return {"error": "Failed to parse decision output", "raw": result}


# --- Orchestrator ---


def run_pipeline(alert: dict) -> dict:
    """
    Run the full agentic pipeline on a single alert.

    Returns a dict with all intermediate results so the demo can show
    each agent's contribution.
    """
    result = {
        "alert": alert,
        "scenario": alert.get("_scenario", "Unknown"),
        "expected_decision": alert.get("_expected", "Unknown"),
    }

    # Step 1: Triage
    triage = triage_alert(alert)
    result["triage"] = triage

    # Step 2: Enrichment (deterministic — no LLM needed)
    enrichments = enrich_alert(alert)
    result["enrichments"] = enrichments

    # Step 3: Investigation (only if triage says it's needed or severity >= medium)
    needs_investigation = triage.get("needs_investigation", True)
    severity = triage.get("severity", "medium")
    if needs_investigation or severity in ("critical", "high", "medium"):
        investigation = investigate_alert(alert, triage, enrichments)
        result["investigation"] = investigation
    else:
        result["investigation"] = {
            "skipped": True,
            "reason": "Triage classified as low/informational with no investigation needed.",
        }

    # Step 4: Decision
    decision = decide_response(alert, result.get("investigation", {}))
    result["decision"] = decision

    return result
