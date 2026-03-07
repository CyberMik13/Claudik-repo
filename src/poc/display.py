"""
Terminal display utilities for the POC demo.

Provides colored, structured output that makes the Master Agent's
orchestration decisions easy to follow during a live demo.
"""

import json
import sys
import time

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"
BG_MAGENTA = "\033[45m"

SEVERITY_COLORS = {
    "critical": BG_RED + WHITE + BOLD,
    "high": RED + BOLD,
    "medium": YELLOW + BOLD,
    "low": GREEN,
    "informational": DIM,
}

VERDICT_COLORS = {
    "auto_close": GREEN + BOLD,
    "monitor": BLUE + BOLD,
    "respond": YELLOW + BOLD,
    "escalate_to_human": RED + BOLD,
}

TOOL_LABELS = {
    "triage_alert": ("Triage Agent", "Claude Haiku", CYAN),
    "enrich_alert": ("Enrichment", "Deterministic", GREEN),
    "investigate_alert": ("Investigation Agent", "Claude Sonnet", BLUE),
    "decide_response": ("Decision Agent", "Claude Haiku", YELLOW),
}


def _separator(char: str = "─", width: int = 72) -> str:
    return DIM + char * width + RESET


def _header(text: str, color: str = CYAN) -> str:
    width = 72
    padding = width - len(text) - 4
    return f"\n{color}{BOLD}{'=' * 2} {text} {'=' * max(padding, 2)}{RESET}"


def _subheader(text: str, color: str = BLUE) -> str:
    return f"\n{color}{BOLD}  >> {text}{RESET}"


def _field(label: str, value: str, indent: int = 4) -> str:
    spaces = " " * indent
    return f"{spaces}{DIM}{label}:{RESET} {value}"


def _spinner(text: str, duration: float = 0.5):
    """Show a brief spinner animation."""
    frames = [".", "..", "..."]
    for frame in frames:
        sys.stdout.write(f"\r{DIM}  {text}{frame}{RESET}  ")
        sys.stdout.flush()
        time.sleep(duration / len(frames))
    sys.stdout.write("\r" + " " * 72 + "\r")
    sys.stdout.flush()


def _word_wrap(text: str, width: int = 66, indent: str = "      "):
    """Word-wrap text with indentation."""
    words = text.split()
    lines = []
    line = indent
    for word in words:
        if len(line) + len(word) > width + len(indent):
            lines.append(line)
            line = indent
        line += word + " "
    if line.strip():
        lines.append(line)
    return "\n".join(lines)


def print_banner():
    """Print the demo banner."""
    banner = f"""
{CYAN}{BOLD}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║          WAZUH AGENTIC SOC — PROOF OF CONCEPT                ║
    ║          AI-Powered Alert Triage, Investigation & Response    ║
    ║                                                              ║
    ║   ┌─────────────────────────────────────────────────────┐    ║
    ║   │  MASTER AGENT (Claude Opus) — SOC Director          │    ║
    ║   │    orchestrates sub-agents via tool calls            │    ║
    ║   │                                                     │    ║
    ║   │   ┌──────────┐ ┌──────────┐ ┌────────┐ ┌────────┐  │    ║
    ║   │   │ Triage   │ │ Enrich   │ │Investi-│ │Decision│  │    ║
    ║   │   │ (Haiku)  │ │ (Determ.)│ │ gate   │ │(Haiku) │  │    ║
    ║   │   │          │ │          │ │(Sonnet)│ │        │  │    ║
    ║   │   └──────────┘ └──────────┘ └────────┘ └────────┘  │    ║
    ║   └─────────────────────────────────────────────────────┘    ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
{RESET}"""
    print(banner)


def print_alert(alert: dict, index: int, total: int):
    """Print an incoming alert."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = rule.get("mitre", {})

    scenario = alert.get("_scenario", "Unknown Scenario")
    print(_header(f"SCENARIO {index}/{total}: {scenario}", MAGENTA))
    print()
    print(_field("Alert ID", alert.get("id", "N/A")))
    print(_field("Timestamp", alert.get("timestamp", "N/A")))
    print(_field("Rule", f"[{rule.get('id', '?')}] {rule.get('description', 'N/A')}"))
    print(_field("Level", str(rule.get("level", "?"))))
    print(_field("Agent", f"{agent.get('name', '?')} ({agent.get('ip', '?')})"))
    if mitre.get("technique"):
        techniques = mitre["technique"] if isinstance(mitre["technique"], list) else [mitre["technique"]]
        print(_field("MITRE", " | ".join(techniques)))
    print(_field("Log", alert.get("full_log", "N/A")))
    print()


# ═══════════════════════════════════════════════════════════════
#  Step Renderers — called for each sub-agent invocation
# ═══════════════════════════════════════════════════════════════

def _print_triage_output(output: dict):
    """Render triage agent results."""
    if "error" in output:
        print(f"    {RED}Error: {output['error']}{RESET}")
        return

    severity = output.get("severity", "unknown")
    color = SEVERITY_COLORS.get(severity, WHITE)
    print(_field("Severity", f"{color} {severity.upper()} {RESET}"))
    print(_field("Confidence", f"{output.get('confidence', '?'):.0%}"))

    category = output.get("category", "unknown")
    cat_color = GREEN if "false" in category else (RED if "true" in category else YELLOW)
    print(_field("Category", f"{cat_color}{category}{RESET}"))

    print(_field("Summary", output.get("summary", "N/A")))
    print(_field("Reasoning", f"{DIM}{output.get('reasoning', 'N/A')}{RESET}"))
    print(_field("Needs Enrichment", str(output.get("needs_enrichment", "?"))))
    print(_field("Needs Investigation", str(output.get("needs_investigation", "?"))))


def _print_enrichment_output(output: dict):
    """Render enrichment results."""
    has_data = False

    for ip_intel in output.get("ip_intel", []):
        has_data = True
        malicious = ip_intel.get("malicious", False)
        status = f"{RED}MALICIOUS{RESET}" if malicious else f"{GREEN}CLEAN{RESET}"
        print(_field("IP", f"{ip_intel['ip']} — {status}"))
        if malicious:
            print(_field("  Country", ip_intel.get("country", "?")))
            print(_field("  Tags", ", ".join(ip_intel.get("tags", []))))
            print(_field("  Abuse Score", f"{ip_intel.get('abuse_confidence', '?')}%"))
            print(_field("  Reports", str(ip_intel.get("total_reports", "?"))))
            print(_field("  Org", ip_intel.get("whois_org", "?")))

    for hash_intel in output.get("hash_intel", []):
        has_data = True
        malicious = hash_intel.get("malicious", False)
        status = f"{RED}MALICIOUS{RESET}" if malicious else f"{GREEN}CLEAN{RESET}"
        print(_field("Hash", f"{hash_intel['md5']} — {status}"))
        if malicious:
            print(_field("  Family", hash_intel.get("malware_family", "?")))
            print(_field("  Detection", hash_intel.get("detection_ratio", "?")))
            for b in hash_intel.get("sandbox_behaviors", []):
                print(_field("  Behavior", b))

    for mitre in output.get("mitre", []):
        has_data = True
        print(_field("MITRE", f"{CYAN}{mitre['id']}{RESET} — {mitre.get('technique', '?')}"))
        print(_field("  Tactic", mitre.get("tactic", "?")))
        for m in mitre.get("mitigations", [])[:2]:
            print(_field("  Mitigation", m))

    if not has_data:
        print(f"    {DIM}No external enrichment applicable.{RESET}")


def _print_investigation_output(output: dict):
    """Render investigation agent results."""
    if output.get("skipped"):
        print(f"    {DIM}Skipped: {output.get('reason', 'N/A')}{RESET}")
        return

    if "error" in output:
        print(f"    {RED}Error: {output['error']}{RESET}")
        return

    severity = output.get("severity_adjusted", "unknown")
    color = SEVERITY_COLORS.get(severity, WHITE)
    print(_field("Investigation", output.get("investigation_id", "N/A")))
    print(_field("Title", f"{BOLD}{output.get('title', 'N/A')}{RESET}"))
    print(_field("Severity", f"{color} {severity.upper()} {RESET}"))
    print()

    narrative = output.get("attack_narrative", "N/A")
    print(f"    {BOLD}Attack Narrative:{RESET}")
    print(_word_wrap(narrative))
    print()

    iocs = output.get("indicators_of_compromise", [])
    if iocs:
        print(f"    {BOLD}IOCs:{RESET}")
        for ioc in iocs:
            if isinstance(ioc, dict):
                print(f"      {RED}- {ioc.get('type', '?')}: {ioc.get('value', '?')}{RESET}")
            else:
                print(f"      {RED}- {ioc}{RESET}")

    assets = output.get("affected_assets", [])
    if assets:
        print(f"    {BOLD}Affected Assets:{RESET}")
        for asset in assets:
            if isinstance(asset, dict):
                name = asset.get("name", asset.get("host", "?"))
                risk = asset.get("risk", asset.get("risk_level", "?"))
                print(f"      - {name} (risk: {risk})")
            else:
                print(f"      - {asset}")

    if output.get("escalation_required"):
        print(f"\n    {RED}{BOLD}ESCALATION REQUIRED:{RESET} {output.get('escalation_reason', 'N/A')}")


def _print_decision_output(output: dict):
    """Render decision agent results."""
    if "error" in output:
        print(f"    {RED}Error: {output['error']}{RESET}")
        return

    verdict = output.get("verdict", "unknown")
    color = VERDICT_COLORS.get(verdict, WHITE)
    print(_field("Decision", output.get("decision_id", "N/A")))
    print(_field("Verdict", f"{color} {verdict.upper()} {RESET}"))

    auto_actions = output.get("auto_actions", [])
    if auto_actions:
        print(f"\n    {GREEN}{BOLD}Auto-executing:{RESET}")
        for action in auto_actions:
            if isinstance(action, dict):
                print(f"      {GREEN}[AUTO]{RESET} {action.get('action', '?')} -> {action.get('target', '?')}")
                print(f"             {DIM}{action.get('reason', '')}{RESET}")
            else:
                print(f"      {GREEN}[AUTO]{RESET} {action}")

    human_actions = output.get("human_approval_required", [])
    if human_actions:
        print(f"\n    {YELLOW}{BOLD}Awaiting human approval:{RESET}")
        for action in human_actions:
            if isinstance(action, dict):
                urgency = action.get("urgency", "?")
                urgency_color = RED if urgency == "immediate" else YELLOW
                print(f"      {YELLOW}[APPROVE]{RESET} {action.get('action', '?')} -> {action.get('target', '?')}")
                print(f"               Urgency: {urgency_color}{urgency}{RESET}")
                print(f"               Risk: {DIM}{action.get('risk', '')}{RESET}")
            else:
                print(f"      {YELLOW}[APPROVE]{RESET} {action}")

    case = output.get("case_management", {})
    if case.get("create_case"):
        print(f"\n    {BLUE}Case: Priority {case.get('priority', '?')} -> {case.get('assigned_to', '?')}{RESET}")

    notification = output.get("notification", {})
    if notification:
        if isinstance(notification, dict):
            channels = [f"{k}: {v}" for k, v in notification.items()]
            print(_field("Notify", ", ".join(channels)))
        else:
            print(_field("Notify", str(notification)))


STEP_RENDERERS = {
    "triage_alert": _print_triage_output,
    "enrich_alert": _print_enrichment_output,
    "investigate_alert": _print_investigation_output,
    "decide_response": _print_decision_output,
}

STEP_SPINNERS = {
    "triage_alert": "Master Agent invoking Triage Agent",
    "enrich_alert": "Master Agent invoking Enrichment",
    "investigate_alert": "Master Agent invoking Investigation Agent",
    "decide_response": "Master Agent invoking Decision Agent",
}


# ═══════════════════════════════════════════════════════════════
#  Live step callback — called from agents.run_pipeline
# ═══════════════════════════════════════════════════════════════

_step_counter = 0


def make_step_callback():
    """Create a step callback for live rendering during pipeline execution."""
    step_counter = {"n": 0}

    def on_step(step_name: str, data: dict):
        if step_name == "master_start":
            print(_subheader("MASTER AGENT (Claude Opus) — SOC Director", BG_MAGENTA + WHITE))
            print(f"    {DIM}Opus is analyzing the alert and deciding which agents to invoke...{RESET}")
            print()

        elif step_name == "tool_call":
            tool = data["tool"]
            label, model, color = TOOL_LABELS.get(tool, (tool, "?", WHITE))
            step_counter["n"] += 1
            guidance = data.get("input", {}).get("guidance", "")

            _spinner(STEP_SPINNERS.get(tool, f"Invoking {tool}"))
            print(_subheader(
                f"Step {step_counter['n']}: {label} ({model})",
                color,
            ))
            if guidance:
                print(f"    {MAGENTA}Master guidance: \"{guidance}\"{RESET}")

        elif step_name == "tool_result":
            tool = data["tool"]
            renderer = STEP_RENDERERS.get(tool)
            if renderer:
                renderer(data["output"])
            print()

        elif step_name == "briefing":
            print(_subheader("EXECUTIVE BRIEFING (Master Agent)", BG_MAGENTA + WHITE))
            print()
            # Render the briefing with basic markdown styling
            for line in data["text"].split("\n"):
                if line.startswith("## "):
                    print(f"    {BOLD}{MAGENTA}{line}{RESET}")
                elif line.startswith("**") and line.endswith("**"):
                    print(f"    {BOLD}{line}{RESET}")
                elif line.startswith("- [AUTO]"):
                    print(f"    {GREEN}{line}{RESET}")
                elif line.startswith("- [PENDING"):
                    print(f"    {YELLOW}{line}{RESET}")
                elif line.startswith("- "):
                    print(f"    {line}")
                elif line.startswith("**"):
                    print(f"    {BOLD}{line}{RESET}")
                else:
                    print(f"    {line}")
            print()

    return on_step


# ═══════════════════════════════════════════════════════════════
#  Result rendering — for after pipeline completes
# ═══════════════════════════════════════════════════════════════

def print_result(result: dict, index: int, total: int):
    """Print the full pipeline result for one alert (post-hoc rendering)."""
    print_alert(result["alert"], index, total)

    # Steps were already rendered live by the callback
    # Just show the expected vs actual comparison
    expected = result.get("expected_decision", "?")
    verdict = result.get("decision", {}).get("verdict", "?")
    steps_taken = len(result.get("steps", []))
    print(f"    {DIM}Steps taken by Master Agent: {steps_taken}{RESET}")
    print(f"    {DIM}Expected outcome: {expected}{RESET}")
    print(f"    {DIM}Agent verdict:    {verdict}{RESET}")
    print(_separator("═"))


def print_summary(results: list[dict]):
    """Print a summary table of all processed alerts."""
    print(_header("PIPELINE SUMMARY", GREEN))
    print()
    print(f"    {'Scenario':<40} {'Severity':<12} {'Verdict':<18} {'Steps':<6}")
    print(f"    {'-'*40} {'-'*12} {'-'*18} {'-'*6}")
    for r in results:
        scenario = r.get("scenario", "?")[:38]
        severity = r.get("triage", {}).get("severity", "?")
        verdict = r.get("decision", {}).get("verdict", "?")
        steps = len(r.get("steps", []))
        sev_color = SEVERITY_COLORS.get(severity, "")
        ver_color = VERDICT_COLORS.get(verdict, "")
        print(f"    {scenario:<40} {sev_color}{severity:<12}{RESET} {ver_color}{verdict:<18}{RESET} {steps}")

    print()
    total = len(results)
    auto_closed = sum(1 for r in results if r.get("decision", {}).get("verdict") == "auto_close")
    escalated = sum(1 for r in results if r.get("decision", {}).get("verdict") == "escalate_to_human")
    total_steps = sum(len(r.get("steps", [])) for r in results)

    print(_field("Total alerts processed", str(total)))
    print(_field("Total agent invocations", str(total_steps)))
    print(_field("Auto-closed (noise)", f"{GREEN}{auto_closed}{RESET}"))
    print(_field("Escalated to human", f"{RED}{escalated}{RESET}"))
    print(_field("Automated responses", str(total - auto_closed - escalated)))
    print()
    print(f"    {BOLD}Key takeaway:{RESET} The Master Agent (Opus) orchestrated {total_steps} sub-agent")
    print(f"    invocations across {total} alerts — dynamically deciding which agents to call,")
    print(f"    skipping unnecessary steps, and producing executive briefings.")
    print()
    print(f"    A human SOC analyst would need ~15-30 minutes per alert.")
    print(f"    That's {BOLD}{total * 20} minutes{RESET} of analyst time saved per batch.")
    print()
