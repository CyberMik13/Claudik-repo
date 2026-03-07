"""
Terminal display utilities for the POC demo.

Provides colored, structured output that makes the agentic pipeline
easy to follow during a live demo.
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


def _separator(char: str = "─", width: int = 72) -> str:
    return DIM + char * width + RESET


def _header(text: str, color: str = CYAN) -> str:
    width = 72
    padding = width - len(text) - 4
    return f"\n{color}{BOLD}{'=' * 2} {text} {'=' * max(padding, 2)}{RESET}"


def _subheader(text: str) -> str:
    return f"\n{BLUE}{BOLD}  >> {text}{RESET}"


def _field(label: str, value: str, indent: int = 4) -> str:
    spaces = " " * indent
    return f"{spaces}{DIM}{label}:{RESET} {value}"


def _json_block(data: dict, indent: int = 4) -> str:
    """Format JSON with syntax highlighting for terminal."""
    raw = json.dumps(data, indent=2)
    spaces = " " * indent
    lines = []
    for line in raw.split("\n"):
        # Highlight keys
        if '": ' in line:
            key, val = line.split('": ', 1)
            line = f"{CYAN}{key}\"{RESET}: {val}"
        lines.append(f"{spaces}{line}")
    return "\n".join(lines)


def _spinner(text: str, duration: float = 0.5):
    """Show a brief spinner animation."""
    frames = [".", "..", "..."]
    for frame in frames:
        sys.stdout.write(f"\r{DIM}  {text}{frame}{RESET}  ")
        sys.stdout.flush()
        time.sleep(duration / len(frames))
    sys.stdout.write("\r" + " " * 60 + "\r")
    sys.stdout.flush()


def print_banner():
    """Print the demo banner."""
    banner = f"""
{CYAN}{BOLD}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║          WAZUH AGENTIC SOC — PROOF OF CONCEPT                ║
    ║          AI-Powered Alert Triage, Investigation & Response    ║
    ║                                                              ║
    ║          Pipeline: Alert -> Triage -> Enrich -> Investigate   ║
    ║                    -> Decide -> Respond                       ║
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
    print(_field("Level", str(rule.get("level", "?")), 4))
    print(_field("Agent", f"{agent.get('name', '?')} ({agent.get('ip', '?')})"))
    if mitre.get("technique"):
        techniques = mitre["technique"] if isinstance(mitre["technique"], list) else [mitre["technique"]]
        print(_field("MITRE", " | ".join(techniques)))
    print(_field("Log", alert.get("full_log", "N/A")))
    print()


def print_triage(triage: dict):
    """Print triage agent results."""
    print(_subheader("AGENT 1: Triage (Claude Haiku)"))

    if "error" in triage:
        print(f"    {RED}Error: {triage['error']}{RESET}")
        return

    severity = triage.get("severity", "unknown")
    color = SEVERITY_COLORS.get(severity, WHITE)
    print(_field("Severity", f"{color} {severity.upper()} {RESET}"))
    print(_field("Confidence", f"{triage.get('confidence', '?'):.0%}"))

    category = triage.get("category", "unknown")
    cat_color = GREEN if "false" in category else (RED if "true" in category else YELLOW)
    print(_field("Category", f"{cat_color}{category}{RESET}"))

    print(_field("Summary", triage.get("summary", "N/A")))
    print(_field("Reasoning", f"{DIM}{triage.get('reasoning', 'N/A')}{RESET}"))
    print(_field("Needs Enrichment", str(triage.get("needs_enrichment", "?"))))
    print(_field("Needs Investigation", str(triage.get("needs_investigation", "?"))))
    print()


def print_enrichments(enrichments: dict):
    """Print enrichment results."""
    print(_subheader("ENRICHMENT: Threat Intelligence Lookup"))

    has_data = False

    for ip_intel in enrichments.get("ip_intel", []):
        has_data = True
        malicious = ip_intel.get("malicious", False)
        status = f"{RED}MALICIOUS{RESET}" if malicious else f"{GREEN}CLEAN{RESET}"
        print(_field("IP", f"{ip_intel['ip']} — {status}"))
        if malicious:
            print(_field("  Country", ip_intel.get("country", "?")))
            print(_field("  Tags", ", ".join(ip_intel.get("tags", []))))
            print(_field("  Abuse Confidence", f"{ip_intel.get('abuse_confidence', '?')}%"))
            print(_field("  Reports", str(ip_intel.get("total_reports", "?"))))
            print(_field("  Organization", ip_intel.get("whois_org", "?")))

    for hash_intel in enrichments.get("hash_intel", []):
        has_data = True
        malicious = hash_intel.get("malicious", False)
        status = f"{RED}MALICIOUS{RESET}" if malicious else f"{GREEN}CLEAN{RESET}"
        print(_field("Hash", f"{hash_intel['md5']} — {status}"))
        if malicious:
            print(_field("  Family", hash_intel.get("malware_family", "?")))
            print(_field("  Detection", hash_intel.get("detection_ratio", "?")))
            behaviors = hash_intel.get("sandbox_behaviors", [])
            for b in behaviors:
                print(_field("  Behavior", b))

    for mitre in enrichments.get("mitre", []):
        has_data = True
        print(_field("MITRE", f"{CYAN}{mitre['id']}{RESET} — {mitre.get('technique', '?')}"))
        print(_field("  Tactic", mitre.get("tactic", "?")))
        mitigations = mitre.get("mitigations", [])
        for m in mitigations[:2]:
            print(_field("  Mitigation", m))

    if not has_data:
        print(f"    {DIM}No external enrichment applicable for this alert.{RESET}")
    print()


def print_investigation(investigation: dict):
    """Print investigation agent results."""
    print(_subheader("AGENT 2: Investigation (Claude Sonnet)"))

    if investigation.get("skipped"):
        print(f"    {DIM}Skipped: {investigation.get('reason', 'N/A')}{RESET}")
        print()
        return

    if "error" in investigation:
        print(f"    {RED}Error: {investigation['error']}{RESET}")
        return

    severity = investigation.get("severity_adjusted", "unknown")
    color = SEVERITY_COLORS.get(severity, WHITE)
    print(_field("Investigation", investigation.get("investigation_id", "N/A")))
    print(_field("Title", f"{BOLD}{investigation.get('title', 'N/A')}{RESET}"))
    print(_field("Adjusted Severity", f"{color} {severity.upper()} {RESET}"))
    print()

    narrative = investigation.get("attack_narrative", "N/A")
    print(f"    {BOLD}Attack Narrative:{RESET}")
    # Word-wrap at ~65 chars
    words = narrative.split()
    line = "      "
    for word in words:
        if len(line) + len(word) > 70:
            print(line)
            line = "      "
        line += word + " "
    if line.strip():
        print(line)
    print()

    iocs = investigation.get("indicators_of_compromise", [])
    if iocs:
        print(f"    {BOLD}IOCs Found:{RESET}")
        for ioc in iocs:
            if isinstance(ioc, dict):
                print(f"      {RED}- {ioc.get('type', '?')}: {ioc.get('value', '?')}{RESET}")
            else:
                print(f"      {RED}- {ioc}{RESET}")

    assets = investigation.get("affected_assets", [])
    if assets:
        print(f"    {BOLD}Affected Assets:{RESET}")
        for asset in assets:
            if isinstance(asset, dict):
                print(f"      - {asset.get('name', asset.get('host', '?'))} (risk: {asset.get('risk', asset.get('risk_level', '?'))})")
            else:
                print(f"      - {asset}")

    escalation = investigation.get("escalation_required", False)
    if escalation:
        print(f"\n    {RED}{BOLD}ESCALATION REQUIRED:{RESET} {investigation.get('escalation_reason', 'N/A')}")
    print()


def print_decision(decision: dict):
    """Print decision agent results."""
    print(_subheader("AGENT 3: Decision (Claude Haiku)"))

    if "error" in decision:
        print(f"    {RED}Error: {decision['error']}{RESET}")
        return

    verdict = decision.get("verdict", "unknown")
    color = VERDICT_COLORS.get(verdict, WHITE)
    print(_field("Decision", decision.get("decision_id", "N/A")))
    print(_field("Verdict", f"{color} {verdict.upper()} {RESET}"))

    # Auto actions
    auto_actions = decision.get("auto_actions", [])
    if auto_actions:
        print(f"\n    {GREEN}{BOLD}Auto-executing (no approval needed):{RESET}")
        for action in auto_actions:
            if isinstance(action, dict):
                print(f"      {GREEN}[AUTO]{RESET} {action.get('action', '?')} -> {action.get('target', '?')}")
                print(f"             {DIM}{action.get('reason', '')}{RESET}")
            else:
                print(f"      {GREEN}[AUTO]{RESET} {action}")

    # Human approval actions
    human_actions = decision.get("human_approval_required", [])
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

    # Case management
    case = decision.get("case_management", {})
    if case.get("create_case"):
        print(f"\n    {BLUE}Case: Priority {case.get('priority', '?')} -> {case.get('assigned_to', '?')}{RESET}")

    # Notification
    notification = decision.get("notification", {})
    if notification:
        if isinstance(notification, dict):
            channels = [f"{k}: {v}" for k, v in notification.items()]
            print(_field("Notify", ", ".join(channels)))
        else:
            print(_field("Notify", str(notification)))

    print()


def print_result(result: dict, index: int, total: int):
    """Print the full pipeline result for one alert."""
    print_alert(result["alert"], index, total)

    _spinner("Triage Agent analyzing")
    print_triage(result.get("triage", {}))

    _spinner("Enriching with threat intelligence")
    print_enrichments(result.get("enrichments", {}))

    _spinner("Investigation Agent correlating")
    print_investigation(result.get("investigation", {}))

    _spinner("Decision Agent determining response")
    print_decision(result.get("decision", {}))

    # Show expected vs actual
    expected = result.get("expected_decision", "?")
    verdict = result.get("decision", {}).get("verdict", "?")
    print(f"    {DIM}Expected outcome: {expected}{RESET}")
    print(f"    {DIM}Agent verdict:    {verdict}{RESET}")
    print(_separator("═"))


def print_summary(results: list[dict]):
    """Print a summary table of all processed alerts."""
    print(_header("PIPELINE SUMMARY", GREEN))
    print()
    print(f"    {'Scenario':<42} {'Severity':<12} {'Verdict':<20}")
    print(f"    {'-'*42} {'-'*12} {'-'*20}")
    for r in results:
        scenario = r.get("scenario", "?")[:40]
        severity = r.get("triage", {}).get("severity", "?")
        verdict = r.get("decision", {}).get("verdict", "?")
        sev_color = SEVERITY_COLORS.get(severity, "")
        ver_color = VERDICT_COLORS.get(verdict, "")
        print(f"    {scenario:<42} {sev_color}{severity:<12}{RESET} {ver_color}{verdict:<20}{RESET}")

    print()
    total = len(results)
    auto_closed = sum(1 for r in results if r.get("decision", {}).get("verdict") == "auto_close")
    escalated = sum(1 for r in results if r.get("decision", {}).get("verdict") == "escalate_to_human")

    print(_field("Total alerts processed", str(total)))
    print(_field("Auto-closed (noise)", f"{GREEN}{auto_closed}{RESET}"))
    print(_field("Escalated to human", f"{RED}{escalated}{RESET}"))
    print(_field("Automated responses", str(total - auto_closed - escalated)))
    print()
    print(f"    {BOLD}Key takeaway:{RESET} The AI pipeline handled {total} alerts in seconds.")
    print(f"    A human SOC analyst would need ~15-30 minutes per alert.")
    print(f"    That's {BOLD}{total * 20} minutes{RESET} of analyst time saved per batch.")
    print()
