"""
Wazuh Agentic SOC — Proof of Concept

Usage:
    python -m src.poc                     # Run all 5 scenarios
    python -m src.poc brute_force         # Run a single scenario
    python -m src.poc malware c2_beacon   # Run specific scenarios

Available scenarios:
    brute_force    - SSH Brute Force from Tor Exit Node
    malware        - Known Malware Dropped on Endpoint
    c2_beacon      - Outbound C2 Beacon (Cobalt Strike)
    privesc        - Suspicious Privilege Escalation
    false_positive - Web Scanner Noise (Expected FP)
"""

import sys
import time

from .agents import run_pipeline
from .alerts import SCENARIOS, generate_all_scenarios, generate_scenario
from .display import print_banner, print_result, print_summary


def main():
    print_banner()

    # Parse arguments
    args = sys.argv[1:]

    if args and args[0] in ("--help", "-h"):
        print(__doc__)
        sys.exit(0)

    # Generate alerts based on arguments
    if args:
        invalid = [a for a in args if a not in SCENARIOS]
        if invalid:
            print(f"Unknown scenario(s): {', '.join(invalid)}")
            print(f"Available: {', '.join(SCENARIOS.keys())}")
            sys.exit(1)
        alerts = [generate_scenario(key) for key in args]
    else:
        alerts = generate_all_scenarios()

    total = len(alerts)
    print(f"  Processing {total} alert(s) through the agentic pipeline...\n")

    # Run each alert through the pipeline
    results = []
    start_time = time.time()

    for i, alert in enumerate(alerts, 1):
        result = run_pipeline(alert)
        results.append(result)
        print_result(result, i, total)

    elapsed = time.time() - start_time
    print_summary(results)
    print(f"  Total pipeline time: {elapsed:.1f}s ({elapsed/total:.1f}s per alert)\n")


if __name__ == "__main__":
    main()
