"""
Simulated threat intelligence enrichment.

In production, these would call real APIs (VirusTotal, AbuseIPDB, MISP, Shodan).
For the POC, we return realistic mock data so the demo runs without API keys.
"""

from .alerts import KNOWN_MALICIOUS_IPS, KNOWN_MALICIOUS_HASHES

# MITRE ATT&CK context (subset for demo)
MITRE_CONTEXT = {
    "T1110.001": {
        "technique": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force to attempt access to accounts when passwords are unknown or obtained hashes cannot be cracked offline.",
        "mitigations": [
            "Account lockout policies after N failed attempts",
            "Multi-factor authentication",
            "Rate limiting on authentication endpoints",
        ],
        "detection": "Monitor authentication logs for a high number of failed login attempts from a single source.",
    },
    "T1059.001": {
        "technique": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is widely available on Windows and can be used to run downloaded payloads.",
        "mitigations": [
            "Constrained Language Mode for PowerShell",
            "Application whitelisting",
            "Script block logging",
        ],
        "detection": "Monitor script execution, enable PowerShell transcription logging, watch for encoded commands.",
    },
    "T1071.001": {
        "technique": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using web protocols (HTTP/HTTPS) to avoid detection by blending in with normal traffic.",
        "mitigations": [
            "SSL/TLS inspection on outbound traffic",
            "Network segmentation",
            "DNS sinkholing for known C2 domains",
        ],
        "detection": "Monitor for beaconing patterns — regular interval connections to external IPs, especially over HTTPS.",
    },
    "T1548.003": {
        "technique": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may perform sudo caching or manipulate sudoers to escalate privileges on Linux/macOS.",
        "mitigations": [
            "Restrict sudoers to specific commands",
            "Require password for sudo",
            "Monitor /etc/sudoers changes",
        ],
        "detection": "Monitor sudo usage for unusual commands or users. Alert on sudo to full root shell.",
    },
    "T1595.002": {
        "technique": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may scan for vulnerabilities to identify weaknesses in target systems.",
        "mitigations": [
            "Rate limiting on web servers",
            "Web application firewalls",
            "Hide version banners",
        ],
        "detection": "Monitor web server logs for high-volume 404 errors from single IPs, scanning user agents.",
    },
}


def enrich_ip(ip: str) -> dict:
    """Simulate VirusTotal/AbuseIPDB lookup for an IP address."""
    if ip in KNOWN_MALICIOUS_IPS:
        info = KNOWN_MALICIOUS_IPS[ip]
        return {
            "ip": ip,
            "source": "VirusTotal + AbuseIPDB (simulated)",
            "malicious": True,
            "reputation_score": 85 + hash(ip) % 15,
            "country": info["country"],
            "tags": info["tags"],
            "abuse_confidence": 95,
            "total_reports": 127 + hash(ip) % 200,
            "last_seen_malicious": "2026-03-06",
            "whois_org": "Bulletproof Hosting Ltd" if info["country"] == "RU" else "Anonymous VPS Provider",
        }
    return {
        "ip": ip,
        "source": "VirusTotal + AbuseIPDB (simulated)",
        "malicious": False,
        "reputation_score": 0,
        "country": "internal" if ip.startswith(("10.", "192.168.", "172.16.")) else "US",
        "tags": [],
        "abuse_confidence": 0,
        "total_reports": 0,
    }


def enrich_hash(md5: str) -> dict:
    """Simulate VirusTotal hash lookup."""
    if md5 in KNOWN_MALICIOUS_HASHES:
        info = KNOWN_MALICIOUS_HASHES[md5]
        return {
            "md5": md5,
            "source": "VirusTotal (simulated)",
            "malicious": True,
            "malware_family": info["malware_family"],
            "detection_ratio": "58/72",
            "first_seen": "2025-11-15",
            "last_seen": "2026-03-05",
            "sandbox_verdict": "malicious",
            "sandbox_behaviors": [
                "Modifies registry run keys",
                "Connects to external C2",
                "Drops additional payloads",
                "Attempts credential harvesting",
            ],
        }
    return {
        "md5": md5,
        "source": "VirusTotal (simulated)",
        "malicious": False,
        "detection_ratio": "0/72",
    }


def enrich_mitre(technique_ids: list[str]) -> list[dict]:
    """Return MITRE ATT&CK context for given technique IDs."""
    results = []
    for tid in technique_ids:
        if tid in MITRE_CONTEXT:
            results.append({"id": tid, **MITRE_CONTEXT[tid]})
        else:
            results.append({"id": tid, "technique": "Unknown", "tactic": "Unknown"})
    return results


def enrich_alert(alert: dict) -> dict:
    """Run all applicable enrichments for an alert and return enrichment context."""
    enrichments = {"mitre": [], "ip_intel": [], "hash_intel": []}

    # MITRE enrichment
    mitre_ids = alert.get("rule", {}).get("mitre", {}).get("id", [])
    if mitre_ids:
        enrichments["mitre"] = enrich_mitre(mitre_ids)

    # IP enrichment
    data = alert.get("data", {})
    for ip_field in ["srcip", "dstip"]:
        ip = data.get(ip_field)
        if ip and not ip.startswith(("10.", "192.168.", "172.16.")):
            enrichments["ip_intel"].append(enrich_ip(ip))

    # Hash enrichment
    syscheck = alert.get("syscheck", {})
    md5 = syscheck.get("md5_after")
    if md5:
        enrichments["hash_intel"].append(enrich_hash(md5))

    return enrichments
