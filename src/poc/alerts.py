"""
Simulated Wazuh alerts for POC demonstration.

Each alert mirrors the structure of a real Wazuh alert from the
wazuh-alerts-* index, with realistic fields SOC analysts recognize.
"""

import random
import uuid
from datetime import datetime, timedelta, timezone

# --- Realistic IOCs for enrichment scenarios ---

KNOWN_MALICIOUS_IPS = {
    "185.220.101.34": {"reputation": "malicious", "tags": ["tor-exit-node", "bruteforce"], "country": "DE"},
    "45.155.205.233": {"reputation": "malicious", "tags": ["c2-server", "cobalt-strike"], "country": "RU"},
    "194.26.192.77": {"reputation": "malicious", "tags": ["scanner", "exploit-attempt"], "country": "NL"},
}

KNOWN_MALICIOUS_HASHES = {
    "e99a18c428cb38d5f260853678922e03": {"malware_family": "Emotet", "severity": "critical"},
    "5d41402abc4b2a76b9719d911017c592": {"malware_family": "AgentTesla", "severity": "high"},
}

CLEAN_IPS = ["10.0.1.50", "10.0.2.100", "192.168.1.25", "172.16.0.10"]
INTERNAL_USERS = ["jsmith", "admin", "svc_backup", "deployer", "alice.jones"]
HOSTNAMES = ["WS-PC-0142", "SRV-DC-01", "SRV-WEB-03", "WS-PC-0087", "SRV-DB-02"]


def _timestamp(minutes_ago: int = 0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _alert_id() -> str:
    return str(uuid.uuid4())[:18]


# --- Alert generators (each returns a dict matching Wazuh alert schema) ---


def brute_force_ssh() -> dict:
    """Multiple failed SSH logins from a known Tor exit node."""
    attacker_ip = "185.220.101.34"
    target = random.choice(HOSTNAMES)
    return {
        "id": _alert_id(),
        "timestamp": _timestamp(random.randint(1, 10)),
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "SSHD brute force attack (multiple failed logins).",
            "groups": ["syslog", "sshd", "authentication_failures"],
            "mitre": {
                "id": ["T1110.001"],
                "tactic": ["Credential Access"],
                "technique": ["Brute Force: Password Guessing"],
            },
        },
        "agent": {"id": "003", "name": target, "ip": "10.0.1.50"},
        "data": {
            "srcip": attacker_ip,
            "srcport": str(random.randint(40000, 65000)),
            "dstuser": random.choice(["root", "admin", "ubuntu"]),
            "program_name": "sshd",
        },
        "location": "/var/log/auth.log",
        "decoder": {"name": "sshd"},
        "full_log": f"Failed password for root from {attacker_ip} port {random.randint(40000, 65000)} ssh2",
    }


def malware_detected() -> dict:
    """File integrity monitoring detects a known malware hash."""
    md5 = random.choice(list(KNOWN_MALICIOUS_HASHES.keys()))
    target = random.choice(HOSTNAMES)
    return {
        "id": _alert_id(),
        "timestamp": _timestamp(random.randint(1, 5)),
        "rule": {
            "id": "554",
            "level": 13,
            "description": "File added to system with known malware hash.",
            "groups": ["ossec", "syscheck", "malware"],
            "mitre": {
                "id": ["T1059.001"],
                "tactic": ["Execution"],
                "technique": ["Command and Scripting Interpreter: PowerShell"],
            },
        },
        "agent": {"id": "007", "name": target, "ip": "10.0.2.100"},
        "syscheck": {
            "path": f"/tmp/.cache/{uuid.uuid4().hex[:8]}.exe",
            "md5_after": md5,
            "sha256_after": uuid.uuid4().hex + uuid.uuid4().hex,
            "size_after": str(random.randint(50000, 500000)),
            "event": "added",
        },
        "location": "syscheck",
        "decoder": {"name": "syscheck_new_entry"},
        "full_log": f"File '/tmp/.cache/payload.exe' added. MD5: {md5}",
    }


def c2_beacon() -> dict:
    """Outbound connection to a known C2 server detected by Suricata/IDS."""
    c2_ip = "45.155.205.233"
    target = random.choice(HOSTNAMES)
    src_ip = random.choice(CLEAN_IPS)
    return {
        "id": _alert_id(),
        "timestamp": _timestamp(random.randint(1, 3)),
        "rule": {
            "id": "86601",
            "level": 12,
            "description": "Suricata: Outbound connection to known C2 infrastructure.",
            "groups": ["ids", "suricata", "network_traffic"],
            "mitre": {
                "id": ["T1071.001"],
                "tactic": ["Command and Control"],
                "technique": ["Application Layer Protocol: Web Protocols"],
            },
        },
        "agent": {"id": "003", "name": target, "ip": src_ip},
        "data": {
            "srcip": src_ip,
            "dstip": c2_ip,
            "dstport": "443",
            "protocol": "TCP",
            "alert": {
                "signature": "ET MALWARE Cobalt Strike Beacon Activity",
                "category": "A Network Trojan was detected",
                "severity": 1,
            },
        },
        "location": "/var/log/suricata/eve.json",
        "decoder": {"name": "json"},
        "full_log": f'{{"src_ip":"{src_ip}","dest_ip":"{c2_ip}","dest_port":443,"alert":{{"signature":"ET MALWARE Cobalt Strike Beacon Activity"}}}}',
    }


def privilege_escalation() -> dict:
    """Suspicious sudo usage or privilege escalation attempt."""
    user = random.choice(["jsmith", "alice.jones"])
    target = random.choice(HOSTNAMES)
    return {
        "id": _alert_id(),
        "timestamp": _timestamp(random.randint(1, 15)),
        "rule": {
            "id": "5405",
            "level": 8,
            "description": "User used sudo to run a shell as root.",
            "groups": ["syslog", "sudo", "privilege_escalation"],
            "mitre": {
                "id": ["T1548.003"],
                "tactic": ["Privilege Escalation", "Defense Evasion"],
                "technique": ["Abuse Elevation Control Mechanism: Sudo and Sudo Caching"],
            },
        },
        "agent": {"id": "012", "name": target, "ip": "10.0.1.50"},
        "data": {
            "srcuser": user,
            "dstuser": "root",
            "command": "/bin/bash",
        },
        "location": "/var/log/auth.log",
        "decoder": {"name": "sudo"},
        "full_log": f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash",
    }


def false_positive_web_scan() -> dict:
    """Low-severity web vulnerability scanner noise (should be auto-closed)."""
    scanner_ip = "194.26.192.77"
    target = random.choice(["SRV-WEB-03"])
    return {
        "id": _alert_id(),
        "timestamp": _timestamp(random.randint(1, 30)),
        "rule": {
            "id": "31104",
            "level": 6,
            "description": "Web server 404 error code (possible reconnaissance).",
            "groups": ["web", "accesslog", "reconnaissance"],
            "mitre": {
                "id": ["T1595.002"],
                "tactic": ["Reconnaissance"],
                "technique": ["Active Scanning: Vulnerability Scanning"],
            },
        },
        "agent": {"id": "005", "name": target, "ip": "10.0.3.10"},
        "data": {
            "srcip": scanner_ip,
            "url": "/.env",
            "status": "404",
            "method": "GET",
        },
        "location": "/var/log/nginx/access.log",
        "decoder": {"name": "nginx-accesslog"},
        "full_log": f'{scanner_ip} - - "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0"',
    }


# --- Scenario builder ---

SCENARIOS = {
    "brute_force": {
        "name": "SSH Brute Force from Tor Exit Node",
        "generator": brute_force_ssh,
        "expected_decision": "block_ip + monitor",
    },
    "malware": {
        "name": "Known Malware Dropped on Endpoint",
        "generator": malware_detected,
        "expected_decision": "isolate_host + quarantine_file",
    },
    "c2_beacon": {
        "name": "Outbound C2 Beacon (Cobalt Strike)",
        "generator": c2_beacon,
        "expected_decision": "isolate_host + block_ip + escalate_ir",
    },
    "privesc": {
        "name": "Suspicious Privilege Escalation",
        "generator": privilege_escalation,
        "expected_decision": "investigate + alert_soc",
    },
    "false_positive": {
        "name": "Web Scanner Noise (Expected FP)",
        "generator": false_positive_web_scan,
        "expected_decision": "auto_close",
    },
}


def generate_scenario(scenario_key: str) -> dict:
    """Generate a single alert for a named scenario."""
    scenario = SCENARIOS[scenario_key]
    alert = scenario["generator"]()
    alert["_scenario"] = scenario["name"]
    alert["_expected"] = scenario["expected_decision"]
    return alert


def generate_all_scenarios() -> list[dict]:
    """Generate one alert per scenario for the full demo."""
    return [generate_scenario(key) for key in SCENARIOS]
