#!/usr/bin/env python3
"""Cross-product incident correlation for XDR Bot.

Groups alerts across MDE, MDO, MDI, and MDA into unified incidents based on:
- Shared entities (users, devices, IPs, URLs)
- Temporal proximity
- MITRE ATT&CK kill chain progression
- Cross-product attack patterns (e.g., phish → credential theft → lateral movement)
"""

import argparse
import json
import os
from datetime import datetime
from collections import defaultdict

# MITRE ATT&CK kill chain stages (ordered)
KILL_CHAIN = [
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact",
]

CATEGORY_TO_STAGE = {
    "InitialAccess": "InitialAccess",
    "Execution": "Execution",
    "Persistence": "Persistence",
    "PrivilegeEscalation": "PrivilegeEscalation",
    "DefenseEvasion": "DefenseEvasion",
    "CredentialAccess": "CredentialAccess",
    "Discovery": "Discovery",
    "LateralMovement": "LateralMovement",
    "Collection": "Collection",
    "CommandAndControl": "CommandAndControl",
    "Exfiltration": "Exfiltration",
    "Impact": "Impact",
    "SuspiciousActivity": "Discovery",
}

# Cross-product attack patterns — known multi-source attack sequences
CROSS_PRODUCT_PATTERNS = [
    {
        "name": "Phishing to Credential Theft",
        "sequence": [("MDO", "InitialAccess"), ("MDI", "CredentialAccess")],
        "severity_boost": 15,
    },
    {
        "name": "Phishing to Endpoint Execution",
        "sequence": [("MDO", "InitialAccess"), ("MDE", "Execution")],
        "severity_boost": 15,
    },
    {
        "name": "Credential Theft to Lateral Movement",
        "sequence": [("MDI", "CredentialAccess"), ("MDE", "LateralMovement")],
        "severity_boost": 10,
    },
    {
        "name": "Cloud Compromise to Data Exfiltration",
        "sequence": [("MDA", "InitialAccess"), ("MDA", "Collection")],
        "severity_boost": 10,
    },
    {
        "name": "Full Kill Chain (Email → Identity → Endpoint)",
        "sequence": [("MDO", "InitialAccess"), ("MDI", "CredentialAccess"), ("MDE", "Execution")],
        "severity_boost": 25,
    },
    {
        "name": "Insider Threat Pattern",
        "sequence": [("MDA", "Collection"), ("MDE", "Exfiltration")],
        "severity_boost": 20,
    },
]


def parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00").replace("+00:00", ""))
    except Exception:
        return datetime.min


def detect_cross_product_pattern(incident_alerts: list) -> list:
    """Check if an incident matches known cross-product attack patterns."""
    # Build set of (source, stage) tuples
    source_stages = set()
    for a in incident_alerts:
        source = a.get("source", "Unknown")
        stage = CATEGORY_TO_STAGE.get(a.get("category", ""), "Unknown")
        source_stages.add((source, stage))

    matched_patterns = []
    for pattern in CROSS_PRODUCT_PATTERNS:
        if all(ss in source_stages for ss in pattern["sequence"]):
            matched_patterns.append(pattern)

    return matched_patterns


def correlate(triaged_alerts: list, time_window_hours: int = 4) -> list:
    """Group alerts into incidents based on shared entities and temporal proximity.
    
    Correlation logic:
    1. Shared user OR shared device within time window → same incident
    2. Cross-product correlation: phishing email to same user + endpoint alert = one incident
    3. Kill chain progression detected → mark as attack chain
    """

    groups = []  # list of sets of alert indices
    alert_to_group = {}

    for i, a in enumerate(triaged_alerts):
        if a.get("action") == "auto_resolve":
            continue

        devices_a = set(a.get("devices", []))
        users_a = set(a.get("users", []))
        emails_a = set(a.get("emails", []))
        ts_a = parse_ts(a.get("created", ""))

        merged = False
        for gi, group in enumerate(groups):
            for j in group:
                b = triaged_alerts[j]
                devices_b = set(b.get("devices", []))
                users_b = set(b.get("users", []))
                emails_b = set(b.get("emails", []))
                ts_b = parse_ts(b.get("created", ""))

                # Check overlap — including cross-product via shared users/emails
                device_overlap = bool(devices_a & devices_b)
                user_overlap = bool(users_a & users_b)
                email_overlap = bool(emails_a & emails_b)
                time_close = abs((ts_a - ts_b).total_seconds()) < time_window_hours * 3600

                if (device_overlap or user_overlap or email_overlap) and time_close:
                    group.add(i)
                    alert_to_group[i] = gi
                    merged = True
                    break
            if merged:
                break

        if not merged:
            alert_to_group[i] = len(groups)
            groups.append({i})

    # Build incident objects
    incidents = []
    for gi, group in enumerate(groups):
        if len(group) < 1:
            continue

        alerts_in_group = [triaged_alerts[i] for i in sorted(group)]
        alerts_in_group.sort(key=lambda x: parse_ts(x.get("created", "")))

        # Determine kill chain stages
        stages = []
        for a in alerts_in_group:
            stage = CATEGORY_TO_STAGE.get(a.get("category", ""), "Unknown")
            if stage not in stages:
                stages.append(stage)
        stages.sort(key=lambda s: KILL_CHAIN.index(s) if s in KILL_CHAIN else 99)

        # Collect all entities
        all_devices = set()
        all_users = set()
        all_emails = set()
        all_cloud_apps = set()
        all_sources = set()
        max_priority = 0
        for a in alerts_in_group:
            all_devices.update(a.get("devices", []))
            all_users.update(a.get("users", []))
            all_emails.update(a.get("emails", []))
            all_cloud_apps.update(a.get("cloudApps", []))
            all_sources.add(a.get("source", "Unknown"))
            max_priority = max(max_priority, a.get("priority", 0))

        # Multi-stage attack chain?
        is_attack_chain = len(stages) >= 3

        # Cross-product detection
        is_cross_product = len(all_sources) >= 2
        matched_patterns = detect_cross_product_pattern(alerts_in_group)

        # Boost priority for cross-product patterns
        pattern_boost = max((p["severity_boost"] for p in matched_patterns), default=0)
        max_priority += pattern_boost

        # Determine incident severity
        if is_attack_chain and is_cross_product:
            severity = "critical"
        elif is_attack_chain or max_priority >= 50:
            severity = "critical"
        elif max_priority >= 40:
            severity = "high"
        elif max_priority >= 25:
            severity = "medium"
        else:
            severity = "low"

        incidents.append({
            "incidentId": f"XDR-INC-{gi + 1:04d}",
            "alertCount": len(alerts_in_group),
            "alerts": [a.get("id") for a in alerts_in_group],
            "killChainStages": stages,
            "isAttackChain": is_attack_chain,
            "isCrossProduct": is_cross_product,
            "matchedPatterns": [p["name"] for p in matched_patterns],
            "xdrSources": sorted(all_sources),
            "devices": sorted(all_devices),
            "users": sorted(all_users),
            "emails": sorted(all_emails),
            "cloudApps": sorted(all_cloud_apps),
            "maxPriority": max_priority,
            "severity": severity,
            "firstSeen": alerts_in_group[0].get("created", ""),
            "lastSeen": alerts_in_group[-1].get("created", ""),
            "timeline": [
                {
                    "time": a.get("created", ""),
                    "title": a.get("title", ""),
                    "source": a.get("source", ""),
                    "sourceLabel": a.get("sourceLabel", ""),
                    "stage": CATEGORY_TO_STAGE.get(a.get("category", ""), "Unknown"),
                    "severity": a.get("severity", ""),
                    "mitre": a.get("mitre_techniques", []),
                }
                for a in alerts_in_group
            ],
        })

    incidents.sort(key=lambda x: x["maxPriority"], reverse=True)
    return incidents


def main():
    p = argparse.ArgumentParser(description="Cross-product XDR incident correlation")
    p.add_argument("--input", required=True, help="Triaged alerts JSON file")
    p.add_argument("--window", type=int, default=4, help="Time window in hours for correlation")
    p.add_argument("--output", help="Output file")
    args = p.parse_args()

    with open(args.input, "r") as f:
        data = json.load(f)

    triaged = data.get("triaged", [])
    incidents = correlate(triaged, args.window)

    # Stats
    cross_product = len([i for i in incidents if i["isCrossProduct"]])
    attack_chains = len([i for i in incidents if i["isAttackChain"]])
    pattern_matches = sum(len(i["matchedPatterns"]) for i in incidents)

    result = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "incidentCount": len(incidents),
        "crossProductIncidents": cross_product,
        "attackChains": attack_chains,
        "patternMatches": pattern_matches,
        "incidents": incidents,
    }

    out = json.dumps(result, indent=2)
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            f.write(out)
        print(f"Written to {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
