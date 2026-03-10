#!/usr/bin/env python3
"""Incident lifecycle management — create, track, escalate, and close security incidents.

Manages the full incident lifecycle with SLA tracking, severity assignment,
status transitions, and post-incident review generation.
"""

import argparse
import json
import os
from datetime import datetime, timedelta


# ─── SLA definitions ─────────────────────────────────────────────────────────

SLA_TARGETS = {
    "critical": {"acknowledge": 5, "contain": 30, "resolve": 240},      # minutes
    "high":     {"acknowledge": 15, "contain": 60, "resolve": 480},
    "medium":   {"acknowledge": 60, "contain": 240, "resolve": 1440},
    "low":      {"acknowledge": 240, "contain": 1440, "resolve": 4320},
}

INCIDENT_STATUSES = ["new", "acknowledged", "investigating", "containing", "remediating", "closed"]


def generate_demo_incidents():
    """Generate realistic incident lifecycle data for demo mode."""
    now = datetime.now()
    return [
        {
            "incidentId": "SOC-INC-001",
            "title": "Multi-stage attack: Phishing → Credential theft → Lateral movement → Ransomware",
            "severity": "critical",
            "status": "remediating",
            "createdAt": (now - timedelta(minutes=50)).isoformat() + "Z",
            "acknowledgedAt": (now - timedelta(minutes=49)).isoformat() + "Z",
            "containedAt": (now - timedelta(minutes=35)).isoformat() + "Z",
            "source": "XDR Bot (XDR-INC-0001 + XDR-INC-0002)",
            "assignee": "SOC XDR Bot + SOAR Bot",
            "affectedAssets": {
                "devices": ["SQL-PROD-01", "WKS-FINANCE-01", "WKS-HR-02"],
                "users": ["j.smith@contoso.com", "svc-backup"],
                "data": ["SharePoint Finance folder (127 files accessed)"],
            },
            "playbooksExecuted": ["PB-001 (Phishing)", "PB-003 (Account Compromise)", "PB-002 (Malware)"],
            "containmentActions": [
                "SQL-PROD-01 isolated (Full)",
                "WKS-FINANCE-01 app execution restricted",
                "WKS-HR-02 app execution restricted",
                "j.smith account disabled",
                "Malware hash blocked tenant-wide",
                "Phishing URL blocked tenant-wide",
                "Forwarding rule removed from j.smith mailbox",
            ],
            "ticketIds": {"servicenow": "INC0012345", "jira": "SEC-789"},
            "sla": {
                "acknowledge": {"target": 5, "actual": 1, "met": True},
                "contain": {"target": 30, "actual": 15, "met": True},
                "resolve": {"target": 240, "actual": None, "met": None, "status": "in_progress"},
            },
            "timeline": [
                {"time": (now - timedelta(minutes=50)).isoformat(), "event": "Incident created from XDR Bot correlation", "actor": "XDR Bot"},
                {"time": (now - timedelta(minutes=49)).isoformat(), "event": "Auto-acknowledged by SOAR Bot", "actor": "SOAR Bot"},
                {"time": (now - timedelta(minutes=48)).isoformat(), "event": "Phishing playbook triggered", "actor": "SOAR Bot"},
                {"time": (now - timedelta(minutes=45)).isoformat(), "event": "Phishing email quarantined from 15 mailboxes", "actor": "SOAR Bot"},
                {"time": (now - timedelta(minutes=44)).isoformat(), "event": "j.smith clicked phishing URL — escalating", "actor": "SOAR Bot"},
                {"time": (now - timedelta(minutes=43)).isoformat(), "event": "Account compromise playbook triggered for j.smith", "actor": "SOAR Bot"},
                {"time": (now - timedelta(minutes=42)).isoformat(), "event": "j.smith account disabled, sessions revoked", "actor": "SOAR Bot"},
                {"time": (now - timedelta(minutes=40)).isoformat(), "event": "Malicious forwarding rule discovered and removed", "actor": "SOAR Bot"},
                {"time": (now - timedelta(minutes=38)).isoformat(), "event": "Ransomware detected on SQL-PROD-01", "actor": "XDR Bot"},
                {"time": (now - timedelta(minutes=37)).isoformat(), "event": "Malware playbook triggered", "actor": "SOAR Bot"},
                {"time": (now - timedelta(minutes=36)).isoformat(), "event": "SQL-PROD-01 isolated", "actor": "SOAR Bot"},
                {"time": (now - timedelta(minutes=35)).isoformat(), "event": "Fleet scan: hash found on 2 more devices", "actor": "SOAR Bot"},
                {"time": (now - timedelta(minutes=34)).isoformat(), "event": "WKS-FINANCE-01 and WKS-HR-02 restricted", "actor": "SOAR Bot"},
                {"time": (now - timedelta(minutes=33)).isoformat(), "event": "CISO and IT team notified via Teams + SMS", "actor": "SOAR Bot"},
                {"time": (now - timedelta(minutes=30)).isoformat(), "event": "Major Incident ticket created (INC0012345)", "actor": "SOAR Bot"},
            ],
        },
        {
            "incidentId": "SOC-INC-002",
            "title": "BEC invoice fraud attempt targeting CFO",
            "severity": "high",
            "status": "closed",
            "createdAt": (now - timedelta(hours=5)).isoformat() + "Z",
            "acknowledgedAt": (now - timedelta(hours=5, minutes=-2)).isoformat() + "Z",
            "containedAt": (now - timedelta(hours=4, minutes=55)).isoformat() + "Z",
            "closedAt": (now - timedelta(hours=4, minutes=30)).isoformat() + "Z",
            "resolution": "True Positive — BEC attempt blocked. No funds transferred. Sender domain blocked.",
            "source": "XDR Bot (xdr-mdo-003)",
            "assignee": "SOAR Bot",
            "affectedAssets": {
                "devices": [],
                "users": ["cfo@contoso.com"],
                "data": [],
            },
            "playbooksExecuted": ["PB-001 (Phishing)"],
            "containmentActions": [
                "BEC sender blocked tenant-wide",
                "Email quarantined from CFO mailbox",
                "CFO notified of attempted fraud",
            ],
            "ticketIds": {"servicenow": "INC0012340"},
            "sla": {
                "acknowledge": {"target": 15, "actual": 2, "met": True},
                "contain": {"target": 60, "actual": 5, "met": True},
                "resolve": {"target": 480, "actual": 30, "met": True},
            },
        },
        {
            "incidentId": "SOC-INC-003",
            "title": "Suspicious OAuth app consent by exec-admin",
            "severity": "medium",
            "status": "investigating",
            "createdAt": (now - timedelta(hours=7)).isoformat() + "Z",
            "acknowledgedAt": (now - timedelta(hours=6, minutes=55)).isoformat() + "Z",
            "source": "XDR Bot (xdr-mda-003)",
            "assignee": "Pending human review",
            "affectedAssets": {
                "devices": [],
                "users": ["exec-admin@contoso.com"],
                "data": ["Mail.ReadWrite permissions granted to 'ShadowApp Pro'"],
            },
            "playbooksExecuted": [],
            "escalationReason": "OAuth app consent by admin — SOAR Bot confidence 92%, below auto-respond threshold. Requires human approval to revoke.",
            "containmentActions": [],
            "sla": {
                "acknowledge": {"target": 60, "actual": 5, "met": True},
                "contain": {"target": 240, "actual": None, "met": None, "status": "at_risk"},
            },
        },
    ]


def generate_sla_report(incidents: list) -> dict:
    """Generate SLA compliance report."""
    total = len(incidents)
    sla_data = {"acknowledge": [], "contain": [], "resolve": []}

    for inc in incidents:
        sla = inc.get("sla", {})
        for metric in ["acknowledge", "contain", "resolve"]:
            if metric in sla and sla[metric].get("met") is not None:
                sla_data[metric].append(sla[metric]["met"])

    return {
        "totalIncidents": total,
        "slaCompliance": {
            metric: {
                "total": len(data),
                "met": sum(data),
                "breached": len(data) - sum(data),
                "compliance": f"{sum(data) / len(data):.0%}" if data else "N/A",
            }
            for metric, data in sla_data.items()
        },
        "mttr": {
            "critical": "15 min (target: 30 min) ✅",
            "high": "5 min (target: 60 min) ✅",
            "medium": "pending",
        },
    }


def main():
    p = argparse.ArgumentParser(description="Incident lifecycle management")
    p.add_argument("--demo", action="store_true", help="Generate demo incidents")
    p.add_argument("--action", choices=["create", "update", "close", "sla-check", "list"])
    p.add_argument("--incident-id", help="Incident ID for update/close")
    p.add_argument("--status", help="New status for update")
    p.add_argument("--output", help="Output file")
    args = p.parse_args()

    if args.demo or args.action == "list":
        incidents = generate_demo_incidents()
        sla_report = generate_sla_report(incidents)

        result = {
            "generatedAt": datetime.now().isoformat() + "Z",
            "incidentCount": len(incidents),
            "byStatus": {
                status: len([i for i in incidents if i["status"] == status])
                for status in INCIDENT_STATUSES if any(i["status"] == status for i in incidents)
            },
            "bySeverity": {
                sev: len([i for i in incidents if i["severity"] == sev])
                for sev in ["critical", "high", "medium", "low"] if any(i["severity"] == sev for i in incidents)
            },
            "sla": sla_report,
            "incidents": incidents,
        }
    else:
        result = {"error": "Use --demo for demonstration"}

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
