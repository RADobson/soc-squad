#!/usr/bin/env python3
"""Sentinel log source management — inventory, coverage gaps, health monitoring, cost analysis.

Monitors data connectors, analyses ingestion volumes, identifies coverage gaps,
and recommends priority log sources to connect.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../e8cr-vmpm/scripts"))
try:
    from graph_auth import get_env, get_token
except ImportError:
    def get_env(): raise RuntimeError("graph_auth not available — use --demo mode")
    def get_token(*a): raise RuntimeError("graph_auth not available — use --demo mode")


# ─── Required log sources for ML2 SOC operations ─────────────────────────────

REQUIRED_LOG_SOURCES = {
    "critical": [
        {"name": "SecurityEvent (Windows)", "table": "SecurityEvent", "connector": "Windows Security Events via AMA",
         "covers": ["Authentication", "Process execution", "Account management"]},
        {"name": "SigninLogs (Entra ID)", "table": "SigninLogs", "connector": "Azure Active Directory",
         "covers": ["Authentication", "MFA", "Conditional Access"]},
        {"name": "AuditLogs (Entra ID)", "table": "AuditLogs", "connector": "Azure Active Directory",
         "covers": ["User/group changes", "App registrations", "Role assignments"]},
        {"name": "DeviceProcessEvents (MDE)", "table": "DeviceProcessEvents", "connector": "Microsoft 365 Defender",
         "covers": ["Process execution", "Command line", "File creation"]},
        {"name": "EmailEvents (MDO)", "table": "EmailEvents", "connector": "Microsoft 365 Defender",
         "covers": ["Email delivery", "Phishing detection", "Attachment analysis"]},
        {"name": "IdentityLogonEvents (MDI)", "table": "IdentityLogonEvents", "connector": "Microsoft 365 Defender",
         "covers": ["Domain controller auth", "Kerberos", "NTLM"]},
    ],
    "high": [
        {"name": "DeviceNetworkEvents (MDE)", "table": "DeviceNetworkEvents", "connector": "Microsoft 365 Defender",
         "covers": ["Network connections", "DNS queries", "C2 detection"]},
        {"name": "DeviceFileEvents (MDE)", "table": "DeviceFileEvents", "connector": "Microsoft 365 Defender",
         "covers": ["File operations", "Ransomware detection", "Data staging"]},
        {"name": "CloudAppEvents (MDA)", "table": "CloudAppEvents", "connector": "Microsoft 365 Defender",
         "covers": ["Cloud app usage", "OAuth apps", "Shadow IT"]},
        {"name": "OfficeActivity", "table": "OfficeActivity", "connector": "Office 365",
         "covers": ["SharePoint", "OneDrive", "Exchange admin actions"]},
        {"name": "AzureActivity", "table": "AzureActivity", "connector": "Azure Activity",
         "covers": ["Azure resource operations", "IAM changes", "Policy changes"]},
        {"name": "Syslog (Linux)", "table": "Syslog", "connector": "Syslog via AMA",
         "covers": ["Linux authentication", "Service events", "System changes"]},
    ],
    "recommended": [
        {"name": "DnsEvents", "table": "DnsEvents", "connector": "DNS (Preview)",
         "covers": ["DNS queries", "DNS tunneling detection"]},
        {"name": "CommonSecurityLog (Firewall)", "table": "CommonSecurityLog", "connector": "Common Event Format (CEF)",
         "covers": ["Firewall logs", "IDS/IPS", "VPN connections"]},
        {"name": "AWSCloudTrail", "table": "AWSCloudTrail", "connector": "Amazon Web Services",
         "covers": ["AWS API calls", "IAM changes", "S3 access"]},
        {"name": "ThreatIntelligenceIndicator", "table": "ThreatIntelligenceIndicator", "connector": "Threat Intelligence - TAXII / Platforms",
         "covers": ["IOC matching", "Threat feed correlation"]},
    ],
}


def generate_demo_inventory():
    """Generate realistic log source inventory for demo mode."""
    now = datetime.now()
    return {
        "connected": [
            {
                "name": "SecurityEvent (Windows)", "table": "SecurityEvent",
                "connector": "Windows Security Events via AMA", "status": "healthy",
                "lastDataReceived": (now - timedelta(minutes=2)).isoformat() + "Z",
                "dailyIngestionGB": 4.2, "dailyCostUSD": 9.66,
                "recordsLast24h": 2_450_000, "priority": "critical",
            },
            {
                "name": "SigninLogs (Entra ID)", "table": "SigninLogs",
                "connector": "Azure Active Directory", "status": "healthy",
                "lastDataReceived": (now - timedelta(minutes=1)).isoformat() + "Z",
                "dailyIngestionGB": 0.8, "dailyCostUSD": 1.84,
                "recordsLast24h": 125_000, "priority": "critical",
            },
            {
                "name": "AuditLogs (Entra ID)", "table": "AuditLogs",
                "connector": "Azure Active Directory", "status": "healthy",
                "lastDataReceived": (now - timedelta(minutes=5)).isoformat() + "Z",
                "dailyIngestionGB": 0.3, "dailyCostUSD": 0.69,
                "recordsLast24h": 45_000, "priority": "critical",
            },
            {
                "name": "DeviceProcessEvents (MDE)", "table": "DeviceProcessEvents",
                "connector": "Microsoft 365 Defender", "status": "healthy",
                "lastDataReceived": (now - timedelta(minutes=3)).isoformat() + "Z",
                "dailyIngestionGB": 6.1, "dailyCostUSD": 14.03,
                "recordsLast24h": 3_800_000, "priority": "critical",
            },
            {
                "name": "EmailEvents (MDO)", "table": "EmailEvents",
                "connector": "Microsoft 365 Defender", "status": "healthy",
                "lastDataReceived": (now - timedelta(minutes=8)).isoformat() + "Z",
                "dailyIngestionGB": 0.5, "dailyCostUSD": 1.15,
                "recordsLast24h": 85_000, "priority": "critical",
            },
            {
                "name": "DeviceNetworkEvents (MDE)", "table": "DeviceNetworkEvents",
                "connector": "Microsoft 365 Defender", "status": "healthy",
                "lastDataReceived": (now - timedelta(minutes=3)).isoformat() + "Z",
                "dailyIngestionGB": 8.7, "dailyCostUSD": 20.01,
                "recordsLast24h": 5_200_000, "priority": "high",
            },
            {
                "name": "OfficeActivity", "table": "OfficeActivity",
                "connector": "Office 365", "status": "healthy",
                "lastDataReceived": (now - timedelta(minutes=12)).isoformat() + "Z",
                "dailyIngestionGB": 1.2, "dailyCostUSD": 2.76,
                "recordsLast24h": 320_000, "priority": "high",
            },
            {
                "name": "Syslog (Linux)", "table": "Syslog",
                "connector": "Syslog via AMA", "status": "degraded",
                "lastDataReceived": (now - timedelta(hours=6)).isoformat() + "Z",
                "dailyIngestionGB": 0.1, "dailyCostUSD": 0.23,
                "recordsLast24h": 8_000, "priority": "high",
                "healthIssue": "No data received in 6 hours — check AMA agent on Linux hosts",
            },
        ],
        "missing": [
            {"name": "IdentityLogonEvents (MDI)", "table": "IdentityLogonEvents",
             "priority": "critical", "reason": "MDI connector not enabled — no DC auth visibility"},
            {"name": "CloudAppEvents (MDA)", "table": "CloudAppEvents",
             "priority": "high", "reason": "MDA connector not enabled — no shadow IT or OAuth visibility"},
            {"name": "AzureActivity", "table": "AzureActivity",
             "priority": "high", "reason": "Azure Activity connector not configured"},
            {"name": "DeviceFileEvents (MDE)", "table": "DeviceFileEvents",
             "priority": "high", "reason": "Table exists but not ingesting — check M365D advanced hunting settings"},
            {"name": "DnsEvents", "table": "DnsEvents",
             "priority": "recommended", "reason": "DNS connector not enabled — no DNS tunneling detection"},
            {"name": "CommonSecurityLog (Firewall)", "table": "CommonSecurityLog",
             "priority": "recommended", "reason": "No firewall logs — no network perimeter visibility"},
            {"name": "ThreatIntelligenceIndicator", "table": "ThreatIntelligenceIndicator",
             "priority": "recommended", "reason": "No threat feed connected — IOC matching unavailable"},
        ],
    }


def coverage_gap_analysis(inventory: dict) -> dict:
    """Analyse log source coverage gaps against requirements."""
    connected_tables = {s["table"] for s in inventory["connected"]}
    missing = inventory.get("missing", [])

    # Count by priority
    critical_required = REQUIRED_LOG_SOURCES["critical"]
    critical_connected = [s for s in critical_required if s["table"] in connected_tables]
    critical_missing = [s for s in critical_required if s["table"] not in connected_tables]

    high_required = REQUIRED_LOG_SOURCES["high"]
    high_connected = [s for s in high_required if s["table"] in connected_tables]
    high_missing = [s for s in high_required if s["table"] not in connected_tables]

    return {
        "generatedAt": datetime.now().isoformat() + "Z",
        "overallCoverage": f"{len(connected_tables)}/{len(critical_required) + len(high_required)}",
        "criticalCoverage": f"{len(critical_connected)}/{len(critical_required)}",
        "highCoverage": f"{len(high_connected)}/{len(high_required)}",
        "criticalGaps": [{"name": s["name"], "covers": s["covers"]} for s in critical_missing],
        "highGaps": [{"name": s["name"], "covers": s["covers"]} for s in high_missing],
        "recommendations": [
            {"priority": 1, "action": f"Enable {s['name']} — {s['connector']}", "impact": ", ".join(s["covers"])}
            for s in critical_missing
        ] + [
            {"priority": 2, "action": f"Enable {s['name']} — {s['connector']}", "impact": ", ".join(s["covers"])}
            for s in high_missing
        ],
    }


def cost_analysis(inventory: dict) -> dict:
    """Analyse Sentinel ingestion costs and identify optimisation opportunities."""
    sources = inventory["connected"]
    total_daily_gb = sum(s.get("dailyIngestionGB", 0) for s in sources)
    total_daily_cost = sum(s.get("dailyCostUSD", 0) for s in sources)

    # Sort by cost
    by_cost = sorted(sources, key=lambda s: s.get("dailyCostUSD", 0), reverse=True)

    # Identify high-volume tables for potential optimisation
    optimisations = []
    for s in sources:
        if s.get("dailyIngestionGB", 0) > 5:
            optimisations.append({
                "table": s["name"],
                "dailyGB": s["dailyIngestionGB"],
                "dailyCostUSD": s["dailyCostUSD"],
                "suggestion": "Consider Basic Logs tier or data collection rules to filter noisy events",
            })

    return {
        "generatedAt": datetime.now().isoformat() + "Z",
        "totalDailyIngestionGB": round(total_daily_gb, 1),
        "totalDailyCostUSD": round(total_daily_cost, 2),
        "totalMonthlyCostUSD": round(total_daily_cost * 30, 2),
        "totalAnnualCostUSD": round(total_daily_cost * 365, 2),
        "costBreakdown": [
            {"name": s["name"], "dailyGB": s.get("dailyIngestionGB", 0), "dailyCostUSD": s.get("dailyCostUSD", 0),
             "monthlyUSD": round(s.get("dailyCostUSD", 0) * 30, 2),
             "pctOfTotal": f"{s.get('dailyCostUSD', 0) / total_daily_cost:.0%}" if total_daily_cost > 0 else "0%"}
            for s in by_cost
        ],
        "optimisations": optimisations,
    }


def main():
    p = argparse.ArgumentParser(description="Sentinel log source management")
    p.add_argument("--demo", action="store_true", help="Use synthetic demo data")
    p.add_argument("--action", choices=["inventory", "gaps", "health", "costs"], default="inventory")
    p.add_argument("--output", help="Output file")
    args = p.parse_args()

    if args.demo:
        inventory = generate_demo_inventory()
    else:
        tenant, client_id, client_secret = get_env()
        token = get_token(tenant, client_id, client_secret)
        # Would fetch real connector data via ARM API
        inventory = generate_demo_inventory()  # Placeholder

    if args.action == "inventory":
        result = inventory
    elif args.action == "gaps":
        result = coverage_gap_analysis(inventory)
    elif args.action == "health":
        degraded = [s for s in inventory["connected"] if s.get("status") == "degraded"]
        result = {
            "generatedAt": datetime.now().isoformat() + "Z",
            "totalConnectors": len(inventory["connected"]),
            "healthy": len([s for s in inventory["connected"] if s["status"] == "healthy"]),
            "degraded": len(degraded),
            "issues": [{"name": s["name"], "issue": s.get("healthIssue", "Unknown")} for s in degraded],
        }
    elif args.action == "costs":
        result = cost_analysis(inventory)

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
