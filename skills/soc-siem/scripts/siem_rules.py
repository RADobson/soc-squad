#!/usr/bin/env python3
"""Sentinel analytics rule management — audit, tune, create, and MITRE coverage analysis.

Real mode: Azure Resource Manager API for Sentinel workspace.
Demo mode: Generates realistic synthetic analytics rules and audit results.

Required: AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, SENTINEL_WORKSPACE_NAME + graph_auth creds.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import HTTPError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../e8cr-vmpm/scripts"))
try:
    from graph_auth import get_env, get_token
except ImportError:
    def get_env(): raise RuntimeError("graph_auth not available — use --demo mode")
    def get_token(*a): raise RuntimeError("graph_auth not available — use --demo mode")


def _arm_base():
    sub = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    rg = os.environ.get("AZURE_RESOURCE_GROUP", "")
    ws = os.environ.get("SENTINEL_WORKSPACE_NAME", "")
    return f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights"


def _arm_get(token: str, endpoint: str, api_version: str = "2023-11-01"):
    url = f"{_arm_base()}/{endpoint}?api-version={api_version}"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(req) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        return {"error": True, "code": e.code, "message": e.read().decode()}


# ─── MITRE ATT&CK coverage map ───────────────────────────────────────────────

MITRE_TACTICS = [
    "InitialAccess", "Execution", "Persistence", "PrivilegeEscalation",
    "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
    "Collection", "CommandAndControl", "Exfiltration", "Impact",
]

# Key techniques per tactic — the must-haves for ML2
KEY_TECHNIQUES = {
    "InitialAccess": ["T1566.001", "T1566.002", "T1078", "T1190", "T1133"],
    "Execution": ["T1059.001", "T1059.003", "T1204.001", "T1204.002", "T1047"],
    "Persistence": ["T1053.005", "T1547.001", "T1136.001", "T1098", "T1543.003"],
    "PrivilegeEscalation": ["T1068", "T1548.002", "T1134.001"],
    "DefenseEvasion": ["T1027", "T1562.001", "T1070.004", "T1036.005", "T1218.011"],
    "CredentialAccess": ["T1003.001", "T1558.003", "T1110.003", "T1555", "T1552.001"],
    "Discovery": ["T1087.002", "T1082", "T1083", "T1018", "T1049"],
    "LateralMovement": ["T1021.001", "T1021.002", "T1047", "T1570"],
    "Collection": ["T1530", "T1213", "T1114.002"],
    "CommandAndControl": ["T1071.001", "T1105", "T1572", "T1090"],
    "Exfiltration": ["T1048", "T1041", "T1567"],
    "Impact": ["T1486", "T1490", "T1489", "T1529"],
}


# ─── Demo data ───────────────────────────────────────────────────────────────

def generate_demo_rules():
    """Generate realistic Sentinel analytics rules for demo mode."""
    now = datetime.now()
    return [
        # Active, healthy rules
        {
            "id": "rule-001", "name": "Suspicious PowerShell Execution",
            "enabled": True, "severity": "High",
            "tactics": ["Execution"], "techniques": ["T1059.001"],
            "query": 'SecurityEvent | where EventID == 4688 | where Process has "powershell" | where CommandLine has_any ("-enc", "-nop", "bypass", "IEX")',
            "queryFrequency": "PT5M", "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "lastTriggered": (now - timedelta(hours=2)).isoformat() + "Z",
            "alertsLast30d": 12, "fpRate": 0.08, "status": "healthy",
        },
        {
            "id": "rule-002", "name": "Brute Force Against Azure AD",
            "enabled": True, "severity": "Medium",
            "tactics": ["CredentialAccess"], "techniques": ["T1110.003"],
            "query": 'SigninLogs | where ResultType == "50126" | summarize FailCount=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m) | where FailCount > 10',
            "queryFrequency": "PT5M", "queryPeriod": "PT10M",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "lastTriggered": (now - timedelta(hours=6)).isoformat() + "Z",
            "alertsLast30d": 45, "fpRate": 0.62, "status": "noisy",
        },
        {
            "id": "rule-003", "name": "Rare Process on Domain Controller",
            "enabled": True, "severity": "High",
            "tactics": ["Execution", "LateralMovement"], "techniques": ["T1059.001", "T1047"],
            "query": 'DeviceProcessEvents | where DeviceName has "DC" | where not(FileName in~ ("svchost.exe","lsass.exe","services.exe"))',
            "queryFrequency": "PT10M", "queryPeriod": "PT10M",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "lastTriggered": (now - timedelta(days=3)).isoformat() + "Z",
            "alertsLast30d": 3, "fpRate": 0.0, "status": "healthy",
        },
        {
            "id": "rule-004", "name": "Impossible Travel Detection",
            "enabled": True, "severity": "Medium",
            "tactics": ["InitialAccess"], "techniques": ["T1078"],
            "query": 'SigninLogs | where RiskLevelDuringSignIn == "high" | where RiskDetail has "impossibleTravel"',
            "queryFrequency": "PT15M", "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "lastTriggered": (now - timedelta(hours=12)).isoformat() + "Z",
            "alertsLast30d": 8, "fpRate": 0.25, "status": "healthy",
        },
        {
            "id": "rule-005", "name": "Mass File Deletion",
            "enabled": True, "severity": "High",
            "tactics": ["Impact"], "techniques": ["T1486", "T1490"],
            "query": 'DeviceFileEvents | where ActionType == "FileDeleted" | summarize DeleteCount=count() by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m) | where DeleteCount > 100',
            "queryFrequency": "PT5M", "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "lastTriggered": None,
            "alertsLast30d": 0, "fpRate": 0.0, "status": "healthy",
        },
        {
            "id": "rule-006", "name": "New Service Installed",
            "enabled": True, "severity": "Low",
            "tactics": ["Persistence"], "techniques": ["T1543.003"],
            "query": 'SecurityEvent | where EventID == 7045',
            "queryFrequency": "PT1H", "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "lastTriggered": (now - timedelta(hours=1)).isoformat() + "Z",
            "alertsLast30d": 156, "fpRate": 0.85, "status": "noisy",
        },
        {
            "id": "rule-007", "name": "Phishing Email Detected (MDO)",
            "enabled": True, "severity": "Medium",
            "tactics": ["InitialAccess"], "techniques": ["T1566.001", "T1566.002"],
            "query": 'EmailEvents | where DetectionMethods has "phish" | where DeliveryAction != "Blocked"',
            "queryFrequency": "PT5M", "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "lastTriggered": (now - timedelta(hours=4)).isoformat() + "Z",
            "alertsLast30d": 22, "fpRate": 0.18, "status": "healthy",
        },
        {
            "id": "rule-008", "name": "LSASS Credential Dump",
            "enabled": True, "severity": "High",
            "tactics": ["CredentialAccess"], "techniques": ["T1003.001"],
            "query": 'DeviceProcessEvents | where FileName == "mimikatz.exe" or (FileName == "rundll32.exe" and ProcessCommandLine has "comsvcs.dll")',
            "queryFrequency": "PT5M", "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "lastTriggered": None,
            "alertsLast30d": 0, "fpRate": 0.0, "status": "healthy",
        },
        # Disabled rules — potential gaps
        {
            "id": "rule-009", "name": "DNS Tunneling Detection",
            "enabled": False, "severity": "Medium",
            "tactics": ["CommandAndControl"], "techniques": ["T1071.001"],
            "query": 'DnsEvents | summarize QueryCount=count() by Name, ClientIP, bin(TimeGenerated, 5m) | where QueryCount > 50',
            "queryFrequency": "PT15M", "queryPeriod": "PT15M",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "lastTriggered": None,
            "alertsLast30d": 0, "fpRate": 0.0, "status": "disabled",
            "disableReason": "Too noisy — needs tuning for internal DNS traffic",
        },
        {
            "id": "rule-010", "name": "Suspicious Azure AD App Registration",
            "enabled": False, "severity": "Medium",
            "tactics": ["Persistence"], "techniques": ["T1098"],
            "query": 'AuditLogs | where OperationName has "Add application" | where InitiatedBy.user.userPrincipalName !in~ ("admin@contoso.com")',
            "queryFrequency": "PT1H", "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "lastTriggered": None,
            "alertsLast30d": 0, "fpRate": 0.0, "status": "disabled",
            "disableReason": "Disabled during dev sprint — needs re-enabling",
        },
        # Stale rule — hasn't fired in forever
        {
            "id": "rule-011", "name": "Kerberoasting Activity",
            "enabled": True, "severity": "High",
            "tactics": ["CredentialAccess"], "techniques": ["T1558.003"],
            "query": 'SecurityEvent | where EventID == 4769 | where TicketEncryptionType == "0x17" | where ServiceName !endswith "$"',
            "queryFrequency": "PT10M", "queryPeriod": "PT10M",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "lastTriggered": (now - timedelta(days=45)).isoformat() + "Z",
            "alertsLast30d": 0, "fpRate": 0.0, "status": "stale",
        },
        {
            "id": "rule-012", "name": "Data Exfiltration via Cloud Storage",
            "enabled": True, "severity": "Medium",
            "tactics": ["Exfiltration"], "techniques": ["T1567"],
            "query": 'CloudAppEvents | where ActionType == "FileUploaded" | where Application in~ ("Dropbox","Google Drive","WeTransfer","Mega")',
            "queryFrequency": "PT30M", "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan", "triggerThreshold": 5,
            "lastTriggered": (now - timedelta(days=7)).isoformat() + "Z",
            "alertsLast30d": 2, "fpRate": 0.5, "status": "healthy",
        },
    ]


def audit_rules(rules: list) -> dict:
    """Audit analytics rules and produce health report."""
    total = len(rules)
    enabled = len([r for r in rules if r["enabled"]])
    disabled = total - enabled
    noisy = [r for r in rules if r.get("status") == "noisy"]
    stale = [r for r in rules if r.get("status") == "stale"]
    healthy = [r for r in rules if r.get("status") == "healthy"]

    # FP analysis
    high_fp = [r for r in rules if r.get("fpRate", 0) > 0.5]
    total_alerts_30d = sum(r.get("alertsLast30d", 0) for r in rules)
    total_fp_30d = sum(int(r.get("alertsLast30d", 0) * r.get("fpRate", 0)) for r in rules)

    recommendations = []
    for r in noisy:
        recommendations.append({
            "rule": r["name"],
            "issue": f"High FP rate ({r['fpRate']:.0%}) — {r['alertsLast30d']} alerts in 30d",
            "action": "Tune threshold or add exclusions",
            "priority": "high",
        })
    for r in stale:
        recommendations.append({
            "rule": r["name"],
            "issue": f"Rule hasn't fired in 30+ days — may indicate broken query or missing log source",
            "action": "Verify log source connectivity and test query manually",
            "priority": "medium",
        })
    for r in rules:
        if not r["enabled"]:
            recommendations.append({
                "rule": r["name"],
                "issue": f"Disabled: {r.get('disableReason', 'No reason documented')}",
                "action": "Review and re-enable or document permanent exclusion",
                "priority": "medium",
            })

    return {
        "generatedAt": datetime.now().isoformat() + "Z",
        "summary": {
            "totalRules": total,
            "enabled": enabled,
            "disabled": disabled,
            "healthy": len(healthy),
            "noisy": len(noisy),
            "stale": len(stale),
            "totalAlerts30d": total_alerts_30d,
            "totalFP30d": total_fp_30d,
            "overallFPRate": f"{total_fp_30d / total_alerts_30d:.0%}" if total_alerts_30d > 0 else "0%",
        },
        "noisyRules": [{"name": r["name"], "fpRate": r["fpRate"], "alerts30d": r["alertsLast30d"]} for r in noisy],
        "staleRules": [{"name": r["name"], "lastTriggered": r.get("lastTriggered")} for r in stale],
        "disabledRules": [{"name": r["name"], "reason": r.get("disableReason", "")} for r in rules if not r["enabled"]],
        "recommendations": recommendations,
        "rules": rules,
    }


def mitre_coverage(rules: list) -> dict:
    """Analyse MITRE ATT&CK detection coverage from analytics rules."""
    # Build covered techniques map
    covered = {}
    for r in rules:
        if not r["enabled"]:
            continue
        for tech in r.get("techniques", []):
            if tech not in covered:
                covered[tech] = []
            covered[tech].append(r["name"])

    # Build coverage per tactic
    tactic_coverage = {}
    for tactic, techniques in KEY_TECHNIQUES.items():
        total = len(techniques)
        detected = [t for t in techniques if t in covered]
        gaps = [t for t in techniques if t not in covered]
        tactic_coverage[tactic] = {
            "total": total,
            "covered": len(detected),
            "coverage_pct": f"{len(detected) / total:.0%}" if total > 0 else "0%",
            "detected_techniques": detected,
            "gap_techniques": gaps,
            "rules": list(set(r for t in detected for r in covered.get(t, []))),
        }

    # Overall stats
    all_key_techniques = [t for techs in KEY_TECHNIQUES.values() for t in techs]
    total_key = len(all_key_techniques)
    total_covered = len([t for t in all_key_techniques if t in covered])

    return {
        "generatedAt": datetime.now().isoformat() + "Z",
        "overallCoverage": f"{total_covered / total_key:.0%}" if total_key > 0 else "0%",
        "totalKeyTechniques": total_key,
        "coveredTechniques": total_covered,
        "gapTechniques": total_key - total_covered,
        "tacticCoverage": tactic_coverage,
        "allCoveredTechniques": list(covered.keys()),
    }


def main():
    p = argparse.ArgumentParser(description="Sentinel analytics rule management")
    p.add_argument("--demo", action="store_true", help="Use synthetic demo data")
    p.add_argument("--action", choices=["list", "audit", "coverage"], default="audit")
    p.add_argument("--output", help="Output file")
    args = p.parse_args()

    if args.demo:
        rules = generate_demo_rules()
    else:
        tenant, client_id, client_secret = get_env()
        token = get_token(tenant, client_id, client_secret)
        data = _arm_get(token, "alertRules")
        rules = data.get("value", [])

    if args.action == "list":
        result = {"rules": rules, "count": len(rules)}
    elif args.action == "audit":
        result = audit_rules(rules)
    elif args.action == "coverage":
        result = mitre_coverage(rules)

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
