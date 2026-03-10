#!/usr/bin/env python3
"""User & Entity Behavior Analytics — baselines, anomaly detection, risk scoring.

Builds behavioral baselines from Sentinel telemetry, detects anomalies,
identifies insider threats, and calculates per-user/entity risk scores.

Real mode: KQL queries against Log Analytics workspace.
Demo mode: Generates realistic synthetic behavioral data and anomalies.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../e8cr-vmpm/scripts"))
try:
    from graph_auth import get_env, get_token
except ImportError:
    def get_env(): raise RuntimeError("graph_auth not available — use --demo mode")
    def get_token(*a): raise RuntimeError("graph_auth not available — use --demo mode")


# ─── Anomaly categories ──────────────────────────────────────────────────────

ANOMALY_TYPES = {
    "auth_unusual_location": {"category": "Authentication", "weight": 3, "description": "Login from unusual location"},
    "auth_unusual_time": {"category": "Authentication", "weight": 2, "description": "Login outside normal hours"},
    "auth_unusual_device": {"category": "Authentication", "weight": 2, "description": "Login from new/unusual device"},
    "auth_impossible_travel": {"category": "Authentication", "weight": 4, "description": "Impossible travel detected"},
    "auth_legacy_protocol": {"category": "Authentication", "weight": 3, "description": "Legacy auth protocol used"},
    "auth_brute_force_success": {"category": "Authentication", "weight": 5, "description": "Successful login after brute force attempts"},
    "data_mass_download": {"category": "Data Access", "weight": 4, "description": "Mass file download/copy"},
    "data_sensitive_access": {"category": "Data Access", "weight": 3, "description": "Access to sensitive data outside normal scope"},
    "data_first_time_repo": {"category": "Data Access", "weight": 2, "description": "First-time access to high-value repository"},
    "data_email_forwarding": {"category": "Data Access", "weight": 4, "description": "Email forwarding rule to external address"},
    "data_usb_usage": {"category": "Data Access", "weight": 3, "description": "USB storage device usage"},
    "priv_unusual_admin": {"category": "Privilege", "weight": 4, "description": "Admin actions outside normal pattern"},
    "priv_service_interactive": {"category": "Privilege", "weight": 5, "description": "Service account used interactively"},
    "priv_role_change": {"category": "Privilege", "weight": 3, "description": "Unusual role/group assignment"},
    "priv_first_psexec": {"category": "Privilege", "weight": 4, "description": "First-time use of PsExec/remote tool"},
    "comm_unusual_external": {"category": "Communication", "weight": 3, "description": "Unusual external email volume"},
    "comm_known_bad_domain": {"category": "Communication", "weight": 5, "description": "Communication with known-bad domain"},
    "comm_large_outbound": {"category": "Communication", "weight": 4, "description": "Large outbound transfer to new destination"},
    "insider_flight_risk": {"category": "Insider Threat", "weight": 5, "description": "Flight risk indicators + increased data access"},
    "insider_policy_violation": {"category": "Insider Threat", "weight": 3, "description": "Security policy violation"},
}


# ─── Demo data ───────────────────────────────────────────────────────────────

def generate_demo_baselines():
    """Generate realistic user behavioral baselines."""
    return [
        {
            "userId": "j.smith@contoso.com",
            "displayName": "John Smith",
            "department": "Finance",
            "title": "Senior Financial Analyst",
            "manager": "a.boss@contoso.com",
            "riskLevel": "high",
            "baseline": {
                "normalLoginHours": {"start": "08:00", "end": "18:00", "timezone": "AEST"},
                "normalLocations": ["Brisbane, AU", "Sydney, AU"],
                "normalDevices": ["WKS-FINANCE-01", "LAPTOP-JSMITH"],
                "normalApps": ["Microsoft 365", "SAP", "SharePoint", "Power BI"],
                "avgDailySignins": 4.2,
                "avgDailyFileAccess": 35,
                "avgDailyEmailsSent": 18,
                "normalPeerGroup": "Finance Team (12 users)",
                "lastBaselineUpdate": (datetime.now() - timedelta(days=1)).isoformat() + "Z",
            },
        },
        {
            "userId": "svc-backup@contoso.com",
            "displayName": "Backup Service Account",
            "department": "IT",
            "title": "Service Account",
            "manager": "it-admin@contoso.com",
            "riskLevel": "critical",
            "baseline": {
                "normalLoginHours": {"start": "00:00", "end": "23:59", "timezone": "AEST"},
                "normalLocations": ["Server Room - DC01"],
                "normalDevices": ["SQL-PROD-01", "BACKUP-SRV-01"],
                "normalApps": ["Veeam", "SQL Server Management Studio"],
                "avgDailySignins": 24,
                "avgDailyFileAccess": 0,
                "avgDailyEmailsSent": 0,
                "normalPeerGroup": "Service Accounts (8 accounts)",
                "lastBaselineUpdate": (datetime.now() - timedelta(days=1)).isoformat() + "Z",
                "note": "Service account — interactive login is ALWAYS anomalous",
            },
        },
        {
            "userId": "m.jones@contoso.com",
            "displayName": "Maria Jones",
            "department": "Sales",
            "title": "Regional Sales Manager",
            "manager": "vp-sales@contoso.com",
            "riskLevel": "medium",
            "baseline": {
                "normalLoginHours": {"start": "07:00", "end": "20:00", "timezone": "AEST"},
                "normalLocations": ["Brisbane, AU", "Gold Coast, AU", "Melbourne, AU"],
                "normalDevices": ["LAPTOP-MJONES", "IPHONE-MJONES"],
                "normalApps": ["Microsoft 365", "Salesforce", "Teams", "Dynamics CRM"],
                "avgDailySignins": 8.5,
                "avgDailyFileAccess": 12,
                "avgDailyEmailsSent": 42,
                "normalPeerGroup": "Sales Team (18 users)",
                "lastBaselineUpdate": (datetime.now() - timedelta(days=1)).isoformat() + "Z",
            },
        },
        {
            "userId": "exec-admin@contoso.com",
            "displayName": "Admin (Executive IT)",
            "department": "IT",
            "title": "Senior Systems Administrator",
            "manager": "cto@contoso.com",
            "riskLevel": "high",
            "baseline": {
                "normalLoginHours": {"start": "07:00", "end": "19:00", "timezone": "AEST"},
                "normalLocations": ["Brisbane, AU"],
                "normalDevices": ["WKS-ADMIN-01", "YOURPHONE-ADMIN"],
                "normalApps": ["Azure Portal", "Microsoft 365 Admin", "Intune", "Entra ID"],
                "avgDailySignins": 12,
                "avgDailyFileAccess": 5,
                "avgDailyEmailsSent": 8,
                "normalPeerGroup": "IT Admins (4 users)",
                "lastBaselineUpdate": (datetime.now() - timedelta(days=1)).isoformat() + "Z",
            },
        },
        {
            "userId": "d.developer@contoso.com",
            "displayName": "Dave Developer",
            "department": "Engineering",
            "title": "Software Developer",
            "manager": "eng-lead@contoso.com",
            "riskLevel": "low",
            "baseline": {
                "normalLoginHours": {"start": "09:00", "end": "17:30", "timezone": "AEST"},
                "normalLocations": ["Brisbane, AU"],
                "normalDevices": ["WKS-DEV-04", "MACBOOK-DDEV"],
                "normalApps": ["GitHub", "VS Code", "Azure DevOps", "Microsoft 365"],
                "avgDailySignins": 3,
                "avgDailyFileAccess": 8,
                "avgDailyEmailsSent": 5,
                "normalPeerGroup": "Engineering Team (15 users)",
                "lastBaselineUpdate": (datetime.now() - timedelta(days=1)).isoformat() + "Z",
            },
        },
        {
            "userId": "cfo@contoso.com",
            "displayName": "Sarah Chen (CFO)",
            "department": "Executive",
            "title": "Chief Financial Officer",
            "manager": "ceo@contoso.com",
            "riskLevel": "medium",
            "baseline": {
                "normalLoginHours": {"start": "07:00", "end": "19:00", "timezone": "AEST"},
                "normalLocations": ["Brisbane, AU", "Sydney, AU"],
                "normalDevices": ["LAPTOP-CFO", "IPAD-CFO", "IPHONE-CFO"],
                "normalApps": ["Microsoft 365", "Power BI", "SAP", "Board Portal"],
                "avgDailySignins": 6,
                "avgDailyFileAccess": 20,
                "avgDailyEmailsSent": 35,
                "normalPeerGroup": "Executive Team (5 users)",
                "lastBaselineUpdate": (datetime.now() - timedelta(days=1)).isoformat() + "Z",
                "note": "VIP user — any anomaly gets priority escalation",
            },
        },
    ]


def generate_demo_anomalies():
    """Generate realistic behavioral anomalies for demo mode."""
    now = datetime.now()
    return [
        # j.smith — compromised account (correlates with XDR Bot findings)
        {
            "anomalyId": "ANOM-001",
            "userId": "j.smith@contoso.com",
            "displayName": "John Smith",
            "type": "auth_unusual_location",
            "detectedAt": (now - timedelta(hours=3)).isoformat() + "Z",
            "severity": "high",
            "confidence": 0.92,
            "description": "Login from Frankfurt, DE — user has never authenticated from Germany",
            "details": {
                "observedLocation": "Frankfurt, DE",
                "normalLocations": ["Brisbane, AU", "Sydney, AU"],
                "ipAddress": "185.220.101.42",
                "device": "Unknown device",
            },
            "baselineDeviation": "Location never seen in 90-day baseline",
            "relatedAlerts": ["xdr-mdi-001", "xdr-mdo-001"],
        },
        {
            "anomalyId": "ANOM-002",
            "userId": "j.smith@contoso.com",
            "displayName": "John Smith",
            "type": "data_mass_download",
            "detectedAt": (now - timedelta(hours=2, minutes=30)).isoformat() + "Z",
            "severity": "high",
            "confidence": 0.88,
            "description": "Downloaded 127 files from Finance SharePoint in 15 minutes — 3.6x above daily average",
            "details": {
                "filesAccessed": 127,
                "normalDailyAvg": 35,
                "deviationMultiple": 3.6,
                "timeWindow": "15 minutes",
                "repository": "Finance - Confidential",
                "fileTypes": {"xlsx": 85, "pdf": 32, "docx": 10},
            },
            "baselineDeviation": "3.6 standard deviations above daily mean",
            "relatedAlerts": ["xdr-mda-002"],
        },
        {
            "anomalyId": "ANOM-003",
            "userId": "j.smith@contoso.com",
            "displayName": "John Smith",
            "type": "data_email_forwarding",
            "detectedAt": (now - timedelta(hours=2)).isoformat() + "Z",
            "severity": "critical",
            "confidence": 0.96,
            "description": "Created inbox rule forwarding all emails to j.smith.backup@protonmail.com",
            "details": {
                "ruleAction": "ForwardTo",
                "destination": "j.smith.backup@protonmail.com",
                "scope": "All incoming email",
                "createdFromIP": "185.220.101.42",
            },
            "baselineDeviation": "No forwarding rules in baseline. External forwarding is against policy.",
            "relatedAlerts": [],
        },
        # svc-backup — interactive login (always anomalous for service accounts)
        {
            "anomalyId": "ANOM-004",
            "userId": "svc-backup@contoso.com",
            "displayName": "Backup Service Account",
            "type": "priv_service_interactive",
            "detectedAt": (now - timedelta(minutes=45)).isoformat() + "Z",
            "severity": "critical",
            "confidence": 0.98,
            "description": "Service account logged in interactively via RDP to SQL-PROD-01",
            "details": {
                "loginType": "Interactive (RDP)",
                "device": "SQL-PROD-01",
                "sourceIP": "10.0.1.55 (WKS-FINANCE-01)",
                "normalLoginType": "Service/Batch only",
            },
            "baselineDeviation": "Interactive login NEVER seen for this service account",
            "relatedAlerts": ["xdr-mde-002"],
        },
        # m.jones — impossible travel
        {
            "anomalyId": "ANOM-005",
            "userId": "m.jones@contoso.com",
            "displayName": "Maria Jones",
            "type": "auth_impossible_travel",
            "detectedAt": (now - timedelta(hours=4)).isoformat() + "Z",
            "severity": "medium",
            "confidence": 0.75,
            "description": "Login from Brisbane at 10:15 AM, then Singapore at 10:42 AM — physically impossible",
            "details": {
                "location1": {"city": "Brisbane", "country": "AU", "time": (now - timedelta(hours=4, minutes=27)).isoformat()},
                "location2": {"city": "Singapore", "country": "SG", "time": (now - timedelta(hours=4)).isoformat()},
                "timeDelta": "27 minutes",
                "distanceKm": 6150,
                "possibleVPN": True,
            },
            "baselineDeviation": "Travel between locations would require minimum 8 hours",
            "relatedAlerts": ["xdr-mda-001"],
            "mitigatingFactors": ["User uses VPN for client visits — may explain Singapore IP"],
        },
        # exec-admin — unusual OAuth consent
        {
            "anomalyId": "ANOM-006",
            "userId": "exec-admin@contoso.com",
            "displayName": "Admin (Executive IT)",
            "type": "priv_unusual_admin",
            "detectedAt": (now - timedelta(hours=7)).isoformat() + "Z",
            "severity": "high",
            "confidence": 0.85,
            "description": "Granted Mail.ReadWrite consent to unrecognised app 'ShadowApp Pro' — first time this admin has granted mail permissions",
            "details": {
                "app": "ShadowApp Pro",
                "permissions": ["Mail.ReadWrite", "User.Read", "Files.ReadWrite.All"],
                "consentType": "Admin consent (tenant-wide)",
                "appPublisher": "Unverified",
                "appRegisteredDate": (now - timedelta(days=5)).isoformat() + "Z",
            },
            "baselineDeviation": "Admin has never granted mail-scope permissions. App is 5 days old and unverified.",
            "relatedAlerts": ["xdr-mda-003"],
        },
        # d.developer — after-hours activity (low severity, likely benign)
        {
            "anomalyId": "ANOM-007",
            "userId": "d.developer@contoso.com",
            "displayName": "Dave Developer",
            "type": "auth_unusual_time",
            "detectedAt": (now - timedelta(hours=10)).isoformat() + "Z",
            "severity": "low",
            "confidence": 0.55,
            "description": "Login at 2:15 AM — outside normal 09:00-17:30 window",
            "details": {
                "loginTime": "02:15 AEST",
                "normalWindow": "09:00-17:30 AEST",
                "device": "MACBOOK-DDEV",
                "location": "Brisbane, AU",
                "app": "GitHub",
            },
            "baselineDeviation": "After-hours login occurs ~2x per month for this user (hobby projects)",
            "mitigatingFactors": ["Device and location are normal", "GitHub access is expected", "Historical pattern of occasional late-night coding"],
        },
        # cfo — targeted BEC (correlates with XDR Bot)
        {
            "anomalyId": "ANOM-008",
            "userId": "cfo@contoso.com",
            "displayName": "Sarah Chen (CFO)",
            "type": "comm_known_bad_domain",
            "detectedAt": (now - timedelta(hours=5)).isoformat() + "Z",
            "severity": "high",
            "confidence": 0.90,
            "description": "Received email from contoso-billing.com — lookalike domain registered 3 days ago",
            "details": {
                "senderDomain": "contoso-billing.com",
                "legitimateDomain": "contoso.com",
                "domainAge": "3 days",
                "emailSubject": "Urgent: Updated Banking Details for Q1 Payment",
                "spf": "fail", "dkim": "none", "dmarc": "none",
            },
            "baselineDeviation": "Domain not in historical communication patterns. Brand impersonation detected.",
            "relatedAlerts": ["xdr-mdo-003"],
        },
    ]


def calculate_risk_scores(baselines: list, anomalies: list) -> list:
    """Calculate per-user risk scores from anomalies."""
    user_anomalies = defaultdict(list)
    for a in anomalies:
        user_anomalies[a["userId"]].append(a)

    risk_scores = []
    for baseline in baselines:
        user_id = baseline["userId"]
        user_anoms = user_anomalies.get(user_id, [])

        # Calculate composite risk score (0-100)
        raw_score = 0
        for a in user_anoms:
            anom_type = ANOMALY_TYPES.get(a["type"], {})
            weight = anom_type.get("weight", 1)
            confidence = a.get("confidence", 0.5)
            raw_score += weight * confidence * 10

        # Cap at 100
        risk_score = min(100, int(raw_score))

        # Determine risk level
        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        elif risk_score > 0:
            risk_level = "low"
        else:
            risk_level = "none"

        # Peer comparison
        peer_group = baseline["baseline"].get("normalPeerGroup", "Unknown")

        risk_scores.append({
            "userId": user_id,
            "displayName": baseline["displayName"],
            "department": baseline["department"],
            "title": baseline["title"],
            "riskScore": risk_score,
            "riskLevel": risk_level,
            "previousRiskLevel": baseline.get("riskLevel", "low"),
            "trend": "increasing" if risk_level in ("critical", "high") else "stable",
            "anomalyCount": len(user_anoms),
            "anomalyCategories": list(set(
                ANOMALY_TYPES.get(a["type"], {}).get("category", "Unknown") for a in user_anoms
            )),
            "topAnomaly": user_anoms[0]["description"] if user_anoms else None,
            "peerGroup": peer_group,
            "peerAvgScore": 12,  # Demo: peer group average
            "deviationFromPeer": f"{risk_score - 12}pts above peer average" if risk_score > 12 else "within peer norm",
            "recommendedAction": _recommend_action(risk_level, user_anoms),
        })

    risk_scores.sort(key=lambda x: x["riskScore"], reverse=True)
    return risk_scores


def _recommend_action(risk_level: str, anomalies: list) -> str:
    """Recommend action based on risk level and anomaly types."""
    if risk_level == "critical":
        return "IMMEDIATE: Disable account, investigate activity, escalate to SOAR Bot"
    elif risk_level == "high":
        return "Investigate within 4 hours. Review anomalies with user's manager."
    elif risk_level == "medium":
        return "Monitor closely. Review at next daily digest."
    elif risk_level == "low":
        return "No action required. Continue monitoring."
    return "No anomalies detected."


def generate_user_profile(user_id: str, baselines: list, anomalies: list, risk_scores: list) -> dict:
    """Generate full investigation profile for a specific user."""
    baseline = next((b for b in baselines if b["userId"] == user_id), None)
    user_anomalies = [a for a in anomalies if a["userId"] == user_id]
    score = next((s for s in risk_scores if s["userId"] == user_id), None)

    if not baseline:
        return {"error": f"User {user_id} not found in baselines"}

    return {
        "generatedAt": datetime.now().isoformat() + "Z",
        "profileType": "investigation",
        "user": {
            "id": user_id,
            "name": baseline["displayName"],
            "department": baseline["department"],
            "title": baseline["title"],
            "manager": baseline.get("manager", "Unknown"),
        },
        "riskAssessment": score,
        "baseline": baseline["baseline"],
        "anomalies": user_anomalies,
        "timeline": sorted(
            [{"time": a["detectedAt"], "event": a["description"], "severity": a["severity"],
              "type": a["type"], "confidence": a["confidence"]}
             for a in user_anomalies],
            key=lambda x: x["time"]
        ),
        "relatedAlerts": list(set(
            alert for a in user_anomalies for alert in a.get("relatedAlerts", [])
        )),
    }


def main():
    p = argparse.ArgumentParser(description="UEBA behavioral analytics engine")
    p.add_argument("--demo", action="store_true", help="Use synthetic demo data")
    p.add_argument("--action", choices=["baselines", "anomalies", "risk-scores", "profile"], default="risk-scores")
    p.add_argument("--user", help="User ID for profile action")
    p.add_argument("--output", help="Output file")
    args = p.parse_args()

    baselines = generate_demo_baselines()
    anomalies = generate_demo_anomalies()
    risk_scores = calculate_risk_scores(baselines, anomalies)

    if args.action == "baselines":
        result = {"generatedAt": datetime.now().isoformat() + "Z", "userCount": len(baselines), "baselines": baselines}
    elif args.action == "anomalies":
        result = {
            "generatedAt": datetime.now().isoformat() + "Z",
            "anomalyCount": len(anomalies),
            "bySeverity": {
                sev: len([a for a in anomalies if a["severity"] == sev])
                for sev in ["critical", "high", "medium", "low"]
                if any(a["severity"] == sev for a in anomalies)
            },
            "byCategory": {
                cat: len([a for a in anomalies if ANOMALY_TYPES.get(a["type"], {}).get("category") == cat])
                for cat in set(ANOMALY_TYPES[a["type"]]["category"] for a in anomalies if a["type"] in ANOMALY_TYPES)
            },
            "anomalies": anomalies,
        }
    elif args.action == "risk-scores":
        result = {
            "generatedAt": datetime.now().isoformat() + "Z",
            "usersAnalysed": len(risk_scores),
            "criticalRisk": len([s for s in risk_scores if s["riskLevel"] == "critical"]),
            "highRisk": len([s for s in risk_scores if s["riskLevel"] == "high"]),
            "mediumRisk": len([s for s in risk_scores if s["riskLevel"] == "medium"]),
            "riskScores": risk_scores,
        }
    elif args.action == "profile":
        if not args.user:
            result = {"error": "Provide --user for profile action"}
        else:
            result = generate_user_profile(args.user, baselines, anomalies, risk_scores)

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
