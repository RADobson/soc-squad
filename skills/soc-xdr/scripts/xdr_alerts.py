#!/usr/bin/env python3
"""Unified alert ingestion and triage across Microsoft Defender XDR stack.

Sources: MDE (endpoints), MDO (email), MDI (identity), MDA (cloud apps).
Real mode: Graph Security API with AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET.
Demo mode: Generates realistic synthetic alerts from all four sources.

Required Graph permissions (Application):
  - SecurityAlert.ReadWrite.All
  - SecurityIncident.ReadWrite.All
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# Reuse graph_auth from shared E8CR infrastructure
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../e8cr-vmpm/scripts"))
try:
    from graph_auth import get_env, get_token
except ImportError:
    def get_env(): raise RuntimeError("graph_auth not available — use --demo mode")
    def get_token(*a): raise RuntimeError("graph_auth not available — use --demo mode")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
SECURITY_BASE = "https://graph.microsoft.com/v1.0/security"

# ─── Alert source classification ─────────────────────────────────────────────

XDR_SOURCES = {
    "microsoftDefenderForEndpoint": "MDE",
    "microsoftDefenderForOffice365": "MDO",
    "microsoftDefenderForIdentity": "MDI",
    "microsoftCloudAppSecurity": "MDA",
    "microsoftDefenderForCloudApps": "MDA",
    "aadIdentityProtection": "MDI",  # Entra ID Protection feeds into identity
}

SOURCE_LABELS = {
    "MDE": "Endpoint",
    "MDO": "Email",
    "MDI": "Identity",
    "MDA": "Cloud Apps",
    "Unknown": "Unknown",
}


def classify_source(alert: dict) -> str:
    """Classify alert source from serviceSource or detectionSource."""
    service = alert.get("serviceSource", "") or alert.get("detectionSource", "")
    return XDR_SOURCES.get(service, "Unknown")


# ─── Live API ─────────────────────────────────────────────────────────────────

def fetch_alerts_real(token: str, days: int = 7, top: int = 200):
    """Fetch recent security alerts from all Defender XDR sources via Graph Security API."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = (
        f"{SECURITY_BASE}/alerts_v2"
        f"?$filter=createdDateTime ge {since}"
        f"&$top={top}"
        f"&$orderby=createdDateTime desc"
    )
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")

    try:
        with urlopen(req) as resp:
            body = json.loads(resp.read())
            return body.get("value", [])
    except HTTPError as e:
        err = e.read().decode()
        print(f"ERROR: Failed to fetch alerts ({e.code}): {err}", file=sys.stderr)
        return []


def update_alert_status(token: str, alert_id: str, status: str, comment: str = ""):
    """Update alert status (new, inProgress, resolved) and add comment."""
    url = f"{SECURITY_BASE}/alerts_v2/{alert_id}"
    body = {"status": status}
    if comment:
        body["comments"] = [{"comment": comment, "createdByDisplayName": "SOC XDR Bot"}]
    data = json.dumps(body).encode()
    req = Request(url, data=data, method="PATCH")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req) as resp:
            return True
    except HTTPError as e:
        print(f"ERROR: Failed to update alert {alert_id} ({e.code})", file=sys.stderr)
        return False


# ─── Known false positive patterns ───────────────────────────────────────────

KNOWN_FP_PATTERNS = [
    # MDE
    {"title_contains": "test alert", "reason": "Known test alert pattern"},
    {"title_contains": "microsoft defender atp test", "reason": "Defender ATP test alert"},
    {"title_contains": "eicar", "reason": "EICAR test file detection"},
    # MDO
    {"title_contains": "safe links test", "reason": "Safe Links test message"},
    {"title_contains": "attack simulation", "reason": "Microsoft Attack Simulation Training"},
    # MDI
    {"title_contains": "honeytoken", "source": "MDI", "reason": "Honeytoken alert — informational by design"},
    # General
    {"category": "SuspiciousActivity", "severity": "informational", "reason": "Low-severity suspicious activity — typically benign"},
]


def is_known_fp(alert: dict, source: str) -> tuple[bool, str]:
    """Check if an alert matches a known false positive pattern."""
    title = (alert.get("title") or "").lower()
    category = alert.get("category", "")
    severity = alert.get("severity", "").lower()

    for pattern in KNOWN_FP_PATTERNS:
        if pattern.get("source") and pattern["source"] != source:
            continue
        if "title_contains" in pattern and pattern["title_contains"] in title:
            return True, pattern["reason"]
        if pattern.get("category") == category and pattern.get("severity") == severity:
            if "title_contains" not in pattern and "source" not in pattern:
                return True, pattern["reason"]
    return False, ""


# ─── Triage logic ────────────────────────────────────────────────────────────

SEVERITY_WEIGHT = {"high": 4, "medium": 3, "low": 2, "informational": 1}

# Critical asset keywords — alerts on these get severity boost
CRITICAL_ASSET_KEYWORDS = [
    "dc", "domain controller", "exchange", "sql", "backup", "admin",
    "server", "cas", "adfs", "adfarm", "sharepoint", "sccm", "wsus",
]

# High-value user keywords
HIGH_VALUE_USER_KEYWORDS = ["admin", "ceo", "cfo", "cto", "ciso", "exec", "svc-", "service"]

# Source-specific severity multipliers
SOURCE_SEVERITY_BOOST = {
    "MDI": 1.2,  # Identity attacks are often high-impact
    "MDA": 1.0,
    "MDO": 1.0,
    "MDE": 1.0,
}


def triage_alert(alert: dict) -> dict:
    """Enrich and classify a single alert. Returns triage result."""
    title = alert.get("title", "Unknown")
    severity = alert.get("severity", "informational").lower()
    category = alert.get("category", "Unknown")
    status = alert.get("status", "new")
    created = alert.get("createdDateTime", "")
    alert_id = alert.get("id", "")
    source = classify_source(alert)

    # Check false positive
    is_fp, fp_reason = is_known_fp(alert, source)
    if is_fp:
        return {
            "id": alert_id,
            "title": title,
            "severity": severity,
            "category": category,
            "source": source,
            "sourceLabel": SOURCE_LABELS.get(source, "Unknown"),
            "action": "auto_resolve",
            "reason": f"Known FP: {fp_reason}",
            "priority": 0,
            "created": created,
        }

    # Extract device info
    evidence = alert.get("evidence", [])
    devices = [e for e in evidence if e.get("@odata.type", "").endswith("deviceEvidence")]
    device_names = [d.get("deviceDnsName", d.get("mdeDeviceId", "unknown")) for d in devices]

    # Extract user info
    users = [e for e in evidence if e.get("@odata.type", "").endswith("userEvidence")]
    user_names = [u.get("userAccount", {}).get("accountName", "unknown") for u in users]

    # Extract email info (MDO)
    emails = [e for e in evidence if e.get("@odata.type", "").endswith("mailboxEvidence")
              or e.get("@odata.type", "").endswith("emailUrlEvidence")]
    email_addresses = [e.get("primaryAddress", e.get("url", "")) for e in emails]

    # Extract cloud app info (MDA)
    cloud_apps = [e for e in evidence if e.get("@odata.type", "").endswith("cloudApplicationEvidence")]
    app_names = [a.get("displayName", "unknown") for a in cloud_apps]

    # Check if critical asset
    is_critical = any(
        kw in name.lower()
        for name in device_names
        for kw in CRITICAL_ASSET_KEYWORDS
    )

    # Check high-value user
    is_high_value_user = any(
        kw in u.lower()
        for u in user_names
        for kw in HIGH_VALUE_USER_KEYWORDS
    )

    # Calculate priority score
    base_score = SEVERITY_WEIGHT.get(severity, 1)
    priority = base_score * 10
    priority *= SOURCE_SEVERITY_BOOST.get(source, 1.0)
    priority = int(priority)

    if is_critical:
        priority += 20  # Boost for critical assets
    if is_high_value_user:
        priority += 15  # Boost for high-value users

    # Cross-source signal boost — alerts from identity/email sources
    # correlating with endpoint are more dangerous
    if source == "MDI" and category in ("CredentialAccess", "LateralMovement"):
        priority += 10  # Identity-based credential attacks are high-signal

    # Determine action
    if priority >= 55:
        action = "escalate_immediate"
    elif priority >= 40:
        action = "escalate"
    elif priority >= 25:
        action = "investigate"
    else:
        action = "monitor"

    return {
        "id": alert_id,
        "title": title,
        "severity": severity,
        "category": category,
        "source": source,
        "sourceLabel": SOURCE_LABELS.get(source, "Unknown"),
        "action": action,
        "priority": priority,
        "devices": device_names,
        "users": user_names,
        "emails": email_addresses,
        "cloudApps": app_names,
        "is_critical_asset": is_critical,
        "is_high_value_user": is_high_value_user,
        "created": created,
        "mitre_techniques": [t.get("techniqueId", "") for t in alert.get("mitreTechniques", [])],
    }


# ─── Demo data ───────────────────────────────────────────────────────────────

def generate_demo_alerts():
    """Generate realistic synthetic alerts from all four Defender XDR sources."""
    now = datetime.now()
    return [
        # ── MDE alerts (endpoints) ──
        {
            "id": "xdr-mde-001",
            "title": "Suspicious PowerShell command line",
            "severity": "high",
            "category": "Execution",
            "status": "new",
            "serviceSource": "microsoftDefenderForEndpoint",
            "createdDateTime": (now - timedelta(hours=2)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WKS-FINANCE-01"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "j.smith"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1059.001"}],
        },
        {
            "id": "xdr-mde-002",
            "title": "Ransomware-related behavior detected",
            "severity": "high",
            "category": "Impact",
            "status": "new",
            "serviceSource": "microsoftDefenderForEndpoint",
            "createdDateTime": (now - timedelta(minutes=30)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "SQL-PROD-01"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "svc-backup"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1486"}],
        },
        {
            "id": "xdr-mde-003",
            "title": "Lateral movement using WMI",
            "severity": "medium",
            "category": "LateralMovement",
            "status": "new",
            "serviceSource": "microsoftDefenderForEndpoint",
            "createdDateTime": (now - timedelta(hours=1, minutes=15)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WKS-FINANCE-01"},
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WKS-HR-02"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "j.smith"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1047"}],
        },
        {
            "id": "xdr-mde-004",
            "title": "Persistence via scheduled task creation",
            "severity": "low",
            "category": "Persistence",
            "status": "new",
            "serviceSource": "microsoftDefenderForEndpoint",
            "createdDateTime": (now - timedelta(hours=6)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WKS-DEV-04"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "d.developer"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1053.005"}],
        },
        {
            "id": "xdr-mde-005",
            "title": "Microsoft Defender ATP test alert",
            "severity": "informational",
            "category": "SuspiciousActivity",
            "status": "new",
            "serviceSource": "microsoftDefenderForEndpoint",
            "createdDateTime": (now - timedelta(hours=8)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WKS-IT-TEST"},
            ],
            "mitreTechniques": [],
        },

        # ── MDO alerts (email) ──
        {
            "id": "xdr-mdo-001",
            "title": "Email messages containing malicious URL removed after delivery",
            "severity": "high",
            "category": "InitialAccess",
            "status": "new",
            "serviceSource": "microsoftDefenderForOffice365",
            "createdDateTime": (now - timedelta(hours=3)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.mailboxEvidence", "primaryAddress": "j.smith@contoso.com"},
                {"@odata.type": "#microsoft.graph.security.emailUrlEvidence", "url": "https://login-contoso.evil.com/auth"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "j.smith"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1566.002"}],
        },
        {
            "id": "xdr-mdo-002",
            "title": "A potentially malicious URL click was detected",
            "severity": "medium",
            "category": "InitialAccess",
            "status": "new",
            "serviceSource": "microsoftDefenderForOffice365",
            "createdDateTime": (now - timedelta(hours=2, minutes=45)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.mailboxEvidence", "primaryAddress": "j.smith@contoso.com"},
                {"@odata.type": "#microsoft.graph.security.emailUrlEvidence", "url": "https://login-contoso.evil.com/auth"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "j.smith"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1204.001"}],
        },
        {
            "id": "xdr-mdo-003",
            "title": "BEC: Invoice fraud attempt detected",
            "severity": "high",
            "category": "InitialAccess",
            "status": "new",
            "serviceSource": "microsoftDefenderForOffice365",
            "createdDateTime": (now - timedelta(hours=5)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.mailboxEvidence", "primaryAddress": "cfo@contoso.com"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "cfo"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1534"}],
        },
        {
            "id": "xdr-mdo-004",
            "title": "Attack simulation training email delivered",
            "severity": "informational",
            "category": "InitialAccess",
            "status": "new",
            "serviceSource": "microsoftDefenderForOffice365",
            "createdDateTime": (now - timedelta(hours=10)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.mailboxEvidence", "primaryAddress": "all-staff@contoso.com"},
            ],
            "mitreTechniques": [],
        },

        # ── MDI alerts (identity) ──
        {
            "id": "xdr-mdi-001",
            "title": "Suspected Kerberoasting activity",
            "severity": "high",
            "category": "CredentialAccess",
            "status": "new",
            "serviceSource": "microsoftDefenderForIdentity",
            "createdDateTime": (now - timedelta(hours=1, minutes=30)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "DC01.contoso.local"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "j.smith"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1558.003"}],
        },
        {
            "id": "xdr-mdi-002",
            "title": "Suspicious authentication activity",
            "severity": "medium",
            "category": "CredentialAccess",
            "status": "new",
            "serviceSource": "microsoftDefenderForIdentity",
            "createdDateTime": (now - timedelta(hours=1, minutes=20)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "DC01.contoso.local"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "admin-svc"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1110.003"}],
        },
        {
            "id": "xdr-mdi-003",
            "title": "Reconnaissance using directory services queries (SAMAccountName)",
            "severity": "medium",
            "category": "Discovery",
            "status": "new",
            "serviceSource": "microsoftDefenderForIdentity",
            "createdDateTime": (now - timedelta(hours=1, minutes=45)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WKS-FINANCE-01"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "j.smith"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1087.002"}],
        },

        # ── MDA alerts (cloud apps) ──
        {
            "id": "xdr-mda-001",
            "title": "Impossible travel activity",
            "severity": "medium",
            "category": "InitialAccess",
            "status": "new",
            "serviceSource": "microsoftCloudAppSecurity",
            "createdDateTime": (now - timedelta(hours=4)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "m.jones"}},
                {"@odata.type": "#microsoft.graph.security.cloudApplicationEvidence", "displayName": "Microsoft 365"},
            ],
            "mitreTechniques": [{"techniqueId": "T1078"}],
        },
        {
            "id": "xdr-mda-002",
            "title": "Mass file download from SharePoint",
            "severity": "medium",
            "category": "Collection",
            "status": "new",
            "serviceSource": "microsoftCloudAppSecurity",
            "createdDateTime": (now - timedelta(hours=3, minutes=30)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "j.smith"}},
                {"@odata.type": "#microsoft.graph.security.cloudApplicationEvidence", "displayName": "SharePoint Online"},
            ],
            "mitreTechniques": [{"techniqueId": "T1530"}],
        },
        {
            "id": "xdr-mda-003",
            "title": "Suspicious OAuth app granted sensitive permissions",
            "severity": "high",
            "category": "Persistence",
            "status": "new",
            "serviceSource": "microsoftCloudAppSecurity",
            "createdDateTime": (now - timedelta(hours=7)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "exec-admin"}},
                {"@odata.type": "#microsoft.graph.security.cloudApplicationEvidence", "displayName": "ShadowApp Pro"},
            ],
            "mitreTechniques": [{"techniqueId": "T1550.001"}],
        },
    ]


def main():
    p = argparse.ArgumentParser(description="Unified XDR alert ingestion and triage")
    p.add_argument("--demo", action="store_true", help="Use synthetic demo data")
    p.add_argument("--days", type=int, default=7, help="Look back N days for alerts")
    p.add_argument("--top", type=int, default=200, help="Max alerts to fetch")
    p.add_argument("--output", help="Output file (default: stdout)")
    args = p.parse_args()

    if args.demo:
        alerts = generate_demo_alerts()
    else:
        tenant, client_id, client_secret = get_env()
        token = get_token(tenant, client_id, client_secret)
        alerts = fetch_alerts_real(token, days=args.days, top=args.top)

    # Triage all alerts
    triaged = [triage_alert(a) for a in alerts]
    triaged.sort(key=lambda x: x["priority"], reverse=True)

    # Summary stats
    actions = {}
    sources = {}
    for t in triaged:
        actions[t["action"]] = actions.get(t["action"], 0) + 1
        sources[t["source"]] = sources.get(t["source"], 0) + 1

    result = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "alertCount": len(alerts),
        "summary": actions,
        "sourceBreakdown": sources,
        "triaged": triaged,
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
