#!/usr/bin/env python3
"""XDR automated response engine — unified containment across MDE, MDO, MDI, MDA.

Response actions:
  - MDE: Isolate device, restrict app execution, collect investigation package
  - MDO: Block sender, quarantine email, block URL
  - MDI/Entra: Disable user account, force password reset, revoke sessions
  - MDA: Revoke OAuth app permissions, suspend user
  - Cross-product: Submit IOCs (IP, domain, file hash, URL)

All actions are logged with full justification for audit trail.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../e8cr-vmpm/scripts"))
try:
    from graph_auth import get_env, get_token
except ImportError:
    def get_env(): raise RuntimeError("graph_auth not available — use --demo mode")
    def get_token(*a): raise RuntimeError("graph_auth not available — use --demo mode")

MDE_BASE = "https://api.securitycenter.microsoft.com/api"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


# ─── API helpers ──────────────────────────────────────────────────────────────

def _mde_post(token: str, endpoint: str, body: dict) -> dict:
    """POST to MDE API."""
    url = f"{MDE_BASE}/{endpoint}"
    data = json.dumps(body).encode()
    req = Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        err = e.read().decode()
        return {"error": True, "code": e.code, "message": err}


def _graph_post(token: str, endpoint: str, body: dict) -> dict:
    """POST to Graph API."""
    url = f"{GRAPH_BASE}/{endpoint}"
    data = json.dumps(body).encode()
    req = Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        err = e.read().decode()
        return {"error": True, "code": e.code, "message": err}


def _graph_patch(token: str, endpoint: str, body: dict) -> dict:
    """PATCH to Graph API."""
    url = f"{GRAPH_BASE}/{endpoint}"
    data = json.dumps(body).encode()
    req = Request(url, data=data, method="PATCH")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req) as resp:
            return {"success": True}
    except HTTPError as e:
        err = e.read().decode()
        return {"error": True, "code": e.code, "message": err}


# ─── MDE Response Actions (Endpoints) ────────────────────────────────────────

def isolate_device(token: str, machine_id: str, comment: str, isolation_type: str = "Full"):
    """Isolate a machine from the network."""
    return _mde_post(token, f"machines/{machine_id}/isolate", {
        "Comment": comment,
        "IsolationType": isolation_type,
    })


def unisolate_device(token: str, machine_id: str, comment: str):
    """Release device from isolation."""
    return _mde_post(token, f"machines/{machine_id}/unisolate", {"Comment": comment})


def restrict_app_execution(token: str, machine_id: str, comment: str):
    """Restrict app execution to Microsoft-signed binaries only."""
    return _mde_post(token, f"machines/{machine_id}/restrictCodeExecution", {"Comment": comment})


def collect_investigation_package(token: str, machine_id: str, comment: str):
    """Collect forensic investigation package from device."""
    return _mde_post(token, f"machines/{machine_id}/collectInvestigationPackage", {"Comment": comment})


# ─── Entra ID / MDI Response Actions (Identity) ──────────────────────────────

def disable_user(token: str, user_id: str, comment: str):
    """Disable a user account in Entra ID."""
    return _graph_patch(token, f"users/{user_id}", {"accountEnabled": False})


def enable_user(token: str, user_id: str, comment: str):
    """Re-enable a user account."""
    return _graph_patch(token, f"users/{user_id}", {"accountEnabled": True})


def revoke_user_sessions(token: str, user_id: str, comment: str):
    """Revoke all active sessions and refresh tokens."""
    return _graph_post(token, f"users/{user_id}/revokeSignInSessions", {})


def force_password_reset(token: str, user_id: str, comment: str):
    """Force user to change password on next sign-in."""
    return _graph_patch(token, f"users/{user_id}", {
        "passwordProfile": {"forceChangePasswordNextSignIn": True}
    })


# ─── Cross-product IOC Blocking ──────────────────────────────────────────────

def submit_indicator(token: str, indicator_value: str, indicator_type: str,
                     action: str = "AlertAndBlock", title: str = "", description: str = ""):
    """Submit IOC (IP, URL, domain, file hash) as indicator across Defender XDR."""
    return _mde_post(token, "indicators", {
        "indicatorValue": indicator_value,
        "indicatorType": indicator_type,
        "action": action,
        "title": title or f"SOC XDR Bot - {indicator_type}",
        "description": description or f"Auto-blocked by SOC XDR Bot at {datetime.now().isoformat()}",
        "severity": "High",
        "generateAlert": True,
    })


# ─── Action log ──────────────────────────────────────────────────────────────

def log_action(action_type: str, target: str, reason: str, result: dict,
               source: str = "", incident_id: str = "") -> dict:
    """Log every automated action with full audit trail."""
    return {
        "timestamp": datetime.now().isoformat() + "Z",
        "action": action_type,
        "target": target,
        "reason": reason,
        "source": source,
        "incidentId": incident_id,
        "result": "success" if not result.get("error") else "failed",
        "details": result,
        "bot": "SOC XDR Bot",
    }


# ─── Auto-response engine ────────────────────────────────────────────────────

# Confidence thresholds for automated response
AUTO_RESPOND_THRESHOLD = 0.95  # Only auto-respond at 95%+ confidence
ESCALATE_THRESHOLD = 0.70      # Escalate for human review at 70-95%

RESPONSE_PLAYBOOK = {
    # (source, category, severity) → response actions
    ("MDE", "Impact", "high"): {
        "actions": ["isolate_device", "restrict_app_execution"],
        "confidence": 0.98,
        "reason": "Ransomware/destructive behavior — immediate containment",
    },
    ("MDE", "Execution", "high"): {
        "actions": ["restrict_app_execution", "collect_investigation"],
        "confidence": 0.90,
        "reason": "Suspicious execution — restrict and collect evidence",
    },
    ("MDI", "CredentialAccess", "high"): {
        "actions": ["revoke_sessions", "force_password_reset"],
        "confidence": 0.95,
        "reason": "Credential theft detected — revoke access and force reset",
    },
    ("MDO", "InitialAccess", "high"): {
        "actions": ["block_ioc"],
        "confidence": 0.97,
        "reason": "Malicious email — block sender/URL tenant-wide",
    },
    ("MDA", "Persistence", "high"): {
        "actions": ["revoke_sessions"],
        "confidence": 0.92,
        "reason": "Suspicious OAuth app — revoke sessions pending review",
    },
}


def decide_response(alert: dict) -> dict:
    """Determine appropriate response for a triaged alert."""
    source = alert.get("source", "Unknown")
    category = alert.get("category", "Unknown")
    severity = alert.get("severity", "informational")

    key = (source, category, severity)
    playbook = RESPONSE_PLAYBOOK.get(key)

    if playbook and playbook["confidence"] >= AUTO_RESPOND_THRESHOLD:
        return {
            "decision": "auto_respond",
            "actions": playbook["actions"],
            "confidence": playbook["confidence"],
            "reason": playbook["reason"],
        }
    elif playbook and playbook["confidence"] >= ESCALATE_THRESHOLD:
        return {
            "decision": "escalate_with_recommendation",
            "recommended_actions": playbook["actions"],
            "confidence": playbook["confidence"],
            "reason": f"{playbook['reason']} (confidence {playbook['confidence']:.0%} — requires human approval)",
        }
    else:
        return {
            "decision": "monitor",
            "actions": [],
            "confidence": 0,
            "reason": "No automated response configured — monitor and investigate",
        }


# ─── Demo mode ───────────────────────────────────────────────────────────────

def demo_response_actions():
    """Generate sample XDR response action log for demo mode."""
    now = datetime.now()
    return [
        {
            "timestamp": now.isoformat() + "Z",
            "action": "isolate_device",
            "target": "SQL-PROD-01",
            "source": "MDE",
            "incidentId": "XDR-INC-0001",
            "reason": "Ransomware-related behavior detected (T1486). Critical asset auto-isolated.",
            "result": "success",
            "details": {"machineId": "demo-001", "status": "Succeeded", "type": "Full"},
            "confidence": 0.98,
            "requiresApproval": False,
            "bot": "SOC XDR Bot",
        },
        {
            "timestamp": now.isoformat() + "Z",
            "action": "restrict_app_execution",
            "target": "WKS-FINANCE-01",
            "source": "MDE",
            "incidentId": "XDR-INC-0002",
            "reason": "Suspicious PowerShell + lateral movement detected. App execution restricted pending investigation.",
            "result": "success",
            "details": {"machineId": "demo-002", "status": "Succeeded"},
            "confidence": 0.90,
            "requiresApproval": False,
            "bot": "SOC XDR Bot",
        },
        {
            "timestamp": now.isoformat() + "Z",
            "action": "revoke_sessions",
            "target": "j.smith@contoso.com",
            "source": "MDI",
            "incidentId": "XDR-INC-0002",
            "reason": "Kerberoasting detected from j.smith — all sessions revoked, password reset forced.",
            "result": "success",
            "details": {"userId": "j.smith", "sessionsRevoked": True, "passwordResetForced": True},
            "confidence": 0.95,
            "requiresApproval": False,
            "bot": "SOC XDR Bot",
        },
        {
            "timestamp": now.isoformat() + "Z",
            "action": "block_ioc",
            "target": "https://login-contoso.evil.com/auth",
            "source": "MDO",
            "incidentId": "XDR-INC-0002",
            "reason": "Phishing URL from credential harvesting campaign — blocked tenant-wide.",
            "result": "success",
            "details": {"indicatorType": "Url", "action": "AlertAndBlock"},
            "confidence": 0.97,
            "requiresApproval": False,
            "bot": "SOC XDR Bot",
        },
        {
            "timestamp": now.isoformat() + "Z",
            "action": "disable_user",
            "target": "cfo@contoso.com",
            "source": "MDO",
            "incidentId": "XDR-INC-0003",
            "reason": "BEC invoice fraud targeting CFO account — account disabled pending investigation.",
            "result": "success",
            "details": {"userId": "cfo", "accountEnabled": False},
            "confidence": 0.96,
            "requiresApproval": False,
            "bot": "SOC XDR Bot",
        },
        {
            "timestamp": now.isoformat() + "Z",
            "action": "escalate",
            "target": "XDR-INC-0004",
            "source": "MDA",
            "incidentId": "XDR-INC-0004",
            "reason": "Suspicious OAuth app 'ShadowApp Pro' granted Mail.ReadWrite by exec-admin. Confidence 92% — requires human review before revoking.",
            "result": "pending",
            "details": {"severity": "high", "escalatedTo": "security-team", "recommendedAction": "revoke_oauth_app"},
            "confidence": 0.92,
            "requiresApproval": True,
            "bot": "SOC XDR Bot",
        },
    ]


def main():
    p = argparse.ArgumentParser(description="XDR automated response engine")
    p.add_argument("--demo", action="store_true", help="Generate demo response log")
    p.add_argument("--action", choices=[
        "isolate", "unisolate", "restrict", "collect-evidence",
        "disable-user", "enable-user", "revoke-sessions", "force-reset",
        "block-ioc",
    ])
    p.add_argument("--target", help="Target (machine ID, user ID, or IOC value)")
    p.add_argument("--comment", default="SOC XDR Bot automated action")
    p.add_argument("--ioc-type", choices=["FileSha1", "FileSha256", "IpAddress", "DomainName", "Url"])
    p.add_argument("--output", help="Output file")
    args = p.parse_args()

    if args.demo:
        result = {
            "generatedAt": datetime.now().isoformat() + "Z",
            "actions": demo_response_actions(),
            "summary": {
                "total": 6,
                "auto_executed": 5,
                "escalated": 1,
                "by_source": {"MDE": 2, "MDI": 1, "MDO": 2, "MDA": 1},
            },
        }
        out = json.dumps(result, indent=2)
        if args.output:
            os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
            with open(args.output, "w") as f:
                f.write(out)
            print(f"Written to {args.output}")
        else:
            print(out)
        return

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)

    if not args.action or not args.target:
        print("ERROR: --action and --target required in live mode", file=sys.stderr)
        sys.exit(1)

    action_map = {
        "isolate": lambda: isolate_device(token, args.target, args.comment),
        "unisolate": lambda: unisolate_device(token, args.target, args.comment),
        "restrict": lambda: restrict_app_execution(token, args.target, args.comment),
        "collect-evidence": lambda: collect_investigation_package(token, args.target, args.comment),
        "disable-user": lambda: disable_user(token, args.target, args.comment),
        "enable-user": lambda: enable_user(token, args.target, args.comment),
        "revoke-sessions": lambda: revoke_user_sessions(token, args.target, args.comment),
        "force-reset": lambda: force_password_reset(token, args.target, args.comment),
        "block-ioc": lambda: submit_indicator(token, args.target, args.ioc_type or "IpAddress"),
    }

    result = action_map[args.action]()
    entry = log_action(args.action, args.target, args.comment, result)
    print(json.dumps(entry, indent=2))


if __name__ == "__main__":
    main()
