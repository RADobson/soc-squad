#!/usr/bin/env python3
"""SOAR playbook engine — define, execute, and audit automated response workflows.

Playbooks are structured sequences of response actions with conditions,
enrichment steps, and rollback capabilities. Each execution is fully logged.
"""

import argparse
import json
import os
from datetime import datetime, timedelta
from copy import deepcopy


# ─── Playbook definitions ────────────────────────────────────────────────────

PLAYBOOKS = {
    "phishing": {
        "id": "PB-001",
        "name": "Phishing Email Response",
        "description": "Respond to confirmed or suspected phishing email delivery",
        "triggerConditions": ["MDO alert: phishing detected", "User-reported phishing"],
        "severity": "medium",
        "estimatedDuration": "2-5 minutes",
        "steps": [
            {"id": 1, "action": "extract_iocs", "description": "Extract IOCs from email (sender, URLs, attachments, hashes)",
             "type": "enrichment", "automated": True},
            {"id": 2, "action": "check_click_data", "description": "Check if any recipients clicked malicious URLs",
             "type": "enrichment", "automated": True, "escalateIf": "clicks_found"},
            {"id": 3, "action": "block_sender", "description": "Block sender address tenant-wide",
             "type": "containment", "automated": True, "reversible": True},
            {"id": 4, "action": "block_urls", "description": "Block malicious URLs via Defender IOC submission",
             "type": "containment", "automated": True, "reversible": True},
            {"id": 5, "action": "quarantine_email", "description": "Quarantine email from all recipient mailboxes",
             "type": "containment", "automated": True, "reversible": True},
            {"id": 6, "action": "scan_recipients", "description": "Check if recipients' devices show post-click activity",
             "type": "enrichment", "automated": True},
            {"id": 7, "action": "notify_recipients", "description": "Send security advisory to affected recipients",
             "type": "notification", "automated": True},
            {"id": 8, "action": "create_ticket", "description": "Create incident ticket in ServiceNow",
             "type": "documentation", "automated": True},
            {"id": 9, "action": "close_alert", "description": "Resolve original Sentinel alert with documented actions",
             "type": "closure", "automated": True},
        ],
    },
    "malware": {
        "id": "PB-002",
        "name": "Malware Detection Response",
        "description": "Respond to confirmed malware detection on endpoint",
        "triggerConditions": ["MDE alert: malware detected", "AV detection with failed remediation"],
        "severity": "high",
        "estimatedDuration": "5-15 minutes",
        "steps": [
            {"id": 1, "action": "isolate_device", "description": "Network-isolate the infected device",
             "type": "containment", "automated": True, "reversible": True,
             "condition": "severity >= high OR critical_asset"},
            {"id": 2, "action": "collect_investigation_package", "description": "Collect forensic package from device",
             "type": "evidence", "automated": True},
            {"id": 3, "action": "extract_file_hash", "description": "Extract file hash and submit to threat intel",
             "type": "enrichment", "automated": True},
            {"id": 4, "action": "block_hash_tenantwide", "description": "Block malware hash across all endpoints",
             "type": "containment", "automated": True, "reversible": True},
            {"id": 5, "action": "scan_fleet", "description": "Search for same hash/IOCs across entire device fleet",
             "type": "enrichment", "automated": True, "escalateIf": "other_devices_found"},
            {"id": 6, "action": "restrict_app_execution", "description": "Restrict app execution on infected device to Microsoft-signed only",
             "type": "containment", "automated": True, "reversible": True},
            {"id": 7, "action": "create_ticket", "description": "Create P2 incident ticket",
             "type": "documentation", "automated": True},
            {"id": 8, "action": "notify_it_team", "description": "Notify IT team for device remediation/rebuild",
             "type": "notification", "automated": True},
        ],
    },
    "account_compromise": {
        "id": "PB-003",
        "name": "Compromised Account Response",
        "description": "Respond to confirmed or suspected account compromise",
        "triggerConditions": ["MDI alert: credential theft", "Impossible travel + suspicious activity", "MFA fatigue attack"],
        "severity": "high",
        "estimatedDuration": "3-10 minutes",
        "steps": [
            {"id": 1, "action": "disable_account", "description": "Disable the compromised user account",
             "type": "containment", "automated": True, "reversible": True,
             "condition": "NOT vip_account"},
            {"id": 2, "action": "revoke_sessions", "description": "Revoke all active sessions and refresh tokens",
             "type": "containment", "automated": True},
            {"id": 3, "action": "revoke_oauth_grants", "description": "Revoke any OAuth app consent grants made during compromise window",
             "type": "containment", "automated": True, "reversible": True},
            {"id": 4, "action": "check_email_rules", "description": "Check for malicious inbox forwarding rules",
             "type": "enrichment", "automated": True},
            {"id": 5, "action": "remove_forwarding_rules", "description": "Remove any suspicious forwarding rules",
             "type": "remediation", "automated": True, "condition": "suspicious_rules_found"},
            {"id": 6, "action": "audit_recent_activity", "description": "Pull last 48h of user activity (sign-ins, file access, email)",
             "type": "evidence", "automated": True},
            {"id": 7, "action": "force_password_reset", "description": "Force password change on next sign-in",
             "type": "remediation", "automated": True},
            {"id": 8, "action": "re_register_mfa", "description": "Require MFA re-registration",
             "type": "remediation", "automated": True},
            {"id": 9, "action": "notify_user_manager", "description": "Notify user's manager about account compromise",
             "type": "notification", "automated": True},
            {"id": 10, "action": "create_ticket", "description": "Create P1 incident ticket with timeline",
             "type": "documentation", "automated": True},
        ],
    },
    "brute_force": {
        "id": "PB-004",
        "name": "Brute Force Response",
        "description": "Respond to brute force attack against accounts",
        "triggerConditions": ["SIEM rule: brute force threshold exceeded", "MDI: password spray detected"],
        "severity": "medium",
        "estimatedDuration": "1-3 minutes",
        "steps": [
            {"id": 1, "action": "block_source_ip", "description": "Block source IP via Conditional Access named location or firewall",
             "type": "containment", "automated": True, "reversible": True},
            {"id": 2, "action": "check_successful_auth", "description": "Check if any brute force attempts succeeded",
             "type": "enrichment", "automated": True, "escalateIf": "successful_login_found"},
            {"id": 3, "action": "audit_target_accounts", "description": "Review target accounts for signs of compromise",
             "type": "enrichment", "automated": True},
            {"id": 4, "action": "verify_mfa_enabled", "description": "Confirm target accounts have MFA enabled",
             "type": "enrichment", "automated": True},
            {"id": 5, "action": "create_ticket", "description": "Create incident ticket if successful auth detected",
             "type": "documentation", "automated": True, "condition": "successful_login_found"},
            {"id": 6, "action": "close_alert", "description": "Close alert if all attempts failed and MFA is enabled",
             "type": "closure", "automated": True, "condition": "all_failed AND mfa_enabled"},
        ],
    },
    "data_exfiltration": {
        "id": "PB-005",
        "name": "Data Exfiltration Response",
        "description": "Respond to suspected data exfiltration via cloud storage, email, or USB",
        "triggerConditions": ["MDA alert: mass download", "DLP policy match", "UEBA: anomalous file activity"],
        "severity": "critical",
        "estimatedDuration": "10-30 minutes",
        "steps": [
            {"id": 1, "action": "restrict_user_access", "description": "Restrict user's access to SharePoint/OneDrive",
             "type": "containment", "automated": False, "requiresApproval": True,
             "reason": "Data exfil containment may disrupt business — needs human approval"},
            {"id": 2, "action": "preserve_evidence", "description": "Enable litigation hold on user's mailbox and OneDrive",
             "type": "evidence", "automated": True},
            {"id": 3, "action": "scope_exposure", "description": "Identify what data was accessed/downloaded/shared",
             "type": "enrichment", "automated": True},
            {"id": 4, "action": "check_external_sharing", "description": "Check for external sharing links created during window",
             "type": "enrichment", "automated": True},
            {"id": 5, "action": "block_usb", "description": "Block USB storage on user's device via MDE policy",
             "type": "containment", "automated": True, "reversible": True},
            {"id": 6, "action": "notify_legal", "description": "Notify legal/compliance team of potential data breach",
             "type": "notification", "automated": True},
            {"id": 7, "action": "notify_manager", "description": "Notify user's manager",
             "type": "notification", "automated": True},
            {"id": 8, "action": "create_ticket", "description": "Create P1 incident ticket with data classification assessment",
             "type": "documentation", "automated": True},
        ],
    },
}


def generate_demo_executions():
    """Generate realistic playbook execution results for demo mode."""
    now = datetime.now()
    return [
        {
            "executionId": "EXEC-001",
            "playbookId": "PB-001",
            "playbookName": "Phishing Email Response",
            "triggeredBy": "XDR-INC-0002 (Phishing URL clicked)",
            "startedAt": (now - timedelta(minutes=45)).isoformat() + "Z",
            "completedAt": (now - timedelta(minutes=42)).isoformat() + "Z",
            "duration": "2m 47s",
            "status": "completed",
            "stepsExecuted": 9,
            "stepsFailed": 0,
            "actions": [
                {"step": 1, "action": "extract_iocs", "status": "success", "duration": "0.8s",
                 "details": {"urls": 1, "senderBlocked": "phisher@evil-domain.com", "hashesFound": 0}},
                {"step": 2, "action": "check_click_data", "status": "success", "duration": "2.1s",
                 "details": {"recipientsChecked": 15, "clicked": 1, "user": "j.smith@contoso.com"}},
                {"step": 3, "action": "block_sender", "status": "success", "duration": "1.2s",
                 "details": {"sender": "phisher@evil-domain.com", "scope": "tenant-wide"}},
                {"step": 4, "action": "block_urls", "status": "success", "duration": "1.5s",
                 "details": {"url": "https://login-contoso.evil.com/auth", "indicator": "AlertAndBlock"}},
                {"step": 5, "action": "quarantine_email", "status": "success", "duration": "3.4s",
                 "details": {"mailboxesScanned": 15, "emailsQuarantined": 15}},
                {"step": 6, "action": "scan_recipients", "status": "success", "duration": "12.3s",
                 "details": {"devicesScanned": 12, "postClickActivity": True, "affectedDevice": "WKS-FINANCE-01"}},
                {"step": 7, "action": "notify_recipients", "status": "success", "duration": "1.1s",
                 "details": {"notified": 15, "channel": "email"}},
                {"step": 8, "action": "create_ticket", "status": "success", "duration": "2.0s",
                 "details": {"ticketId": "INC0012345", "platform": "ServiceNow", "priority": "P2"}},
                {"step": 9, "action": "close_alert", "status": "success", "duration": "0.9s",
                 "details": {"alertId": "xdr-mdo-001", "resolution": "True Positive - Remediated"}},
            ],
        },
        {
            "executionId": "EXEC-002",
            "playbookId": "PB-003",
            "playbookName": "Compromised Account Response",
            "triggeredBy": "XDR-INC-0002 (Kerberoasting + credential theft)",
            "startedAt": (now - timedelta(minutes=40)).isoformat() + "Z",
            "completedAt": (now - timedelta(minutes=36)).isoformat() + "Z",
            "duration": "3m 52s",
            "status": "completed",
            "stepsExecuted": 10,
            "stepsFailed": 0,
            "actions": [
                {"step": 1, "action": "disable_account", "status": "success", "duration": "1.1s",
                 "details": {"user": "j.smith@contoso.com", "accountEnabled": False}},
                {"step": 2, "action": "revoke_sessions", "status": "success", "duration": "1.3s",
                 "details": {"user": "j.smith@contoso.com", "sessionsRevoked": True}},
                {"step": 3, "action": "revoke_oauth_grants", "status": "success", "duration": "2.0s",
                 "details": {"grantsRevoked": 0, "noSuspiciousGrants": True}},
                {"step": 4, "action": "check_email_rules", "status": "success", "duration": "1.8s",
                 "details": {"rulesFound": 1, "suspicious": True, "rule": "Forward all to protonmail.com"}},
                {"step": 5, "action": "remove_forwarding_rules", "status": "success", "duration": "1.2s",
                 "details": {"rulesRemoved": 1}},
                {"step": 6, "action": "audit_recent_activity", "status": "success", "duration": "8.5s",
                 "details": {"signIns48h": 34, "suspiciousSignIns": 3, "filesAccessed": 127, "emailsSent": 0}},
                {"step": 7, "action": "force_password_reset", "status": "success", "duration": "0.9s",
                 "details": {"user": "j.smith@contoso.com", "forceChangeOnNextLogin": True}},
                {"step": 8, "action": "re_register_mfa", "status": "success", "duration": "1.0s",
                 "details": {"mfaMethodsCleared": True, "reRegistrationRequired": True}},
                {"step": 9, "action": "notify_user_manager", "status": "success", "duration": "1.5s",
                 "details": {"manager": "a.boss@contoso.com", "channel": "email+teams"}},
                {"step": 10, "action": "create_ticket", "status": "success", "duration": "2.1s",
                 "details": {"ticketId": "INC0012346", "platform": "ServiceNow", "priority": "P1"}},
            ],
        },
        {
            "executionId": "EXEC-003",
            "playbookId": "PB-002",
            "playbookName": "Malware Detection Response",
            "triggeredBy": "XDR-INC-0001 (Ransomware on SQL-PROD-01)",
            "startedAt": (now - timedelta(minutes=35)).isoformat() + "Z",
            "completedAt": (now - timedelta(minutes=30)).isoformat() + "Z",
            "duration": "4m 31s",
            "status": "completed_with_escalation",
            "stepsExecuted": 8,
            "stepsFailed": 0,
            "escalated": True,
            "escalationReason": "Same malware hash found on 2 additional devices during fleet scan",
            "actions": [
                {"step": 1, "action": "isolate_device", "status": "success", "duration": "3.2s",
                 "details": {"device": "SQL-PROD-01", "isolationType": "Full"}},
                {"step": 2, "action": "collect_investigation_package", "status": "success", "duration": "45.0s",
                 "details": {"device": "SQL-PROD-01", "packageSize": "2.3 GB"}},
                {"step": 3, "action": "extract_file_hash", "status": "success", "duration": "1.1s",
                 "details": {"sha256": "a1b2c3d4e5f6...", "vtHits": 52, "family": "LockBit 3.0"}},
                {"step": 4, "action": "block_hash_tenantwide", "status": "success", "duration": "1.8s",
                 "details": {"hash": "a1b2c3d4e5f6...", "action": "AlertAndBlock", "scope": "tenant-wide"}},
                {"step": 5, "action": "scan_fleet", "status": "success", "duration": "120.0s",
                 "details": {"devicesScanned": 450, "matchesFound": 2, "additionalDevices": ["WKS-FINANCE-01", "WKS-HR-02"]},
                 "escalation": "ESCALATED: Hash found on 2 additional devices — triggering isolation"},
                {"step": 6, "action": "restrict_app_execution", "status": "success", "duration": "2.1s",
                 "details": {"devices": ["SQL-PROD-01", "WKS-FINANCE-01", "WKS-HR-02"]}},
                {"step": 7, "action": "create_ticket", "status": "success", "duration": "2.3s",
                 "details": {"ticketId": "INC0012347", "platform": "ServiceNow", "priority": "P1", "type": "Major Incident"}},
                {"step": 8, "action": "notify_it_team", "status": "success", "duration": "1.5s",
                 "details": {"notified": ["it-team@contoso.com", "ciso@contoso.com"], "channel": "teams+email+sms"}},
            ],
        },
    ]


def main():
    p = argparse.ArgumentParser(description="SOAR playbook engine")
    p.add_argument("--demo", action="store_true", help="Generate demo playbook executions")
    p.add_argument("--list", action="store_true", help="List available playbooks")
    p.add_argument("--playbook", choices=list(PLAYBOOKS.keys()), help="Execute specific playbook")
    p.add_argument("--dry-run", action="store_true", help="Dry-run mode")
    p.add_argument("--output", help="Output file")
    args = p.parse_args()

    if args.list:
        result = {
            "playbooks": [
                {"id": pb["id"], "name": pb["name"], "description": pb["description"],
                 "severity": pb["severity"], "steps": len(pb["steps"]),
                 "estimatedDuration": pb["estimatedDuration"]}
                for pb in PLAYBOOKS.values()
            ],
            "count": len(PLAYBOOKS),
        }
    elif args.demo:
        executions = generate_demo_executions()
        result = {
            "generatedAt": datetime.now().isoformat() + "Z",
            "executionsCount": len(executions),
            "totalSteps": sum(e["stepsExecuted"] for e in executions),
            "escalations": len([e for e in executions if e.get("escalated")]),
            "executions": executions,
        }
    else:
        result = {"error": "Use --demo for demonstration or --list to see available playbooks"}

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
