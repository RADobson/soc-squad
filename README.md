# SOC Squad — Autonomous Security Operations Centre

## What Is This?
Four specialised autonomous AI agents that deliver full SOC capabilities on-prem. Built on Microsoft Defender XDR + Sentinel, running on Apple Silicon hardware via OpenClaw. No data leaves your building.

## The Problem
Running a Security Operations Centre costs $500K-$2M/year in staffing alone. SMBs (50-500 seats) paying for M365 E5 or Business Premium get Defender XDR and Sentinel but lack the people to operate them. Alerts pile up. Threats go uninvestigated. Compliance auditors ask for evidence that doesn't exist.

## The Solution
Four autonomous agents that operate your SOC 24/7:

| # | Bot | Core Function | Key Outputs |
|---|-----|---------------|-------------|
| 1 | **🛡️ XDR Bot** | Multi-source alert triage + cross-product correlation + auto-response | Triaged alerts, correlated incidents, containment actions |
| 2 | **📊 SIEM Bot** | Analytics rule audit + log source inventory + threat hunting | Rule health, MITRE coverage gaps, hunt findings |
| 3 | **⚡ SOAR Bot** | Automated playbooks + incident lifecycle + SLA tracking | Playbook executions, response metrics, compliance evidence |
| 4 | **🔍 UEBA Bot** | Behavioral baselines + anomaly detection + insider threat scoring | Risk scores, investigation profiles, peer comparisons |

## Coverage

| SOC Function | Bot(s) | Automation Level |
|-------------|--------|-----------------|
| Alert Triage | XDR | Fully autonomous — auto-resolves known FPs, escalates unknowns |
| Incident Correlation | XDR | Cross-product attack chain detection (MDE + MDO + MDI + MDA) |
| Threat Hunting | SIEM | Scheduled + on-demand hunts with MITRE ATT&CK mapping |
| Rule Management | SIEM | Continuous health monitoring, noise detection, gap analysis |
| Incident Response | SOAR | 5 playbook types with automated containment |
| SLA Compliance | SOAR | Real-time tracking against acknowledge/contain/resolve targets |
| User Risk Scoring | UEBA | 90-day behavioral baselines, 20 anomaly types, peer comparison |
| Insider Threat | UEBA | Composite risk scoring with investigation profiles |

## Relationship to E8CR Squad
SOC Squad is the **operational complement** to E8CR Squad:
- **E8CR Squad** = Prevention & Compliance (Essential Eight controls, hardening, patching)
- **SOC Squad** = Detection & Response (monitoring, hunting, incident management)

Together they deliver a complete autonomous cybersecurity program.

## Quick Start (Demo Mode)

```bash
# Run all 4 bots with sample data
python3 run_all.py --output-dir /tmp/soc-demo

# Open the unified dashboard
open /tmp/soc-demo/dashboard.html
```

## Architecture

```
┌─────────────────────────────────────────────┐
│           SOC Squad Orchestrator            │
│              (run_all.py)                   │
├──────────┬──────────┬──────────┬────────────┤
│ 🛡️ XDR   │ 📊 SIEM  │ ⚡ SOAR  │ 🔍 UEBA   │
│          │          │          │            │
│ Defender │ Sentinel │ Playbook │ Behavioral │
│ XDR API  │ KQL API  │ Engine   │ Analytics  │
├──────────┴──────────┴──────────┴────────────┤
│         Microsoft 365 / Azure AD            │
│    (Defender XDR + Sentinel + Entra ID)     │
└─────────────────────────────────────────────┘
```

## Requirements
- Microsoft 365 Business Premium or E5
- Microsoft Sentinel workspace (for SIEM Bot)
- Azure AD app registration with Security.Read + SecurityActions.ReadWrite
- Python 3.10+
- Apple Silicon Mac (recommended) or any Linux host

## Pricing Model (Proposed)
- **Starter:** $1,500/mo — XDR Bot + SOAR Bot (alert triage + response)
- **Professional:** $2,500/mo — All 4 bots (full SOC capability)
- **Enterprise:** $4,000/mo — All bots + custom playbooks + 24/7 escalation support
- **Setup:** $2,500 one-time (app registration, tuning, baseline establishment)

Compare: Managed SOC/MDR services charge $5,000-$15,000/mo for similar coverage.
