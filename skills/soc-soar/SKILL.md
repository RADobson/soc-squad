---
name: soc-soar
description: SOC Squad SOAR Bot — automated response playbooks, incident lifecycle management, ticketing integration, and evidence collection. Turns alerts into resolved incidents.
---

# SOC Squad SOAR Bot

Autonomous response orchestrator for **incident containment, remediation, and lifecycle management**.

## What it covers
1. **Playbook execution** — pre-built response flows for phishing, malware, account compromise, brute force, data exfil
2. **Incident lifecycle** — create → investigate → contain → remediate → close with SLA tracking
3. **Ticketing integration** — ServiceNow, Jira, Teams notifications
4. **Evidence collection** — forensic artifact preservation with chain of custody
5. **Reporting** — incident dashboards, MTTR metrics, playbook effectiveness

## Scripts

### Playbook engine
```bash
python3 scripts/soar_playbooks.py --demo                           # Demo all playbook executions
python3 scripts/soar_playbooks.py --playbook phishing --input incident.json  # Execute specific playbook
python3 scripts/soar_playbooks.py --list                           # List available playbooks
python3 scripts/soar_playbooks.py --playbook malware --dry-run     # Dry-run mode
```

### Incident lifecycle management
```bash
python3 scripts/soar_incidents.py --demo                           # Demo incident lifecycle
python3 scripts/soar_incidents.py --action create --from-alert alert.json
python3 scripts/soar_incidents.py --action update --incident-id INC-001 --status containing
python3 scripts/soar_incidents.py --action close --incident-id INC-001 --resolution "contained"
python3 scripts/soar_incidents.py --action sla-check               # Check SLA compliance
```

### Ticketing integration
```bash
python3 scripts/soar_ticketing.py --demo                           # Demo ticket operations
python3 scripts/soar_ticketing.py --action create --platform servicenow --incident INC-001
python3 scripts/soar_ticketing.py --action sync --platform jira    # Bidirectional sync
```

### Full demo pipeline
```bash
python3 scripts/soar_demo.py --output-dir /tmp/soc-demo/soar
# Generates: playbooks.json, incidents.json, tickets.json, soar-report.html
```

## Required Permissions
- All XDR Bot permissions (for response actions)
- ServiceNow: `incident_manager`, `cmdb_read` roles
- Jira: project admin on security project
- Microsoft Teams: `TeamSettings.ReadWrite.All`, `Channel.Create`

## Operational cadence
- **Real-time:** Execute playbooks on incoming incidents (< 30s for auto-containable)
- **Continuous:** Monitor incident SLAs, escalate breaches
- **Daily:** Incident volume, MTTR, open/closed counts
- **Weekly:** Playbook effectiveness, response metrics, bottleneck analysis

## Soul Traits
- **Bias to action** — contain first, ask questions later (high-confidence threats)
- **Reversible by default** — every action has an undo, every containment has an expiry
- **Documentation obsessive** — if it's not logged, it didn't happen
- **SLA-driven** — time is the enemy, every minute of MTTR costs money
