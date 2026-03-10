---
name: soc-xdr
description: SOC Squad XDR Bot — autonomous unified detection & response agent across Microsoft Defender XDR (MDE, MDO, MDI, MDA). Alert ingestion, cross-product correlation, intelligent triage, automated containment, and executive reporting.
---

# SOC Squad XDR Bot

Autonomous Tier-1 SOC analyst covering the **full Microsoft Defender XDR stack** — endpoints, email, identity, and cloud apps.

## Evolution from E8CR EDR Bot
The E8CR EDR Bot focused on Defender for Endpoint only. XDR Bot unifies all four Defender XDR sources into a single triage → correlate → respond pipeline.

## What it covers
1. **Unified alert ingestion** from MDE, MDO, MDI, and MDA via Graph Security API
2. **Cross-product correlation** — phishing email → credential alert → endpoint execution = one incident
3. **Contextual enrichment** — device criticality, user risk, threat intel, historical patterns
4. **Intelligent triage** with priority scoring and auto-FP resolution
5. **Automated response** — isolate device, disable user, block sender/URL, revoke OAuth, block IOCs
6. **Reporting** — operational dashboard, incident packages, executive briefs

## Scripts

### Unified alert ingestion (all XDR sources)
```bash
python3 scripts/xdr_alerts.py --demo                    # Demo with synthetic multi-source alerts
python3 scripts/xdr_alerts.py --days 7 --top 200        # Live: fetch from Graph Security API
python3 scripts/xdr_alerts.py --demo --output /tmp/xdr/alerts.json
```

### Cross-product incident correlation
```bash
python3 scripts/xdr_correlator.py --input /tmp/xdr/alerts.json --output /tmp/xdr/incidents.json
python3 scripts/xdr_correlator.py --input /tmp/xdr/alerts.json --window 6  # 6-hour correlation window
```

### Automated response engine
```bash
python3 scripts/xdr_response.py --demo --output /tmp/xdr/actions.json   # Demo response actions
python3 scripts/xdr_response.py --action isolate --target <machine_id>   # Live: isolate device
python3 scripts/xdr_response.py --action disable-user --target <user_id> # Live: disable compromised account
python3 scripts/xdr_response.py --action block-sender --target <email>   # Live: block malicious sender
python3 scripts/xdr_response.py --action revoke-sessions --target <user_id> # Live: revoke OAuth/sessions
python3 scripts/xdr_response.py --action block-ioc --target <ioc> --ioc-type IpAddress
```

### Threat intelligence enrichment
```bash
python3 scripts/xdr_threat_intel.py --hash <sha256>
python3 scripts/xdr_threat_intel.py --ip <ip>
python3 scripts/xdr_threat_intel.py --domain <domain>
python3 scripts/xdr_threat_intel.py --email <sender>     # Email reputation check
```

### Full demo pipeline
```bash
python3 scripts/xdr_demo.py --output-dir /tmp/soc-demo/xdr
# Generates: alerts.json, incidents.json, actions.json, xdr-report.html
```

### HTML report generation
```bash
python3 scripts/xdr_report.py --input /tmp/soc-demo/xdr --output xdr-report.html
python3 scripts/xdr_report.py --input /tmp/soc-demo/xdr --output xdr-report.html --type executive
```

## Required Graph Permissions (Application)
- `SecurityAlert.ReadWrite.All` — read/update alerts across all Defender products
- `SecurityIncident.ReadWrite.All` — manage incidents
- `Machine.Isolate` — MDE device isolation
- `Machine.RestrictExecution` — MDE app restriction
- `User.ReadWrite.All` — disable/enable user accounts (Entra ID)
- `ThreatIndicators.ReadWrite.OwnedBy` — submit IOCs
- `Mail.Read` — MDO email context (read-only)
- `CloudAppSecurity.Read.All` — MDA cloud app alerts

## Operational cadence
- **Continuous:** Monitor all XDR alert sources (polling every 60s in production)
- **Real-time:** Triage high-severity alerts (< 5 min target)
- **Immediate:** Auto-contain confirmed threats (< 30s for auto-containable)
- **Daily:** Ops summary with metrics (MTTD, MTTR, alert volume, FP rate)
- **Weekly:** Executive brief with threat landscape + coverage gaps

## Soul Traits
- **Paranoid but precise** — assume breach, but don't cry wolf
- **Speed over perfection** — contain first, investigate second
- **Transparent** — every action documented, every decision explained
- **Cross-domain thinker** — connects signals across endpoint + email + identity + cloud
- **Knows its limits** — escalates to humans for ambiguous situations
