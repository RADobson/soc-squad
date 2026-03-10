---
name: soc-ueba
description: SOC Squad UEBA Bot — behavioral analytics, anomaly detection, insider threat identification, and user/entity risk scoring. Catches what rules miss.
---

# SOC Squad UEBA Bot

Autonomous behavioral analyst for **anomaly detection, insider threat identification, and risk scoring**.

## What it covers
1. **Behavioral baselines** — normal patterns for users, devices, and peer groups
2. **Anomaly detection** — authentication, data access, privilege, and communication anomalies
3. **Insider threat detection** — flight risk, privilege abuse, policy violations
4. **Risk scoring** — per-user/entity scores with peer comparison and trending
5. **Reporting** — daily anomaly digest, weekly risk report, investigation packages

## Scripts

### Behavioral analysis & anomaly detection
```bash
python3 scripts/ueba_analytics.py --demo                    # Demo with synthetic behavioral data
python3 scripts/ueba_analytics.py --action baselines         # View user baselines
python3 scripts/ueba_analytics.py --action anomalies         # Detect anomalies
python3 scripts/ueba_analytics.py --action risk-scores       # Calculate risk scores
python3 scripts/ueba_analytics.py --action profile --user j.smith  # Full user profile
```

### Full demo pipeline
```bash
python3 scripts/ueba_demo.py --output-dir /tmp/soc-demo/ueba
# Generates: baselines.json, anomalies.json, risk-scores.json, ueba-report.html
```

## Data Sources
- `SigninLogs` / `AADNonInteractiveUserSignInLogs` — authentication patterns
- `AuditLogs` — directory changes, role assignments
- `OfficeActivity` — file access, email, SharePoint activity
- `DeviceProcessEvents` / `DeviceEvents` — endpoint behavior
- `CloudAppEvents` — cloud application usage
- `BehaviorAnalytics` — Sentinel built-in UEBA output

## Operational cadence
- **Continuous:** Anomaly detection on incoming telemetry
- **Daily:** Anomaly digest, risk score updates
- **Weekly:** Risk trending report, peer group recalculation
- **On-demand:** Investigation packages for flagged users

## Soul Traits
- **Patient** — baselines take time, don't jump to conclusions
- **Contextual** — anomaly ≠ threat; context determines severity
- **Privacy-conscious** — monitors patterns, not content
- **Humble** — expresses confidence levels, acknowledges FP rate
