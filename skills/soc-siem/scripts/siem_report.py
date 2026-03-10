#!/usr/bin/env python3
"""Generate SIEM operations HTML report — detection health, coverage, hunts, costs."""

import argparse
import json
import os
from datetime import datetime

SEVERITY_COLORS = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#65a30d"}
OUTCOME_COLORS = {"confirmed_threat": "#dc2626", "suspicious": "#d97706", "clean": "#16a34a"}
STATUS_COLORS = {"healthy": "#16a34a", "noisy": "#ea580c", "stale": "#d97706", "disabled": "#6b7280", "degraded": "#ea580c"}


def badge(text, color="#6b7280"):
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">{text}</span>'


def generate_html(rules_data: dict, logs_data: dict, hunts_data: dict) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M AEST")
    rules_summary = rules_data.get("summary", {})
    rules = rules_data.get("rules", [])
    recommendations = rules_data.get("recommendations", [])
    connected = logs_data.get("connected", [])
    missing = logs_data.get("missing", [])
    hunts = hunts_data.get("hunts", [])

    # Cost totals
    total_daily_gb = sum(s.get("dailyIngestionGB", 0) for s in connected)
    total_daily_cost = sum(s.get("dailyCostUSD", 0) for s in connected)
    total_monthly_cost = total_daily_cost * 30

    # Rules table
    rule_rows = ""
    for r in sorted(rules, key=lambda x: x.get("fpRate", 0), reverse=True):
        status_color = STATUS_COLORS.get(r.get("status", ""), "#6b7280")
        fp_color = "#dc2626" if r.get("fpRate", 0) > 0.5 else "#d97706" if r.get("fpRate", 0) > 0.2 else "#16a34a"
        enabled = "✅" if r["enabled"] else "❌"
        techniques = ", ".join(r.get("techniques", [])) or "—"
        last_fired = r.get("lastTriggered", "—")
        if last_fired and last_fired != "—":
            last_fired = last_fired[:16]
        rule_rows += f"""<tr>
            <td>{enabled}</td>
            <td>{r['name']}</td>
            <td>{badge(r.get('severity','').upper(), SEVERITY_COLORS.get(r.get('severity','').lower(), '#6b7280'))}</td>
            <td>{badge(r.get('status',''), status_color)}</td>
            <td><span class="tag">{techniques}</span></td>
            <td>{r.get('alertsLast30d', 0)}</td>
            <td style="color:{fp_color};font-weight:600">{r.get('fpRate', 0):.0%}</td>
            <td><small>{last_fired}</small></td>
        </tr>"""

    # Log sources table
    log_rows = ""
    for s in connected:
        status_color = STATUS_COLORS.get(s.get("status", ""), "#6b7280")
        pct = (s.get("dailyCostUSD", 0) / total_daily_cost * 100) if total_daily_cost > 0 else 0
        log_rows += f"""<tr>
            <td>{badge(s.get('status','').upper(), status_color)}</td>
            <td>{s['name']}</td>
            <td>{s.get('dailyIngestionGB', 0):.1f} GB</td>
            <td>${s.get('dailyCostUSD', 0):.2f}</td>
            <td>${s.get('dailyCostUSD', 0) * 30:.0f}</td>
            <td>{pct:.0f}%</td>
            <td>{s.get('recordsLast24h', 0):,}</td>
        </tr>"""

    # Missing sources
    missing_rows = ""
    for s in missing:
        priority_color = "#dc2626" if s["priority"] == "critical" else "#d97706" if s["priority"] == "high" else "#3b82f6"
        missing_rows += f"""<tr>
            <td>{badge(s['priority'].upper(), priority_color)}</td>
            <td>{s['name']}</td>
            <td>{s.get('reason', '')}</td>
        </tr>"""

    # Hunt results
    hunt_rows = ""
    for h in hunts:
        outcome_color = OUTCOME_COLORS.get(h.get("outcome", ""), "#6b7280")
        findings_html = ""
        for f in h.get("findings", []):
            f_color = SEVERITY_COLORS.get(f.get("severity", ""), "#6b7280")
            findings_html += f'<div style="border-left:3px solid {f_color};padding-left:8px;margin:4px 0;font-size:0.85em"><strong>{f["description"]}</strong><br><small style="color:#94a3b8">{f["recommendation"]}</small></div>'
        if not findings_html:
            findings_html = '<small style="color:#16a34a">No findings — clean</small>'

        hunt_rows += f"""<tr>
            <td><strong>{h.get('huntId','')}</strong></td>
            <td>{h['name']}</td>
            <td>{badge(h.get('outcome','').replace('_',' ').upper(), outcome_color)}</td>
            <td>{h.get('findingsCount', 0)}</td>
            <td><small>{h.get('recordsScanned', 0):,} records in {h.get('duration','')}</small></td>
            <td>{findings_html}</td>
        </tr>"""

    # Recommendations
    rec_rows = ""
    for r in recommendations[:10]:
        priority_color = "#dc2626" if r.get("priority") == "high" else "#d97706"
        rec_rows += f"""<tr>
            <td>{badge(r.get('priority','').upper(), priority_color)}</td>
            <td><strong>{r.get('rule', r.get('action', ''))}</strong></td>
            <td>{r.get('issue', r.get('impact', ''))}</td>
            <td>{r.get('action', '')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Squad — SIEM Operations Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 24px; }}
    .container {{ max-width: 1400px; margin: 0 auto; }}
    h2 {{ font-size: 1.3em; margin: 32px 0 12px; color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }}
    .card {{ background: #1e293b; border-radius: 8px; padding: 16px; text-align: center; }}
    .card .value {{ font-size: 1.8em; font-weight: 700; }}
    .card .label {{ font-size: 0.8em; color: #94a3b8; margin-top: 4px; }}
    .card.critical {{ border-left: 4px solid #dc2626; }}
    .card.warning {{ border-left: 4px solid #d97706; }}
    .card.success {{ border-left: 4px solid #16a34a; }}
    .card.info {{ border-left: 4px solid #3b82f6; }}
    .card.purple {{ border-left: 4px solid #8b5cf6; }}
    .card.green {{ border-left: 4px solid #10b981; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; margin-bottom: 16px; }}
    th {{ background: #334155; padding: 10px 12px; text-align: left; font-size: 0.8em; color: #94a3b8; text-transform: uppercase; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 0.9em; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    .tag {{ display: inline-block; background: #334155; padding: 2px 6px; border-radius: 3px; font-size: 0.8em; font-family: monospace; }}
    .footer {{ text-align: center; margin-top: 40px; color: #475569; font-size: 0.8em; padding: 16px; border-top: 1px solid #1e293b; }}
    .banner {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 24px; display: flex; align-items: center; gap: 16px; }}
    .banner .icon {{ font-size: 2.5em; }}
    .banner h1 {{ font-size: 1.8em; background: linear-gradient(135deg, #f59e0b, #ef4444); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }}
    .banner .subtitle {{ color: #64748b; }}
</style>
</head>
<body>
<div class="container">
    <div class="banner">
        <div class="icon">📡</div>
        <div>
            <h1>SIEM Operations Report</h1>
            <p class="subtitle">SOC Squad — Detection Engineering & Threat Hunting | Generated {now}</p>
        </div>
    </div>

    <div class="cards">
        <div class="card info"><div class="value">{rules_summary.get('totalRules', 0)}</div><div class="label">Total Rules</div></div>
        <div class="card success"><div class="value">{rules_summary.get('healthy', 0)}</div><div class="label">Healthy</div></div>
        <div class="card warning"><div class="value">{rules_summary.get('noisy', 0)}</div><div class="label">Noisy</div></div>
        <div class="card critical"><div class="value">{rules_summary.get('disabled', 0)}</div><div class="label">Disabled</div></div>
        <div class="card purple"><div class="value">{rules_summary.get('overallFPRate', '0%')}</div><div class="label">Overall FP Rate</div></div>
        <div class="card info"><div class="value">{len(connected)}</div><div class="label">Log Sources</div></div>
        <div class="card green"><div class="value">{total_daily_gb:.0f} GB/d</div><div class="label">Daily Ingestion</div></div>
        <div class="card warning"><div class="value">${total_monthly_cost:,.0f}</div><div class="label">Monthly Cost</div></div>
    </div>

    <h2>📋 Analytics Rules Health</h2>
    <table>
        <thead><tr><th>On</th><th>Rule Name</th><th>Severity</th><th>Status</th><th>MITRE</th><th>Alerts/30d</th><th>FP Rate</th><th>Last Fired</th></tr></thead>
        <tbody>{rule_rows}</tbody>
    </table>

    <h2>🔌 Connected Log Sources</h2>
    <table>
        <thead><tr><th>Status</th><th>Source</th><th>Daily Volume</th><th>Daily Cost</th><th>Monthly Cost</th><th>% Total</th><th>Records/24h</th></tr></thead>
        <tbody>{log_rows}</tbody>
    </table>

    <h2>⚠️ Missing Log Sources</h2>
    <table>
        <thead><tr><th>Priority</th><th>Source</th><th>Impact</th></tr></thead>
        <tbody>{missing_rows}</tbody>
    </table>

    <h2>🔍 Threat Hunt Results</h2>
    <table>
        <thead><tr><th>ID</th><th>Hunt</th><th>Outcome</th><th>Findings</th><th>Scope</th><th>Details</th></tr></thead>
        <tbody>{hunt_rows}</tbody>
    </table>

    <h2>💡 Recommendations</h2>
    <table>
        <thead><tr><th>Priority</th><th>Target</th><th>Issue</th><th>Recommended Action</th></tr></thead>
        <tbody>{rec_rows}</tbody>
    </table>

    <div class="footer">
        <p><strong>SOC Squad — SIEM Bot</strong> | Autonomous Detection Engineering & Threat Hunting | Dobson Development</p>
        <p>Detection rule tuning • Log source coverage • Hypothesis-driven threat hunting • Cost optimisation</p>
    </div>
</div>
</body>
</html>"""
    return html


def main():
    p = argparse.ArgumentParser(description="Generate SIEM operations HTML report")
    p.add_argument("--input", required=True, help="Directory containing rules.json, logs.json, hunts.json")
    p.add_argument("--output", help="Output HTML file")
    args = p.parse_args()

    with open(os.path.join(args.input, "rules.json"), "r") as f:
        rules = json.load(f)
    with open(os.path.join(args.input, "logs.json"), "r") as f:
        logs = json.load(f)
    with open(os.path.join(args.input, "hunts.json"), "r") as f:
        hunts = json.load(f)

    html = generate_html(rules, logs, hunts)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            f.write(html)
        print(f"Report written to {args.output}")
    else:
        print(html)


if __name__ == "__main__":
    main()
