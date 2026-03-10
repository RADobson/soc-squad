#!/usr/bin/env python3
"""Generate XDR operations HTML report — unified dashboard across all Defender XDR sources."""

import argparse
import json
import os
from datetime import datetime

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "informational": "#6b7280",
}

SOURCE_COLORS = {
    "MDE": "#3b82f6",   # Blue — endpoints
    "MDO": "#f59e0b",   # Amber — email
    "MDI": "#8b5cf6",   # Purple — identity
    "MDA": "#10b981",   # Green — cloud apps
    "Unknown": "#6b7280",
}

SOURCE_ICONS = {
    "MDE": "🖥️",
    "MDO": "📧",
    "MDI": "🔑",
    "MDA": "☁️",
}


def badge(text: str, color: str = "#6b7280") -> str:
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">{text}</span>'


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#6b7280")
    return badge(severity.upper(), color)


def source_badge(source: str) -> str:
    color = SOURCE_COLORS.get(source, "#6b7280")
    icon = SOURCE_ICONS.get(source, "")
    return badge(f"{icon} {source}", color)


def generate_html(alerts_data: dict, incidents_data: dict, actions_data: dict,
                  report_type: str = "operational") -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M AEST")
    triaged = alerts_data.get("triaged", [])
    summary = alerts_data.get("summary", {})
    source_breakdown = alerts_data.get("sourceBreakdown", {})
    incidents = incidents_data.get("incidents", [])
    actions = actions_data.get("actions", [])

    # Summary stats
    total_alerts = alerts_data.get("alertCount", 0)
    auto_resolved = summary.get("auto_resolve", 0)
    escalated_immediate = summary.get("escalate_immediate", 0)
    escalated = summary.get("escalate", 0)
    investigating = summary.get("investigate", 0)
    monitoring = summary.get("monitor", 0)
    attack_chains = incidents_data.get("attackChains", 0)
    cross_product = incidents_data.get("crossProductIncidents", 0)
    pattern_matches = incidents_data.get("patternMatches", 0)
    total_actions = len(actions)
    auto_actions = len([a for a in actions if not a.get("requiresApproval")])

    # Source breakdown bars
    source_bars = ""
    max_source_count = max(source_breakdown.values()) if source_breakdown else 1
    for src, count in sorted(source_breakdown.items(), key=lambda x: -x[1]):
        pct = (count / max_source_count) * 100
        color = SOURCE_COLORS.get(src, "#6b7280")
        icon = SOURCE_ICONS.get(src, "")
        source_bars += f'''
        <div style="display:flex;align-items:center;gap:8px;margin:4px 0">
            <span style="width:80px;font-size:0.9em">{icon} {src}</span>
            <div style="flex:1;background:#1e293b;border-radius:4px;height:24px;overflow:hidden">
                <div style="width:{pct}%;background:{color};height:100%;border-radius:4px;display:flex;align-items:center;padding-left:8px">
                    <span style="font-size:0.8em;font-weight:600">{count}</span>
                </div>
            </div>
        </div>'''

    # Alerts table
    alert_rows = ""
    for t in triaged[:25]:
        sev = t.get("severity", "informational")
        source = t.get("source", "Unknown")
        devices = ", ".join(t.get("devices", [])) or "—"
        users = ", ".join(t.get("users", [])) or "—"
        emails = ", ".join(t.get("emails", [])) or ""
        apps = ", ".join(t.get("cloudApps", [])) or ""
        mitre = ", ".join(t.get("mitre_techniques", [])) or "—"
        action = t.get("action", "").replace("_", " ").title()
        reason = t.get("reason", "")
        # Show most relevant entity based on source
        entity = devices
        if source == "MDO":
            entity = emails or users
        elif source == "MDA":
            entity = apps or users
        elif source == "MDI":
            entity = users or devices

        alert_rows += f"""<tr>
            <td>{source_badge(source)}</td>
            <td>{severity_badge(sev)}</td>
            <td>{t.get('title','')}</td>
            <td>{entity}</td>
            <td><span class="tag">{mitre}</span></td>
            <td><strong>{action}</strong>{f'<br><small style="color:#94a3b8">{reason}</small>' if reason else ''}</td>
        </tr>"""

    # Incidents table
    incident_rows = ""
    for inc in incidents:
        sev = inc.get("severity", "low")
        chain_badge = badge("ATTACK CHAIN", "#7c3aed") if inc.get("isAttackChain") else ""
        cross_badge = badge("CROSS-PRODUCT", "#0ea5e9") if inc.get("isCrossProduct") else ""
        pattern_badges = " ".join(badge(p, "#7c3aed") for p in inc.get("matchedPatterns", []))
        stages = " → ".join(inc.get("killChainStages", []))
        sources = " ".join(source_badge(s) for s in inc.get("xdrSources", []))
        devices = ", ".join(inc.get("devices", [])) or "—"
        users = ", ".join(inc.get("users", [])) or "—"

        timeline_html = ""
        for event in inc.get("timeline", []):
            ev_color = SEVERITY_COLORS.get(event.get("severity", ""), "#6b7280")
            src_icon = SOURCE_ICONS.get(event.get("source", ""), "")
            timeline_html += f'''<div style="border-left:3px solid {ev_color};padding-left:8px;margin:4px 0">
                <small style="color:#64748b">{event.get("time","")[:16]}</small>
                <span style="margin-left:4px">{src_icon}</span>
                <strong>{event.get("title","")}</strong>
                <small style="color:#94a3b8">[{event.get("stage","")}]</small>
            </div>'''

        incident_rows += f"""<tr>
            <td><strong>{inc.get('incidentId','')}</strong><br>{chain_badge} {cross_badge}</td>
            <td>{severity_badge(sev)}</td>
            <td>{sources}</td>
            <td>{inc.get('alertCount',0)}</td>
            <td style="font-size:0.85em">{stages}</td>
            <td>{users}<br><small style="color:#64748b">{devices}</small></td>
            <td>{timeline_html}</td>
        </tr>"""

    # Actions table
    action_rows = ""
    for act in actions:
        result_color = "#16a34a" if act.get("result") == "success" else "#dc2626" if act.get("result") == "failed" else "#d97706"
        src = act.get("source", "")
        conf = act.get("confidence", 0)
        conf_display = f"{conf:.0%}" if conf else "—"
        approval = "⚠️ PENDING" if act.get("requiresApproval") else "✅ AUTO"
        action_rows += f"""<tr>
            <td><small>{act.get('timestamp','')[:16]}</small></td>
            <td>{source_badge(src) if src else '—'}</td>
            <td><strong>{act.get('action','').replace('_',' ').title()}</strong></td>
            <td>{act.get('target','')}</td>
            <td style="max-width:300px;font-size:0.85em">{act.get('reason','')}</td>
            <td>{conf_display}</td>
            <td style="color:{result_color};font-weight:600">{act.get('result','').upper()}</td>
            <td>{approval}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Squad — XDR Operations Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 24px; }}
    .container {{ max-width: 1400px; margin: 0 auto; }}
    h1 {{ font-size: 1.8em; margin-bottom: 4px; }}
    h2 {{ font-size: 1.3em; margin: 32px 0 12px; color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
    .subtitle {{ color: #64748b; margin-bottom: 24px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }}
    .card {{ background: #1e293b; border-radius: 8px; padding: 16px; text-align: center; }}
    .card .value {{ font-size: 1.8em; font-weight: 700; }}
    .card .label {{ font-size: 0.8em; color: #94a3b8; margin-top: 4px; }}
    .card.critical {{ border-left: 4px solid #dc2626; }}
    .card.warning {{ border-left: 4px solid #d97706; }}
    .card.success {{ border-left: 4px solid #16a34a; }}
    .card.info {{ border-left: 4px solid #3b82f6; }}
    .card.purple {{ border-left: 4px solid #8b5cf6; }}
    .source-breakdown {{ background: #1e293b; border-radius: 8px; padding: 16px; margin-bottom: 24px; }}
    .source-breakdown h3 {{ font-size: 1em; margin-bottom: 12px; color: #94a3b8; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; margin-bottom: 16px; }}
    th {{ background: #334155; padding: 10px 12px; text-align: left; font-size: 0.8em; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 0.9em; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    .tag {{ display: inline-block; background: #334155; padding: 2px 6px; border-radius: 3px; font-size: 0.8em; margin: 1px; font-family: monospace; }}
    .footer {{ text-align: center; margin-top: 40px; color: #475569; font-size: 0.8em; padding: 16px; border-top: 1px solid #1e293b; }}
    .xdr-banner {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 24px; display: flex; align-items: center; gap: 16px; }}
    .xdr-banner .icon {{ font-size: 2.5em; }}
    .xdr-banner h1 {{ background: linear-gradient(135deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }}
</style>
</head>
<body>
<div class="container">
    <div class="xdr-banner">
        <div class="icon">🛡️</div>
        <div>
            <h1>XDR Operations Report</h1>
            <p class="subtitle">SOC Squad — Unified Detection & Response | Generated {now}</p>
        </div>
    </div>

    <div class="cards">
        <div class="card info"><div class="value">{total_alerts}</div><div class="label">Total Alerts</div></div>
        <div class="card critical"><div class="value">{escalated_immediate + escalated}</div><div class="label">Escalated</div></div>
        <div class="card warning"><div class="value">{investigating}</div><div class="label">Investigating</div></div>
        <div class="card success"><div class="value">{auto_resolved}</div><div class="label">Auto-Resolved FP</div></div>
        <div class="card purple"><div class="value">{incidents_data.get('incidentCount', 0)}</div><div class="label">Incidents</div></div>
        <div class="card critical"><div class="value">{attack_chains}</div><div class="label">Attack Chains</div></div>
        <div class="card info"><div class="value">{cross_product}</div><div class="label">Cross-Product</div></div>
        <div class="card success"><div class="value">{auto_actions}/{total_actions}</div><div class="label">Auto-Responded</div></div>
    </div>

    <div class="source-breakdown">
        <h3>Alert Sources</h3>
        {source_bars}
    </div>

    <h2>🎯 Alert Triage</h2>
    <table>
        <thead><tr><th>Source</th><th>Severity</th><th>Alert</th><th>Entity</th><th>MITRE</th><th>Action</th></tr></thead>
        <tbody>{alert_rows}</tbody>
    </table>

    <h2>🔗 Correlated Incidents</h2>
    <table>
        <thead><tr><th>Incident</th><th>Severity</th><th>Sources</th><th>Alerts</th><th>Kill Chain</th><th>Entities</th><th>Timeline</th></tr></thead>
        <tbody>{incident_rows}</tbody>
    </table>

    <h2>⚡ Automated Response Actions</h2>
    <table>
        <thead><tr><th>Time</th><th>Source</th><th>Action</th><th>Target</th><th>Reason</th><th>Confidence</th><th>Result</th><th>Mode</th></tr></thead>
        <tbody>{action_rows}</tbody>
    </table>

    <div class="footer">
        <p><strong>SOC Squad — XDR Bot</strong> | Autonomous Tier-1 SOC Analyst | Dobson Development</p>
        <p>Covering: 🖥️ Endpoints (MDE) · 📧 Email (MDO) · 🔑 Identity (MDI) · ☁️ Cloud Apps (MDA)</p>
        <p style="margin-top:8px">Confidence threshold: ≥95% auto-respond | 70-95% escalate with recommendation | &lt;70% monitor</p>
    </div>
</div>
</body>
</html>"""
    return html


def main():
    p = argparse.ArgumentParser(description="Generate XDR operations HTML report")
    p.add_argument("--input", required=True, help="Directory containing alerts.json, incidents.json, actions.json")
    p.add_argument("--output", help="Output HTML file (default: stdout)")
    p.add_argument("--type", choices=["operational", "executive"], default="operational")
    args = p.parse_args()

    with open(os.path.join(args.input, "alerts.json"), "r") as f:
        alerts = json.load(f)
    with open(os.path.join(args.input, "incidents.json"), "r") as f:
        incidents = json.load(f)
    with open(os.path.join(args.input, "actions.json"), "r") as f:
        actions = json.load(f)

    html = generate_html(alerts, incidents, actions, args.type)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            f.write(html)
        print(f"Report written to {args.output}")
    else:
        print(html)


if __name__ == "__main__":
    main()
