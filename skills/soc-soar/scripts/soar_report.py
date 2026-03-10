#!/usr/bin/env python3
"""Generate SOAR operations HTML report — playbook executions, incidents, SLAs, response metrics."""

import argparse
import json
import os
from datetime import datetime

SEVERITY_COLORS = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#65a30d"}
STATUS_COLORS = {"new": "#3b82f6", "acknowledged": "#8b5cf6", "investigating": "#d97706",
                 "containing": "#ea580c", "remediating": "#f59e0b", "closed": "#16a34a",
                 "completed": "#16a34a", "completed_with_escalation": "#d97706"}


def badge(text, color="#6b7280"):
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">{text}</span>'


def generate_html(playbooks_data: dict, incidents_data: dict) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M AEST")
    executions = playbooks_data.get("executions", [])
    incidents = incidents_data.get("incidents", [])
    sla = incidents_data.get("sla", {})

    total_steps = playbooks_data.get("totalSteps", 0)
    total_executions = playbooks_data.get("executionsCount", 0)
    total_incidents = incidents_data.get("incidentCount", 0)
    escalations = playbooks_data.get("escalations", 0)

    # SLA compliance
    sla_compliance = sla.get("slaCompliance", {})
    ack_compliance = sla_compliance.get("acknowledge", {}).get("compliance", "N/A")
    contain_compliance = sla_compliance.get("contain", {}).get("compliance", "N/A")
    resolve_compliance = sla_compliance.get("resolve", {}).get("compliance", "N/A")

    # Playbook execution rows
    exec_rows = ""
    for ex in executions:
        status_color = STATUS_COLORS.get(ex.get("status", ""), "#6b7280")
        steps_html = ""
        for act in ex.get("actions", [])[:6]:
            act_color = "#16a34a" if act["status"] == "success" else "#dc2626"
            esc = " 🚨" if act.get("escalation") else ""
            steps_html += f'<div style="border-left:3px solid {act_color};padding-left:6px;margin:2px 0;font-size:0.8em">{act["action"]}{esc} <small style="color:#64748b">({act["duration"]})</small></div>'
        if len(ex.get("actions", [])) > 6:
            steps_html += f'<small style="color:#64748b">... +{len(ex["actions"]) - 6} more steps</small>'

        exec_rows += f"""<tr>
            <td><strong>{ex.get('executionId','')}</strong></td>
            <td>{ex.get('playbookName','')}</td>
            <td>{badge(ex.get('status','').replace('_',' ').upper(), status_color)}</td>
            <td>{ex.get('stepsExecuted',0)}/{ex.get('stepsExecuted',0)}</td>
            <td>{ex.get('duration','')}</td>
            <td style="max-width:400px">{steps_html}</td>
        </tr>"""

    # Incident rows
    inc_rows = ""
    for inc in incidents:
        sev_color = SEVERITY_COLORS.get(inc.get("severity", ""), "#6b7280")
        status_color = STATUS_COLORS.get(inc.get("status", ""), "#6b7280")
        assets = inc.get("affectedAssets", {})
        devices = ", ".join(assets.get("devices", [])) or "—"
        users = ", ".join(assets.get("users", [])) or "—"
        playbooks = ", ".join(inc.get("playbooksExecuted", [])) or "—"
        actions_list = "<br>".join(f"• {a}" for a in inc.get("containmentActions", [])[:5]) or "—"

        # SLA display
        inc_sla = inc.get("sla", {})
        sla_html = ""
        for metric in ["acknowledge", "contain", "resolve"]:
            if metric in inc_sla:
                m = inc_sla[metric]
                if m.get("met") is True:
                    sla_html += f'<span style="color:#16a34a">✅ {metric[:3].upper()}: {m["actual"]}m</span> '
                elif m.get("met") is False:
                    sla_html += f'<span style="color:#dc2626">❌ {metric[:3].upper()}: {m["actual"]}m</span> '
                elif m.get("status") == "at_risk":
                    sla_html += f'<span style="color:#d97706">⚠️ {metric[:3].upper()}: at risk</span> '
                else:
                    sla_html += f'<span style="color:#64748b">⏳ {metric[:3].upper()}</span> '

        inc_rows += f"""<tr>
            <td><strong>{inc.get('incidentId','')}</strong></td>
            <td>{badge(inc.get('severity','').upper(), sev_color)}</td>
            <td>{badge(inc.get('status','').upper(), status_color)}</td>
            <td style="max-width:250px;font-size:0.85em">{inc.get('title','')}</td>
            <td style="font-size:0.8em">{users}<br><small style="color:#64748b">{devices}</small></td>
            <td style="font-size:0.8em">{sla_html}</td>
            <td style="font-size:0.8em">{actions_list}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Squad — SOAR Operations Report</title>
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
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; margin-bottom: 16px; }}
    th {{ background: #334155; padding: 10px 12px; text-align: left; font-size: 0.8em; color: #94a3b8; text-transform: uppercase; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 0.9em; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    .footer {{ text-align: center; margin-top: 40px; color: #475569; font-size: 0.8em; padding: 16px; border-top: 1px solid #1e293b; }}
    .banner {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 24px; display: flex; align-items: center; gap: 16px; }}
    .banner .icon {{ font-size: 2.5em; }}
    .banner h1 {{ font-size: 1.8em; background: linear-gradient(135deg, #10b981, #3b82f6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }}
    .banner .subtitle {{ color: #64748b; }}
</style>
</head>
<body>
<div class="container">
    <div class="banner">
        <div class="icon">⚡</div>
        <div>
            <h1>SOAR Operations Report</h1>
            <p class="subtitle">SOC Squad — Automated Response & Incident Lifecycle | Generated {now}</p>
        </div>
    </div>

    <div class="cards">
        <div class="card info"><div class="value">{total_incidents}</div><div class="label">Incidents</div></div>
        <div class="card purple"><div class="value">{total_executions}</div><div class="label">Playbooks Run</div></div>
        <div class="card success"><div class="value">{total_steps}</div><div class="label">Steps Executed</div></div>
        <div class="card warning"><div class="value">{escalations}</div><div class="label">Escalations</div></div>
        <div class="card success"><div class="value">{ack_compliance}</div><div class="label">SLA: Acknowledge</div></div>
        <div class="card success"><div class="value">{contain_compliance}</div><div class="label">SLA: Contain</div></div>
        <div class="card info"><div class="value">{resolve_compliance}</div><div class="label">SLA: Resolve</div></div>
    </div>

    <h2>🎭 Playbook Executions</h2>
    <table>
        <thead><tr><th>ID</th><th>Playbook</th><th>Status</th><th>Steps</th><th>Duration</th><th>Actions</th></tr></thead>
        <tbody>{exec_rows}</tbody>
    </table>

    <h2>📋 Incident Lifecycle</h2>
    <table>
        <thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Title</th><th>Assets</th><th>SLA</th><th>Containment</th></tr></thead>
        <tbody>{inc_rows}</tbody>
    </table>

    <div class="footer">
        <p><strong>SOC Squad — SOAR Bot</strong> | Automated Response & Incident Lifecycle | Dobson Development</p>
        <p>5 playbooks • SLA tracking • ServiceNow/Jira integration • Full audit trail</p>
    </div>
</div>
</body>
</html>"""
    return html


def main():
    p = argparse.ArgumentParser(description="Generate SOAR operations HTML report")
    p.add_argument("--input", required=True, help="Directory containing playbooks.json, incidents.json")
    p.add_argument("--output", help="Output HTML file")
    args = p.parse_args()

    with open(os.path.join(args.input, "playbooks.json"), "r") as f:
        playbooks = json.load(f)
    with open(os.path.join(args.input, "incidents.json"), "r") as f:
        incidents = json.load(f)

    html = generate_html(playbooks, incidents)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            f.write(html)
        print(f"Report written to {args.output}")
    else:
        print(html)


if __name__ == "__main__":
    main()
