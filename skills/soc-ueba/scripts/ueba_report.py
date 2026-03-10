#!/usr/bin/env python3
"""Generate UEBA operations HTML report — risk scores, anomalies, user profiles, trends."""

import argparse
import json
import os
from datetime import datetime

SEVERITY_COLORS = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#65a30d", "none": "#6b7280"}
RISK_COLORS = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#65a30d", "none": "#16a34a"}
CATEGORY_ICONS = {
    "Authentication": "🔑", "Data Access": "📂", "Privilege": "👑",
    "Communication": "📧", "Insider Threat": "🕵️",
}


def badge(text, color="#6b7280"):
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">{text}</span>'


def risk_bar(score):
    """Generate a visual risk bar."""
    color = "#dc2626" if score >= 80 else "#ea580c" if score >= 60 else "#d97706" if score >= 30 else "#65a30d" if score > 0 else "#334155"
    return f'<div style="display:flex;align-items:center;gap:6px"><div style="width:80px;background:#1e293b;border-radius:3px;height:16px;overflow:hidden"><div style="width:{score}%;background:{color};height:100%;border-radius:3px"></div></div><strong style="color:{color}">{score}</strong></div>'


def generate_html(risk_data: dict, anomaly_data: dict, baselines_data: dict) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M AEST")
    risk_scores = risk_data.get("riskScores", [])
    anomalies = anomaly_data.get("anomalies", [])
    baselines = baselines_data.get("baselines", [])

    total_users = risk_data.get("usersAnalysed", 0)
    critical = risk_data.get("criticalRisk", 0)
    high = risk_data.get("highRisk", 0)
    medium = risk_data.get("mediumRisk", 0)
    total_anomalies = anomaly_data.get("anomalyCount", 0)
    by_severity = anomaly_data.get("bySeverity", {})
    by_category = anomaly_data.get("byCategory", {})

    # Risk score table
    risk_rows = ""
    for rs in risk_scores:
        risk_color = RISK_COLORS.get(rs.get("riskLevel", "none"), "#6b7280")
        trend_icon = "📈" if rs.get("trend") == "increasing" else "📉" if rs.get("trend") == "decreasing" else "➡️"
        categories = " ".join(CATEGORY_ICONS.get(c, "") for c in rs.get("anomalyCategories", []))
        risk_rows += f"""<tr>
            <td><strong>{rs.get('displayName','')}</strong><br><small style="color:#64748b">{rs.get('title','')}</small></td>
            <td>{rs.get('department','')}</td>
            <td>{risk_bar(rs.get('riskScore', 0))}</td>
            <td>{badge(rs.get('riskLevel','').upper(), risk_color)}</td>
            <td>{trend_icon}</td>
            <td>{rs.get('anomalyCount', 0)}</td>
            <td>{categories}</td>
            <td style="font-size:0.8em">{rs.get('deviationFromPeer','')}</td>
            <td style="font-size:0.8em;max-width:200px">{rs.get('recommendedAction','')}</td>
        </tr>"""

    # Anomaly table
    anomaly_rows = ""
    for a in sorted(anomalies, key=lambda x: x.get("confidence", 0), reverse=True):
        sev_color = SEVERITY_COLORS.get(a.get("severity", ""), "#6b7280")
        cat = next((v["category"] for k, v in __import__('ueba_analytics', fromlist=['ANOMALY_TYPES']).ANOMALY_TYPES.items() if k == a["type"]), "Unknown") if False else a.get("type", "").split("_")[0].title()
        mitigating = a.get("mitigatingFactors", [])
        mitigating_html = "<br>".join(f'<small style="color:#16a34a">✓ {m}</small>' for m in mitigating) if mitigating else ""

        anomaly_rows += f"""<tr>
            <td>{badge(a.get('severity','').upper(), sev_color)}</td>
            <td><strong>{a.get('displayName','')}</strong></td>
            <td>{a.get('description','')}{f'<br>{mitigating_html}' if mitigating_html else ''}</td>
            <td>{a.get('confidence', 0):.0%}</td>
            <td style="font-size:0.8em">{a.get('baselineDeviation','')}</td>
            <td><small>{a.get('detectedAt','')[:16]}</small></td>
        </tr>"""

    # Category breakdown
    cat_bars = ""
    max_cat = max(by_category.values()) if by_category else 1
    cat_colors = {"Authentication": "#3b82f6", "Data Access": "#f59e0b", "Privilege": "#8b5cf6",
                  "Communication": "#10b981", "Insider Threat": "#dc2626"}
    for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
        pct = (count / max_cat) * 100
        color = cat_colors.get(cat, "#6b7280")
        icon = CATEGORY_ICONS.get(cat, "")
        cat_bars += f'''
        <div style="display:flex;align-items:center;gap:8px;margin:4px 0">
            <span style="width:120px;font-size:0.85em">{icon} {cat}</span>
            <div style="flex:1;background:#1e293b;border-radius:4px;height:22px;overflow:hidden">
                <div style="width:{pct}%;background:{color};height:100%;border-radius:4px;display:flex;align-items:center;padding-left:8px">
                    <span style="font-size:0.8em;font-weight:600">{count}</span>
                </div>
            </div>
        </div>'''

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Squad — UEBA Operations Report</title>
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
    .breakdown {{ background: #1e293b; border-radius: 8px; padding: 16px; margin-bottom: 24px; }}
    .breakdown h3 {{ font-size: 1em; margin-bottom: 12px; color: #94a3b8; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; margin-bottom: 16px; }}
    th {{ background: #334155; padding: 10px 12px; text-align: left; font-size: 0.8em; color: #94a3b8; text-transform: uppercase; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 0.9em; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    .footer {{ text-align: center; margin-top: 40px; color: #475569; font-size: 0.8em; padding: 16px; border-top: 1px solid #1e293b; }}
    .banner {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 24px; display: flex; align-items: center; gap: 16px; }}
    .banner .icon {{ font-size: 2.5em; }}
    .banner h1 {{ font-size: 1.8em; background: linear-gradient(135deg, #8b5cf6, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }}
    .banner .subtitle {{ color: #64748b; }}
</style>
</head>
<body>
<div class="container">
    <div class="banner">
        <div class="icon">🧠</div>
        <div>
            <h1>UEBA Operations Report</h1>
            <p class="subtitle">SOC Squad — Behavioral Analytics & Insider Threat Detection | Generated {now}</p>
        </div>
    </div>

    <div class="cards">
        <div class="card info"><div class="value">{total_users}</div><div class="label">Users Analysed</div></div>
        <div class="card critical"><div class="value">{critical}</div><div class="label">Critical Risk</div></div>
        <div class="card warning"><div class="value">{high}</div><div class="label">High Risk</div></div>
        <div class="card purple"><div class="value">{medium}</div><div class="label">Medium Risk</div></div>
        <div class="card info"><div class="value">{total_anomalies}</div><div class="label">Anomalies</div></div>
        <div class="card critical"><div class="value">{by_severity.get('critical', 0)}</div><div class="label">Critical Anomalies</div></div>
        <div class="card warning"><div class="value">{by_severity.get('high', 0)}</div><div class="label">High Anomalies</div></div>
    </div>

    <div class="breakdown">
        <h3>Anomaly Categories</h3>
        {cat_bars}
    </div>

    <h2>👤 User Risk Scores</h2>
    <table>
        <thead><tr><th>User</th><th>Dept</th><th>Risk Score</th><th>Level</th><th>Trend</th><th>Anomalies</th><th>Categories</th><th>Peer Comparison</th><th>Recommended Action</th></tr></thead>
        <tbody>{risk_rows}</tbody>
    </table>

    <h2>⚠️ Detected Anomalies</h2>
    <table>
        <thead><tr><th>Severity</th><th>User</th><th>Description</th><th>Confidence</th><th>Baseline Deviation</th><th>Detected</th></tr></thead>
        <tbody>{anomaly_rows}</tbody>
    </table>

    <div class="footer">
        <p><strong>SOC Squad — UEBA Bot</strong> | Behavioral Analytics & Insider Threat Detection | Dobson Development</p>
        <p>Baselines: 90-day rolling window | Anomaly detection: statistical + peer comparison | Risk scoring: weighted composite</p>
    </div>
</div>
</body>
</html>"""
    return html


def main():
    p = argparse.ArgumentParser(description="Generate UEBA operations HTML report")
    p.add_argument("--input", required=True, help="Directory containing risk-scores.json, anomalies.json, baselines.json")
    p.add_argument("--output", help="Output HTML file")
    args = p.parse_args()

    with open(os.path.join(args.input, "risk-scores.json"), "r") as f:
        risks = json.load(f)
    with open(os.path.join(args.input, "anomalies.json"), "r") as f:
        anomalies = json.load(f)
    with open(os.path.join(args.input, "baselines.json"), "r") as f:
        baselines = json.load(f)

    html = generate_html(risks, anomalies, baselines)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            f.write(html)
        print(f"Report written to {args.output}")
    else:
        print(html)


if __name__ == "__main__":
    main()
