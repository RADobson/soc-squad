#!/usr/bin/env python3
"""Full UEBA demo pipeline: baselines → anomalies → risk scores → report."""

import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from ueba_analytics import (
    generate_demo_baselines, generate_demo_anomalies,
    calculate_risk_scores, generate_user_profile, ANOMALY_TYPES,
)
import importlib.util

_spec = importlib.util.spec_from_file_location("ueba_report", os.path.join(os.path.dirname(__file__), "ueba_report.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
generate_html = _mod.generate_html


def main():
    import argparse
    p = argparse.ArgumentParser(description="Generate full UEBA demo artifacts")
    p.add_argument("--output-dir", default="/tmp/soc-demo/ueba", help="Output directory")
    args = p.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("🧠 SOC Squad — UEBA Bot Demo Pipeline")
    print("=" * 50)

    # 1. Behavioral baselines
    print("\n📊 Stage 1: Building behavioral baselines...")
    baselines = generate_demo_baselines()
    baselines_data = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "userCount": len(baselines),
        "baselines": baselines,
    }
    print(f"   Users baselined: {len(baselines)}")
    for b in baselines:
        print(f"   ├─ {b['displayName']} ({b['department']})")

    # 2. Anomaly detection
    print("\n⚠️ Stage 2: Detecting anomalies...")
    anomalies = generate_demo_anomalies()

    by_severity = {}
    by_category = {}
    for a in anomalies:
        sev = a["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
        cat = ANOMALY_TYPES.get(a["type"], {}).get("category", "Unknown")
        by_category[cat] = by_category.get(cat, 0) + 1

    anomaly_data = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "anomalyCount": len(anomalies),
        "bySeverity": by_severity,
        "byCategory": by_category,
        "anomalies": anomalies,
    }
    print(f"   Total anomalies: {len(anomalies)}")
    for sev, count in sorted(by_severity.items()):
        print(f"   ├─ {sev}: {count}")

    # 3. Risk scoring
    print("\n🎯 Stage 3: Calculating risk scores...")
    risk_scores = calculate_risk_scores(baselines, anomalies)
    risk_data = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "usersAnalysed": len(risk_scores),
        "criticalRisk": len([s for s in risk_scores if s["riskLevel"] == "critical"]),
        "highRisk": len([s for s in risk_scores if s["riskLevel"] == "high"]),
        "mediumRisk": len([s for s in risk_scores if s["riskLevel"] == "medium"]),
        "riskScores": risk_scores,
    }
    for rs in risk_scores:
        icon = "🔴" if rs["riskLevel"] == "critical" else "🟠" if rs["riskLevel"] == "high" else "🟡" if rs["riskLevel"] == "medium" else "🟢" if rs["riskLevel"] == "low" else "⚪"
        print(f"   {icon} {rs['displayName']}: {rs['riskScore']}/100 ({rs['riskLevel']}) — {rs['anomalyCount']} anomalies")

    # 4. Generate user investigation profile (highest risk user)
    print("\n🔍 Stage 4: Generating investigation profile for highest-risk user...")
    top_risk = risk_scores[0] if risk_scores else None
    if top_risk:
        profile = generate_user_profile(top_risk["userId"], baselines, anomalies, risk_scores)
        profile_path = os.path.join(args.output_dir, "investigation-profile.json")
        with open(profile_path, "w") as f:
            json.dump(profile, f, indent=2)
        print(f"   ✅ {profile_path} ({top_risk['displayName']})")

    # 5. Write JSON artifacts
    print("\n💾 Stage 5: Writing artifacts...")
    for name, data in [("baselines.json", baselines_data), ("anomalies.json", anomaly_data), ("risk-scores.json", risk_data)]:
        path = os.path.join(args.output_dir, name)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"   ✅ {path}")

    # 6. Generate HTML report
    print("\n📊 Stage 6: Generating UEBA operations report...")
    html = generate_html(risk_data, anomaly_data, baselines_data)
    report_path = os.path.join(args.output_dir, "ueba-report.html")
    with open(report_path, "w") as f:
        f.write(html)
    print(f"   ✅ {report_path}")

    # Summary
    print(f"\n{'=' * 50}")
    print(f"📊 UEBA Demo Summary")
    print(f"{'=' * 50}")
    print(f"   Users baselined:        {len(baselines)}")
    print(f"   Anomalies detected:     {len(anomalies)}")
    print(f"   ├─ Critical:            {by_severity.get('critical', 0)}")
    print(f"   ├─ High:                {by_severity.get('high', 0)}")
    print(f"   ├─ Medium:              {by_severity.get('medium', 0)}")
    print(f"   └─ Low:                 {by_severity.get('low', 0)}")
    print(f"   Risk scores:")
    print(f"   ├─ Critical risk users: {risk_data['criticalRisk']}")
    print(f"   ├─ High risk users:     {risk_data['highRisk']}")
    print(f"   └─ Medium risk users:   {risk_data['mediumRisk']}")
    print(f"   Categories:             {', '.join(by_category.keys())}")
    print(f"\n   📄 Report: {report_path}")


if __name__ == "__main__":
    main()
