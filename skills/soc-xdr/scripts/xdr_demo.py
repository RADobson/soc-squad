#!/usr/bin/env python3
"""Full XDR demo pipeline: multi-source alerts → triage → cross-product correlation → response → HTML report."""

import json
import os
import sys
from datetime import datetime

# Add script dir to path
sys.path.insert(0, os.path.dirname(__file__))

from xdr_alerts import generate_demo_alerts, triage_alert
from xdr_response import demo_response_actions
from xdr_correlator import correlate
import importlib.util

_spec = importlib.util.spec_from_file_location("xdr_report", os.path.join(os.path.dirname(__file__), "xdr_report.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
generate_html = _mod.generate_html


def main():
    import argparse
    p = argparse.ArgumentParser(description="Generate full XDR demo artifacts")
    p.add_argument("--output-dir", default="/tmp/soc-demo/xdr", help="Output directory")
    args = p.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("🛡️  SOC Squad — XDR Bot Demo Pipeline")
    print("=" * 50)

    # 1. Generate multi-source demo alerts
    print("\n📡 Stage 1: Ingesting alerts from all XDR sources...")
    raw_alerts = generate_demo_alerts()
    triaged = [triage_alert(a) for a in raw_alerts]
    triaged.sort(key=lambda x: x["priority"], reverse=True)

    actions_summary = {}
    source_breakdown = {}
    for t in triaged:
        actions_summary[t["action"]] = actions_summary.get(t["action"], 0) + 1
        source_breakdown[t["source"]] = source_breakdown.get(t["source"], 0) + 1

    alerts_data = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "alertCount": len(raw_alerts),
        "summary": actions_summary,
        "sourceBreakdown": source_breakdown,
        "triaged": triaged,
    }

    for src, count in sorted(source_breakdown.items()):
        print(f"   {src}: {count} alerts")

    # 2. Cross-product correlation
    print("\n🔗 Stage 2: Cross-product incident correlation...")
    incidents = correlate(triaged)
    cross_product = len([i for i in incidents if i["isCrossProduct"]])
    attack_chains = len([i for i in incidents if i["isAttackChain"]])
    pattern_matches = sum(len(i["matchedPatterns"]) for i in incidents)

    incidents_data = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "incidentCount": len(incidents),
        "crossProductIncidents": cross_product,
        "attackChains": attack_chains,
        "patternMatches": pattern_matches,
        "incidents": incidents,
    }

    # 3. Automated response
    print("\n⚡ Stage 3: Automated response engine...")
    response_actions = demo_response_actions()
    actions_data = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "actions": response_actions,
        "summary": {
            "total": len(response_actions),
            "auto_executed": len([a for a in response_actions if not a.get("requiresApproval")]),
            "escalated": len([a for a in response_actions if a.get("requiresApproval")]),
        },
    }

    # 4. Write JSON artifacts
    print("\n💾 Stage 4: Writing artifacts...")
    for name, data in [("alerts.json", alerts_data), ("incidents.json", incidents_data), ("actions.json", actions_data)]:
        path = os.path.join(args.output_dir, name)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"   ✅ {path}")

    # 5. Generate HTML report
    print("\n📊 Stage 5: Generating XDR operations report...")
    html = generate_html(alerts_data, incidents_data, actions_data)
    report_path = os.path.join(args.output_dir, "xdr-report.html")
    with open(report_path, "w") as f:
        f.write(html)
    print(f"   ✅ {report_path}")

    # Summary
    print(f"\n{'=' * 50}")
    print(f"📊 XDR Demo Summary")
    print(f"{'=' * 50}")
    print(f"   Total alerts:           {len(raw_alerts)}")
    print(f"   ├─ 🖥️  MDE (Endpoint):   {source_breakdown.get('MDE', 0)}")
    print(f"   ├─ 📧 MDO (Email):       {source_breakdown.get('MDO', 0)}")
    print(f"   ├─ 🔑 MDI (Identity):    {source_breakdown.get('MDI', 0)}")
    print(f"   └─ ☁️  MDA (Cloud Apps):  {source_breakdown.get('MDA', 0)}")
    print(f"   Auto-resolved FPs:      {actions_summary.get('auto_resolve', 0)}")
    print(f"   Escalated:              {actions_summary.get('escalate_immediate', 0) + actions_summary.get('escalate', 0)}")
    print(f"   Incidents:              {len(incidents)}")
    print(f"   ├─ Attack chains:       {attack_chains}")
    print(f"   ├─ Cross-product:       {cross_product}")
    print(f"   └─ Pattern matches:     {pattern_matches}")
    print(f"   Response actions:       {len(response_actions)}")
    print(f"   ├─ Auto-executed:       {actions_data['summary']['auto_executed']}")
    print(f"   └─ Escalated:           {actions_data['summary']['escalated']}")
    print(f"\n   📄 Report: {report_path}")


if __name__ == "__main__":
    main()
