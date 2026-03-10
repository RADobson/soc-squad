#!/usr/bin/env python3
"""Full SOAR demo pipeline: playbooks → incidents → report."""

import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from soar_playbooks import generate_demo_executions, PLAYBOOKS
from soar_incidents import generate_demo_incidents, generate_sla_report
import importlib.util

_spec = importlib.util.spec_from_file_location("soar_report", os.path.join(os.path.dirname(__file__), "soar_report.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
generate_html = _mod.generate_html


def main():
    import argparse
    p = argparse.ArgumentParser(description="Generate full SOAR demo artifacts")
    p.add_argument("--output-dir", default="/tmp/soc-demo/soar", help="Output directory")
    args = p.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("⚡ SOC Squad — SOAR Bot Demo Pipeline")
    print("=" * 50)

    # 1. Playbook executions
    print("\n🎭 Stage 1: Playbook executions...")
    executions = generate_demo_executions()
    playbooks_data = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "availablePlaybooks": len(PLAYBOOKS),
        "executionsCount": len(executions),
        "totalSteps": sum(e["stepsExecuted"] for e in executions),
        "escalations": len([e for e in executions if e.get("escalated")]),
        "executions": executions,
    }
    print(f"   Playbooks executed: {len(executions)}")
    print(f"   Total steps: {playbooks_data['totalSteps']}")
    print(f"   Escalations: {playbooks_data['escalations']}")

    # 2. Incident lifecycle
    print("\n📋 Stage 2: Incident lifecycle...")
    incidents = generate_demo_incidents()
    sla_report = generate_sla_report(incidents)
    incidents_data = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "incidentCount": len(incidents),
        "byStatus": {},
        "sla": sla_report,
        "incidents": incidents,
    }
    for inc in incidents:
        s = inc["status"]
        incidents_data["byStatus"][s] = incidents_data["byStatus"].get(s, 0) + 1

    print(f"   Incidents: {len(incidents)}")
    for status, count in incidents_data["byStatus"].items():
        print(f"   ├─ {status}: {count}")

    # 3. Write artifacts
    print("\n💾 Stage 3: Writing artifacts...")
    for name, data in [("playbooks.json", playbooks_data), ("incidents.json", incidents_data)]:
        path = os.path.join(args.output_dir, name)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"   ✅ {path}")

    # 4. Generate HTML report
    print("\n📊 Stage 4: Generating SOAR operations report...")
    html = generate_html(playbooks_data, incidents_data)
    report_path = os.path.join(args.output_dir, "soar-report.html")
    with open(report_path, "w") as f:
        f.write(html)
    print(f"   ✅ {report_path}")

    # Summary
    print(f"\n{'=' * 50}")
    print(f"📊 SOAR Demo Summary")
    print(f"{'=' * 50}")
    print(f"   Available playbooks:    {len(PLAYBOOKS)}")
    print(f"   Playbooks executed:     {len(executions)}")
    print(f"   Total response steps:   {playbooks_data['totalSteps']}")
    print(f"   Incidents managed:      {len(incidents)}")
    print(f"   Escalations:            {playbooks_data['escalations']}")
    print(f"   SLA compliance:")
    for metric, data in sla_report.get("slaCompliance", {}).items():
        print(f"     {metric}: {data.get('compliance', 'N/A')} ({data.get('met', 0)}/{data.get('total', 0)} met)")
    print(f"\n   📄 Report: {report_path}")


if __name__ == "__main__":
    main()
