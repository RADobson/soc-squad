#!/usr/bin/env python3
"""Full SIEM demo pipeline: rules audit → log inventory → threat hunts → HTML report."""

import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from siem_rules import generate_demo_rules, audit_rules, mitre_coverage
from siem_logs import generate_demo_inventory, coverage_gap_analysis, cost_analysis
from siem_hunting import generate_demo_hunt_results
import importlib.util

_spec = importlib.util.spec_from_file_location("siem_report", os.path.join(os.path.dirname(__file__), "siem_report.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
generate_html = _mod.generate_html


def main():
    import argparse
    p = argparse.ArgumentParser(description="Generate full SIEM demo artifacts")
    p.add_argument("--output-dir", default="/tmp/soc-demo/siem", help="Output directory")
    args = p.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("📡 SOC Squad — SIEM Bot Demo Pipeline")
    print("=" * 50)

    # 1. Analytics rules audit
    print("\n📋 Stage 1: Auditing analytics rules...")
    rules = generate_demo_rules()
    rules_audit = audit_rules(rules)
    coverage = mitre_coverage(rules)
    rules_audit["mitreCoverage"] = coverage

    s = rules_audit["summary"]
    print(f"   Total rules: {s['totalRules']} (enabled: {s['enabled']}, disabled: {s['disabled']})")
    print(f"   Healthy: {s['healthy']}, Noisy: {s['noisy']}, Stale: {s['stale']}")
    print(f"   Overall FP rate: {s['overallFPRate']}")
    print(f"   MITRE coverage: {coverage['overallCoverage']} ({coverage['coveredTechniques']}/{coverage['totalKeyTechniques']} key techniques)")

    # 2. Log source inventory
    print("\n🔌 Stage 2: Log source inventory & gap analysis...")
    inventory = generate_demo_inventory()
    gaps = coverage_gap_analysis(inventory)
    costs = cost_analysis(inventory)

    print(f"   Connected sources: {len(inventory['connected'])}")
    print(f"   Missing sources: {len(inventory['missing'])}")
    print(f"   Critical gaps: {len(gaps['criticalGaps'])}")
    print(f"   Daily ingestion: {costs['totalDailyIngestionGB']} GB")
    print(f"   Monthly cost: ${costs['totalMonthlyCostUSD']:,.2f}")

    # 3. Threat hunting
    print("\n🔍 Stage 3: Executing threat hunts...")
    hunt_results = generate_demo_hunt_results()

    hunts_data = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "huntsExecuted": len(hunt_results),
        "totalFindings": sum(h["findingsCount"] for h in hunt_results),
        "confirmedThreats": len([h for h in hunt_results if h["outcome"] == "confirmed_threat"]),
        "suspicious": len([h for h in hunt_results if h["outcome"] == "suspicious"]),
        "clean": len([h for h in hunt_results if h["outcome"] == "clean"]),
        "hunts": hunt_results,
    }

    print(f"   Hunts executed: {hunts_data['huntsExecuted']}")
    print(f"   Findings: {hunts_data['totalFindings']}")
    print(f"   Confirmed threats: {hunts_data['confirmedThreats']}")
    print(f"   Suspicious: {hunts_data['suspicious']}")
    print(f"   Clean: {hunts_data['clean']}")

    # 4. Write JSON artifacts
    print("\n💾 Stage 4: Writing artifacts...")
    artifacts = [
        ("rules.json", rules_audit),
        ("logs.json", inventory),
        ("hunts.json", hunts_data),
        ("coverage.json", coverage),
        ("costs.json", costs),
        ("gaps.json", gaps),
    ]
    for name, data in artifacts:
        path = os.path.join(args.output_dir, name)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"   ✅ {path}")

    # 5. Generate HTML report
    print("\n📊 Stage 5: Generating SIEM operations report...")
    html = generate_html(rules_audit, inventory, hunts_data)
    report_path = os.path.join(args.output_dir, "siem-report.html")
    with open(report_path, "w") as f:
        f.write(html)
    print(f"   ✅ {report_path}")

    # Summary
    print(f"\n{'=' * 50}")
    print(f"📊 SIEM Demo Summary")
    print(f"{'=' * 50}")
    print(f"   Analytics rules:        {s['totalRules']} ({s['healthy']} healthy, {s['noisy']} noisy, {s['disabled']} disabled)")
    print(f"   MITRE ATT&CK coverage:  {coverage['overallCoverage']} ({coverage['gapTechniques']} technique gaps)")
    print(f"   Log sources:            {len(inventory['connected'])} connected, {len(inventory['missing'])} missing")
    print(f"   Critical log gaps:      {len(gaps['criticalGaps'])}")
    print(f"   Sentinel cost:          ${costs['totalMonthlyCostUSD']:,.0f}/month (${costs['totalAnnualCostUSD']:,.0f}/year)")
    print(f"   Threat hunts:           {hunts_data['huntsExecuted']} executed, {hunts_data['totalFindings']} findings")
    print(f"   ├─ Confirmed threats:   {hunts_data['confirmedThreats']}")
    print(f"   ├─ Suspicious:          {hunts_data['suspicious']}")
    print(f"   └─ Clean:               {hunts_data['clean']}")
    print(f"\n   📄 Report: {report_path}")


if __name__ == "__main__":
    main()
