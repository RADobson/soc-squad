#!/usr/bin/env python3
"""SOC Squad — Unified Orchestrator

Runs all 4 SOC bots in sequence and generates a combined demo dashboard.
Usage: python3 run_all.py [--output-dir /tmp/soc-demo]
"""

import json
import os
import subprocess
import sys
from datetime import datetime

SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "skills")

BOTS = [
    {
        "name": "XDR Bot",
        "icon": "🛡️",
        "slug": "xdr",
        "script": os.path.join(SKILLS_DIR, "soc-xdr", "scripts", "xdr_demo.py"),
        "report": "xdr-report.html",
        "desc": "Multi-source alert triage, cross-product correlation, automated response",
    },
    {
        "name": "SIEM Bot",
        "icon": "📊",
        "slug": "siem",
        "script": os.path.join(SKILLS_DIR, "soc-siem", "scripts", "siem_demo.py"),
        "report": "siem-report.html",
        "desc": "Analytics rules audit, log source inventory, threat hunting engine",
    },
    {
        "name": "SOAR Bot",
        "icon": "⚡",
        "slug": "soar",
        "script": os.path.join(SKILLS_DIR, "soc-soar", "scripts", "soar_demo.py"),
        "report": "soar-report.html",
        "desc": "Automated playbooks, incident lifecycle, SLA tracking",
    },
    {
        "name": "UEBA Bot",
        "icon": "🔍",
        "slug": "ueba",
        "script": os.path.join(SKILLS_DIR, "soc-ueba", "scripts", "ueba_demo.py"),
        "report": "ueba-report.html",
        "desc": "Behavioral baselines, anomaly detection, insider threat risk scoring",
    },
]


def run_bot(bot: dict, output_dir: str) -> dict:
    """Run a single bot demo and return result metadata."""
    bot_dir = os.path.join(output_dir, bot["slug"])
    os.makedirs(bot_dir, exist_ok=True)
    start = datetime.now()

    try:
        result = subprocess.run(
            [sys.executable, bot["script"], "--output-dir", bot_dir],
            capture_output=True, text=True, timeout=120,
        )
        elapsed = (datetime.now() - start).total_seconds()
        report_path = os.path.join(bot_dir, bot["report"])
        return {
            **bot,
            "status": "success" if result.returncode == 0 else "error",
            "elapsed": round(elapsed, 1),
            "report_exists": os.path.exists(report_path),
            "report_path": report_path,
            "output": result.stdout[-500:] if result.stdout else "",
            "error": result.stderr[-300:] if result.returncode != 0 else "",
        }
    except Exception as e:
        return {**bot, "status": "error", "elapsed": 0, "report_exists": False, "error": str(e)}


def generate_dashboard(results: list, output_dir: str) -> str:
    """Generate unified HTML dashboard linking all bot reports."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S AEST")
    succeeded = sum(1 for r in results if r["status"] == "success")
    total_time = sum(r.get("elapsed", 0) for r in results)

    bot_cards = ""
    for r in results:
        status_badge = (
            '<span style="background:#22c55e;color:#fff;padding:2px 10px;border-radius:12px;font-size:13px;">✅ Success</span>'
            if r["status"] == "success"
            else '<span style="background:#ef4444;color:#fff;padding:2px 10px;border-radius:12px;font-size:13px;">❌ Error</span>'
        )
        report_link = (
            f'<a href="{r["slug"]}/{r["report"]}" style="color:#60a5fa;text-decoration:none;font-weight:600;">View Report →</a>'
            if r.get("report_exists")
            else '<span style="color:#6b7280;">No report</span>'
        )
        bot_cards += f"""
        <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;display:flex;flex-direction:column;gap:12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <h3 style="margin:0;color:#f8fafc;font-size:20px;">{r['icon']} {r['name']}</h3>
                {status_badge}
            </div>
            <p style="color:#94a3b8;margin:0;font-size:14px;">{r['desc']}</p>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-top:auto;">
                {report_link}
                <span style="color:#64748b;font-size:13px;">⏱️ {r.get('elapsed', 0)}s</span>
            </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Squad — Operations Dashboard</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0f172a; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; min-height: 100vh; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 24px; }}
  .hero {{ text-align: center; margin-bottom: 48px; }}
  .hero h1 {{ font-size: 36px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 8px; }}
  .hero p {{ color: #94a3b8; font-size: 16px; }}
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
  .stat {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 20px; text-align: center; }}
  .stat .num {{ font-size: 28px; font-weight: 700; color: #f8fafc; }}
  .stat .label {{ color: #64748b; font-size: 13px; margin-top: 4px; }}
  .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }}
  .footer {{ text-align: center; margin-top: 48px; color: #475569; font-size: 13px; }}
  .footer a {{ color: #3b82f6; text-decoration: none; }}
  @media (max-width: 700px) {{ .stats, .grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="container">
  <div class="hero">
    <h1>🔮 SOC Squad — Operations Dashboard</h1>
    <p>Autonomous Security Operations Centre • Generated {now}</p>
  </div>
  <div class="stats">
    <div class="stat"><div class="num">{len(results)}</div><div class="label">Bots</div></div>
    <div class="stat"><div class="num">{succeeded}/{len(results)}</div><div class="label">Healthy</div></div>
    <div class="stat"><div class="num">{total_time:.1f}s</div><div class="label">Total Runtime</div></div>
    <div class="stat"><div class="num">24/7</div><div class="label">Coverage</div></div>
  </div>
  <div class="grid">
    {bot_cards}
  </div>
  <div class="footer">
    <p>SOC Squad by <a href="https://dobsondevelopment.com.au">Dobson Development</a> — Powered by OpenClaw + Microsoft Defender XDR + Sentinel</p>
  </div>
</div>
</body>
</html>"""
    return html


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SOC Squad — Run all bots")
    parser.add_argument("--output-dir", default="/tmp/soc-demo", help="Output directory")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("🔮 SOC Squad — Unified Orchestrator")
    print("=" * 55)
    print(f"   Output: {args.output_dir}")
    print(f"   Bots:   {len(BOTS)}")
    print()

    results = []
    for bot in BOTS:
        print(f"{'─' * 55}")
        print(f"▶ Running {bot['icon']} {bot['name']}...")
        r = run_bot(bot, args.output_dir)
        results.append(r)
        if r["status"] == "success":
            print(f"  ✅ Complete ({r['elapsed']}s)")
        else:
            print(f"  ❌ Failed: {r.get('error', 'unknown')[:100]}")

    # Write run metadata
    meta = {
        "generatedAt": datetime.now().isoformat(),
        "bots": [{k: v for k, v in r.items() if k not in ("output",)} for r in results],
        "summary": {
            "total": len(results),
            "succeeded": sum(1 for r in results if r["status"] == "success"),
            "failed": sum(1 for r in results if r["status"] != "success"),
            "totalSeconds": round(sum(r.get("elapsed", 0) for r in results), 1),
        },
    }
    meta_path = os.path.join(args.output_dir, "run-metadata.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    # Generate dashboard
    dashboard_html = generate_dashboard(results, args.output_dir)
    dashboard_path = os.path.join(args.output_dir, "dashboard.html")
    with open(dashboard_path, "w") as f:
        f.write(dashboard_html)

    # Summary
    print(f"\n{'=' * 55}")
    print(f"🔮 SOC Squad Run Complete")
    print(f"{'=' * 55}")
    for r in results:
        status = "✅" if r["status"] == "success" else "❌"
        print(f"   {status} {r['icon']} {r['name']} ({r.get('elapsed', 0)}s)")
    print(f"\n   📊 Dashboard: {dashboard_path}")
    print(f"   📄 Metadata:  {meta_path}")


if __name__ == "__main__":
    main()
