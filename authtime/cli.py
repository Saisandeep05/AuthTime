"""
Command-Line Interface (CLI) for AuthTime Engine.
"""

import argparse
import sys
import os
import json
import asyncio
import uvicorn
from typing import Optional

from app.config import settings
from authtime.controller.experiment import ExperimentController
from authtime.scenarios.generator import ScenarioGenerator
from authtime.reporting.generator import ReportGenerator


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authtime",
        description="AuthTime — Temporal Authorization Attack & Verification Engine",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command: run
    run_parser = subparsers.add_parser("run", help="Run authorization exposure experiment scenario.")
    run_parser.add_argument("--fault-type", type=str, default="stale_cache", help="Fault type (stale_cache, role_revocation, token_expiry, agent_session_revocation, cross_user_isolation).")
    run_parser.add_argument("--target-url", type=str, default="http://127.0.0.1:8000", help="Target URL (must be 127.0.0.1 or localhost).")
    run_parser.add_argument("--time-scale", type=float, default=1.0, help="Time scaling factor (e.g. 0.1 for 10x accelerated execution).")
    run_parser.add_argument("--repetitions", type=int, default=1, help="Number of trial repetitions.")
    run_parser.add_argument("--output-dir", type=str, default="reports", help="Directory to save generated reports.")

    # Command: report
    report_parser = subparsers.add_parser("report", help="Regenerate reports from saved JSON experiment result.")
    report_parser.add_argument("--input", type=str, required=True, help="Path to input result JSON file.")
    report_parser.add_argument("--format", type=str, choices=["markdown", "json"], default="markdown", help="Report output format.")

    # Command: target
    target_parser = subparsers.add_parser("target", help="Manage reference application target.")
    target_sub = target_parser.add_subparsers(dest="target_action", required=True)
    start_parser = target_sub.add_parser("start", help="Start local reference target server.")
    start_parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address (must be 127.0.0.1).")
    start_parser.add_argument("--port", type=int, default=8000, help="Port number.")

    return parser


async def async_run_command(args):
    # Safety Check
    if "127.0.0.1" not in args.target_url and "localhost" not in args.target_url:
        print(f"[FATAL SAFETY ERROR] Target URL '{args.target_url}' is non-local! AuthTime local testing is restricted to 127.0.0.1 / localhost.", file=sys.stderr)
        sys.exit(1)

    controller = ExperimentController(args.target_url)

    if args.fault_type == "cross_user_isolation":
        scenario = ScenarioGenerator.generate_cross_user_isolation_scenario(
            user_a_id="admin1", user_b_id="user1", time_scale_factor=args.time_scale
        )
    else:
        scenario = ScenarioGenerator.generate_single_fault_scenario(
            fault_type=args.fault_type, target_user_id="admin1", time_scale_factor=args.time_scale
        )

    results = []
    print(f"[*] Executing AuthTime Experiment Scenario '{scenario.scenario_id}' ({args.repetitions} repetitions, scale={args.time_scale})...")

    for i in range(args.repetitions):
        exp_id = f"EXP-{int(asyncio.get_event_loop().time())}-{i+1}"
        res = await controller.run_single_trial(exp_id, scenario)
        results.append(res)
        print(f"  [+] Trial {i+1}/{args.repetitions} Complete: Exposure={res.exposure_metrics.estimated_exposure_sec:.2f}s, Severity={res.finding.severity_score:.1f} ({res.finding.severity_label})")

    stats = controller.aggregate_trial_statistics(results)
    last_res = results[-1]

    os.makedirs(args.output_dir, exist_ok=True)
    md_content = ReportGenerator.generate_markdown_report(last_res, stats)
    json_content = ReportGenerator.generate_json_report(last_res, stats)
    poc_path = ReportGenerator.generate_poc_script(last_res, os.path.join(args.output_dir, "poc"))

    md_path = os.path.join(args.output_dir, f"{last_res.experiment_id}_report.md")
    json_path = os.path.join(args.output_dir, f"{last_res.experiment_id}_result.json")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    with open(json_path, "w", encoding="utf-8") as f:
        f.write(json_content)

    print(f"\n[+] Execution Complete!")
    print(f"    - Markdown Report: {md_path}")
    print(f"    - JSON Result:     {json_path}")
    print(f"    - Standalone PoC:  {poc_path}")


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "run":
        asyncio.run(async_run_command(args))

    elif args.command == "report":
        if not os.path.exists(args.input):
            print(f"[ERROR] Input file '{args.input}' not found.", file=sys.stderr)
            sys.exit(1)
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
            print(json.dumps(data, indent=2))

    elif args.command == "target":
        if args.target_action == "start":
            if args.host not in ("127.0.0.1", "localhost"):
                print(f"[FATAL SAFETY ERROR] Host '{args.host}' is not local loopback!", file=sys.stderr)
                sys.exit(1)
            print(f"[*] Starting AuthTime Reference Target on {args.host}:{args.port}...")
            uvicorn.run("app.main:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
