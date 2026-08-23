"""
AuthTime — Top-Level Execution Launcher & Demonstration Suite.
"""

import sys
import os

src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

import time
import threading
import asyncio
import uvicorn

from app.main import app as fastapi_app
from authtime.controller.experiment import ExperimentController
from authtime.scenarios.generator import ScenarioGenerator
from authtime.reporting.generator import ReportGenerator


def start_server_in_thread(host: str = "127.0.0.1", port: int = 8000):
    import httpx
    try:
        r = httpx.get(f"http://{host}:{port}/faults/reset", timeout=1.0)
        print(f"[*] Target server already running on http://{host}:{port}.", flush=True)
        return None
    except Exception:
        pass

    config = uvicorn.Config(app=fastapi_app, host=host, port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.5)
    return server


async def run_demo_experiment():
    print("[*] AuthTime — Temporal Authorization Attack & Verification Engine", flush=True)
    print("[*] Starting local reference target application on http://127.0.0.1:8000...", flush=True)

    server = start_server_in_thread()

    target_url = "http://127.0.0.1:8000"
    controller = ExperimentController(target_url)

    print("\n[*] Executing Demonstration Experiment Scenario ('stale_cache', time_scale=0.1)...", flush=True)
    scenario = ScenarioGenerator.generate_single_fault_scenario(
        fault_type="stale_cache", target_user_id="admin1", time_scale_factor=0.1
    )

    results = []
    repetitions = 3
    for i in range(repetitions):
        exp_id = f"EXP-DEMO-{int(time.time())}-{i+1}"
        res = await controller.run_single_trial(exp_id, scenario)
        results.append(res)
        print(f"  [+] Trial {i+1}/{repetitions} Complete: Exposure={res.exposure_metrics.estimated_exposure_sec:.2f}s, Severity={res.finding.severity_score:.1f} ({res.finding.severity_label})", flush=True)

    stats = controller.aggregate_trial_statistics(results)
    last_res = results[-1]

    os.makedirs("reports", exist_ok=True)
    md_content = ReportGenerator.generate_markdown_report(last_res, stats)
    html_content = ReportGenerator.generate_html_report(last_res, stats)
    json_content = ReportGenerator.generate_json_report(last_res, stats)
    poc_path = ReportGenerator.generate_poc_script(last_res, "reports/poc")

    sample_md = "reports/sample_report.md"
    sample_html = "reports/sample_report.html"
    results_json = "reports/results.json"

    with open(sample_md, "w", encoding="utf-8") as f:
        f.write(md_content)

    with open(sample_html, "w", encoding="utf-8") as f:
        f.write(html_content)

    with open(results_json, "w", encoding="utf-8") as f:
        f.write(json_content)

    print("\n[+] Demonstration Complete! Reports successfully generated:", flush=True)
    print(f"    - Sample Markdown: {sample_md}", flush=True)
    print(f"    - Sample HTML:     {sample_html}", flush=True)
    print(f"    - Machine JSON:    {results_json}", flush=True)
    print(f"    - Standalone PoC:  {poc_path}\n", flush=True)

    print(f"Headline Finding:", flush=True)
    print(f"  Revoked admin access remained exploitable for {last_res.exposure_metrics.estimated_exposure_sec:.1f}s ± {last_res.exposure_metrics.precision_sec:.1f}s due to authorization cache staleness.", flush=True)
    print(f"  Severity Score: {last_res.finding.severity_score:.1f} / 10.0 ({last_res.finding.severity_label})", flush=True)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage: python run.py")
        print("Executes local target server and runs standard AuthTime demonstration experiment.")
        sys.exit(0)

    asyncio.run(run_demo_experiment())


if __name__ == "__main__":
    main()
