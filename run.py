"""
AuthTime — Top-Level Main Engine Launcher & Execution Controller.
"""

import sys
import os

src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import time
import argparse
import threading
import asyncio
import importlib

# Dynamic module imports to bypass static IDE interpreter mismatch
try:
    uvicorn_mod = importlib.import_module("uvicorn")
except Exception:
    uvicorn_mod = None

try:
    httpx_mod = importlib.import_module("httpx")
except Exception:
    httpx_mod = None

from app.main import app as fastapi_app
from authtime.controller.experiment import ExperimentController
from authtime.scenarios.generator import ScenarioGenerator
from authtime.reporting.generator import ReportGenerator
from authtime.history.tracker import ExposureHistoryTracker


import webbrowser

from urllib.parse import urlparse

def start_server_in_thread(host: str = "127.0.0.1", port: int = 8000):
    url = f"http://{host}:{port}"
    if httpx_mod is not None:
        try:
            r = httpx_mod.get(f"{url}/target/identity", timeout=1.0)
            if r.status_code == 200:
                print(f"[*] Target server & Web Control Center active on {url}", flush=True)
                return None
        except Exception:
            pass

    print(f"[*] Launching local reference target server & Web Control Center on {url}...", flush=True)
    if uvicorn_mod is not None:
        config = uvicorn_mod.Config(app=fastapi_app, host=host, port=port, log_level="error")
        server = uvicorn_mod.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        
        # Exponential backoff readiness polling
        for _ in range(15):
            time.sleep(0.2)
            if httpx_mod is not None:
                try:
                    r = httpx_mod.get(f"{url}/target/identity", timeout=0.5)
                    if r.status_code == 200:
                        break
                except Exception:
                    pass
        return server
    return None




async def run_experiment(
    mode: str = "main",
    fault_type: str = "stale_cache",
    time_scale: float = 1.0,
    repetitions: int = 3,
    target_url: str = "http://127.0.0.1:8000",
    no_wait: bool = False,
):

    print("=" * 70, flush=True)
    print(" [AuthTime Main Temporal Authorization Verification Engine]", flush=True)
    print("=" * 70, flush=True)

    from authtime.network.safety import validate_and_resolve_loopback
    is_ok, resolved_ip, err = validate_and_resolve_loopback(target_url)
    if not is_ok:
        print(f"[FATAL SAFETY ERROR] Target URL '{target_url}' safety violation: {err}", file=sys.stderr)
        sys.exit(1)


    start_server_in_thread()

    controller = ExperimentController(target_url)

    mode_label = "MAIN FULL-TIMING MODE" if mode == "main" else "ACCELERATED DEMO MODE"
    print(f"\n[*] Execution Mode: [{mode_label}]", flush=True)
    print(f"[*] Scenario: '{fault_type}' | Time Scale: {time_scale}x | Repetitions: {repetitions}", flush=True)

    if fault_type == "cross_user_isolation":
        scenario = ScenarioGenerator.generate_cross_user_isolation_scenario(
            user_a_id="admin1", user_b_id="user1", time_scale_factor=time_scale
        )
    else:
        scenario = ScenarioGenerator.generate_single_fault_scenario(
            fault_type=fault_type, target_user_id="admin1", time_scale_factor=time_scale
        )

    results = []
    for i in range(repetitions):
        exp_id = f"EXP-MAIN-{int(time.time())}-{i+1}"
        res = await controller.run_single_trial(exp_id, scenario)
        results.append(res)
        exp_disp = f"{res.exposure_metrics.estimated_exposure_sec:.2f}s" if res.exposure_metrics.estimated_exposure_sec is not None else f"≥{res.exposure_metrics.exposure_interval_min_sec:.2f}s (Censored)"
        print(
            f"  [+] Trial {i+1}/{repetitions} Complete: Exposure={exp_disp}, "
            f"Severity={res.finding.severity_score:.1f} ({res.finding.severity_label})",
            flush=True,
        )


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

    tracker = ExposureHistoryTracker()
    tracker.record_run(last_res)

    print("\n[+] Verification Engine Complete! Output files generated:", flush=True)
    print(f"    - Markdown Report: {sample_md}", flush=True)
    print(f"    - HTML Report:     {sample_html}", flush=True)
    print(f"    - Machine JSON:    {results_json}", flush=True)
    print(f"    - Standalone PoC:  {poc_path}\n", flush=True)

    exp_val = (
        f"{last_res.exposure_metrics.estimated_exposure_sec:.1f}s"
        if last_res.exposure_metrics.estimated_exposure_sec is not None
        else f"≥ {last_res.exposure_metrics.exposure_interval_min_sec:.1f}s (RIGHT-CENSORED LOWER BOUND)"
    )
    prec_str = f"± {last_res.exposure_metrics.precision_sec:.1f}s" if last_res.exposure_metrics.precision_sec is not None else ""
    print(
        f"  Revoked admin access remained exploitable for "
        f"{exp_val} {prec_str} due to authorization cache staleness.",
        flush=True,
    )
    print(f"  Severity Score: {last_res.finding.severity_score:.1f} / 10.0 ({last_res.finding.severity_label})\n", flush=True)


    print("=" * 70, flush=True)

    if not no_wait:
        print("[🌐] Web Control Center is ACTIVE and LISTENING at http://127.0.0.1:8000", flush=True)
        print("[*] You can test endpoints, run live experiments, and view history directly in your browser.", flush=True)
        print("[*] Press Ctrl+C in this terminal to stop the server.\n", flush=True)

        try:
            while True:
                await asyncio.sleep(1)
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\n[*] Shutting down AuthTime Web Control Center.", flush=True)


def main():
    parser = argparse.ArgumentParser(description="AuthTime — Main Engine Launcher")
    parser.add_argument("--demo", action="store_true", help="Run fast 10x accelerated demonstration mode (time_scale=0.1)")
    parser.add_argument("--main", action="store_true", help="Run full main engine mode (time_scale=1.0, default)")
    parser.add_argument("--fault-type", type=str, default="stale_cache", help="Fault scenario type")
    parser.add_argument("--time-scale", type=float, default=None, help="Custom time scale factor")
    parser.add_argument("--repetitions", type=int, default=3, help="Number of trial repetitions")
    parser.add_argument("--target-url", type=str, default="http://127.0.0.1:8000", help="Target server URL")
    parser.add_argument("--no-wait", action="store_true", help="Exit immediately after experiment execution without keeping server process alive")

    args = parser.parse_args()

    if args.demo:
        mode = "demo"
        time_scale = args.time_scale if args.time_scale is not None else 0.1
    else:
        mode = "main"
        time_scale = args.time_scale if args.time_scale is not None else 1.0

    asyncio.run(
        run_experiment(
            mode=mode,
            fault_type=args.fault_type,
            time_scale=time_scale,
            repetitions=args.repetitions,
            target_url=args.target_url,
            no_wait=args.no_wait,
        )
    )



if __name__ == "__main__":
    main()

