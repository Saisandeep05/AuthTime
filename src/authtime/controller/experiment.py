"""
Experiment Controller & Statistical Aggregator.

Orchestrates baseline verification, fault injection, timed probing, adaptive refinement,
event correlation, exposure metrics computation, and trial statistical aggregation.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta

from urllib.parse import urlparse
import time
import asyncio
import statistics
import math
import httpx

from app.config import settings
from authtime.models.schemas import (
    ExperimentResult,
    ProbeResult,
    ExposureMetric,
    SecurityFinding,
)
from authtime.ground_truth.manager import ground_truth_manager
from authtime.fault_injector.client import FaultInjectorClient
from authtime.events.collector import EventCollector
from authtime.scenarios.generator import ScenarioGenerator, Scenario
from authtime.timing.clock import measure_scheduler_jitter
from authtime.verification.harness import VerificationHarness
from authtime.verification.adaptive_prober import AdaptiveProber
from authtime.verification.root_cause import RootCauseAnalyzer
from authtime.reporting.generator import compute_severity_score


class ExperimentController:
    def __init__(self, target_url: Optional[str] = None, http_client: Optional[httpx.AsyncClient] = None):
        self.target_url = target_url or f"http://{settings.TARGET_HOST}:{settings.TARGET_PORT}"
        self._enforce_safety_boundary()
        self.fault_injector = FaultInjectorClient(self.target_url, http_client=http_client)
        self.event_collector = EventCollector(self.target_url, http_client=http_client)

    def _enforce_safety_boundary(self):
        parsed = urlparse(self.target_url)
        hostname = parsed.hostname or ""
        if hostname not in ("127.0.0.1", "localhost", "::1", "testclient"):
            raise ValueError(
                f"SAFETY VIOLATION: ExperimentController target URL '{self.target_url}' "
                f"is not a local loopback address (127.0.0.1 / localhost)."
            )

    async def verify_baseline(
        self,
        user_id: str = "admin1",
        resource_path: str = "/admin/users",
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> bool:
        close_client = False
        client = http_client or self.fault_injector._shared_client
        if client is None:
            client = httpx.AsyncClient()
            close_client = True

        try:
            await self.fault_injector.reset(http_client=client)
            ground_truth_manager.reset_to_defaults()

            login_resp = await client.post(f"{self.target_url}/auth/login", json={"user_id": user_id})
            if login_resp.status_code != 200:
                return False
            token = login_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}", "X-AuthTime-Request-ID": "baseline-probe"}

            resp = await client.get(f"{self.target_url}{resource_path}", headers=headers)
            expected = ground_truth_manager.get_expected_decision(user_id, resource_path, time.monotonic())
            
            if resp.status_code == 200:
                actual = "ALLOW"
            elif resp.status_code in (401, 403):
                actual = "DENY"
            else:
                actual = "ERROR"

            return expected == actual
        except Exception:
            return False
        finally:
            if close_client and client:
                await client.aclose()

    async def run_single_trial(
        self,
        experiment_id: str,
        scenario: Scenario,
        cache_ttl_seconds: float = 60.0,
        jwt_ttl_seconds: int = 300,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> ExperimentResult:
        self._enforce_safety_boundary()
        close_client = False
        client = http_client or self.fault_injector._shared_client
        if client is None:
            client = httpx.AsyncClient()
            close_client = True

        try:
            baseline_ok = await self.verify_baseline(user_id=scenario.target_user_id, resource_path=scenario.resource_path, http_client=client)
            jitter_ms = await measure_scheduler_jitter(n_probes=10, delay_ms=2.0)

            # ABORT IMMEDIATELY IF BASELINE FAILS
            if not baseline_ok:
                empty_metrics = ExposureMetric(
                    fault_timestamp_monotonic=time.monotonic(),
                    exposure_interval_min_sec=0.0,
                    exposure_interval_max_sec=0.0,
                    estimated_exposure_sec=0.0,
                    precision_sec=0.0,
                    scheduler_jitter_ms=jitter_ms,
                    unauthorized_request_count=0,
                    total_probes_fired=0,
                )
                finding = SecurityFinding(
                    finding_id=f"FIND-{experiment_id}",
                    title="Baseline Verification Failed",
                    fault_type=scenario.fault_type,
                    severity_score=0.0,
                    severity_label="LOW",
                    config_snapshot={"cache_ttl_seconds": cache_ttl_seconds, "jwt_ttl_seconds": jwt_ttl_seconds},
                    time_scale_enabled=(scenario.time_scale_factor != 1.0),
                    time_scale_factor=scenario.time_scale_factor,
                    observed_exposure=empty_metrics,
                    root_cause="TARGET_UNHEALTHY",
                    root_cause_confidence="HIGH",
                    explanation="Baseline health check failed before fault injection. Target server returned non-expected status.",
                    real_world_calibration="N/A",
                    reproduction_curl=f"curl -H 'Authorization: Bearer <token>' {self.target_url}{scenario.resource_path}",
                    poc_script_path=f"reports/poc/{experiment_id}_poc.py",
                )
                return ExperimentResult(
                    experiment_id=experiment_id,
                    created_at_utc=datetime.now(timezone.utc),
                    config={"target_url": self.target_url, "fault_type": scenario.fault_type},
                    baseline_passed=False,
                    probes=[],
                    events=[],
                    exposure_metrics=empty_metrics,
                    finding=finding,
                    summary_stats={"trial_count": 1, "mean_exposure_sec": 0.0},
                )

            login_resp = await client.post(
                f"{self.target_url}/auth/login",
                json={"user_id": scenario.target_user_id, "ttl_seconds": int(jwt_ttl_seconds * scenario.time_scale_factor)}
            )
            token_a = login_resp.json()["access_token"]
            headers_a = {"Authorization": f"Bearer {token_a}"}

            headers_b = None
            if scenario.secondary_user_id:
                login_b = await client.post(
                    f"{self.target_url}/auth/login",
                    json={"user_id": scenario.secondary_user_id, "ttl_seconds": int(jwt_ttl_seconds * scenario.time_scale_factor)}
                )
                token_b = login_b.json()["access_token"]
                headers_b = {"Authorization": f"Bearer {token_b}"}

            t_send = time.monotonic()
            fault_res = await self.fault_injector.inject_fault(
                fault_type=scenario.fault_type,
                user_id=scenario.target_user_id,
                secondary_user_id=scenario.secondary_user_id,
                new_role="User",
                cache_ttl_seconds=cache_ttl_seconds,
                time_scale_factor=scenario.time_scale_factor,
                experiment_id=experiment_id,
                http_client=client,
            )



            t_fault = fault_res.get("fault_applied_monotonic") or t_send

            ground_truth_manager.record_fault_event(
                fault_type=scenario.fault_type,
                user_id=scenario.target_user_id,
                timestamp_monotonic=t_fault,
                new_role="User"
            )

            probes: List[ProbeResult] = []
            has_cross_user_collision = False

            for probe_spec in scenario.probes:
                target_offset = probe_spec.offset_seconds
                now = time.monotonic()
                elapsed_since_fault = now - t_fault
                if target_offset > elapsed_since_fault:
                    await asyncio.sleep(target_offset - elapsed_since_fault)

                probe_t = time.monotonic()
                utc_now = datetime.now(timezone.utc)
                req_id = f"probe-{experiment_id}-{probe_spec.probe_index}"

                curr_headers = dict(headers_b if probe_spec.user_id == scenario.secondary_user_id else headers_a)
                curr_headers["X-AuthTime-Request-ID"] = req_id
                curr_headers["X-AuthTime-Experiment-ID"] = experiment_id
                curr_headers["X-AuthTime-Trial-ID"] = f"{experiment_id}-trial"

                p_start = time.monotonic()
                try:
                    res = await client.get(f"{self.target_url}{probe_spec.resource_path}", headers=curr_headers)
                    status_code = res.status_code
                except Exception:
                    status_code = 500

                lat_ms = (time.monotonic() - p_start) * 1000.0
                if status_code == 200:
                    actual_dec = "ALLOW"
                elif status_code in (401, 403):
                    actual_dec = "DENY"
                else:
                    actual_dec = "ERROR"

                gt_dec = ground_truth_manager.get_expected_decision(probe_spec.user_id, probe_spec.resource_path, probe_t)
                is_violation = (gt_dec == "DENY" and actual_dec == "ALLOW")

                if scenario.fault_type == "cross_user_isolation" and probe_spec.user_id == scenario.secondary_user_id and is_violation:
                    has_cross_user_collision = True

                probes.append(
                    ProbeResult(
                        request_id=req_id,
                        experiment_id=experiment_id,
                        scenario_id=scenario.scenario_id,
                        probe_index=probe_spec.probe_index,
                        offset_target=target_offset,
                        monotonic_timestamp=probe_t,
                        utc_timestamp=utc_now,
                        http_status=status_code,
                        actual_decision=actual_dec,
                        ground_truth_decision=gt_dec,
                        is_violation=is_violation,
                        response_latency_ms=lat_ms,
                    )
                )

            if scenario.fault_type == "token_expiry":
                total_window_sec = jwt_ttl_seconds * scenario.time_scale_factor
            else:
                total_window_sec = cache_ttl_seconds * scenario.time_scale_factor

            adaptive = AdaptiveProber(target_ms=100.0, max_depth=10)
            metrics = VerificationHarness.calculate_exposure_metrics(t_fault, probes, jitter_ms, 100.0, total_window_sec=total_window_sec)

            if metrics.last_unauth_monotonic and metrics.first_blocked_monotonic:
                target_user = scenario.secondary_user_id if (scenario.fault_type == "cross_user_isolation" and scenario.secondary_user_id) else scenario.target_user_id
                base_headers = dict(headers_b if (scenario.fault_type == "cross_user_isolation" and headers_b) else headers_a)
                utc_fault_start = datetime.now(timezone.utc)

                async def adaptive_probe_func(offset_sec: float):
                    target_time = t_fault + offset_sec
                    now_t = time.monotonic()
                    if target_time > now_t:
                        await asyncio.sleep(target_time - now_t)
                    p_start = time.monotonic()
                    req_id = f"probe-{experiment_id}-adaptive-{int(offset_sec * 1000)}"
                    curr_h = dict(base_headers)
                    curr_h["X-AuthTime-Request-ID"] = req_id
                    curr_h["X-AuthTime-Experiment-ID"] = experiment_id
                    curr_h["X-AuthTime-Trial-ID"] = f"{experiment_id}-trial"
                    try:
                        r = await client.get(f"{self.target_url}{scenario.resource_path}", headers=curr_h)
                        st = r.status_code
                        lat = (time.monotonic() - p_start) * 1000.0
                        actual_t = time.monotonic()
                        dec_str = "ALLOW" if st == 200 else ("DENY" if st in (401, 403) else "ERROR")
                        return (dec_str, st, lat, actual_t)
                    except Exception:
                        return ("ERROR", 500, 0.0, time.monotonic())

                left_t, right_t, adapt_records = await adaptive.refine_boundary(
                    t_fault, metrics.last_unauth_monotonic, metrics.first_blocked_monotonic, adaptive_probe_func
                )

                # Persist adaptive probes directly into evidence dataset
                for rec in adapt_records:
                    gt_dec = ground_truth_manager.get_expected_decision(target_user, scenario.resource_path, rec["monotonic_timestamp"])
                    is_viol = (gt_dec == "DENY" and rec["actual_decision"] == "ALLOW")
                    offset_delta = rec["monotonic_timestamp"] - t_fault
                    rec_utc = utc_fault_start + timedelta(seconds=max(0.0, offset_delta))
                    probes.append(
                        ProbeResult(
                            request_id=f"probe-{experiment_id}-{rec['probe_index']}",
                            experiment_id=experiment_id,
                            scenario_id=scenario.scenario_id,
                            probe_index=rec["probe_index"],
                            offset_target=rec["offset_target"],
                            monotonic_timestamp=rec["monotonic_timestamp"],
                            utc_timestamp=rec_utc,
                            http_status=rec["http_status"],
                            actual_decision=rec["actual_decision"],
                            ground_truth_decision=gt_dec,
                            is_violation=is_viol,
                            response_latency_ms=rec["latency_ms"],
                        )
                    )

                # Incorporate refined boundary into metrics
                exp_min = left_t - t_fault
                exp_max = right_t - t_fault
                metrics.last_unauth_monotonic = left_t
                metrics.first_blocked_monotonic = right_t
                metrics.exposure_interval_min_sec = exp_min
                metrics.exposure_interval_max_sec = exp_max
                metrics.estimated_exposure_sec = (exp_min + exp_max) / 2.0
                metrics.precision_sec = (right_t - left_t) / 2.0
                metrics.total_probes_fired = len(probes)

            events = await self.event_collector.fetch_evidence_events(experiment_id, http_client=client)

            rc_code, rc_conf, rc_expl = RootCauseAnalyzer.analyze_root_cause(
                scenario.fault_type,
                {"cache_ttl_seconds": cache_ttl_seconds, "jwt_ttl_seconds": jwt_ttl_seconds, "time_scale_factor": scenario.time_scale_factor},
                metrics,
                has_cache_key_collision=has_cross_user_collision,
                events=events,
            )


            sev_score, sev_label = compute_severity_score(metrics, scenario.resource_path, rc_conf)

            finding = SecurityFinding(
                finding_id=f"FIND-{experiment_id}",
                title=f"Authorization Exposure Finding: {rc_code}",
                fault_type=scenario.fault_type,
                severity_score=sev_score,
                severity_label=sev_label,
                config_snapshot={"cache_ttl_seconds": cache_ttl_seconds, "jwt_ttl_seconds": jwt_ttl_seconds},
                time_scale_enabled=(scenario.time_scale_factor != 1.0),
                time_scale_factor=scenario.time_scale_factor,
                observed_exposure=metrics,
                root_cause=rc_code,
                root_cause_confidence=rc_conf,
                explanation=rc_expl,
                real_world_calibration=f"Tested cache_ttl={cache_ttl_seconds}s. Mirrors standard API gateway caching defaults.",
                reproduction_curl=f"curl -H 'Authorization: Bearer <token>' {self.target_url}{scenario.resource_path}",
                poc_script_path=f"reports/{experiment_id}/poc_{experiment_id}.py",
            )

            return ExperimentResult(
                experiment_id=experiment_id,
                created_at_utc=datetime.now(timezone.utc),
                config={"target_url": self.target_url, "fault_type": scenario.fault_type, "cache_ttl": cache_ttl_seconds},
                baseline_passed=baseline_ok,
                probes=probes,
                events=events,
                exposure_metrics=metrics,
                finding=finding,
                summary_stats={"trial_count": 1, "mean_exposure_sec": metrics.estimated_exposure_sec or metrics.exposure_interval_min_sec},
            )
        finally:
            if close_client and client:
                await client.aclose()

    @staticmethod
    def aggregate_trial_statistics(results: List[ExperimentResult]) -> Dict[str, Any]:
        valid_results = [r for r in results if r.baseline_passed]
        if not valid_results:
            return {"trial_count": 0, "message": "No valid trials passed baseline."}

        uncensored = [r for r in valid_results if not r.exposure_metrics.is_censored]
        censored = [r for r in valid_results if r.exposure_metrics.is_censored]

        if uncensored:
            exposures = [r.exposure_metrics.estimated_exposure_sec for r in uncensored if r.exposure_metrics.estimated_exposure_sec is not None]
            mean_exp = statistics.mean(exposures) if exposures else 0.0
            std_exp = statistics.stdev(exposures) if len(exposures) > 1 else 0.0
            min_exp = min(exposures) if exposures else 0.0
            max_exp = max(exposures) if exposures else 0.0
        else:
            all_exp = [r.exposure_metrics.exposure_interval_min_sec for r in valid_results]
            mean_exp = statistics.mean(all_exp)
            std_exp = 0.0
            min_exp = min(all_exp)
            max_exp = max(all_exp)


        severities = [r.finding.severity_score for r in valid_results]

        return {
            "trial_count": len(valid_results),
            "uncensored_trial_count": len(uncensored),
            "censored_trial_count": len(censored),
            "mean_exposure_sec": mean_exp,
            "std_dev_sec": std_exp,
            "min_exposure_sec": min_exp,
            "max_exposure_sec": max_exp,
            "mean_severity_score": statistics.mean(severities),
            "consistent_finding": len(set(r.finding.root_cause for r in valid_results)) == 1,
        }

