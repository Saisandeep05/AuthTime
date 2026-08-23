"""
AuthTime Experiment Controller & Verification Coordinator.
"""

import asyncio
import hashlib
import json
import os
import sys
import statistics
import time
import uuid
from typing import List, Dict, Any, Optional, Literal
from datetime import datetime, timezone, timedelta

import httpx

from authtime.constants import CURRENT_PROTOCOL_VERSION, CURRENT_SCHEMA_VERSION
from authtime.fault_injector.client import FaultInjectorClient
from authtime.events.collector import EventCollector
from authtime.scenarios.generator import Scenario, ScenarioProbeSpec

from authtime.verification.harness import VerificationHarness, measure_scheduler_jitter
from authtime.verification.adaptive_prober import AdaptiveProber
from authtime.verification.predicate import evaluate_http_decision, evaluate_authorization_violation
from authtime.verification.root_cause import RootCauseAnalyzer
from authtime.reporting.generator import compute_severity_score
from authtime.models.schemas import (
    ExperimentResult,
    ProbeResult,
    ExposureMetric,
    SecurityFinding,
    EvidenceEvent,
    SeverityLabel,
    GroundTruthDecision,
)
from authtime.ground_truth.manager import ground_truth_manager


class ExperimentController:
    def __init__(
        self,
        target_url: str = "http://127.0.0.1:8000",
        fault_injector: Optional[FaultInjectorClient] = None,
        event_collector: Optional[EventCollector] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self._enforce_safety_boundary()
        self.fault_injector = fault_injector or FaultInjectorClient(self.target_url, http_client=http_client)
        self.event_collector = event_collector or EventCollector(self.target_url, http_client=http_client)

    def _enforce_safety_boundary(self):
        if "testclient" in self.target_url:
            return
        from authtime.network.safety import validate_and_resolve_loopback
        is_ok, resolved_ip, err = validate_and_resolve_loopback(self.target_url)
        if not is_ok:
            raise ValueError(f"SAFETY VIOLATION: {err}")


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
            id_resp = await client.get(f"{self.target_url}/target/identity")
            if id_resp.status_code != 200:
                return False
            id_data = id_resp.json() if id_resp.text else {}
            if id_data.get("product") != "AuthTime" or "authtime" not in str(id_data.get("target", "")).lower():
                return False

            await self.fault_injector.reset(http_client=client)
            ground_truth_manager.reset_to_defaults()

            login_resp = await client.post(f"{self.target_url}/auth/login", json={"user_id": user_id})
            if login_resp.status_code != 200:
                return False
            token = login_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}", "X-AuthTime-Request-ID": "baseline-probe"}

            resp = await client.get(f"{self.target_url}{resource_path}", headers=headers)
            expected = ground_truth_manager.get_expected_decision(user_id, resource_path, time.monotonic())
            actual = evaluate_http_decision(resp.status_code, resp.text, resource_path)

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
        trial_index: int = 1,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> ExperimentResult:
        self._enforce_safety_boundary()
        close_client = False
        client = http_client or self.fault_injector._shared_client
        if client is None:
            client = httpx.AsyncClient()
            close_client = True

        trial_id = f"{experiment_id}-trial-{trial_index}-{uuid.uuid4().hex[:6]}"
        config_dict = {
            "target_url": self.target_url,
            "fault_type": scenario.fault_type,
            "cache_ttl": cache_ttl_seconds,
            "jwt_ttl": jwt_ttl_seconds,
            "time_scale_factor": scenario.time_scale_factor,
            "trial_index": trial_index,
        }
        config_json = json.dumps(config_dict, sort_keys=True)
        config_hash = hashlib.sha256(config_json.encode("utf-8")).hexdigest()

        env_metadata = {
            "python_version": sys.version.split()[0],
            "os_platform": sys.platform,
            "httpx_version": httpx.__version__,
            "architecture": sys.maxsize > 2**32 and "64bit" or "32bit",
        }

        cleanup_status: Literal["SUCCESS", "FAILED", "NOT_ATTEMPTED"] = "NOT_ATTEMPTED"

        try:
            baseline_ok = await self.verify_baseline(user_id=scenario.target_user_id, resource_path=scenario.resource_path, http_client=client)
            jitter_ms = await measure_scheduler_jitter(n_probes=10, delay_ms=2.0)

            if not baseline_ok:
                empty_metrics = ExposureMetric(
                    fault_timestamp_monotonic=time.monotonic(),
                    exposure_interval_min_sec=0.0,
                    exposure_interval_max_sec=0.0,
                    estimated_exposure_sec=None,
                    precision_sec=None,
                    scheduler_jitter_ms=jitter_ms,
                    unauthorized_request_count=0,
                    total_probes_fired=0,
                    measurement_status="INVALID_BASELINE",
                    is_censored=True,
                )
                finding = SecurityFinding(
                    finding_id=f"FIND-{experiment_id}",
                    title="Baseline Verification Failed",
                    fault_type=scenario.fault_type,
                    severity_score=0.0,
                    severity_label="LOW",
                    config_snapshot=config_dict,
                    time_scale_enabled=(scenario.time_scale_factor != 1.0),
                    time_scale_factor=scenario.time_scale_factor,
                    observed_exposure=empty_metrics,
                    root_cause="TARGET_UNHEALTHY",
                    root_cause_confidence="PROVEN",
                    explanation="Baseline health check or target identity handshake failed before fault injection.",
                    real_world_calibration="N/A",
                    reproduction_curl=f"curl -H 'Authorization: Bearer <token>' {self.target_url}{scenario.resource_path}",
                    poc_script_path=f"reports/poc/{experiment_id}_poc.py",
                )
                return ExperimentResult(
                    schema_version=CURRENT_SCHEMA_VERSION,
                    protocol_version=CURRENT_PROTOCOL_VERSION,
                    experiment_id=experiment_id,
                    created_at_utc=datetime.now(timezone.utc),
                    config=config_dict,
                    config_hash=config_hash,
                    baseline_passed=False,
                    cleanup_status="SUCCESS",
                    probes=[],
                    events=[],
                    exposure_metrics=empty_metrics,
                    finding=finding,
                    summary_stats={"trial_count": 1, "mean_exposure_sec": 0.0},
                    exact_probe_schedule=[],
                    environment=env_metadata,
                )

            login_resp = await client.post(
                f"{self.target_url}/auth/login",
                json={"user_id": scenario.target_user_id, "ttl_seconds": int(jwt_ttl_seconds * scenario.time_scale_factor)}
            )
            token_a = login_resp.json()["access_token"]
            headers_a: Dict[str, str] = {"Authorization": f"Bearer {token_a}"}

            headers_b: Optional[Dict[str, str]] = None
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
            exact_schedule: List[Dict[str, Any]] = []

            for probe_spec in scenario.probes:
                target_offset = probe_spec.offset_seconds
                now = time.monotonic()
                elapsed_since_fault = now - t_fault
                if target_offset > elapsed_since_fault:
                    await asyncio.sleep(target_offset - elapsed_since_fault)

                probe_t = time.monotonic()
                utc_now = datetime.now(timezone.utc)
                req_id = f"probe-{experiment_id}-{probe_spec.probe_index}"

                curr_headers = dict(headers_b if (probe_spec.user_id == scenario.secondary_user_id and headers_b) else headers_a)
                curr_headers["X-AuthTime-Request-ID"] = req_id
                curr_headers["X-AuthTime-Experiment-ID"] = experiment_id
                curr_headers["X-AuthTime-Trial-ID"] = trial_id

                p_start = time.monotonic()
                try:
                    res = await client.get(f"{self.target_url}{probe_spec.resource_path}", headers=curr_headers)
                    status_code = res.status_code
                    body_text = res.text
                except httpx.TimeoutException:
                    status_code = 408
                    body_text = ""
                except httpx.NetworkError:
                    status_code = 502
                    body_text = ""
                except Exception:
                    status_code = 500
                    body_text = ""

                lat_ms = (time.monotonic() - p_start) * 1000.0
                actual_dec = evaluate_http_decision(status_code, body_text, probe_spec.resource_path)
                gt_raw = ground_truth_manager.get_expected_decision(probe_spec.user_id, probe_spec.resource_path, probe_t)
                gt_dec: GroundTruthDecision = "ALLOW" if gt_raw == "ALLOW" else "DENY"
                is_violation, _ = evaluate_authorization_violation(actual_dec, gt_dec, status_code, body_text, probe_spec.resource_path)

                exact_schedule.append({
                    "probe_index": probe_spec.probe_index,
                    "requested_offset_sec": probe_spec.offset_seconds,
                    "actual_offset_sec": round(probe_t - t_fault, 4),
                    "probe_type": "scheduled",
                })

                probes.append(
                    ProbeResult(
                        request_id=req_id,
                        experiment_id=experiment_id,
                        scenario_id=scenario.scenario_id,
                        probe_index=probe_spec.probe_index,
                        offset_target=probe_spec.offset_seconds,
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
                    curr_h["X-AuthTime-Trial-ID"] = trial_id
                    try:
                        r = await client.get(f"{self.target_url}{scenario.resource_path}", headers=curr_h)
                        st = r.status_code
                        lat = (time.monotonic() - p_start) * 1000.0
                        actual_t = time.monotonic()
                        dec_str = evaluate_http_decision(st, r.text, scenario.resource_path)
                        return (dec_str, st, lat, actual_t)
                    except httpx.TimeoutException:
                        return ("TIMEOUT", 408, 0.0, time.monotonic())
                    except httpx.NetworkError:
                        return ("CONNECTION_ERROR", 502, 0.0, time.monotonic())
                    except Exception:
                        return ("ERROR", 500, 0.0, time.monotonic())

                left_t, right_t, adapt_records = await adaptive.refine_boundary(
                    t_fault, metrics.last_unauth_monotonic, metrics.first_blocked_monotonic, adaptive_probe_func
                )

                for rec in adapt_records:
                    gt_raw = ground_truth_manager.get_expected_decision(target_user, scenario.resource_path, rec["monotonic_timestamp"])
                    gt_dec_adapt: GroundTruthDecision = "ALLOW" if gt_raw == "ALLOW" else "DENY"
                    is_viol, _ = evaluate_authorization_violation(rec["actual_decision"], gt_dec_adapt, rec["http_status"], resource_path=scenario.resource_path)
                    offset_delta = rec["monotonic_timestamp"] - t_fault
                    exact_schedule.append({
                        "probe_index": rec["probe_index"],
                        "requested_offset_sec": rec["offset_target"],
                        "actual_offset_sec": round(offset_delta, 4),
                        "probe_type": "adaptive",
                    })
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
                            ground_truth_decision=gt_dec_adapt,
                            is_violation=is_viol,
                            response_latency_ms=rec["latency_ms"],
                        )
                    )

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
                config_dict,
                metrics,
                has_cache_key_collision=has_cross_user_collision,
                events=events,
            )

            sev_score, sev_label_raw = compute_severity_score(metrics, scenario.resource_path, rc_conf)
            sev_label: SeverityLabel = "CRITICAL" if sev_label_raw == "CRITICAL" else ("HIGH" if sev_label_raw == "HIGH" else ("MEDIUM" if sev_label_raw == "MEDIUM" else "LOW"))

            finding = SecurityFinding(
                finding_id=f"FIND-{experiment_id}",
                title=f"Authorization Exposure Finding: {rc_code}",
                fault_type=scenario.fault_type,
                severity_score=sev_score,
                severity_label=sev_label,
                config_snapshot=config_dict,
                time_scale_enabled=(scenario.time_scale_factor != 1.0),
                time_scale_factor=scenario.time_scale_factor,
                observed_exposure=metrics,
                root_cause=rc_code,
                root_cause_confidence=rc_conf,
                explanation=rc_expl,
                real_world_calibration=f"Experimental cache_ttl configured to {cache_ttl_seconds}s; this is a representative test value and is not evidence of a production default.",
                reproduction_curl=f"curl -H 'Authorization: Bearer <token>' {self.target_url}{scenario.resource_path}",
                poc_script_path=f"reports/{experiment_id}/poc_{experiment_id}.py",
            )

            # Perform state cleanup
            try:
                await self.fault_injector.reset(http_client=client)
                cleanup_status = "SUCCESS"
            except Exception:
                cleanup_status = "FAILED"

            return ExperimentResult(
                schema_version=CURRENT_SCHEMA_VERSION,
                protocol_version=CURRENT_PROTOCOL_VERSION,
                experiment_id=experiment_id,
                created_at_utc=datetime.now(timezone.utc),
                config=config_dict,
                config_hash=config_hash,
                baseline_passed=baseline_ok,
                cleanup_status=cleanup_status,
                probes=probes,
                events=events,
                exposure_metrics=metrics,
                finding=finding,
                summary_stats={"trial_count": 1, "mean_exposure_sec": metrics.estimated_exposure_sec or metrics.exposure_interval_min_sec},
                exact_probe_schedule=exact_schedule,
                environment=env_metadata,
            )
        finally:
            if cleanup_status == "NOT_ATTEMPTED":
                try:
                    await self.fault_injector.reset(http_client=client)
                    cleanup_status = "SUCCESS"
                except Exception:
                    cleanup_status = "FAILED"
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
            median_exp = statistics.median(exposures) if exposures else 0.0
            std_exp = statistics.stdev(exposures) if len(exposures) > 1 else 0.0
            min_exp = min(exposures) if exposures else 0.0
            max_exp = max(exposures) if exposures else 0.0
        else:
            all_exp = [r.exposure_metrics.exposure_interval_min_sec for r in valid_results]
            mean_exp = None  # Right-censored lower bound; point mean is undefined!
            median_exp = statistics.median(all_exp)
            std_exp = None
            min_exp = min(all_exp)
            max_exp = max(all_exp)

        severities = [r.finding.severity_score for r in valid_results]

        limited_note = None
        if len(uncensored) < 5 or len(censored) > 0:
            limited_note = "Sample size N < 5 or right-censored data present: inferential P95 and standard deviation are suppressed."

        return {
            "trial_count": len(valid_results),
            "uncensored_trial_count": len(uncensored),
            "censored_trial_count": len(censored),
            "mean_exposure_sec": mean_exp,
            "median_sec": median_exp,
            "std_dev_sec": std_exp,
            "min_exposure_sec": min_exp,
            "max_exposure_sec": max_exp,
            "mean_severity_score": statistics.mean(severities),
            "limited_sample_note": limited_note,
        }
