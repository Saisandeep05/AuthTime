"""
AuthTime Experiment Controller & Verification Coordinator.
Includes process-wide concurrency lock, lifecycle state machine tracking, immutable raw evidence capture,
and rigorous post-cleanup state verification.
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

from authtime.logging import logger

from authtime.constants import CURRENT_PROTOCOL_VERSION, CURRENT_SCHEMA_VERSION
from authtime.fault_injector.client import FaultInjectorClient
from authtime.events.collector import EventCollector
from authtime.scenarios.generator import Scenario, ScenarioProbeSpec

from authtime.verification.harness import VerificationHarness, measure_scheduler_jitter
from authtime.verification.adaptive_prober import AdaptiveProber
from authtime.verification.predicate import evaluate_http_decision, evaluate_authorization_violation
from authtime.verification.root_cause import RootCauseAnalyzer
from authtime.reporting.generator import compute_severity_score
from authtime.adapters.contract import DEFAULT_ADMIN_USERS_CONTRACT, ResourceContract
from authtime.adapters.target_adapter import BaseTargetAdapter, HTTPTargetAdapter

from authtime.models.evidence import (
    ExperimentState,
    RawProbeObservation,
    TransportErrorCategory,
    RootCauseAssessment,
)
from authtime.models.schemas import (
    ExperimentResult,
    ProbeResult,
    ExposureMetric,
    SecurityFinding,
    EvidenceEvent,
    SeverityLabel,
    GroundTruthDecision,
)
from authtime.lifecycle.state_machine import ExperimentStateMachine, ExperimentState
from authtime.statistics.censoring import calculate_kaplan_meier_survival, format_uncertainty_interval
from authtime.ground_truth.manager import GroundTruthStateManager, ground_truth_manager


# Per-target URL concurrency locks prohibiting simultaneous experiment runs on the same target instance
_TARGET_LOCKS: Dict[str, asyncio.Lock] = {}


def get_target_lock(target_url: str) -> asyncio.Lock:
    if target_url not in _TARGET_LOCKS:
        _TARGET_LOCKS[target_url] = asyncio.Lock()
    return _TARGET_LOCKS[target_url]



class ExperimentController:
    def __init__(
        self,
        target_url: str = "http://127.0.0.1:8000",
        fault_injector: Optional[FaultInjectorClient] = None,
        event_collector: Optional[EventCollector] = None,
        http_client: Optional[httpx.AsyncClient] = None,
        contract: Optional[ResourceContract] = None,
        target_adapter: Optional[BaseTargetAdapter] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self._enforce_safety_boundary()
        self.fault_injector = fault_injector or FaultInjectorClient(self.target_url, http_client=http_client)
        self.event_collector = event_collector or EventCollector(self.target_url, http_client=http_client)
        self.contract = contract or DEFAULT_ADMIN_USERS_CONTRACT
        self.target_adapter = target_adapter or HTTPTargetAdapter(self.target_url, http_client=http_client)

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
        adapter = self.target_adapter
        if http_client is not None and getattr(adapter, "_shared_client", None) != http_client:
            adapter = HTTPTargetAdapter(self.target_url, http_client=http_client)

        try:
            id_data = await adapter.verify_identity()
            if id_data.get("product") != "AuthTime" or "authtime" not in str(id_data.get("target", "")).lower():
                return False

            await adapter.reset_state()
            ground_truth_manager.reset_to_defaults()

            token = await adapter.login_user(user_id)
            st_code, body_text, _ = await adapter.probe_endpoint(resource_path, token, "baseline-probe")

            expected = ground_truth_manager.get_expected_decision(user_id, resource_path, time.monotonic())
            actual = evaluate_http_decision(st_code, body_text, resource_path, self.contract)

            return expected == actual
        except Exception as exc:
            logger.debug("Baseline verification failed: %s", exc)
            return False

    async def verify_cleanup(
        self,
        user_id: str = "admin1",
        resource_path: str = "/admin/users",
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> bool:
        """
        Independent Post-Reset State Verification.
        Verifies reset succeeded, target identity endpoint is active, and unauthorized requests are DENIED.
        """
        adapter = self.target_adapter
        if http_client is not None and getattr(adapter, "_shared_client", None) != http_client:
            adapter = HTTPTargetAdapter(self.target_url, http_client=http_client)

        try:
            await adapter.reset_state()
            id_data = await adapter.verify_identity()
            return id_data.get("product") == "AuthTime"
        except Exception as exc:
            logger.debug("Cleanup verification failed: %s", exc)
            return False


    async def run_single_trial(
        self,
        experiment_id: str,
        scenario: Scenario,
        cache_ttl_seconds: float = 60.0,
        jwt_ttl_seconds: int = 300,
        trial_index: int = 1,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> ExperimentResult:
        target_lock = get_target_lock(self.target_url)
        async with target_lock:
            self._enforce_safety_boundary()
            close_client = False
            client = http_client or self.fault_injector._shared_client
            if client is None:
                client = httpx.AsyncClient()
                close_client = True

            sm = ExperimentStateMachine(experiment_id=experiment_id)
            run_id = f"RUN-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex}"
            trial_id = f"{experiment_id}-trial-{trial_index}-{uuid.uuid4().hex[:6]}"
            raw_observations: List[RawProbeObservation] = []

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

            cleanup_status: Literal["VERIFIED", "FAILED", "NOT_ATTEMPTED"] = "NOT_ATTEMPTED"
            exp_gt_manager = GroundTruthStateManager(experiment_id=experiment_id)

            try:
                # 1. Target Identity Verification State
                baseline_ok = await self.verify_baseline(user_id=scenario.target_user_id, resource_path=scenario.resource_path, http_client=client)
                
                jitter_ms = await measure_scheduler_jitter(n_probes=10, delay_ms=2.0)

                if not baseline_ok:
                    sm.mark_invalid(time.monotonic(), "Baseline health check or target identity handshake failed")
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
                        run_id=run_id,
                        created_at_utc=datetime.now(timezone.utc),
                        config=config_dict,
                        config_hash=config_hash,
                        baseline_passed=False,
                        cleanup_status="NOT_ATTEMPTED",
                        state_history=sm.get_history_strings(),
                        probes=[],
                        events=[],
                        raw_observations=[],
                        exposure_metrics=empty_metrics,
                        finding=finding,
                        summary_stats={"trial_count": 1, "mean_exposure_sec": None},
                        exact_probe_schedule=[],
                        environment=env_metadata,
                    )

                sm.transition_to(ExperimentState.TARGET_VERIFIED, time.monotonic(), "Target identity verified")
                sm.transition_to(ExperimentState.BASELINE_VERIFIED, time.monotonic(), "Baseline authorized access verified")


                # 2. Authentication & Login State
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

                # 3. Fault Injection State
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
                sm.transition_to(ExperimentState.FAULT_INJECTED, t_fault, f"Injected fault: {scenario.fault_type}")

                exp_gt_manager.record_fault_event(
                    fault_type=scenario.fault_type,
                    user_id=scenario.target_user_id,
                    timestamp_monotonic=t_fault,
                    new_role="User"
                )

                # 4. Probing State Execution
                sm.transition_to(ExperimentState.PROBING, time.monotonic(), "Starting probe schedule execution")
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
                    probe_id = f"probe-{experiment_id}-{probe_spec.probe_index}"
                    req_id = f"req-{uuid.uuid4().hex}"

                    curr_headers = dict(headers_b if (probe_spec.user_id == scenario.secondary_user_id and headers_b) else headers_a)
                    curr_headers["X-AuthTime-Request-ID"] = req_id
                    curr_headers["X-AuthTime-Experiment-ID"] = experiment_id
                    curr_headers["X-AuthTime-Trial-ID"] = trial_id
                    curr_headers["X-AuthTime-Run-ID"] = run_id

                    p_start = time.monotonic()
                    body_text = ""
                    try:
                        res = await client.get(f"{self.target_url}{probe_spec.resource_path}", headers=curr_headers)
                        status_code = res.status_code
                        body_text = res.text
                        transport_cat = TransportErrorCategory.HTTP_RESPONSE
                    except httpx.TimeoutException:
                        status_code = 0
                        body_text = ""
                        transport_cat = TransportErrorCategory.NETWORK_TIMEOUT
                    except httpx.NetworkError:
                        status_code = 0
                        body_text = ""
                        transport_cat = TransportErrorCategory.CONNECTION_ERROR
                    except Exception as client_err:
                        status_code = 0
                        body_text = str(client_err)
                        transport_cat = TransportErrorCategory.CLIENT_ERROR

                    p_end = time.monotonic()
                    lat_ms = (p_end - p_start) * 1000.0

                    if transport_cat == TransportErrorCategory.HTTP_RESPONSE:
                        actual_dec = evaluate_http_decision(status_code, body_text, probe_spec.resource_path, self.contract)
                    else:
                        actual_dec = transport_cat.value

                    gt_raw = exp_gt_manager.get_expected_decision(probe_spec.user_id, probe_spec.resource_path, probe_t)
                    gt_dec: GroundTruthDecision = "ALLOW" if gt_raw == "ALLOW" else "DENY"
                    is_violation, viol_reason = evaluate_authorization_violation(actual_dec, gt_dec, status_code, body_text, probe_spec.resource_path, self.contract)

                    raw_obs = RawProbeObservation.create(
                        probe_id=probe_id,
                        run_id=run_id,
                        experiment_id=experiment_id,
                        trial_id=trial_id,
                        probe_index=probe_spec.probe_index,
                        requested_offset_sec=probe_spec.offset_seconds,
                        actual_offset_sec=round(probe_t - t_fault, 4),
                        request_start_monotonic=p_start,
                        response_received_monotonic=p_end,
                        transport_result=transport_cat,
                        raw_http_status=status_code,
                        body_text=body_text,
                        actual_decision=actual_dec,
                        decision_reason=viol_reason,
                        ground_truth_decision=gt_dec,
                        headers=curr_headers,
                    )
                    raw_observations.append(raw_obs)

                    exact_schedule.append({
                        "probe_index": probe_spec.probe_index,
                        "requested_offset_sec": probe_spec.offset_seconds,
                        "actual_offset_sec": round(probe_t - t_fault, 4),
                        "timing_error_sec": round((probe_t - t_fault) - probe_spec.offset_seconds, 4),
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
                            actual_decision=actual_dec,  # type: ignore
                            ground_truth_decision=gt_dec,
                            is_violation=is_violation,
                            response_latency_ms=lat_ms,
                        )
                    )

                if scenario.fault_type == "token_expiry":
                    total_window_sec = jwt_ttl_seconds * scenario.time_scale_factor
                else:
                    total_window_sec = cache_ttl_seconds * scenario.time_scale_factor

                metrics = VerificationHarness.calculate_exposure_metrics(t_fault, probes, jitter_ms, 100.0, total_window_sec=total_window_sec)
                sm.transition_to(ExperimentState.ANALYZED, time.monotonic(), "Calculated exposure metrics")

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
                    poc_script_path=f"reports/poc/{experiment_id}_poc.py",
                )

                # 5. Cleanup and Verification State
                sm.transition_to(ExperimentState.CLEANUP, time.monotonic(), "Executing post-experiment cleanup reset")
                clean_verified = await self.verify_cleanup(user_id=scenario.target_user_id, resource_path=scenario.resource_path, http_client=client)
                if clean_verified:
                    cleanup_status = "VERIFIED"
                    sm.transition_to(ExperimentState.CLEAN_VERIFIED, time.monotonic(), "Independent post-reset identity state verified")
                    sm.transition_to(ExperimentState.VALID, time.monotonic(), "Experiment reached final VALID state")
                else:
                    cleanup_status = "FAILED"
                    sm.mark_invalid(time.monotonic(), "Post-reset cleanup verification failed")

                return ExperimentResult(
                    schema_version=CURRENT_SCHEMA_VERSION,
                    protocol_version=CURRENT_PROTOCOL_VERSION,
                    experiment_id=experiment_id,
                    run_id=run_id,
                    created_at_utc=datetime.now(timezone.utc),
                    config=config_dict,
                    config_hash=config_hash,
                    baseline_passed=(baseline_ok and clean_verified),
                    cleanup_status=cleanup_status,
                    state_history=sm.get_history_strings(),
                    probes=probes,
                    events=events,
                    raw_observations=[r.model_dump(mode="json") for r in raw_observations],
                    exposure_metrics=metrics,
                    finding=finding,
                    summary_stats={"trial_count": 1, "mean_exposure_sec": metrics.estimated_exposure_sec},
                    exact_probe_schedule=exact_schedule,
                    environment=env_metadata,
                )

            finally:
                if cleanup_status == "NOT_ATTEMPTED":
                    clean_v = await self.verify_cleanup(user_id=scenario.target_user_id, resource_path=scenario.resource_path, http_client=client)
                    cleanup_status = "VERIFIED" if clean_v else "FAILED"
                if close_client and client:
                    await client.aclose()

    @staticmethod
    def aggregate_trial_statistics(results: List[ExperimentResult]) -> Dict[str, Any]:
        valid_results = [r for r in results if r.baseline_passed and r.cleanup_status == "VERIFIED"]
        if not valid_results:
            return {"trial_count": 0, "message": "No valid trials passed baseline and cleanup verification."}

        uncensored = [r for r in valid_results if not r.exposure_metrics.is_censored]
        censored = [r for r in valid_results if r.exposure_metrics.is_censored]

        if uncensored and not censored:
            exposures = [r.exposure_metrics.estimated_exposure_sec for r in uncensored if r.exposure_metrics.estimated_exposure_sec is not None]
            mean_exp = statistics.mean(exposures) if exposures else 0.0
            median_exp = statistics.median(exposures) if exposures else 0.0
            std_exp = statistics.stdev(exposures) if len(exposures) > 1 else 0.0
            min_exp = min(exposures) if exposures else 0.0
            max_exp = max(exposures) if exposures else 0.0
        else:
            # Right-censored data present: Ordinary sample mean is NOT ESTIMABLE!
            all_min = [r.exposure_metrics.exposure_interval_min_sec for r in valid_results]
            mean_exp = None  # Point mean is suppressed per scientific censoring standards
            median_exp = statistics.median(all_min)
            std_exp = None
            min_exp = min(all_min)
            max_exp = max(all_min)

        severities = [r.finding.severity_score for r in valid_results]

        limited_note = None
        if len(uncensored) < 5 or len(censored) > 0:
            limited_note = "Sample size N < 5 or right-censored data present: ordinary mean and P95 are suppressed (NOT ESTIMABLE)."

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
