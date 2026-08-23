"""
Experiment Controller & Statistical Aggregator.

Orchestrates baseline verification, fault injection, timed probing, adaptive refinement,
event correlation, exposure metrics computation, and trial statistical aggregation.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
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
        """Verifies target application behaves correctly before fault injection."""
        close_client = False
        client = http_client or self.fault_injector._shared_client
        if client is None:
            client = httpx.AsyncClient()
            close_client = True

        try:
            await self.fault_injector.reset(http_client=client)
            ground_truth_manager.reset_to_defaults()

            # Login as target user
            login_resp = await client.post(f"{self.target_url}/auth/login", json={"user_id": user_id})
            if login_resp.status_code != 200:
                return False

            token = login_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}", "X-AuthTime-Request-ID": "baseline-probe"}

            resp = await client.get(f"{self.target_url}{resource_path}", headers=headers)
            expected = ground_truth_manager.get_expected_decision(user_id, resource_path, time.monotonic())
            actual = "ALLOW" if resp.status_code == 200 else "DENY"

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
            # 1. Baseline verification
            baseline_ok = await self.verify_baseline(user_id=scenario.target_user_id, resource_path=scenario.resource_path, http_client=client)

            # 2. Pre-flight harness calibration burst
            jitter_ms = await measure_scheduler_jitter(n_probes=10, delay_ms=2.0)

            # 3. Authenticate and obtain JWT
            login_resp = await client.post(
                f"{self.target_url}/auth/login",
                json={"user_id": scenario.target_user_id, "ttl_seconds": int(jwt_ttl_seconds * scenario.time_scale_factor)}
            )
            token_a = login_resp.json()["access_token"]
            headers_a = {"Authorization": f"Bearer {token_a}"}

            token_b = None
            headers_b = None
            if scenario.secondary_user_id:
                login_b = await client.post(
                    f"{self.target_url}/auth/login",
                    json={"user_id": scenario.secondary_user_id, "ttl_seconds": int(jwt_ttl_seconds * scenario.time_scale_factor)}
                )
                token_b = login_b.json()["access_token"]
                headers_b = {"Authorization": f"Bearer {token_b}"}

            # 4. Record fault injection & execute fault
            t_fault = time.monotonic()
            ground_truth_manager.record_fault_event(
                fault_type=scenario.fault_type,
                user_id=scenario.target_user_id,
                timestamp_monotonic=t_fault,
                new_role="User"
            )

            await self.fault_injector.inject_fault(
                fault_type=scenario.fault_type,
                user_id=scenario.target_user_id,
                new_role="User",
                cache_ttl_seconds=cache_ttl_seconds,
                time_scale_factor=scenario.time_scale_factor,
                http_client=client,
            )

            # 5. Execute scheduled probes
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

                p_start = time.monotonic()
                try:
                    res = await client.get(f"{self.target_url}{probe_spec.resource_path}", headers=curr_headers)
                    status_code = res.status_code
                except Exception:
                    status_code = 500

                lat_ms = (time.monotonic() - p_start) * 1000.0
                actual_dec = "ALLOW" if status_code == 200 else "DENY"
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

            # 6. Adaptive Binary Search Refinement if transition detected
            adaptive = AdaptiveProber(target_ms=100.0, max_depth=5)
            metrics = VerificationHarness.calculate_exposure_metrics(t_fault, probes, jitter_ms, 100.0)

            if metrics.last_unauth_monotonic and metrics.first_blocked_monotonic:
                async def adaptive_probe_func(offset_sec: float) -> bool:
                    await asyncio.sleep(offset_sec)
                    try:
                        r = await client.get(f"{self.target_url}{scenario.resource_path}", headers=headers_a)
                        return r.status_code == 200
                    except Exception:
                        return False

                await adaptive.refine_boundary(t_fault, metrics.last_unauth_monotonic, metrics.first_blocked_monotonic, adaptive_probe_func)

            # 7. Collect structured events
            events = await self.event_collector.fetch_evidence_events(experiment_id, http_client=client)

            # 8. Root Cause Analysis & Severity Scoring
            rc_code, rc_conf, rc_expl = RootCauseAnalyzer.analyze_root_cause(
                scenario.fault_type,
                {"cache_ttl_seconds": cache_ttl_seconds, "jwt_ttl_seconds": jwt_ttl_seconds},
                metrics,
                has_cache_key_collision=has_cross_user_collision,
            )

            sev_score, sev_label = compute_severity_score(metrics.estimated_exposure_sec, scenario.resource_path, rc_conf)

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
                poc_script_path=f"reports/poc/{experiment_id}_poc.py",
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
                summary_stats={"trial_count": 1, "mean_exposure_sec": metrics.estimated_exposure_sec},
            )
        finally:
            if close_client and client:
                await client.aclose()

    @staticmethod
    def aggregate_trial_statistics(results: List[ExperimentResult]) -> Dict[str, Any]:
        """
        Aggregates trial statistics across N repetitions (min, max, mean, median, stddev, P95).
        """
        if not results:
            return {}

        exposures = [r.exposure_metrics.estimated_exposure_sec for r in results]
        n = len(exposures)

        mean_val = statistics.mean(exposures)
        median_val = statistics.median(exposures)
        min_val = min(exposures)
        max_val = max(exposures)
        stddev_val = statistics.stdev(exposures) if n > 1 else 0.0

        sorted_exp = sorted(exposures)
        p95_idx = int(math.ceil(0.95 * n)) - 1
        p95_val = sorted_exp[max(0, min(p95_idx, n - 1))]

        limited_sample_note = None
        if n < 5:
            limited_sample_note = "If N < 5, the report must explicitly identify the result as a limited-sample observation and must avoid inferential statistical claims."

        return {
            "repetitions": n,
            "min_sec": min_val,
            "max_sec": max_val,
            "mean_sec": mean_val,
            "median_sec": median_val,
            "stddev_sec": stddev_val,
            "p95_sec": p95_val,
            "limited_sample_note": limited_sample_note,
        }
