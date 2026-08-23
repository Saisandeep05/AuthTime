"""
Integration Test Suite: Positive/Negative Controls & Detector Benchmark (TP/TN/FP/FN/Precision/Recall/F1).
"""

import pytest
import httpx
from app.main import app
from authtime.controller.experiment import ExperimentController
from authtime.scenarios.generator import ScenarioGenerator


@pytest.mark.asyncio
async def test_positive_control_scenario():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testclient") as async_client:
        controller = ExperimentController("http://testclient", http_client=async_client)
        scen = ScenarioGenerator.generate_positive_control_scenario(time_scale_factor=0.01)

        result = await controller.run_single_trial("exp-pos-control", scen, http_client=async_client)
        assert result.baseline_passed is True
        assert result.exposure_metrics.unauthorized_request_count > 0


@pytest.mark.asyncio
async def test_negative_control_scenario():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testclient") as async_client:
        controller = ExperimentController("http://testclient", http_client=async_client)
        scen = ScenarioGenerator.generate_negative_control_scenario(time_scale_factor=0.01)

        result = await controller.run_single_trial("exp-neg-control", scen, http_client=async_client)
        assert result.baseline_passed is True
        assert result.exposure_metrics.unauthorized_request_count == 0
        assert result.exposure_metrics.exposure_interval_min_sec == 0.0


@pytest.mark.asyncio
async def test_detector_benchmark_metrics():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testclient") as async_client:
        controller = ExperimentController("http://testclient", http_client=async_client)

        tp = fn = fp = tn = 0

        # Positive controls (vulnerable)
        for i in range(2):
            scen = ScenarioGenerator.generate_positive_control_scenario(time_scale_factor=0.01)
            res = await controller.run_single_trial(f"bench-pos-{i}", scen, http_client=async_client)
            if res.exposure_metrics.unauthorized_request_count > 0:
                tp += 1
            else:
                fn += 1

        # Negative controls (safe)
        for i in range(2):
            scen = ScenarioGenerator.generate_negative_control_scenario(time_scale_factor=0.01)
            res = await controller.run_single_trial(f"bench-neg-{i}", scen, http_client=async_client)
            if res.exposure_metrics.unauthorized_request_count == 0:
                tn += 1
            else:
                fp += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0

        assert tp == 2
        assert tn == 2
        assert fp == 0
        assert fn == 0
        assert precision == 1.0
        assert recall == 1.0
        assert f1 == 1.0
