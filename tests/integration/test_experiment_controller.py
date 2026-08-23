"""
Integration tests for ExperimentController.
"""

import pytest
import httpx
from app.main import app
from authtime.controller.experiment import ExperimentController
from authtime.scenarios.generator import ScenarioGenerator


@pytest.mark.asyncio
async def test_experiment_controller_safety_boundary():
    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        ExperimentController("http://external-target.com:8000")


@pytest.mark.asyncio
async def test_experiment_controller_single_trial_run():
    controller = ExperimentController("http://127.0.0.1:8000")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        # Run baseline check
        baseline_ok = await controller.verify_baseline(http_client=client)
        assert baseline_ok is True

        # Generate scenario
        scenario = ScenarioGenerator.generate_single_fault_scenario(
            fault_type="stale_cache",
            coarse_offsets=[0.0, 0.1, 0.2],
            time_scale_factor=0.1,
        )

        result = await controller.run_single_trial(
            experiment_id="EXP-TEST-001",
            scenario=scenario,
            cache_ttl_seconds=1.0,
            jwt_ttl_seconds=300,
            http_client=client,
        )

        assert result.experiment_id == "EXP-TEST-001"
        assert result.baseline_passed is True
        assert len(result.probes) == 3
        assert result.finding is not None
        assert result.finding.fault_type == "stale_cache"
