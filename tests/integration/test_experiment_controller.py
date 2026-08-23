"""
Integration tests for ExperimentController.
"""

import pytest
import httpx
from app.main import app
from authtime.controller.experiment import ExperimentController
from authtime.scenarios.generator import ScenarioGenerator


@pytest.mark.asyncio
async def test_experiment_controller_safety():
    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        ExperimentController("http://external-target-domain.com")


@pytest.mark.asyncio
async def test_experiment_controller_single_trial():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testclient") as async_client:
        controller = ExperimentController("http://testclient", http_client=async_client)
        scenario = ScenarioGenerator.generate_single_fault_scenario(
            fault_type="stale_cache", target_user_id="admin1", time_scale_factor=0.01
        )

        res = await controller.run_single_trial("exp-test-1", scenario, http_client=async_client)
        assert res.baseline_passed is True
        assert len(res.probes) == 5
        assert res.finding.root_cause == "AUTHORIZATION_CACHE"
