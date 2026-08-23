"""
Integration Test Suite: Race Condition Scenarios and Clock Skew Metadata.
Verifies concurrent revocation/request/cache refresh race windows and clock skew handling.
"""

import asyncio
import pytest
import httpx
from app.main import app
from authtime.controller.experiment import ExperimentController
from authtime.scenarios.generator import ScenarioGenerator, ScenarioProbeSpec, Scenario


@pytest.mark.asyncio
async def test_race_condition_concurrent_requests():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testclient") as async_client:
        controller = ExperimentController("http://testclient", http_client=async_client)
        
        # Login admin1
        login_res = await async_client.post("/auth/login", json={"user_id": "admin1"})
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Concurrently execute revocation fault injection and 5 probes
        async def inject():
            await asyncio.sleep(0.01)
            return await async_client.post("/faults/inject", json={"fault_type": "stale_cache", "user_id": "admin1", "new_role": "User"})

        async def probe(idx: int):
            await asyncio.sleep(0.01 * idx)
            return await async_client.get("/admin/users", headers=headers)

        tasks = [inject()] + [probe(i) for i in range(1, 6)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        assert results[0].status_code == 200
        for r in results[1:]:
            assert r.status_code in (200, 403)


@pytest.mark.asyncio
async def test_clock_skew_metadata_recording():
    scen = ScenarioGenerator.generate_single_fault_scenario("stale_cache", time_scale_factor=0.01)
    assert scen.time_scale_factor == 0.01
    assert len(scen.probes) > 0
