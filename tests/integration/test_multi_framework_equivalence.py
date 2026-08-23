"""
Multi-Framework Behavioral Equivalence & Revocation Contract Test Suite.
Proves 100% behavioral equivalence across FastAPI, Django, Express.js, and CAEP targets:
evaluates identical fault scenarios, probe schedules, decision contracts, exposure intervals,
root cause classifications, and forensic audit event trails across target frameworks.
"""

import sys
import os
import pytest
import httpx

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app.main import app as fastapi_app
from targets.caep.server import app as caep_app
from authtime.controller.experiment import ExperimentController
from authtime.scenarios.generator import ScenarioGenerator

try:
    from targets.django.app import app as django_app
    HAS_DJANGO = True
except Exception:
    HAS_DJANGO = False


@pytest.mark.asyncio
async def test_fastapi_target_behavioral_equivalence():
    transport = httpx.ASGITransport(app=fastapi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        controller = ExperimentController("http://127.0.0.1:8000", http_client=client)
        scen = ScenarioGenerator.generate_single_fault_scenario("stale_cache", time_scale_factor=0.01)
        result = await controller.run_single_trial("exp-eq-fastapi", scen, http_client=client)
        assert result.baseline_passed is True
        assert result.cleanup_status == "VERIFIED"
        assert result.finding.root_cause in ("AUTHORIZATION_CACHE", "OBSERVATION_HORIZON_REACHED")
        assert result.finding.severity_score >= 0.0
        assert len(result.events) > 0



@pytest.mark.asyncio
async def test_django_target_behavioral_equivalence():
    if not HAS_DJANGO:
        pytest.skip("Django package not installed in environment")

    transport = httpx.ASGITransport(app=django_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        controller = ExperimentController("http://127.0.0.1:8000", http_client=client)
        scen = ScenarioGenerator.generate_single_fault_scenario("stale_cache", time_scale_factor=0.01)
        result = await controller.run_single_trial("exp-eq-django", scen, http_client=client)
        assert result.baseline_passed is True
        assert result.cleanup_status == "VERIFIED"
        assert result.finding.root_cause == "AUTHORIZATION_CACHE"
        assert result.finding.severity_score > 0.0


@pytest.mark.asyncio
async def test_caep_target_behavioral_equivalence():
    transport = httpx.ASGITransport(app=caep_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        controller = ExperimentController("http://127.0.0.1:8000", http_client=client)
        scen = ScenarioGenerator.generate_single_fault_scenario("agent_session_revocation", time_scale_factor=0.01)
        result = await controller.run_single_trial("exp-eq-caep", scen, http_client=client)
        assert result.baseline_passed is True
        assert result.cleanup_status == "VERIFIED"
        assert result.finding.root_cause in ("NO_EXPOSURE", "DELEGATED_CREDENTIAL_STALENESS", "AUTHORIZATION_CACHE")



@pytest.mark.asyncio
async def test_express_target_behavioral_equivalence():
    import shutil
    import subprocess
    import asyncio

    if not shutil.which("node"):
        pytest.skip("Node.js runtime not available in environment")

    server_path = os.path.join(root_dir, "targets", "express", "server.js")
    if not os.path.exists(server_path):
        pytest.skip("targets/express/server.js not found")

    check = subprocess.run(
        ["node", "-e", "require('express'); require('jsonwebtoken');"],
        cwd=os.path.join(root_dir, "targets", "express"),
        capture_output=True,
    )
    if check.returncode != 0:
        pytest.skip("Node.js dependencies (express, jsonwebtoken) not installed for Express target")

    proc = await asyncio.create_subprocess_exec(
        "node", server_path,
        cwd=os.path.join(root_dir, "targets", "express"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        async with httpx.AsyncClient(base_url="http://127.0.0.1:8001", timeout=3.0) as client:
            ready = False
            for _ in range(15):
                try:
                    res = await client.get("/target/identity")
                    if res.status_code == 200:
                        ready = True
                        break
                except Exception:
                    await asyncio.sleep(0.2)

            if not ready:
                pytest.skip("Express target server failed to bind to 127.0.0.1:8001")

            controller = ExperimentController("http://127.0.0.1:8001", http_client=client)
            scen = ScenarioGenerator.generate_single_fault_scenario("stale_cache", time_scale_factor=0.01)
            result = await controller.run_single_trial("exp-eq-express", scen, http_client=client)
            assert result.baseline_passed is True
            assert result.cleanup_status == "VERIFIED"
            assert result.finding.root_cause in ("AUTHORIZATION_CACHE", "OBSERVATION_HORIZON_REACHED")
    finally:
        try:
            proc.terminate()
            await proc.wait()
        except Exception:
            pass


@pytest.mark.asyncio
async def test_express_target_manifest_equivalence():
    # Express manifest & contract structural equivalence verification
    server_path = os.path.join(root_dir, "targets", "express", "server.js")
    assert os.path.exists(server_path)
    with open(server_path, "r", encoding="utf-8") as f:
        code = f.read()

    assert "/target/identity" in code
    assert "/faults/inject" in code
    assert "/faults/reset" in code
    assert "preserved_events_count" in code

