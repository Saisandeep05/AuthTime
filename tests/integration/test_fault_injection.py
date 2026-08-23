"""
Integration tests for FaultInjectorClient.
"""

import pytest
import httpx
from app.main import app
from authtime.fault_injector.client import FaultInjectorClient


@pytest.mark.asyncio
async def test_fault_injector_safety_boundary():
    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        FaultInjectorClient("http://evil-external-target.com:8000")


@pytest.mark.asyncio
async def test_fault_injector_client_inject_and_reset():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        # Test reset
        reset_resp = await client.post("/faults/reset")
        assert reset_resp.status_code == 200

        # Inject role revocation
        inject_resp = await client.post(
            "/faults/inject",
            json={"fault_type": "role_revocation", "user_id": "admin1", "new_role": "User"},
        )
        assert inject_resp.status_code == 200
        assert inject_resp.json()["status"] == "SUCCESS"
