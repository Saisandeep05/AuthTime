"""
Integration tests for FaultInjectorClient.
"""

import pytest
import httpx
from fastapi.testclient import TestClient
from app.main import app
from authtime.fault_injector.client import FaultInjectorClient


@pytest.mark.asyncio
async def test_fault_injector_safety_boundary():
    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        FaultInjectorClient("http://evil-external-site.com:8000")


@pytest.mark.asyncio
async def test_fault_injector_with_app():
    # Use ASGITransport for testing FastAPI app directly with httpx AsyncClient
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testclient") as async_client:
        injector = FaultInjectorClient("http://testclient", http_client=async_client)

        reset_res = await injector.reset(http_client=async_client)
        assert reset_res["status"] == "RESET_COMPLETE"

        inject_res = await injector.inject_fault(
            fault_type="stale_cache", user_id="admin1", new_role="User", http_client=async_client
        )
        assert inject_res["status"] == "SUCCESS"
        assert inject_res["fault_type"] == "stale_cache"
