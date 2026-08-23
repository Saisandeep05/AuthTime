"""
Unit tests for Target Adapter Abstraction layer.
"""

import pytest
import httpx
from app.main import app
from authtime.adapters.target_adapter import HTTPTargetAdapter


@pytest.mark.asyncio
async def test_http_target_adapter_flow():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testclient") as client:
        adapter = HTTPTargetAdapter("http://testclient", http_client=client)

        identity = await adapter.verify_identity()
        assert identity["product"] == "AuthTime"

        reset_res = await adapter.reset_state("exp-test-adapter")
        assert reset_res["status"] == "RESET_COMPLETE"

        token = await adapter.login_user("admin1")
        assert isinstance(token, str) and len(token) > 10

        st_code, body_text, lat_ms = await adapter.probe_endpoint("/admin/users", token, "req-test-1")
        assert st_code == 200
        assert "users" in body_text

        fault_res = await adapter.inject_fault("stale_cache", "admin1", "User", cache_ttl_seconds=10.0)
        assert fault_res["status"] == "SUCCESS"

        events = await adapter.fetch_evidence_events("exp-test-adapter")
        assert isinstance(events, list)
