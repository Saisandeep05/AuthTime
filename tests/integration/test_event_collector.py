"""
Integration tests for EventCollector.
"""

import pytest
import httpx
from app.main import app
from authtime.events.collector import EventCollector


@pytest.mark.asyncio
async def test_event_collector_fetch():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        # Trigger an endpoint call with X-AuthTime-Request-ID
        login_token = (await client.post("/auth/login", json={"user_id": "admin1"})).json()["access_token"]
        headers = {"Authorization": f"Bearer {login_token}", "X-AuthTime-Request-ID": "correlation-test-999"}
        await client.get("/admin/users", headers=headers)

    from app.api.endpoints import audit_events
    assert len(audit_events) > 0
    matched = [e for e in audit_events if e.get("request_id") == "correlation-test-999"]
    assert len(matched) >= 2
    event_types = [e["event_type"] for e in matched]
    assert "CACHE_MISS" in event_types
    assert "RESOURCE_ACCESS" in event_types
