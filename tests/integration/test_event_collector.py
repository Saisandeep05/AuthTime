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
    async with httpx.AsyncClient(transport=transport, base_url="http://testclient") as async_client:
        collector = EventCollector("http://testclient", http_client=async_client)

        # Trigger login to generate audit event
        await async_client.post("/faults/reset")
        await async_client.post("/auth/login", json={"user_id": "admin1"})

        events = await collector.fetch_evidence_events("exp-1", http_client=async_client)
        assert len(events) > 0
        assert events[0].experiment_id == "exp-1"
