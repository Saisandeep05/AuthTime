"""
Integration & Safety Tests for EventCollector & Evidential Isolation.
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

        await async_client.post("/faults/reset")
        login_res = await async_client.post("/auth/login", json={"user_id": "admin1"})
        token = login_res.json()["access_token"]

        await async_client.get(
            "/admin/users",
            headers={
                "Authorization": f"Bearer {token}",
                "X-AuthTime-Request-ID": "random-req-123",
                "X-AuthTime-Experiment-ID": "exp-1",
            },
        )

        events = await collector.fetch_evidence_events("exp-1", http_client=async_client)
        assert len(events) > 0
        assert events[0].experiment_id == "exp-1"


@pytest.mark.asyncio
async def test_event_collector_strict_isolation():
    """Verifies that events generated under Experiment A never leak into Experiment B queries, even with arbitrary request IDs."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testclient") as async_client:
        collector = EventCollector("http://testclient", http_client=async_client)

        await async_client.post("/faults/reset")
        login_res = await async_client.post("/auth/login", json={"user_id": "admin1"})
        token = login_res.json()["access_token"]

        # Generate event for Experiment A with unrelated request ID
        await async_client.get(
            "/admin/users",
            headers={
                "Authorization": f"Bearer {token}",
                "X-AuthTime-Request-ID": "unrelated-req-alpha",
                "X-AuthTime-Experiment-ID": "exp-AAA",
            },
        )

        # Generate event for Experiment B with unrelated request ID
        await async_client.get(
            "/admin/users",
            headers={
                "Authorization": f"Bearer {token}",
                "X-AuthTime-Request-ID": "unrelated-req-beta",
                "X-AuthTime-Experiment-ID": "exp-BBB",
            },
        )

        events_a = await collector.fetch_evidence_events("exp-AAA", http_client=async_client)
        events_b = await collector.fetch_evidence_events("exp-BBB", http_client=async_client)

        assert len(events_a) == 1
        assert events_a[0].experiment_id == "exp-AAA"
        assert events_a[0].request_id == "unrelated-req-alpha"

        assert len(events_b) == 1
        assert events_b[0].experiment_id == "exp-BBB"
        assert events_b[0].request_id == "unrelated-req-beta"


@pytest.mark.asyncio
async def test_events_endpoint_requires_experiment_id():
    """Verifies that calling /events without experiment_id returns 400 Bad Request."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testclient") as async_client:
        resp = await async_client.get("/events")
        assert resp.status_code == 400
        assert "REQUIRED" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_fault_reset_preserves_evidence_store():
    """Verifies that /faults/reset resets target authorization state without clearing historical audit evidence."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testclient") as async_client:
        collector = EventCollector("http://testclient", http_client=async_client)

        # Record event under exp-PERSIST
        login_res = await async_client.post("/auth/login", json={"user_id": "admin1"})
        token = login_res.json()["access_token"]
        await async_client.get(
            "/admin/users",
            headers={
                "Authorization": f"Bearer {token}",
                "X-AuthTime-Request-ID": "pre-reset-req",
                "X-AuthTime-Experiment-ID": "exp-PERSIST",
            },
        )

        # Execute fault reset
        await async_client.post("/faults/reset")

        # Verify evidence remains intact after reset
        events = await collector.fetch_evidence_events("exp-PERSIST", http_client=async_client)
        assert len(events) == 1
        assert events[0].experiment_id == "exp-PERSIST"
