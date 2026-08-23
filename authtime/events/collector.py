"""
Event Collector & Correlation ID Tracker for AuthTime Engine.

Fetches and correlates reference application structured audit logs via HTTP or internal buffer.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import httpx
from app.config import settings
from authtime.models.schemas import EvidenceEvent


class EventCollector:
    def __init__(self, target_url: Optional[str] = None):
        self.target_url = target_url or f"http://{settings.TARGET_HOST}:{settings.TARGET_PORT}"

    async def fetch_raw_events() -> List[Dict[str, Any]]:
        """Fetch raw audit logs from reference target GET /events."""
        endpoint = f"{self.target_url}/events"
        async with httpx.AsyncClient() as client:
            resp = await client.get(endpoint)
            if resp.status_code == 200:
                return resp.json().get("events", [])
            return []

    async def fetch_evidence_events(
        self,
        experiment_id: str,
        request_id: Optional[str] = None,
    ) -> List[EvidenceEvent]:
        """
        Retrieves and filters audit events converted into EvidenceEvent models.
        """
        endpoint = f"{self.target_url}/events"
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(endpoint)
                if resp.status_code != 200:
                    return []
                raw_list = resp.json().get("events", [])
            except Exception:
                return []

        events: List[EvidenceEvent] = []
        for item in raw_list:
            if request_id and item.get("request_id") != request_id:
                continue

            utc_time = item.get("utc_timestamp")
            if utc_time and isinstance(utc_time, str):
                try:
                    dt = datetime.fromisoformat(utc_time)
                except ValueError:
                    dt = datetime.now(timezone.utc)
            else:
                dt = datetime.now(timezone.utc)

            ev = EvidenceEvent(
                event_id=item.get("event_id", "evt-0"),
                request_id=item.get("request_id", "untracked"),
                experiment_id=experiment_id,
                monotonic_timestamp=item.get("monotonic_timestamp", 0.0),
                utc_timestamp=dt,
                event_type=item.get("event_type", "UNKNOWN"),
                details=item.get("details", {}),
            )
            events.append(ev)

        return events
