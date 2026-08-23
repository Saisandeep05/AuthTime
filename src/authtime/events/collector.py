"""
Event Collector & Correlation Tracker.

Collects structured target audit events and correlates them by X-AuthTime-Request-ID.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import httpx
from authtime.models.schemas import EvidenceEvent


class EventCollector:
    def __init__(self, target_url: str = "http://127.0.0.1:8000", http_client: Optional[httpx.AsyncClient] = None):
        self.target_url = target_url.rstrip("/")
        self._shared_client = http_client

    async def fetch_evidence_events(
        self, experiment_id: str, http_client: Optional[httpx.AsyncClient] = None
    ) -> List[EvidenceEvent]:
        close_client = False
        client = http_client or self._shared_client
        if client is None:
            client = httpx.AsyncClient()
            close_client = True

        try:
            resp = await client.get(f"{self.target_url}/events", params={"experiment_id": experiment_id})
            if resp.status_code != 200:
                return []

            raw_events = resp.json().get("events", [])
            events: List[EvidenceEvent] = []

            for item in raw_events:
                utc_dt = datetime.fromisoformat(item["utc_timestamp"])
                events.append(
                    EvidenceEvent(
                        event_id=item["event_id"],
                        request_id=item["request_id"],
                        experiment_id=experiment_id,
                        monotonic_timestamp=float(item["monotonic_timestamp"]),
                        utc_timestamp=utc_dt,
                        event_type=item["event_type"],
                        details=item.get("details", {}),
                    )
                )
            return events
        except Exception:
            return []
        finally:
            if close_client and client:
                await client.aclose()
