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
                return [
                    EvidenceEvent(
                        event_id=f"evt-err-{experiment_id}",
                        request_id="req-none",
                        experiment_id=experiment_id,
                        monotonic_timestamp=0.0,
                        utc_timestamp=datetime.now(timezone.utc),
                        event_type="EVENT_FETCH_FAILED",
                        details={"status_code": resp.status_code, "reason": "Target /events endpoint returned non-200 status"},
                    )
                ]

            raw_events = resp.json().get("events", [])
            events: List[EvidenceEvent] = []

            for item in raw_events:
                try:
                    utc_dt = datetime.fromisoformat(item["utc_timestamp"])
                except Exception:
                    utc_dt = datetime.now(timezone.utc)

                events.append(
                    EvidenceEvent(
                        event_id=item.get("event_id", f"evt-{len(events)+1}"),
                        request_id=item.get("request_id", "req-unknown"),
                        experiment_id=experiment_id,
                        monotonic_timestamp=float(item.get("monotonic_timestamp", 0.0)),
                        utc_timestamp=utc_dt,
                        event_type=item.get("event_type", "AUDIT_LOG"),
                        details=item.get("details", {}),
                    )
                )
            return events
        except Exception as e:
            return [
                EvidenceEvent(
                    event_id=f"evt-err-{experiment_id}",
                    request_id="req-none",
                    experiment_id=experiment_id,
                    monotonic_timestamp=0.0,
                    utc_timestamp=datetime.now(timezone.utc),
                    event_type="EVENT_FETCH_FAILED",
                    details={"error": str(e)},
                )
            ]
        finally:
            if close_client and client:
                await client.aclose()

