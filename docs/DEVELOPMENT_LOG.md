# AuthTime — Development Log

| Phase | Checkpoint | Changes | Test Result | Commit Hash | Known Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Phase 1** | Project Setup & Architecture | Initialized repository structure, `requirements.txt`, `LICENSE`, `CONTRIBUTING.md`, Pydantic schemas in `authtime/models/schemas.py`, and documentation suite in `docs/`. | 3/3 passed | `79463c9` | Target app and harness implementation begins in Phase 2. |
| **Phase 2** | Reference Auth Target (`app/`) | Implemented FastAPI reference application factory, JWT generation/validation, custom RBAC roles, in-memory TTL auth cache, protected routes (`/invoices`, `/admin/users`), and local-only fault API (`/faults/inject`, `/faults/reset`). | 11/11 passed | `8188be7` | Single instance local target; multi-node support scheduled for post-MVP. |
| **Phase 3** | Ground Truth Manager | Implemented `GroundTruthStateManager` in `authtime/ground_truth/manager.py` modeling expected authorization states at timestamp $T$. | 13/13 passed | `0d22555` | Initialized with default 4 role mappings; extensible for dynamic scenarios. |
| **Phase 4** | Fault Injector Client | Implemented `FaultInjectorClient` in `authtime/fault_injector/client.py` with `127.0.0.1` safety guards and integration tests. | 15/15 passed | `398f2a6` | Operates against local target endpoint; supports role_revocation, stale_cache, token_expiry, agent_session_revocation. |
| **Phase 5** | Event Collector | Implemented `EventCollector` in `authtime/events/collector.py` correlating `X-AuthTime-Request-ID` across structured audit events. | 16/16 passed | `334403c` | Collects live target audit logs via HTTP / buffer interface. |
