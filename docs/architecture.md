# AuthTime Architecture Specification

AuthTime is organized into decoupled, modular components:

1. **Reference Auth Target (`src/app/`)**: Deliberately vulnerable FastAPI reference target running strictly on `127.0.0.1`.
2. **Multi-Framework Reference Replicas (`targets/`)**: Native reference targets for Node.js Express (`targets/express/`), Django (`targets/django/`), and OpenID CAEP/SSF (`targets/caep/`).
3. **Target Adapter Layer (`authtime/adapters/target_adapter.py`)**: Abstract target communication interface (`BaseTargetAdapter`, `HTTPTargetAdapter`) standardizing identity verification, fault injection, probe execution, state resets, and audit event collection.
4. **Ground Truth State Manager (`authtime/ground_truth/`)**: Evaluates expected authorization decisions.
5. **Fault Injector Client (`authtime/fault_injector/`)**: Communicates with local `/faults/inject` endpoint.
6. **Event Collector (`authtime/events/`)**: Collects structured audit events tagged with `X-AuthTime-Request-ID`.
7. **Verification & Timing Harness (`authtime/timing/`, `authtime/verification/`)**: Measures probe latencies and scheduler jitter, executes adaptive binary search, and calculates exposure windows.
8. **Scenario Generator (`authtime/scenarios/`)**: Produces coarse offsets, adaptive binary search, and multi-user isolation test suites.
9. **Experiment Controller (`authtime/controller/`)**: Coordinates baseline verification, fault injection, timing harness execution, target adapter dispatch, and trial aggregation.
10. **Report Generator (`authtime/reporting/`)**: Formats Markdown, HTML, JSON, and standalone zero-dependency PoC scripts.
11. **Distributed Authorization Validation Laboratory (`targets/distributed_lab/`)**: Distributed multi-replica architecture featuring PostgreSQL as authoritative source of truth, Redis as authorization & invalidation bus, signed JWT lifecycle management, multiple protected API replicas (API-1, API-2, API-3), controlled failure injection, and `DistributedLabAdapter`.


