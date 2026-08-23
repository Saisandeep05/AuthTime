# AuthTime Architecture Specification

AuthTime is organized into decoupled, modular components:

1. **Reference Auth Target (`app/`)**: Deliberately vulnerable FastAPI application running strictly on `127.0.0.1`.
2. **Ground Truth State Manager (`authtime/ground_truth/`)**: Evaluates expected authorization decisions.
3. **Fault Injector Client (`authtime/fault_injector/`)**: Communicates with local `/faults/inject` endpoint.
4. **Event Collector (`authtime/events/`)**: Collects structured audit events tagged with `X-AuthTime-Request-ID`.
5. **Verification & Timing Harness (`authtime/timing/`, `authtime/verification/`)**: Measures probe latencies and scheduler jitter, executes adaptive binary search, and calculates exposure windows.
6. **Scenario Generator (`authtime/scenarios/`)**: Produces coarse offsets and multi-user isolation test suites.
7. **Experiment Controller (`authtime/controller/`)**: Coordinates baseline verification, fault injection, timing harness execution, and trial aggregation.
8. **Report Generator (`authtime/reporting/`)**: Formats Markdown, HTML, JSON, and standalone PoC scripts.
