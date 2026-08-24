# AuthTime Software Engineering Methodology & Capability Matrix

> **Comprehensive overview of software engineering architecture, testing methodologies, security practices, and metrology standards applied across the AuthTime project.**

---

## 🌐 Engineering Architecture & Capability Map

AuthTime integrates standard software engineering principles across 10 specialized domains. Below is the technical breakdown of methodologies applied across the AuthTime distributed authorization laboratory.

### A. Software Engineering & Architecture
- **Asynchronous Processing**: Non-blocking I/O using Python `asyncio` and `httpx` for high-throughput HTTP probing.
- **RESTful API Services**: ASGI service design using `FastAPI` with dependency injection and middleware routing.
- **Framework Adapters**: WSGI/ASGI application integration for `Django` and `Node.js Express`.
- **Decoupled Architecture**: Target Adapter Abstraction (`BaseTargetAdapter`, `HTTPTargetAdapter`, `DistributedLabAdapter`).

### B. Security Engineering & Threat Modeling
- **Loopback Enforcement**: Runtime safety boundaries restricting HTTP execution exclusively to `127.0.0.1` / `localhost`.
- **Cryptographic Token Verification**: HMAC-SHA256 & RS256 JWT signature checks, expiration (`exp`), and replay protection (`jti`).
- **Authorization Versioning**: Dynamic `auth_version` state tracking in PostgreSQL and Redis to eliminate stale cache access.
- **Fail-Closed Security**: Default 401/403 denial when database or cache infrastructure is disconnected.

### C. Automated Testing & Verification
- **Unit & Integration Testing**: `pytest` test suites covering schemas, database store transactions, and HTTP target adapters.
- **Property-Based Fuzzing**: Randomized timing invariant validation using `Hypothesis`.
- **Race Condition Analysis**: High-concurrency test suite validating simultaneous revocation, login, and out-of-order version events.
- **Privacy & Security Audit**: Automated repo cleanliness tests verifying zero hardcoded keys or local machine paths.

### D. Distributed Systems & Infrastructure
- **Containerized Environment**: `docker-compose.lab.yml` defining PostgreSQL 16, Redis 7, and 3 independent API replicas.
- **State Store Abstraction**: `AuthorizationStateStore` providing `InMemoryAuthorizationStateStore` (Level B) and `PostgreSQLAuthorizationStateStore` (Level C).
- **Cache Propagation Bus**: Redis Pub/Sub channel (`authtime:invalidations`) with controlled fault injection modes.

### E. Metrology & Performance Analysis
- **Monotonic Timing**: High-resolution `time.monotonic()` clocking to prevent wall-clock NTP drift.
- **High-Concurrency Load Testing**: `ConcurrentLoadTester` measuring RPS, P50/P95/P99 latency, and exposure under load.
- **Kaplan-Meier Survival Analysis**: Right-censoring statistics for exposure window duration estimation.

---

## 📊 Development Phases & Engineering Artifacts

| Project Phase | Core Methodologies | Technical Implementation | Verified Outcome |
| :--- | :--- | :--- | :--- |
| **Phase 1: Problem Definition** | Security Research, Threat Modeling | Formulated Temporal Exposure Window ($\Delta t_{\text{exp}}$) math. | Defined formal exposure model spec. |
| **Phase 2: Target Abstraction** | Design Patterns, Adapter Pattern | Implemented `HTTPTargetAdapter` & `BaseTargetAdapter`. | Decoupled prober from targets. |
| **Phase 3: Reference Targets** | FastAPI, Express.js, Django, CAEP | Authored 4 multi-framework test applications. | Tested cross-framework equivalence. |
| **Phase 4: Fault Injection Engine** | Event Driven Architecture | Implemented `FaultInjectorClient` & `/faults/*` endpoints. | Controlled fault triggering. |
| **Phase 5: Probing Metrology** | Monotonic Clocks, Async Probing | High-precision prober ($\le 100\text{ms}$ resolution). | Accurate exposure measurement. |
| **Phase 6: Survival Analysis** | Kaplan-Meier Estimator | Built right-censored statistical estimator. | Statistically sound metrics. |
| **Phase 7: Case Study Modeling** | Real-World Scenario Design | Employee offboarding scenario (`alice` demotion). | 4.25s vulnerable exposure gap. |
| **Phase 8: Versioning Mitigation** | Authorization Versioning | Added `auth_version` checks to DB & tokens. | 100.0% exposure reduction (0.00s @ 100ms). |
| **Phase 9: State Store Layer** | Abstract Base Classes, asyncpg | Created `AuthorizationStateStore` & `LabDatabase`. | Dual-mode Level B / Level C support. |
| **Phase 10: Load & Stress Testing** | Async Worker Pools, Performance | Built `ConcurrentLoadTester` & `scripts/run_load_test.py`. | Verified performance under load. |
| **Phase 11: Race Testing** | Concurrency Testing | Authored `tests/test_race_conditions.py` (7 scenarios). | Verified atomic transactions. |
| **Phase 12: Performance Benchmark**| Latency Profiling, Throughput | Created `scripts/benchmark_mitigation.py` & Tradeoff Report. | Quantified 11.1% throughput cost. |
| **Phase 13: CI/CD Pipeline** | GitHub Actions Workflows | Created `.github/workflows/ci.yml` & `level_c_lab.yml`. | Automated test execution. |
