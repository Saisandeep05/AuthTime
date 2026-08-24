# AuthTime

> **An open-source controlled security research harness for experimentally measuring and quantifying Temporal Authorization Exposure Windows ($\Delta t_{\text{exp}}$) during access revocation fault injection.**

<p align="center">
  <img src="assets/animations/authtime-exposure-window.svg" alt="AuthTime Exposure Window Measurement Animation" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Saisandeep05/AuthTime/actions"><img src="https://github.com/Saisandeep05/AuthTime/actions/workflows/ci.yml/badge.svg" alt="CI Pipeline"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.12-green.svg" alt="Python 3.12"></a>
  <a href="#-safety-boundary--constraints"><img src="https://img.shields.io/badge/Security-Local%20Loopback%20Only-red.svg" alt="Security Boundary"></a>
  <a href="#-verified-project-status"><img src="https://img.shields.io/badge/Tests-85%20Passed%20%7C%201%20Skipped-success.svg" alt="Tests Status"></a>
</p>

**Tech Stack**: `Python 3.12` • `FastAPI` • `PostgreSQL` • `Redis` • `Django` • `Express.js` • `OpenID CAEP/SSF` • `JWT` • `HTTPX` • `Pytest` • `Hypothesis` • `Docker`

<details>
<summary><strong>📚 Table of Contents</strong> (Click to Expand)</summary>

- [⚡ What You Get](#-what-you-get)
- [💼 Real-World Case Study](#-real-world-problem-solving-case-study)
- [📊 Explore Results](#-explore-results--sample-artifacts)
- [🌐 Distributed Validation Lab](#-distributed-authorization-validation-laboratory)
- [🎯 The Security Exposure Problem](#-the-security-exposure-problem)
- [⚡ Reference Benchmark Result](#-reference-benchmark-result)
- [✅ Verified Project Status](#-verified-project-status)
- [🔄 Visual Experiment Lifecycle](#-visual-experiment-lifecycle)
- [🏗️ System Architecture](#-system-architecture)
- [💻 Supported Target Frameworks](#-supported-target-frameworks)
- [📂 Directory Structure](#-directory-structure)
- [🚀 Quickstart](#-quickstart)
- [🛠️ Key Engineering Highlights](#-key-engineering-highlights)
- [🛡️ Safety Boundary & Constraints](#-safety-boundary--constraints)
</details>

---

## ⚡ What You Get

| ⏱️ **Measure Exposure Window ($\Delta t_{\text{exp}}$)** | 🔍 **Classify Root Cause** | 📜 **Generate Standalone PoC** |
| :--- | :--- | :--- |
| Pinpoint exact temporal delay between role revocation and enforcement down to $\le 100\text{ms}$ precision. | Diagnose revocation lag (stale cache, unrevoked JWT, async delay) with confidence metrics. | Automatically output executable zero-dependency Python scripts reproducing findings. |

---

## 💼 Real-World Problem-Solving Case Study

AuthTime includes an end-to-end enterprise case study modeling a real-world authorization failure during **Employee Offboarding**:

### Enterprise Scenario: Employee Offboarding (Alice)
- **Business Context**: Employee `alice` holds the `Finance Admin` role with access to `/finance/payroll`, `/finance/payments`, and `/finance/reports`.
- **Revocation Event**: HR demotes `alice` to `Employee` at $t_0$ in the central database.
- **Vulnerable Baseline**: Due to asynchronous cache invalidation lag and dropped pub/sub events, `API-3` continues allowing access for **`4.25s`** post-revocation (5-run average; range: 3.97s - 4.34s).
- **Engineering Mitigation**: Implemented **Authorization Versioning & Version-Aware Cache Validation** (`auth_version`). Replicas detect version mismatch and evict stale cache immediately.
- **Experimental Re-Validation**: Re-running the experiment across 5 runs under mitigated mode demonstrates a **`100.0% reduction in observed exposure`** (no post-revocation ALLOW decisions observed within the 100ms measurement resolution).

| Experiment State | Max Exposure ($\Delta t_{\text{exp}}$) | Mean Replica Exposure | Engineering Outcome |
| :--- | :---: | :---: | :--- |
| **Vulnerable Baseline (5 Runs)** | `4.25s` (Std Dev: 0.16s) | `4.22s` | Stale cache exposure on Replica API-3 |
| **Mitigated State (5 Runs)** | **`0.00s`** | **`0.00s`** | **100.0% Reduction (No ALLOW @ 100ms Res)** |

> **Validation Level**: Level B — Multi-Process Distributed Application Validation (3 independent FastAPI process replicas over HTTP).

### Case Study Links & Artifacts

- 📘 [**Full Case Study Documentation**](docs/real-world-case-study.md) — Comprehensive technical write-up & root cause analysis
- 🧪 [**Vulnerable Evidence JSON**](experiments/employee_offboarding_case_study/vulnerable-results.json) — Per-replica probe logs & metrics under baseline
- 🛡️ [**Mitigated Evidence JSON**](experiments/employee_offboarding_case_study/mitigated-results.json) — Per-replica timing logs under Authorization Versioning
- 📊 [**Before vs After Comparison JSON**](experiments/employee_offboarding_case_study/comparison.json) — Structured before/after metrics summary with reproducibility metadata

---

## 📊 Explore Results & Sample Artifacts

- 📘 [**Real-World Offboarding Case Study**](docs/real-world-case-study.md) — End-to-end offboarding failure & versioning fix
- 📈 [**Interactive Visual Dashboard**](dashboard/index.html) — Timeline charts, probe markers, and audit logs
- 🧪 [**Live Multi-Process Validation Results**](docs/distributed-validation-results.md) — Empirical evidence & scenario metrics
- 📄 [**Sample Security Report (Markdown)**](reports/examples/sample_report.md) — Generated audit write-up
- 🌐 [**Sample Security Report (HTML)**](reports/examples/sample_report.html) — Styled HTML audit artifact
- 🤖 [**Machine-Readable Telemetry (JSON)**](reports/examples/results.json) — Auditable JSON metadata & results
- 🔬 [**Technical Research Write-up**](docs/findings-report.md) — Deep-dive research on authorization revocation gaps

---

## 🌐 Distributed Authorization Validation Laboratory

AuthTime includes a full **Distributed Authorization Validation Laboratory** (`targets/distributed_lab/`) proving real-world authorization propagation and revocation dynamics across actual distributed infrastructure components:

- **PostgreSQL Source of Truth**: Authoritative DB storing users, roles, authorization version counters, and revocation audit events (`targets/distributed_lab/db/schema.sql`).
- **Redis Authorization & Invalidation Bus**: Caches user role states and streams invalidation pub/sub events (`targets/distributed_lab/cache/redis_cache.py`).
- **JWT Authorization Lifecycle**: Cryptographic tokens verified against per-replica role cache or DB (`targets/distributed_lab/auth/jwt_handler.py`).
- **Multi-Replica Protected APIs**: Three independent API instances (`API-1`, `API-2`, `API-3` on ports `8010`, `8011`, `8012`).
- **Controlled Failure Injection**:
  - `NO_FAULT`: Immediate DB update & Redis cache invalidation across all 3 replicas ($\Delta t_{\text{exp}} = 0.0\text{s}$).
  - `STALE_CACHE`: DB update with 60.0s TTL cache expiration ($\Delta t_{\text{exp}} = 60.0\text{s}$).
  - `DELAYED_INVALIDATION`: DB update with 2.0s Redis invalidation delay ($\Delta t_{\text{exp}} = 2.0\text{s}$).
  - `PARTIAL_PROPAGATION`: Replica 2 receives invalidation event 1.5s later than Replica 1 & 3.
  - `DROPPED_EVENT`: Replica 3 misses invalidation event entirely until TTL fallback.
  - `REDIS_UNAVAILABLE`: Temporary Redis transport failure fallback behavior.

### Launching the Distributed Laboratory with Docker Compose

```bash
docker compose -f docker-compose.lab.yml up --build
```

---

## 🎯 The Security Exposure Problem

When an administrative user's privileges are revoked in a primary database (due to employee termination, role demotion, or security compromise), distributed microservices and web applications often **fail to immediately enforce revocation**. 

Applications continue accepting unauthorized requests during a silent **Temporal Authorization Exposure Window** ($\Delta t_{\text{exp}}$) caused by:
1. **Stale In-Memory Caches**: Application workers caching user permissions until a local TTL expires.
2. **Unrevoked Stateless JWT Tokens**: Valid cryptographic signatures accepted until token expiration (`exp`).
3. **Asynchronous Propagation Delays**: Back-channel revocation events failing or delayed across message brokers.

<p align="center">
  <img src="assets/diagrams/authorization-exposure-model.svg" alt="Stale Authorization Exposure Model" width="100%">
</p>

**AuthTime** provides an empirical, automated research harness to inject controlled revocation faults, execute high-precision HTTP probing ($\le 100\text{ms}$ resolution), measure exact exposure windows, and generate standalone proof-of-concept reproduction scripts.

---

## ⚡ Reference Benchmark Result

In our reference web application benchmark setup:

- **What Happened**: An admin user's role was demoted to a standard `User` in the primary ground-truth database.
- **The Vulnerability**: The application continued executing privileged admin requests for **60.0 seconds** of configured TTL (or **4.52s ± 0.05s** in accelerated 0.1x experimental mode) because the worker authorization cache was stale.
- **Severity Score**: Assigned a **Severity Score of 7.3 / 10.0 (HIGH)** per the auditable formula in [`docs/severity-scoring.md`](docs/severity-scoring.md).
- **Root Cause**: `AUTHORIZATION_CACHE` (Stale in-memory cache trusting outdated role claims post-revocation).

```
[10:00:00 AM] HR Revokes Admin Rights in Database ────────┐
                                                         ├── ⚠️ 60.0-Second Vulnerability Gap (60.0s Configured TTL at 1.0x Real-Time)
[10:01:00 AM] Application Cache Finally Expires ─────────┘
```
*(Note: In 0.1x accelerated experimental mode, the 60.0s TTL window completes in 4.52s ± 0.05s of wall-clock time).*

---

## ✅ Verified Project Status

- **85 Automated Tests Passing (85 passed, 1 skipped cleanly)** across unit, integration, property fuzzing, system CLI, case study, race condition, and failure mode test suites.
- **Target Adapter Abstraction Layer** (`BaseTargetAdapter` / `HTTPTargetAdapter`) decoupling measurement orchestration from target web frameworks.
- **Cryptographically Hardened SSF/CAEP Implementation** (HMAC-SHA256 & RS256 token verification, `jti` replay resistance with 300s TTL eviction).
- **Forensic Audit Log Preservation** (`AUDIT_EVENTS` preserved across state reset cycles).
- **Strict Local Loopback Boundary** (Hardcoded runtime enforcement restricting execution exclusively to `127.0.0.1` / `localhost`).

---

## 🔄 Visual Experiment Lifecycle

AuthTime coordinates a multi-stage experimental pipeline to measure access revocation lag with high precision:

<p align="center">
  <img src="assets/animations/experiment-lifecycle.svg" alt="AuthTime Experiment Execution Pipeline" width="100%">
</p>

1. **Configure Target**: Select reference target application (FastAPI, Node.js Express, Django, or OpenID CAEP/SSF).
2. **Establish Baseline**: Perform identity verification and validate pre-fault authorized access (`ALLOW`).
3. **Inject Controlled Fault**: Demote user role or revoke session in database/control plane.
4. **Execute High-Precision Probes**: Fire background HTTP probes at scheduled offsets ($\le 100\text{ms}$ schedule resolution) using `time.monotonic()`.
5. **Collect Evidence & Analyze**: Evaluate response contracts, compute exposure window $[t_{\text{last\_unauth}}, t_{\text{first\_block}}]$, determine root cause, and generate runnable PoC scripts.
6. **Generate Reports & Reset State**: Output formatted JSON, HTML, and standalone Python PoC reproduction scripts, resetting target state while preserving immutable forensic audit trails.

---

## 🏗️ System Architecture

AuthTime uses a modular, decoupled architecture where the core measurement engine communicates with target applications exclusively through a standardized **Target Adapter Abstraction Layer**.

### Visual Data Flow Overview

<p align="center">
  <img src="assets/animations/architecture-flow.svg" alt="AuthTime System Architecture Data Flow" width="100%">
</p>

### Detailed Component Architecture

```mermaid
flowchart TD
    subgraph Core Engine
        CSM["Experiment State Machine\n(state_machine.py)"]
        GTM["Ground Truth Manager\n(ground_truth/manager.py)"]
        EC["Experiment Controller\n(controller/experiment.py)"]
        TA["Target Adapter Layer\n(adapters/target_adapter.py)"]
    end

    subgraph Reference Target Replicas
        FAP["FastAPI Target\n(src/app/main.py)"]
        EXP["Express Target\n(targets/express/server.js)"]
        DJG["Django Native Target\n(targets/django/app.py)"]
        CAEP["Cryptographic CAEP Target\n(targets/caep/server.py)"]
    end

    subgraph Evidence & Analysis
        KM["Kaplan-Meier Survival Analysis\n(statistics/censoring.py)"]
        RCA["Root Cause Analyzer\n(verification/root_cause.py)"]
        RG["Report & PoC Generator\n(reporting/generator.py)"]
    end

    CSM --> EC
    GTM --> EC
    EC --> TA
    TA -->|HTTP / Loopback| FAP
    TA -->|HTTP / Loopback| EXP
    TA -->|HTTP / Loopback| DJG
    TA -->|Cryptographic SSF| CAEP

    EC --> KM
    EC --> RCA
    RCA --> RG

    RG --> MD["reports/examples/sample_report.md"]
    RG --> HTML["reports/examples/sample_report.html"]
    RG --> JSON["reports/examples/results.json"]
    RG --> POC["reports/poc/<exp>_poc.py"]
    RG --> DASH["dashboard/index.html"]
```

---

## 💻 Supported Target Frameworks

| Target Framework | Implementation Path | Execution Mode | Adapter Interface | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Distributed Lab** | `targets/distributed_lab/` | Postgres + Redis + 3 API Replicas | `DistributedLabAdapter` | ✅ Tested E2E |
| **FastAPI** | `src/app/main.py` | Python 3.12 (ASGI) | `HTTPTargetAdapter` | ✅ Primary Tested |
| **Node.js Express** | `targets/express/server.js` | Node.js 18+ (HTTP) | `HTTPTargetAdapter` | ✅ Tested E2E |
| **Django Native** | `targets/django/app.py` | Python 3.12 (WSGI) | `HTTPTargetAdapter` | ✅ Tested (Optional Req) |
| **OpenID CAEP / SSF** | `targets/caep/server.py` | Cryptographic SSF | `HTTPTargetAdapter` | ✅ Tested (HMAC/RS256) |

---

## 📂 Directory Structure

```
AuthTime/
├── assets/                         # Visual Assets & Animations
│   ├── animations/                 # SVG Animated Visualizations
│   │   ├── authtime-exposure-window.svg
│   │   ├── experiment-lifecycle.svg
│   │   └── architecture-flow.svg
│   └── diagrams/                   # Conceptual Visual Diagrams
│       └── authorization-exposure-model.svg
│
├── src/                            # Source Packages
│   ├── app/                        # Reference Auth Target Application (FastAPI on 127.0.0.1:8000)
│   │   ├── main.py                 # FastAPI application factory
│   │   ├── config.py               # Settings & secrets
│   │   ├── api/endpoints.py        # Protected routes & /faults/* injection controller
│   │   ├── auth/jwt.py             # PyJWT creation & verification
│   │   ├── cache/ttl_cache.py      # Thread-safe in-memory authorization TTL cache
│   │   └── rbac/roles.py           # Role definitions & RBAC checks
│   │
│   └── authtime/                   # AuthTime Core Engine
│       ├── adapters/               # Target Adapter Abstraction (target_adapter.py, contract.py)
│       ├── cli.py                  # CLI entrypoint (authtime)
│       ├── controller/             # Trial controller & statistical aggregator (experiment.py)
│       ├── events/                 # Audit event collector (collector.py)
│       ├── fault_injector/         # Loopback fault injection client (client.py)
│       ├── ground_truth/           # Dynamic Ground Truth state manager (manager.py)
│       ├── history/                # Exposure history tracker & regression diffing (tracker.py)
│       ├── lifecycle/              # State machine & transition invariants (state_machine.py)
│       ├── models/                 # Pydantic v2 schemas & evidence models
│       ├── network/                # DNS-rebinding loopback safety (safety.py)
│       ├── reporting/              # Markdown, HTML, JSON & runnable PoC generator (generator.py)
│       ├── scenarios/              # Coarse, matrix & cross-user scenario generators
│       ├── statistics/             # Kaplan-Meier survival estimator & censoring analysis
│       ├── timing/                 # Monotonic clock & scheduler jitter calibration (clock.py)
│       └── verification/           # Exposure calculator, prober & root cause analyzer
│
├── targets/                        # Multi-Framework Target Replicas
│   ├── distributed_lab/            # Distributed Auth Lab (PostgreSQL, Redis, JWT, API Replicas 1/2/3)
│   │   ├── db/                     # PostgreSQL schema & database store (schema.sql, database.py, store.py)
│   │   ├── cache/                  # Redis authorization & invalidation bus (redis_cache.py)
│   │   ├── auth/                   # JWT lifecycle & verifier (jwt_handler.py)
│   │   └── service/                # Multi-replica API app factory (app.py, server.py)
│   ├── caep/                       # OpenID CAEP/SSF push revocation target (server.py)
│   ├── express/                    # Node.js Express target (server.js, 127.0.0.1:8001)
│   └── django/                     # Django native target (app.py, 127.0.0.1:8002)
│
├── dashboard/                      # Visual Exposure Timeline Dashboard
│   └── index.html                  # Interactive HTML5/Chart.js visual dashboard
│
├── docs/                           # Technical Specifications & Research
│   ├── architecture.md             # System architecture & component interface spec
│   ├── real-world-case-study.md    # Offboarding case study & mitigation analysis
│   ├── mitigation-tradeoff-report.md # Mitigation performance overhead benchmark report
│   ├── distributed-validation-results.md # Empirical multi-replica validation evidence
│   ├── severity-scoring.md         # Transparent 0-10 severity formula spec
│   ├── findings-report.md          # Technical security research write-up
│   ├── engineering-methodology.md  # Software engineering architecture & testing methodology
│   └── development/                # Development Milestone Log
│       └── DEVELOPMENT_LOG.md      # Development milestone log
│
├── tests/                          # Automated Verification Suite
│   ├── unit/                       # Unit tests (schemas, adapters, ground truth, root cause)
│   ├── integration/                # Integration tests (controller, fault injection, multi-framework)
│   ├── scenarios/                  # Scenario tests (cross-user isolation)
│   ├── system/                     # System CLI tests
│   └── property/                   # Property-based randomized fuzzing suite (Hypothesis)
│
├── reports/                        # Output Reports & Reproduction Scripts
│   ├── examples/                   # Committed Sample Demonstration Artifacts
│   │   ├── sample_report.md
│   │   ├── sample_report.html
│   │   └── results.json
│   └── poc/                        # Standalone Python PoC scripts
│
├── Dockerfile                      # Container build manifest (bound to 127.0.0.1)
├── docker-compose.yml              # Single target compose configuration
├── pyproject.toml                  # Setuptools package configuration
├── requirements.txt                # Python dependencies
├── run.py                          # Top-level demonstration launcher
└── README.md                       # Portfolio overview & documentation
```

---

## 🚀 Quickstart

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/Saisandeep05/AuthTime.git
cd AuthTime

# Install dependencies and package in editable mode
pip install -r requirements.txt
pip install -e .
```

### 2. Run Interactive Live Verification

```bash
# On Windows / Linux / macOS:
python test_live.py

# Or in Windows PowerShell:
.\test_live.ps1
```

### 3. Run Top-Level Demonstration Engine

```bash
python run.py
```
This automatically starts the local reference target, executes experiment trials, and generates formatted reports in `reports/examples/`.

### 4. Execute Full Automated Test Suite

```bash
pytest --verbose
```

### 5. Open Visual Exposure Dashboard

Open [`dashboard/index.html`](dashboard/index.html) in any web browser to view interactive timeline charts, probe markers, severity badges, and audit logs.

### 6. Using the `authtime` CLI

```bash
# Start local reference target server
python -m authtime.cli target start --port 8000

# Execute experiment scenario
python -m authtime.cli run --fault-type stale_cache --repetitions 3 --output-dir reports/examples

# Compare current exposure against historical baseline for regression testing
python -m authtime.cli compare --current-exposure 6.0 --threshold 0.5
```

---

## 🛠️ Key Engineering Highlights

- **Target Adapter Abstraction**: Modular `BaseTargetAdapter` interface standardizing identity verification, fault injection, probe execution, state resets, and audit event collection across web frameworks.
- **High-Precision Monotonic Timing**: Leverages `time.monotonic()` to eliminate wall-clock drift, automatically measuring scheduler jitter and harness overhead.
- **Adaptive Binary Search Probing**: Pinpoints exact revocation transition boundaries down to $\le 100\text{ms}$ precision.
- **Cryptographic SSF/CAEP Security**: Implements OpenID CAEP/SSF event reception with HMAC-SHA256/RS256 token verification and `jti` replay resistance with 300s TTL eviction.
- **Forensic Audit Log Preservation**: State resets restore authorization roles and caches while leaving immutable audit logs (`AUDIT_EVENTS`) intact for forensic auditing.
- **Property-Based Fuzzing Suite**: 100-iteration randomized property testing with Hypothesis validating timing invariant guarantees.
- **Standalone PoC Generation**: Automatically outputs zero-dependency, executable Python reproduction scripts (`reports/poc/<exp>_poc.py`).

---

## 🛡️ Safety Boundary & Constraints

> [!CAUTION]
> **Strict Local Loopback Boundary**: AuthTime operates **exclusively** against local reference targets running on `127.0.0.1` or `localhost`.
> - **NO** external network scanning or third-party targets.
> - **NO** real credentials or personal data.
> - **NO** external network traffic.
> - **Fail-Safe Abort**: AuthTime includes hardcoded runtime enforcement (`validate_and_resolve_loopback`) that immediately aborts execution if a non-loopback URL is supplied.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
