# AuthTime

> **An open-source controlled security research harness for experimentally measuring and quantifying Temporal Authorization Exposure Windows ($\Delta t_{\text{exp}}$) during access revocation fault injection.**

[![AuthTime CI & Verification Pipeline](https://github.com/Saisandeep05/AuthTime/actions/workflows/ci.yml/badge.svg)](https://github.com/Saisandeep05/AuthTime/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-green.svg)](https://www.python.org/)

**Tech Stack**: `Python 3.12` • `FastAPI` • `Django` • `Express.js` • `JWT` • `HTTPX` • `Pytest` • `Hypothesis` • `Docker`

---

## 🎯 Why AuthTime?

- **Investigates Access Revocation Delay**: When permissions are revoked in a database (e.g. employee termination or privilege demotion), web applications often continue trusting stale in-memory caches or unrevoked JWT tokens.
- **Quantifies Vulnerability Windows**: Measures exact time delays ($\le 100\text{ms}$ schedule precision) during which unauthorized requests succeed post-revocation.
- **Multi-Framework Behavioral Testing**: Evaluates identical revocation fault scenarios across FastAPI, Django, Express.js, and OpenID CAEP/SSF push revocation targets.
- **Empirical Security Research Engine**: Automatically generates standalone, zero-dependency Python PoC reproduction scripts to verify findings independently.

---

## ✅ Verified Project Status

- **58 Automated Tests Passing (58 passed, 1 skipped cleanly)** across unit, integration, property fuzzing, and system CLI test suites.
- **Target Adapter Abstraction Layer** (`BaseTargetAdapter` / `HTTPTargetAdapter`) decoupling measurement orchestration from target web frameworks.
- **Cryptographically Hardened SSF/CAEP Implementation** (HMAC-SHA256 & RS256 token verification, `jti` replay resistance with 300s TTL eviction).
- **Forensic Audit Log Preservation** (`AUDIT_EVENTS` preserved across state reset cycles).
- **Strict Local Loopback Boundary** (Hardcoded runtime enforcement restricting execution exclusively to `127.0.0.1` / `localhost`).

---

## 🔄 How It Works

```
 1. Configure Target ────> 2. Baseline Check ────> 3. Inject Fault ────> 4. High-Precision Probing ────> 5. Evidence & Analysis
    (FastAPI / Express /      (Verify pre-fault       (Demote role or        (Fire probes at <=100ms        (Compute exposure window,
    Django / CAEP)             authorized access)     revoke session)         offsets)                       root cause & PoC)
```

1. **Configure Target**: Select a reference target application (FastAPI, Node.js Express, Django, or OpenID CAEP/SSF).
2. **Establish Baseline**: Perform identity verification and validate pre-fault authorized access (`ALLOW`).
3. **Inject Controlled Fault**: Demote user role or revoke session in database/control plane.
4. **Execute High-Precision Probes**: Fire background HTTP probes at scheduled offsets ($\le 100\text{ms}$ schedule resolution) using `time.monotonic()`.
5. **Collect Evidence & Analyze**: Evaluate response contracts, compute exposure window $[t_{\text{last\_unauth}}, t_{\text{first\_block}}]$, determine root cause, and generate runnable PoC scripts.

---

## ⚡ Headline Discovery

In our reference web application setup:
- **What Happened**: An admin user's role was changed to a standard `User`.
- **The Vulnerability**: The application continued accepting admin requests for **60.0 seconds** of configured TTL (or **4.52s ± 0.05s** in accelerated 0.1x experimental mode) because the authorization cache was stale.
- **Severity Score**: Assigned a **Severity Score of 7.3 / 10.0 (HIGH)** per the auditable formula in [`docs/severity-scoring.md`](docs/severity-scoring.md).

```
[10:00:00 AM] HR Revokes Admin Rights in Database ────────┐
                                                         ├── ⚠️ 60-Second Vulnerability Gap (60.0s Configured TTL at 1.0x Real-Time)
[10:01:00 AM] Application Cache Finally Expires ─────────┘
```
*(Note: In 0.1x accelerated experimental mode, the 60.0s TTL window completes in 4.52s ± 0.05s of wall-clock time).*

---

## 🏗️ System Architecture

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

    RG --> MD["reports/sample_report.md"]
    RG --> HTML["reports/sample_report.html"]
    RG --> JSON["reports/results.json"]
    RG --> POC["reports/poc/<exp>_poc.py"]
    RG --> DASH["dashboard/index.html"]
```

---

## 📂 Directory Structure

```
AuthTime/
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
│   ├── caep/                       # OpenID CAEP/SSF push revocation target (server.py)
│   ├── express/                    # Node.js Express target (server.js, 127.0.0.1:8001)
│   └── django/                     # Django native target (app.py, 127.0.0.1:8002)
│
├── dashboard/                      # Visual Exposure Timeline Dashboard
│   └── index.html                  # Interactive HTML5/Chart.js visual dashboard
│
├── docs/                           # Specifications & Research Papers
│   ├── architecture.md             # System architecture & component interface spec
│   ├── severity-scoring.md         # Transparent 0-10 severity formula spec
│   └── findings-report.md          # Technical security research write-up
│
├── tests/                          # Automated Verification Suite (57 Tests)
│   ├── unit/                       # Unit tests (schemas, adapters, ground truth, root cause)
│   ├── integration/                # Integration tests (controller, fault injection, multi-framework)
│   ├── scenarios/                  # Scenario tests (cross-user isolation)
│   ├── system/                     # System CLI tests
│   └── property/                   # Property-based randomized fuzzing suite (Hypothesis)
│
├── reports/                        # Auto-generated Output Reports & PoCs
│   ├── sample_report.md
│   ├── sample_report.html
│   ├── results.json
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
This automatically starts the local reference target, executes experiment trials, and generates formatted reports in `reports/`.

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
python -m authtime.cli run --fault-type stale_cache --repetitions 3 --output-dir reports

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
