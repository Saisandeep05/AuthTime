# AuthTime Repository Curation & Structural Audit Report

This document records the systematic inventory, dependency reference audit, structural curation, and validation results for the **AuthTime** repository.

---

## 🌐 1. Repository Architectural Structure

```text
AuthTime/
├── README.md                           # Master project overview & quickstart
├── LICENSE                             # MIT Open Source License
├── SECURITY.md                         # Responsible security disclosure policy
├── CONTRIBUTING.md                     # Engineering contribution guidelines
├── pyproject.toml                      # Build metadata & dependency specs
├── requirements.txt                    # Python dependencies
├── .env.example                        # Environment variables template
├── config.example.json                 # Target configuration template
├── Dockerfile                          # Primary single-app reference target Dockerfile
├── Dockerfile.lab                      # Distributed lab multi-replica Dockerfile
├── docker-compose.yml                  # Primary reference target Compose setup
├── docker-compose.lab.yml              # Distributed lab Compose environment (PostgreSQL + Redis + 3 API replicas)
├── docker-compose.multi-node.yml       # Multi-node loopback cluster setup
├── run.py                              # Top-level interactive runner script
│
├── src/                                # Primary Source Packages
│   ├── app/                            # Reference FastAPI Target Application
│   │   ├── api/endpoints.py            # Protected routes & fault injection endpoints
│   │   ├── auth/jwt.py                 # JWT token generation & verification
│   │   ├── cache/ttl_cache.py          # In-memory TTL authorization cache
│   │   ├── rbac/roles.py               # RBAC role definitions
│   │   ├── static/index.html           # Target web UI
│   │   └── main.py                     # Target application entrypoint
│   │
│   ├── authtime/                       # Core Monotonic Timing & Probing Engine
│   │   ├── adapters/                   # Target adapter interfaces & HTTP prober
│   │   ├── controller/                 # Experiment controller & trial runner
│   │   ├── events/                     # Audit event collector & correlation
│   │   ├── fault_injector/             # Controlled HTTP fault injector client
│   │   ├── ground_truth/               # Ground truth state manager
│   │   ├── history/                    # Exposure regression tracker
│   │   ├── models/                     # Evidence & Pydantic validation schemas
│   │   ├── network/                    # Loopback safety boundary enforcement
│   │   ├── reporting/                  # Report generator & PoC script generator
│   │   ├── scenarios/                  # Scenario generator & offset matrix
│   │   ├── statistics/                 # Kaplan-Meier censoring & statistical metrics
│   │   ├── timing/                     # Monotonic clock & prober timing math
│   │   ├── verification/               # Adaptive prober, predicate, & root cause analyzer
│   │   └── cli.py                      # Command-line interface entrypoint
│   │
│   └── targets/                        # CAEP Target Adapter
│       └── caep_target.py              # CAEP target adapter implementation
│
├── targets/                            # Experiment Target Replicas & Distributed Lab
│   ├── caep/server.py                  # OpenID CAEP/SSF push revocation server
│   ├── django/app.py                   # Django target replica application
│   ├── express/server.js               # Node.js Express target replica server
│   └── distributed_lab/                # Multi-Replica Validation Laboratory
│       ├── auth/jwt_handler.py         # Shared JWT handler with versioning claim
│       ├── cache/redis_cache.py        # Redis pub/sub invalidation bus & fault modes
│       ├── db/store.py                 # State store abstraction (InMemory & PostgreSQL)
│       └── service/app.py              # Multi-replica FastAPI application factory
│
├── tests/                              # Automated Verification Suite
│   ├── unit/                           # Unit tests (math, adapters, schemas, root cause)
│   ├── integration/                    # Integration tests (controller, events, multi-framework)
│   ├── infrastructure/                 # Level C infrastructure tests (PostgreSQL, Redis, replicas)
│   ├── property/                       # Property-based fuzzing suite (Hypothesis)
│   ├── system/                         # CLI system integration tests
│   ├── test_case_study.py              # Employee offboarding case study test suite
│   ├── test_mitigation_failure_modes.py# Fail-closed security tests
│   └── test_race_conditions.py         # 7 authorization race condition tests
│
├── docs/                               # Project Documentation Suite
│   ├── architecture.md                 # System architecture & component boundaries
│   ├── engineering-methodology.md      # Software engineering methodology & capability map
│   ├── findings-report.md              # Technical security research write-up
│   ├── distributed-validation-results.md # Empirical multi-replica validation evidence
│   ├── mitigation-tradeoff-report.md   # Tradeoff & overhead benchmark report
│   ├── real-world-case-study.md        # Employee offboarding case study
│   ├── severity-scoring.md             # Transparent 0-10 severity formula spec
│   ├── repository-curation.md          # Curation audit report (this document)
│   └── development/                    # Development History
│       └── DEVELOPMENT_LOG.md          # Milestone development log
│
├── experiments/                        # Empirical Evidence Artifacts
│   ├── employee_offboarding_case_study/# Offboarding scenario raw evidence & results
│   └── infrastructure_validation/      # Level C infrastructure scenario evidence JSONs
│
├── reports/examples/                   # Reusable Sample Artifacts
│   ├── results.json                    # Sample raw experiment results
│   ├── sample_report.md                # Sample markdown exposure report
│   └── sample_report.html              # Sample HTML exposure report
│
├── scripts/                            # Standalone Utility & Test Scripts
│   ├── benchmark_mitigation.py         # Performance overhead benchmarking CLI
│   ├── run_case_study.py               # Offboarding case study runner
│   ├── run_endurance_test.py           # Long-run endurance tester
│   └── run_load_test.py                # High-concurrency load tester
│
└── assets/                             # Displayed Visual Assets
    ├── animations/                     # SVG animation diagrams
    └── diagrams/                       # SVG architecture flow diagrams
```

---

## 📋 2. Inventory Classification Matrix

| File Path | Classification | Rationale |
| :--- | :--- | :--- |
| `src/authtime/` | **A. Core Required** | Core timing, probing, controller, and reporting engine |
| `src/app/` | **A. Core Required** | Primary FastAPI reference target application |
| `targets/distributed_lab/` | **B. Required Infrastructure** | Multi-replica distributed validation laboratory |
| `targets/express/` | **E. Required Example** | Node.js Express target replica server |
| `targets/django/` | **E. Required Example** | Django target replica application |
| `targets/caep/` | **E. Required Example** | OpenID CAEP/SSF push revocation server |
| `tests/` | **C. Required Testing** | Complete 89-test verification suite |
| `docs/*.md` | **D. Required Documentation** | Technical research, architecture, and case study reports |
| `experiments/` | **E. Required Evidence** | Empirical JSON evidence artifacts |
| `reports/examples/` | **E. Required Example** | Canonical sample output reports |
| `assets/` | **F. Active Asset** | SVGs rendered in `README.md` |
| `scripts/` | **C/E. Required Tool/Script** | Standalone load, endurance, and benchmarking CLI scripts |
| `.gitignore` | **G. Generated Gitignore** | Excludes temporary logs, caches, and `reports/poc/EXP-*.py` |

---

## 🧪 3. Validation Summary

```text
================= 85 passed, 4 skipped, 3 warnings in 29.81s ==================
```

All 89 unit, integration, infrastructure, property, and system tests were verified cleanly without regression.
