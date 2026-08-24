# Contributing to AuthTime

Thank you for your interest in contributing to AuthTime! AuthTime is an open-source security verification engine for measuring temporal authorization exposure windows ($\Delta t_{\text{exp}}$) in distributed architectures.

This guide outlines our safety principles, developer environment setup, architecture overview, and how to extend AuthTime by adding custom target adapters and fault scenarios.

---

## 🛡️ Safety & Ethical Boundaries

AuthTime is designed **exclusively** for controlled cybersecurity verification against local loopback target endpoints (`127.0.0.1`, `localhost`, `::1`).

1. **Loopback Only**: All network probes and fault injections are strictly constrained to local loopback interfaces (`validate_and_resolve_loopback`).
2. **No Third-Party Probing**: Pull requests attempting to relax or remove safety target URL boundary checks will be **immediately rejected**.
3. **No Embedded Credentials/PII**: Never commit real API tokens, private keys, or actual user data.

---

## 🏗️ Architecture Overview

AuthTime is structured as a modular measurement engine:

```text
src/authtime/
├── adapters/          # Target framework contracts & HTTP/gRPC adapters
├── controller/        # Experiment execution coordinator & concurrency lock
├── events/            # Event collector & correlation tracker
├── fault_injector/    # Controlled revocation fault injection client
├── ground_truth/      # Expected authorization state manager
├── history/           # Cross-run regression tracker (JSONL)
├── lifecycle/         # Finite State Machine enforcing trial state rules
├── models/            # Pydantic v2 domain schemas and raw evidence models
├── network/           # Loopback IP resolution & safety boundary validation
├── reporting/         # MD/HTML/JSON report & standalone PoC generator
├── scenarios/         # Scenario parameter generators (stale cache, cross-user)
├── statistics/        # Kaplan-Meier survival estimator & formatting
└── verification/      # High-resolution HTTP prober & root cause analyzer
```

---

## 🔌 Extending AuthTime: Implementing a Custom Target Adapter

AuthTime uses standardized adapters to interact with different backend target frameworks (e.g., FastAPI, Express, Django, Go, or Rust services).

To add support for a new target framework or API protocol:

### 1. Subclass `BaseTargetAdapter`

Create a new file in `src/authtime/adapters/` and subclass `BaseTargetAdapter` ([`target_adapter.py`](src/authtime/adapters/target_adapter.py)):

```python
from typing import Tuple, Dict, Any, Optional
import httpx
from authtime.adapters.target_adapter import BaseTargetAdapter

class MyCustomTargetAdapter(BaseTargetAdapter):
    def __init__(self, target_url: str, http_client: Optional[httpx.AsyncClient] = None):
        super().__init__(target_url, http_client=http_client)

    async def verify_identity(self) -> Dict[str, Any]:
        """Queries /target/identity and returns health/metadata dictionary."""
        # Must return dict containing at least {"product": "AuthTime", ...}
        ...

    async def reset_state(self) -> bool:
        """Resets target authorization caches and databases to default clean state."""
        ...

    async def login_user(self, user_id: str) -> str:
        """Obtains a valid auth token for the target user."""
        ...

    async def probe_endpoint(
        self, resource_path: str, token: str, request_id: str
    ) -> Tuple[int, str, float]:
        """
        Fires a probe request against resource_path.
        Returns: (status_code, body_text, latency_ms)
        """
        ...
```

### 2. Define a `ResourceContract`

Specify how HTTP status codes and JSON payloads map to `ALLOW` vs `DENY` decisions:

```python
from authtime.adapters.contract import ResourceContract

MY_CUSTOM_CONTRACT = ResourceContract(
    resource_path="/api/v1/protected",
    accepted_status_codes=[200, 201],
    denial_status_codes=[401, 403],
    denial_json_values=["unauthorized", "forbidden", "revoked"],
    required_json_keys=["data", "result"],
)
```

---

## 💻 Local Development Workflow

### 1. Clone & Install in Editable Mode

```bash
git clone https://github.com/Saisandeep05/AuthTime.git
cd AuthTime

# Install runtime and test dependencies
pip install -r requirements.txt

# Install authtime in editable mode
pip install -e .
```

### 2. Running the Test Suite

AuthTime enforces a strict test verification rule before completing any PR:

```bash
# Run full automated test suite (Unit, Integration, Fuzzing, Invariants)
pytest -v

# Run only unit tests
pytest tests/unit/ -v

# Run static architectural invariant checks
pytest tests/unit/test_static_architectural_invariants.py -v
```

### 3. Key Invariants to Maintain

When making changes, ensure the following core invariants remain satisfied:
- **Zero-Dependency PoCs**: Generated reproduction PoC scripts in `reporting/generator.py` MUST remain 100% standalone using only standard Python 3.8+ library and `httpx`.
- **No Swallowed Exceptions**: Exception handlers in core modules must log diagnostic messages via `authtime.logging.logger.debug` rather than silently passing (`except Exception: pass`).
- **Loopback Enforcement**: Every outbound network request must pass through `validate_and_resolve_loopback`.

---

## 📜 Pull Request Guidelines

1. **Branching**: Create a clean feature branch off `main` (`feature/your-feature-name`).
2. **Commit Messages**: Follow standard conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
3. **Verification Evidence**: Include command output showing `pytest -v` passing with zero failures.
4. **Documentation**: Update relevant Markdown docs in `docs/` or `README.md` if changing user-facing APIs or capabilities.
