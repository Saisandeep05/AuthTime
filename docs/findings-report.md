# Quantifying Temporal Authorization Exposure Windows in Distributed Caching Systems

**Abstract**:
Modern web architectures rely heavily on memory TTL caches, API gateways, and stateless JSON Web Tokens (JWT) to reduce database read pressure and lower API latencies. However, when an administrator revokes a user's permissions or downgrades an account role in the primary database, authorization state changes are rarely propagated synchronously across all application replicas. This document presents the empirical methodology and results of **AuthTime**, a specialized framework for measuring the *Temporal Authorization Exposure Window* ($\Delta t_{\text{exp}}$) during controlled revocation fault injection.

---

## 1. Introduction & Threat Model

In a standard Role-Based Access Control (RBAC) architecture, authorization decisions should adhere strictly to the principle of immediate revocation: once an identity's access rights are revoked at time $t_{\text{fault}}$, any subsequent HTTP request at $t > t_{\text{fault}}$ must return `403 Forbidden`.

In practice, distributed applications introduce caching layers to optimize authorization checks:

$$\text{Decision}(u, r, t) = \begin{cases} \text{Cache}[u] & \text{if } t < t_{\text{cache\_expire}} \\ \text{Database}[u] & \text{otherwise} \end{cases}$$

When $t_{\text{fault}} < t < t_{\text{cache\_expire}}$, a temporal gap opens wherein the database reports `DENY` but the application cache evaluates to `ALLOW`. An attacker with a revoked credential can exploit this window to perform unauthorized actions.

---

## 2. Experimental Methodology

AuthTime quantifies this vulnerability through a four-stage experimental loop:

1. **Ground Truth Baseline ($\mathcal{GT}$)**: Evaluates policy state dynamically based on recorded fault injection timestamps.
2. **Controlled Fault Injection**: Programmatically injects role revocations and stale cache entries with configurable TTLs.
3. **Monotonic Timing & Adaptive Binary Search Probing**:
   - Fires HTTP probes calibrated against system scheduler jitter.
   - Executes adaptive binary search to pinpoint the boundary between `200 OK` (unauthorized access) and `403 Forbidden` (blocked access) to within $\le 100\text{ms}$ precision.
4. **Severity Scoring & Root Cause Analysis**:
   Calculates an auditable severity score ($0.0 \dots 10.0$) using the formula:
   $$\text{Severity} = \min\left(10.0,\, 3.0 \cdot \log_{10}(\text{Exposure\_Sec} + 1.0) + \text{Impact\_Weight}\right)$$

---

## 3. Empirical Results & Findings

Testing against reference authorization targets yielded the following baseline metrics:

| Scenario | Injected Cache TTL | Measured Exposure Window ($\Delta t_{\text{exp}}$) | Precision | Root Cause | Severity Score |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Stale Cache (10s)** | 10.0s | **10.00s** | $\pm 0.05\text{s}$ | `AUTHORIZATION_CACHE` | **6.2 (MEDIUM)** |
| **Stale Cache (30s)** | 30.0s | **30.00s** | $\pm 0.05\text{s}$ | `AUTHORIZATION_CACHE` | **7.5 (HIGH)** |
| **Cross-User Isolation** | N/A | **0.00s** | $\pm 0.01\text{s}$ | `NONE` | **0.0 (NONE)** |

### Headline Observation:
Without explicit cache invalidation mechanisms, access revocation latency is **100% bound to the configured cache TTL**. Revoked credentials remain fully functional for the entire duration of the TTL.

---

## 4. Remediation & Defense Recommendations

To eliminate or bound the temporal authorization exposure window:

1. **Event-Driven Cache Invalidation**:
   Publish revocation events over Pub/Sub (e.g., Redis, Kafka) upon any DB role mutation to purge stale authorization keys instantly across all application nodes.
2. **OpenID CAEP / Shared Signals Framework (SSF)**:
   Adopt CAEP push revocation standards (`https://schemas.openid.net/secevent/caep`) for cross-domain session invalidation.
3. **Short TTLs & Bounded Exposure**:
   Where synchronous invalidation is infeasible, cap authorization cache TTLs to $\le 5.0\text{s}$ to minimize the window of vulnerability.

---

## 5. Security & Safety Controls

AuthTime enforces hardcoded loopback restrictions (`127.0.0.1` / `localhost`) across all target URLs and fault injection controllers to prevent accidental execution against external network targets.
