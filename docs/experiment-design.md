# AuthTime — Experiment Design & Timing Methodology

AuthTime measures authorization exposure windows through systematic, timed experiments against a local reference application.

---

## 1. Timing Mechanics

### Monotonic Clock & Calibration
- Duration measurements use Python's high-precision monotonic clock (`time.monotonic()`).
- UTC wall-clock timestamps (`datetime.now(timezone.utc)`) are recorded alongside for human-readable audit trails.
- Prior to experiment launch, a 20-probe calibration burst measures harness scheduling jitter (`scheduler_jitter_ms`).

### Exposure Window Formulas
- **Revocation Timestamp ($t_{\text{fault}}$)**: Monotonic time of fault injection.
- **First Observed Unauthorized Access ($t_{\text{first\_unauth}}$)**: First probe returning `ALLOW` post-revocation.
- **Last Observed Unauthorized Access ($t_{\text{last\_unauth}}$)**: Final probe returning `ALLOW` post-revocation.
- **First Reliably Blocked Access ($t_{\text{first\_block}}$)**: First probe returning `BLOCK` post-revocation.

$$\text{Exposure Interval} = [t_{\text{last\_unauth}} - t_{\text{fault}},\, t_{\text{first\_block}} - t_{\text{fault}}]$$
$$\text{estimated\_exposure} = \frac{(t_{\text{last\_unauth}} - t_{\text{fault}}) + (t_{\text{first\_block}} - t_{\text{fault}})}{2}$$
$$\text{precision} = \frac{t_{\text{first\_block}} - t_{\text{last\_unauth}}}{2}$$

---

## 2. Probing Strategies

### Coarse Probing
Default probe schedule offsets: `+0.0s`, `+1.0s`, `+5.0s`, `+30.0s`, `+60.0s`.

### Adaptive Binary Search Probing
When a transition from `ALLOW` at $t_{\text{last\_unauth}}$ to `BLOCK` at $t_{\text{first\_block}}$ is detected, the engine executes binary search probes between $[t_{\text{last\_unauth}}, t_{\text{first\_block}}]$ until target precision (e.g. $\le 100\text{ms}$) is achieved.

### Holistic Time-Scaling
When `time_scale.enabled` is `true`, ALL temporal parameters (probe offsets, JWT TTL, cache TTL, fault delays) scale uniformly by `time_scale.factor` (e.g. `0.1` for CI test acceleration).

---

## 3. Experiment Types

1. **Token Expiry Experiment**: Tests exposure during stateless JWT lifetime.
2. **Role Revocation Experiment**: Tests exposure when user role is modified in backend storage.
3. **Stale Cache Experiment**: Tests exposure while in-memory authorization cache retains stale entry.
4. **Cross-User Isolation Experiment**: Tests whether revoking User A impacts User B (detects `CACHE_KEY_COLLISION`).
5. **Matrix Experiments**: Sweeps combinations of $JWT\_TTL \times Cache\_TTL$.
