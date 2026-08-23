# AuthTime Security Verification Report: FIND-EXP-MAIN-1787435225-3

## Executive Summary
- **Finding Title**: Authorization Exposure Finding: OBSERVATION_HORIZON_REACHED
- **Fault Type**: `stale_cache`
- **Severity Score**: `6.5 / 10.0` (**MEDIUM**)
- **Root Cause**: `OBSERVATION_HORIZON_REACHED` (Confidence: **SUPPORTED (Observation Horizon Reached)**)
- **Measurement Status**: `CENSORED_LOWER_BOUND`
- **Baseline Verification**: `PASSED`

---

## Exposure Window Metrics
- **Revocation Timestamp (t_fault)**: `42115.375s`
- **First Unauthorized Access (t_first_unauth)**: `42115.375s`
- **Last Unauthorized Access (t_last_unauth)**: `42121.375s`
- **First Blocked Access (t_first_block)**: `NOT OBSERVED`
- **Exposure Interval**: `[6.00s, ∞] (RIGHT-CENSORED at horizon 6.00s)`
- **Estimated Exposure**: `≥ 6.00s (Censored)`
- **Measurement Precision**: `UNBOUNDED (Censored Observation)`
- **Scheduler Jitter**: `15.20ms`


## Aggregate Trial Statistics (N=1)

- **Minimum Exposure**: `0.00s`
- **Maximum Exposure**: `0.00s`
- **Mean Exposure (µ)**: `0.00s`
- **Median Exposure (x̃)**: `0.00s`
- **Standard Deviation (σ)**: `0.00s`
- **95th Percentile (P95)**: `0.00s`


---

## Root Cause Explanation
Unauthorized access remained observable through the full observation horizon (6.00s). Consistent with extended exposure.

### Real-World System Calibration
Tested cache_ttl=60.0s. Mirrors standard API gateway caching defaults.

---

## Reproduction & PoC Script
```bash
curl -H 'Authorization: Bearer <token>' http://127.0.0.1:8000/admin/users
```
Standalone reproduction script generated at: [`reports/EXP-MAIN-1787435225-3/poc_EXP-MAIN-1787435225-3.py`](reports/EXP-MAIN-1787435225-3/poc_EXP-MAIN-1787435225-3.py)
