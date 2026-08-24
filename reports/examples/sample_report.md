# AuthTime Security Verification Report: FIND-EXP-MAIN-1787592981-3

## Executive Summary
- **Protocol Version**: `1.0`
- **Schema Version**: `1.1`
- **Run Identifier**: `RUN-20260824-e7e120e05bd8430a9d380e9db1759bf6`
- **Finding Title**: Authorization Exposure Finding: OBSERVATION_HORIZON_REACHED
- **Fault Type**: `stale_cache`
- **Severity Score**: `5.4 / 10.0` (**MEDIUM**)
- **Root Cause**: `OBSERVATION_HORIZON_REACHED` (Confidence: **INFERRED**)
- **Measurement Status**: `CENSORED_LOWER_BOUND`
- **Baseline Verification**: `PASSED`
- **Cleanup Verification**: `VERIFIED`

---

## Exposure Window Metrics & Timing Methodology
- **Revocation Timestamp (t_fault)**: `6880.078s`
- **First Unauthorized Access (t_first_unauth)**: `6880.078s`
- **Last Unauthorized Access (t_last_unauth)**: `6886.078s`
- **First Blocked Access (t_first_block)**: `NOT OBSERVED`
- **Exposure Interval**: `[6.00s, ∞] (RIGHT-CENSORED at horizon 6.00s)`
- **Estimated Exposure**: `≥ 6.00s (Conservative Lower Bound)`
- **Measurement Precision**: `UNBOUNDED (Censored Observation)`
- **Scheduler Jitter**: `11.30ms`


## Aggregate Trial Statistics (N=3)

> **Note**: Sample size N < 5 or right-censored data present: ordinary mean and P95 are suppressed (NOT ESTIMABLE).

- **Minimum Exposure**: `3.00s`
- **Maximum Exposure**: `6.00s`
- **Mean Exposure (µ)**: `NOT ESTIMABLE (Right-Censored Data Present)`
- **Median Exposure (x̃)**: `6.00s`


---

## Root Cause Explanation
Unauthorized access remained observable through the full observation horizon (6.00s). Consistent with extended exposure.

### Real-World System Calibration
Experimental cache_ttl configured to 60.0s; this is a representative test value and is not evidence of a production default.

---

## Reproduction & PoC Script
```bash
curl -H 'Authorization: Bearer <token>' http://127.0.0.1:8000/admin/users
```
Standalone reproduction script generated at: [`reports/poc/sample_poc.py`](../poc/sample_poc.py)
