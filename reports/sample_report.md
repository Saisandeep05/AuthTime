# AuthTime Security Verification Report: FIND-EXP-MAIN-1787491866-3

## Executive Summary
- **Protocol Version**: `1.0`
- **Schema Version**: `1.1`
- **Run Identifier**: `RUN-20260823-e2713c11f4074eaa98654d771c341a44`
- **Finding Title**: Authorization Exposure Finding: OBSERVATION_HORIZON_REACHED
- **Fault Type**: `stale_cache`
- **Severity Score**: `5.4 / 10.0` (**MEDIUM**)
- **Root Cause**: `OBSERVATION_HORIZON_REACHED` (Confidence: **INFERRED**)
- **Measurement Status**: `CENSORED_LOWER_BOUND`
- **Baseline Verification**: `FAILED`
- **Cleanup Verification**: `FAILED`

---

## Exposure Window Metrics
- **Revocation Timestamp (t_fault)**: `10984.046s`
- **First Unauthorized Access (t_first_unauth)**: `10984.046s`
- **Last Unauthorized Access (t_last_unauth)**: `10990.046s`
- **First Blocked Access (t_first_block)**: `NOT OBSERVED`
- **Exposure Interval**: `[6.00s, ∞] (RIGHT-CENSORED at horizon 6.00s)`
- **Estimated Exposure**: `≥ 6.00s (Conservative Lower Bound)`
- **Measurement Precision**: `UNBOUNDED (Censored Observation)`
- **Scheduler Jitter**: `7.80ms`


## Aggregate Trial Statistics (N=0)

- **Minimum Exposure**: `0.00s`
- **Maximum Exposure**: `0.00s`
- **Mean Exposure (µ)**: `NOT ESTIMABLE (Right-Censored Data Present)`
- **Median Exposure (x̃)**: `0.00s`


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
Standalone reproduction script generated at: [`reports/poc/EXP-MAIN-1787491866-3_poc.py`](reports/poc/EXP-MAIN-1787491866-3_poc.py)
