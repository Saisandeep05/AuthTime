# AuthTime Security Verification Report: FIND-EXP-MAIN-1787488711-3

## Executive Summary
- **Protocol Version**: `1.0`
- **Schema Version**: `1.1`
- **Finding Title**: Authorization Exposure Finding: AUTHORIZATION_CACHE
- **Fault Type**: `stale_cache`
- **Severity Score**: `7.3 / 10.0` (**HIGH**)
- **Root Cause**: `AUTHORIZATION_CACHE` (Confidence: **PROVEN**)
- **Measurement Status**: `OBSERVED_TRANSITION`
- **Baseline Verification**: `PASSED`

---

## Exposure Window Metrics
- **Revocation Timestamp (t_fault)**: `7828.593s`
- **First Unauthorized Access (t_first_unauth)**: `7828.593s`
- **Last Unauthorized Access (t_last_unauth)**: `7831.609s`
- **First Blocked Access (t_first_block)**: `7834.625s`
- **Exposure Interval**: `[3.02s, 6.03s]`
- **Estimated Exposure**: `4.52s`
- **Measurement Precision**: `±1.51s`
- **Scheduler Jitter**: `13.60ms`


## Aggregate Trial Statistics (N=1)

> **Note**: Sample size N < 5 or right-censored data present: inferential P95 and standard deviation are suppressed.

- **Minimum Exposure**: `0.00s`
- **Maximum Exposure**: `0.00s`
- **Mean Exposure (µ)**: `0.00s`
- **Median Exposure (x̃)**: `4.52s`
- **Standard Deviation (σ)**: `0.00s`
- **95th Percentile (P95)**: `0.00s`


---

## Root Cause Explanation
Observed exposure boundary (4.52s) matches effective authorization cache TTL (6.00s; raw TTL=60.0s at 0.10x scale) within ±1.48s (24.6% relative tolerance).

### Real-World System Calibration
Experimental cache_ttl configured to 60.0s; this is a representative test value and is not evidence of a production default.

---

## Reproduction & PoC Script
```bash
curl -H 'Authorization: Bearer <token>' http://127.0.0.1:8000/admin/users
```
Standalone reproduction script generated at: [`reports/EXP-MAIN-1787488711-3/poc_EXP-MAIN-1787488711-3.py`](reports/EXP-MAIN-1787488711-3/poc_EXP-MAIN-1787488711-3.py)
