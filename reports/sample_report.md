# AuthTime Security Verification Report: FIND-EXP-DEMO-1787410614-3

## Executive Summary
- **Finding Title**: Authorization Exposure Finding: AUTHORIZATION_CACHE
- **Fault Type**: `stale_cache`
- **Severity Score**: `6.5 / 10.0` (**MEDIUM**)
- **Root Cause**: `AUTHORIZATION_CACHE` (Confidence: **Likely**)
- **Baseline Verification**: `PASSED`

---

## Exposure Window Metrics
- **Revocation Timestamp (t_fault)**: `17503.671s`
- **First Unauthorized Access (t_first_unauth)**: `17503.671s`
- **Last Unauthorized Access (t_last_unauth)**: `17509.671s`
- **First Blocked Access (t_first_block)**: `0.000s`
- **Exposure Interval**: `[6.00s, 6.00s]`
- **Estimated Exposure**: `6.00s`
- **Measurement Precision (±)**: `0.00s`
- **Scheduler Jitter**: `13.60ms`


## Aggregate Trial Statistics (N=3)

> **Note**: If N < 5, the report must explicitly identify the result as a limited-sample observation and must avoid inferential statistical claims.

- **Minimum Exposure**: `4.51s`
- **Maximum Exposure**: `6.00s`
- **Mean Exposure (µ)**: `5.50s`
- **Median Exposure (x̃)**: `6.00s`
- **Standard Deviation (σ)**: `0.86s`
- **95th Percentile (P95)**: `6.00s`


---

## Root Cause Explanation
Authorization cache retained stale role/permissions for up to 60.0 seconds.

### Real-World System Calibration
Tested cache_ttl=60.0s. Mirrors standard API gateway caching defaults.

---

## Reproduction & PoC Script
```bash
curl -H 'Authorization: Bearer <token>' http://127.0.0.1:8000/admin/users
```
Standalone reproduction script generated at: [`reports/poc/EXP-DEMO-1787410614-3_poc.py`](reports/poc/EXP-DEMO-1787410614-3_poc.py)
