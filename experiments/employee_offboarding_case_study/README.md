# Employee Offboarding Case Study Artifacts

This folder contains durable evidence artifacts collected during the real-world **Employee Offboarding Temporal Authorization Exposure Case Study**.

## Case Study Summary

- **User**: `alice`
- **Initial Role**: `Finance Admin`
- **Revoked Role**: `Employee`
- **Protected Resource**: `/finance/payroll`
- **Mitigation Technique**: Authorization Versioning & Version-Aware Cache Validation
- **Validation Level**: Level B — Multi-Process Distributed Application Validation
- **Git Commit**: `df5c6e22ad875677aebaf70c3b6b366c7ba0a992`

## Empirical Results Summary (5 Runs)

| Metric | Vulnerable Baseline | Mitigated State | Measured Improvement |
| :--- | :---: | :---: | :---: |
| **Max Exposure Duration ($\Delta t_{\text{exp}}$)** | `4.25s` | `0.00s` | **`100.0% Reduction`** |
| **Mean Replica Exposure Duration** | `4.22s` | `0.00s` | **`100.0% Reduction`** |

> **Scientific Qualification**: No post-revocation ALLOW decision was observed within the configured measurement resolution ($\le 100\text{ms}$ probe interval).

## Artifact Manifest

- [`vulnerable-results.json`](vulnerable-results.json): Per-replica timing logs and aggregate metrics under vulnerable state.
- [`mitigated-results.json`](mitigated-results.json): Per-replica timing logs under Authorization Versioning mitigation.
- [`comparison.json`](comparison.json): Structured before/after metrics summary with reproducibility metadata.
- [`raw-evidence/`](raw-evidence/): Raw HTTP probe logs captured during high-frequency trial execution.
