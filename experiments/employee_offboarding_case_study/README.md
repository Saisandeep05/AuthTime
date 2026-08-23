# Employee Offboarding Case Study Artifacts

This folder contains durable evidence artifacts collected during the real-world **Employee Offboarding Temporal Authorization Exposure Case Study**.

## Case Study Summary

- **User**: `alice`
- **Initial Role**: `Finance Admin`
- **Revoked Role**: `Employee`
- **Protected Resource**: `/finance/payroll`
- **Mitigation Technique**: Authorization Versioning & Version-Aware Cache Validation
- **Validation Level**: Level B — Multi-Process Distributed Application Validation

## Empirical Key Metrics

| Metric | Vulnerable Baseline | Mitigated State | Improvement |
| :--- | :---: | :---: | :---: |
| **Max Exposure Duration** | `4.05s` | `0.00s` | **`100.0%`** |
| **Mean Exposure Duration** | `4.05s` | `0.00s` | **`100.0%`** |

## Artifact Manifest

- [`vulnerable-results.json`](vulnerable-results.json): Per-replica timing logs and aggregate metrics under vulnerable state.
- [`mitigated-results.json`](mitigated-results.json): Per-replica timing logs under Authorization Versioning mitigation.
- [`comparison.json`](comparison.json): Structured before/after metrics summary.
- [`raw-evidence/`](raw-evidence/): Raw HTTP probe logs captured during high-frequency trial execution.
