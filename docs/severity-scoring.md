# AuthTime — Transparent Severity Scoring Model (0–10)

AuthTime uses a transparent, deterministic formula to compute a `severity_score` (0.0 to 10.0) for every `SecurityFinding`.

---

## Formula Specification

$$\text{Severity Score} = \min\left(10.0,\, S_{\text{exposure}} \times W_{\text{endpoint}} \times C_{\text{confidence}}\right)$$

### 1. Exposure Factor ($S_{\text{exposure}}$)
Base score derived from estimated exposure duration $\text{estimated\_exposure\_sec}$:
$$S_{\text{exposure}} = \begin{cases} 0.0, & \text{estimated\_exposure\_sec} = 0 \\ 3.0 + 2.5 \times \log_{10}(\text{estimated\_exposure\_sec} + 1), & \text{estimated\_exposure\_sec} > 0 \end{cases}$$

### 2. Endpoint Sensitivity Weight ($W_{\text{endpoint}}$)
- `/admin/*`: $1.5$ (High sensitivity admin functionality)
- `/invoices/*`: $1.0$ (Standard protected user resource)
- Default / other: $1.0$

### 3. Root Cause Confidence Multiplier ($C_{\text{confidence}}$)
- `High` confidence: $1.0$
- `Likely` confidence: $0.85$
- `Undetermined` confidence: $0.70$

---

## Severity Scale Mapping

| Severity Score Range | Severity Label | Description |
| :--- | :--- | :--- |
| `0.0 – 3.9` | `LOW` | Minimal exposure window or low sensitivity endpoint. |
| `4.0 – 6.9` | `MEDIUM` | Moderate exposure window ($\le 10\text{s}$) on standard resource. |
| `7.0 – 8.9` | `HIGH` | Significant exposure window ($\le 60\text{s}$) or sensitive admin route. |
| `9.0 – 10.0` | `CRITICAL` | Extended exposure window ($> 60\text{s}$) on sensitive route. |
