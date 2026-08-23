# AuthTime Transparent Severity Scoring Formula Spec

AuthTime computes severity score (0.0 to 10.0) using an auditable, transparent mathematical model:

$$\text{Severity Score} = \min\left(10.0,\, S_{\text{exposure}} \times W_{\text{endpoint}} \times C_{\text{confidence}}\right)$$

### Components

1. **Exposure Factor ($S_{\text{exposure}}$)**:
   $$S_{\text{exposure}} = 3.0 + 2.5 \times \log_{10}(\text{estimated\_exposure\_sec} + 1.0)$$

2. **Endpoint Weight ($W_{\text{endpoint}}$)**:
   - Sensitive endpoints (e.g. `/admin/*`): `1.5`
   - General endpoints (e.g. `/invoices/*`): `1.0`

3. **Confidence Multiplier ($C_{\text{confidence}}$)**:
   - `High`: `1.0`
   - `Likely`: `0.85`
   - `Undetermined`: `0.70`

### Labels
- `9.0 – 10.0`: **CRITICAL**
- `7.0 – 8.9`: **HIGH**
- `4.0 – 6.9`: **MEDIUM**
- `0.0 – 3.9`: **LOW**
