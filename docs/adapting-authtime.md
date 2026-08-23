# Adapting AuthTime to Custom Local Applications

AuthTime is designed as reusable testing infrastructure. While it includes a reference FastAPI target out of the box, it can be adapted to test any custom local application running on `127.0.0.1`.

---

## Adapter Interface Requirements

To test a custom local target, implement an adapter that provides two interfaces:

### 1. Fault Injection Interface
Expose or implement local hooks to trigger authorization events:
- `role_revocation`: Revoke a role or permission for a test user account.
- `token_expiry`: Invalidate token state or simulate token expiration.
- `stale_cache`: Inject or clear authorization cache entries.

### 2. Protected Probe Endpoints
Provide target HTTP endpoints that AuthTime can probe using JWT Bearer tokens.

---

## Safety Constraint

> [!CAUTION]
> AuthTime enforces a strict local safety boundary. Target URLs MUST resolve to `127.0.0.1` or `localhost`. Non-local target configurations will be rejected at runtime.
