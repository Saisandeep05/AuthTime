# AuthTime — Development Log

| Phase | Checkpoint | Changes | Test Result | Commit Hash | Known Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Phase 1** | Project Setup & Architecture | Initialized repository structure, `requirements.txt`, `LICENSE`, `CONTRIBUTING.md`, Pydantic schemas in `authtime/models/schemas.py`, and documentation suite in `docs/`. | 3/3 passed | `79463c9` | Target app and harness implementation begins in Phase 2. |
| **Phase 2** | Reference Auth Target (`app/`) | Implemented FastAPI reference application factory, JWT generation/validation, custom RBAC roles, in-memory TTL auth cache, protected routes (`/invoices`, `/admin/users`), and local-only fault API (`/faults/inject`, `/faults/reset`). | 11/11 passed | `8188be7` | Single instance local target; multi-node support scheduled for post-MVP. |
