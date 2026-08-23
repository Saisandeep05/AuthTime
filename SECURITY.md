# Security Policy & Vulnerability Disclosure Procedure

## 🛡️ Scope & Safety Guarantees

**AuthTime** is a security verification framework designed exclusively for local reference targets, staging environments, and authorized penetration testing against local loopback interfaces (`127.0.0.1`, `localhost`, `::1`).

AuthTime is **not** designed or licensed for unauthorized network scanning, real-world credential brute-forcing, or testing against non-local third-party applications without explicit written authorization.

---

## 🔒 Reference Application Security Model

The reference target application (`src/app/`) included in this repository contains deliberately injected vulnerabilities (such as authorization cache staleness and permissive fault endpoints) for scientific research and verification testing.

- **DO NOT** deploy the reference target application (`src/app/`) in production or public-facing internet environments.
- **DO NOT** use the default secret keys (`AUTHTIME_SECRET_KEY`) outside isolated local testing.

---

## 📩 Reporting Security Vulnerabilities

If you discover a vulnerability in the AuthTime verification engine or CLI itself, please report it responsibly:

1. **Email**: Open an issue or contact the maintainer directly at `Saisandeep05@users.noreply.github.com`.
2. **Details**: Provide a detailed description of the flaw, reproduction steps, and potential impact.
3. **Disclosure Timeline**: We commit to acknowledging reports within **48 hours** and providing a fix or remediation roadmap within **14 days**.

---

## 📜 Safe Harbor

Activities conducted in accordance with this security policy against local reference targets are considered authorized and safe-harbor research.
