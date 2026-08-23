# Contributing to AuthTime

Thank you for your interest in contributing to AuthTime!

## Safety First
- AuthTime is designed **exclusively** for local cybersecurity verification against local loopback target endpoints (`127.0.0.1` / `localhost`).
- Pull requests attempting to relax or remove safety target URL boundary checks will be rejected.

## Development Workflow
1. Create a feature branch off `main`.
2. Implement your changes following established Pydantic v2 schemas and FastAPI patterns.
3. Run the automated test suite using `pytest`. All tests must pass cleanly.
4. Ensure no real secrets, credentials, or PII are committed.
5. Submit a detailed Pull Request.
