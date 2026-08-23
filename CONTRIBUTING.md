# Contributing to AuthTime

Thank you for your interest in AuthTime — Temporal Authorization Attack & Verification Engine.

## Local Development & Testing

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Test Suite**:
   ```bash
   pytest -v
   ```

3. **Run Local Target & Engine**:
   ```bash
   python run.py
   ```

## Development Guidelines

- **Local Safety Boundary**: All testing must operate strictly against `127.0.0.1`. Do not add features that target external domains or network interfaces.
- **Monotonic Timing**: Use `time.monotonic()` for all duration/interval calculations.
- **Clean Code & Typings**: Use Pydantic v2 schemas for all experiment data structures.
- **Commit Format**: Use conventional commit messages (`feat(...)`, `fix(...)`, `test(...)`, `docs(...)`).
