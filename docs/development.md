# AuthTime — Development & Workflow Guide

## Prerequisites & Installation

- Python 3.10+
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```

## Development Workflow Loop

Every development phase follows this strict workflow loop:
```
IMPLEMENT → LOCAL TEST → REVIEW DIFF → SECRET CHECK → COMMIT → PUSH → GITHUB ACTIONS → VERIFY CI RESULT
```

## Running Tests

- Run complete automated test suite:
  ```bash
  pytest -v
  ```

## Running AuthTime CLI

- Run complete MVP experiment suite locally:
  ```bash
  python run.py
  ```

## Safety Enforcement

- Reference application target URL must be `http://127.0.0.1:8000` or `http://localhost:8000`.
- Non-local target configurations will be rejected immediately by runtime safety guards.
