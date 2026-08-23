"""
AuthTime — Automated Repository Privacy, Security & Cleanliness Test Suite.
Verifies that tracked files do not contain sensitive developer paths, private keys,
or temporary junk files.
"""

import os
import subprocess
import pytest


def get_tracked_files():
    try:
        res = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [f for f in res.stdout.splitlines() if f]
    except Exception:
        pytest.skip("Git not available or not a git repository.")


def test_no_local_developer_windows_paths():
    """Verify that no local developer paths (C:\\Users\\, D:\\PROJECTS\\, SAISANDEEP) are in tracked source files."""
    tracked_files = get_tracked_files()

    forbidden_patterns = [
        "C:\\Users\\",
        "C:/Users/",
        "D:\\PROJECTS\\",
        "D:/PROJECTS/",
    ]

    violations = []
    for filepath in tracked_files:
        # Skip binary or auto-generated cache files and the test script itself
        if filepath.endswith((".png", ".jpg", ".svg", ".ico", ".db", ".zst")) or "test_repo_privacy_and_cleanliness.py" in filepath:
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            for pattern in forbidden_patterns:
                if pattern in content:
                    violations.append((filepath, pattern))
        except Exception:
            pass

    assert not violations, f"Forbidden local developer paths found in tracked files: {violations}"


def test_no_hardcoded_jwt_private_keys():
    """Verify that no raw RSA private keys are hardcoded in source files outside test key fixtures."""
    tracked_files = get_tracked_files()

    violations = []
    for filepath in tracked_files:
        # Ignore test files that intentionally contain RSA key fixtures
        if "test" in filepath or filepath.endswith(".pem"):
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if "-----BEGIN RSA PRIVATE KEY-----" in content or "-----BEGIN PRIVATE KEY-----" in content:
                violations.append(filepath)
        except Exception:
            pass

    assert not violations, f"Raw RSA private keys found in production files: {violations}"


def test_no_temporary_or_cache_files_tracked():
    """Verify that no .pyc, .log, or __pycache__ files are tracked in git."""
    tracked_files = get_tracked_files()

    forbidden_exts = (".pyc", ".pyo", ".log", ".tmp")
    violations = [f for f in tracked_files if f.endswith(forbidden_exts) or "__pycache__" in f]

    assert not violations, f"Temporary/cache files accidentally tracked in git: {violations}"
