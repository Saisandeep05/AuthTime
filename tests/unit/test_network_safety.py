"""
Unit tests for Network Safety & Loopback IP Validation (`authtime.network.safety`).
"""

from authtime.network.safety import validate_and_resolve_loopback


def test_valid_loopback_urls():
    is_ok, ip, err = validate_and_resolve_loopback("http://127.0.0.1:8000")
    assert is_ok is True
    assert ip == "127.0.0.1"
    assert err == ""

    is_ok_lh, ip_lh, err_lh = validate_and_resolve_loopback("http://localhost:8000/admin/users")
    assert is_ok_lh is True
    assert err_lh == ""


def test_invalid_external_urls():
    is_ok, _, err = validate_and_resolve_loopback("http://example.com:8000")
    assert is_ok is False
    assert "SAFETY VIOLATION" in err

    is_ok_ext_ip, _, err_ext_ip = validate_and_resolve_loopback("http://8.8.8.8:8000")
    assert is_ok_ext_ip is False
    assert "SAFETY VIOLATION" in err_ext_ip


def test_invalid_schemes_and_credentials():
    is_ok, _, err = validate_and_resolve_loopback("ftp://127.0.0.1:8000")
    assert is_ok is False
    assert "Invalid scheme" in err

    is_ok_cred, _, err_cred = validate_and_resolve_loopback("http://admin:secret@127.0.0.1:8000")
    assert is_ok_cred is False
    assert "credentials" in err_cred
