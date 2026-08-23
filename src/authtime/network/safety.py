"""
Network Safety, URL Validation, and Loopback IP Resolution for AuthTime.
Centralizes scheme, hostname, port, and IPv4/IPv6 getaddrinfo validation.
"""

import socket
import ipaddress
from urllib.parse import urlparse
from typing import Tuple


def validate_and_resolve_loopback(target_url: str) -> Tuple[bool, str, str]:
    """
    Validates URL safety and resolves hostname to IP addresses via getaddrinfo.
    Enforces loopback-only safety constraints (127.0.0.1 / ::1 / localhost).
    Returns tuple of (is_valid: bool, resolved_ip: str, error_message: str).
    """
    if not target_url or not isinstance(target_url, str):
        return False, "", "URL must be a non-empty string"

    try:
        parsed = urlparse(target_url)
    except Exception as e:
        return False, "", f"URL parsing error: {e}"

    if parsed.scheme not in ("http", "https"):
        return False, "", f"Invalid scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed."

    if parsed.username or parsed.password:
        return False, "", "Embedded credentials in URL are prohibited."

    hostname = parsed.hostname
    if not hostname:
        return False, "", "Missing hostname in URL."

    # Validate allowed loopback hostnames
    if hostname not in ("127.0.0.1", "localhost", "::1"):
        return False, "", f"SAFETY VIOLATION: Target hostname '{hostname}' is non-local! AuthTime is restricted to loopback addresses."

    # Perform socket getaddrinfo resolution to validate all IP addresses
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return False, "", f"DNS resolution returned no addresses for hostname '{hostname}'"

        resolved_ips = set()
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip_str = sockaddr[0]
            resolved_ips.add(ip_str)
            ip_obj = ipaddress.ip_address(ip_str)
            if not ip_obj.is_loopback:
                return False, ip_str, f"SAFETY VIOLATION: Resolved IP '{ip_str}' for hostname '{hostname}' is not a local loopback IP!"

        primary_ip = sorted(list(resolved_ips))[0]
        return True, primary_ip, ""

    except Exception as e:
        return False, "", f"DNS resolution failure for hostname '{hostname}': {e}"
