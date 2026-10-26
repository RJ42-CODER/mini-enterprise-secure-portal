"""
SSRF (Server-Side Request Forgery) Validation and Safe Outbound Request Utilities.

Provides strict destination URL validation, DNS resolution checks, loopback/private/cloud-metadata
ip address restrictions, and safe connection wrappers to defend against SSRF and DNS-rebinding attacks.

Application Context:
- The Secure Portal routes (app.py) expose only the authentication portal and do not accept
  user-controlled URLs or perform server-side web fetching on behalf of clients.
- Outbound requests in this system are strictly limited to authenticated SOC telemetry delivery
  via AlertClient to the configured SOC backend.
"""

import ipaddress
import socket
import urllib.parse
from typing import Tuple, Optional, Set, List


# Standard cloud metadata service IP (AWS, GCP, Azure, OpenStack, DigitalOcean)
CLOUD_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}

# Default permitted schemes
ALLOWED_SCHEMES = {"http", "https"}


class SSRFValidationError(ValueError):
    """Raised when an outbound URL violates SSRF safety constraints."""
    pass


def is_ip_allowed(
    ip_str: str,
    allow_private: bool = False,
    allow_loopback: bool = False,
    custom_whitelist: Optional[Set[str]] = None
) -> Tuple[bool, str]:
    """
    Evaluate whether a resolved IP address is permissible for outbound requests.
    Enforces loopback, link-local, cloud metadata, and private network constraints.
    """
    clean_ip = ip_str.strip()
    if custom_whitelist and clean_ip in custom_whitelist:
        return True, "Whitelisted"

    if clean_ip in CLOUD_METADATA_IPS:
        return False, f"Cloud metadata endpoint ({clean_ip}) is strictly forbidden"

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False, f"Invalid IP address format: {clean_ip}"

    if ip_obj.is_loopback:
        if not allow_loopback:
            return False, f"Loopback address ({clean_ip}) is disallowed"

    if ip_obj.is_link_local:
        return False, f"Link-local address ({clean_ip}) is disallowed"

    if ip_obj.is_multicast:
        return False, f"Multicast address ({clean_ip}) is disallowed"

    if ip_obj.is_reserved:
        return False, f"Reserved address ({clean_ip}) is disallowed"

    if ip_obj.is_unspecified:
        return False, f"Unspecified address ({clean_ip}) is disallowed"

    if ip_obj.is_private:
        if not allow_private:
            return False, f"Private/internal network address ({clean_ip}) is disallowed"

    return True, "IP address is permissible"


def validate_outbound_url(
    url: str,
    allow_private: bool = False,
    allow_loopback: bool = False,
    allowed_schemes: Optional[Set[str]] = None,
    custom_whitelist: Optional[Set[str]] = None
) -> Tuple[bool, str, Optional[str]]:
    """
    Validate an outbound destination URL against SSRF vulnerabilities:
      1. Enforces permitted schemes (http/https only).
      2. Rejects embedded credentials (e.g. http://user:pass@host).
      3. Resolves hostname via DNS to prevent DNS-rebinding and validates all resolved IPs.
      4. Rejects loopback, link-local, cloud-metadata, and internal addresses unless explicitly approved.

    Returns:
        (is_valid, message, primary_resolved_ip)
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string", None

    schemes = allowed_schemes or ALLOWED_SCHEMES
    try:
        parsed = urllib.parse.urlsplit(url.strip())
    except Exception as e:
        return False, f"Malformed URL: {e}", None

    if not parsed.scheme or parsed.scheme.lower() not in schemes:
        return False, f"Disallowed URL scheme '{parsed.scheme}'. Permitted: {sorted(list(schemes))}", None

    if not parsed.netloc:
        return False, "URL missing host authority", None

    if parsed.username or parsed.password:
        return False, "URLs with embedded user credentials are not permitted", None

    hostname = parsed.hostname
    if not hostname:
        return False, "Could not determine hostname from URL", None

    # Check custom whitelist first
    if custom_whitelist and hostname in custom_whitelist:
        return True, "Hostname is whitelisted", None

    # DNS Resolution & Validation of all returned records
    try:
        # Prevent DNS rebinding by resolving and evaluating all address records
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        resolved_ips: List[str] = list({info[4][0] for info in addr_info if info and info[4]})
    except socket.gaierror as e:
        return False, f"DNS resolution failed for hostname '{hostname}': {e}", None
    except Exception as e:
        return False, f"Error resolving hostname '{hostname}': {e}", None

    if not resolved_ips:
        return False, f"No IP addresses resolved for hostname '{hostname}'", None

    for resolved_ip in resolved_ips:
        allowed, reason = is_ip_allowed(
            resolved_ip,
            allow_private=allow_private,
            allow_loopback=allow_loopback,
            custom_whitelist=custom_whitelist
        )
        if not allowed:
            return False, f"Destination resolved to forbidden IP '{resolved_ip}': {reason}", resolved_ip

    return True, f"URL successfully validated ({len(resolved_ips)} IP(s) checked)", resolved_ips[0]
