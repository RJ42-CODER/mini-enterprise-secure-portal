"""
Configuration loader and startup validator for Secure Portal & Security Agent.
Loads settings from .env file with robust fallback parsing and validates required
telemetry and network parameters.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, Union, List, Set


def get_project_root() -> Path:
    """Return resolved Path to the secure-portal project root directory."""
    return Path(__file__).resolve().parent.parent


def load_portal_env(env_path: Optional[Union[str, Path]] = None) -> bool:
    """
    Load environment variables from project root .env file if present.
    Supports python-dotenv with a robust fallback parser if dotenv is not installed.
    Also synchronizes SOC_API_KEY and SOC_AGENT_TOKEN aliases.
    """
    if env_path:
        target_path = Path(env_path).resolve()
    else:
        env_override = os.getenv("PORTAL_ENV_FILE")
        if env_override:
            target_path = Path(env_override).resolve()
        else:
            target_path = get_project_root() / ".env"

    if not target_path.is_file():
        # Also check current working directory as a secondary fallback
        cwd_env = Path.cwd() / ".env"
        if cwd_env.is_file():
            target_path = cwd_env
        else:
            return False

    # Attempt to load using python-dotenv first
    loaded_via_dotenv = False
    try:
        from dotenv import load_dotenv
        load_dotenv(target_path, override=False)
        loaded_via_dotenv = True
    except ImportError:
        pass

    # Fallback / supplement: manual parser to guarantee loading even without python-dotenv
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
    except OSError:
        pass

    # Synchronize SOC_API_KEY and SOC_AGENT_TOKEN aliases
    api_key = os.getenv("SOC_API_KEY")
    agent_token = os.getenv("SOC_AGENT_TOKEN")
    if api_key and not agent_token:
        os.environ["SOC_AGENT_TOKEN"] = api_key
    elif agent_token and not api_key:
        os.environ["SOC_API_KEY"] = agent_token

    return True


def validate_portal_config() -> Dict[str, Any]:
    """
    Validate all required environment settings for Secure Portal and SOC integration.
    Collects and reports all missing settings at once to provide clear, actionable diagnostics.
    """
    cn_server_ip = os.getenv("CN_SERVER_IP")
    soc_url = os.getenv("SOC_URL")
    soc_token = os.getenv("SOC_API_KEY") or os.getenv("SOC_AGENT_TOKEN")

    missing: List[str] = []
    if not cn_server_ip or not cn_server_ip.strip():
        missing.append("CN_SERVER_IP (e.g. 192.168.31.91)")
    if not soc_url or not soc_url.strip():
        missing.append("SOC_URL (e.g. http://192.168.31.73:8443)")
    if not soc_token or not soc_token.strip():
        missing.append("SOC_API_KEY or SOC_AGENT_TOKEN (SOC Telemetry Bearer Token)")

    if missing:
        missing_list = "\n  - ".join(missing)
        raise ValueError(
            f"Portal configuration validation failed. The following required setting(s) are missing:\n"
            f"  - {missing_list}\n"
            f"Please configure them in your .env file (e.g. {get_project_root() / '.env'}) or environment."
        )

    # Format validations
    soc_url_clean = soc_url.strip().rstrip("/")
    if not (soc_url_clean.startswith("http://") or soc_url_clean.startswith("https://")):
        raise ValueError(f"Invalid SOC_URL '{soc_url}': Must start with http:// or https://")

    try:
        port = int(os.getenv("PORT", "5000"))
    except ValueError:
        raise ValueError(f"Invalid PORT '{os.getenv('PORT')}': Must be a valid integer port number.")

    flask_host = os.getenv("FLASK_HOST", "127.0.0.1")

    return {
        "CN_SERVER_IP": cn_server_ip.strip(),
        "SOC_URL": soc_url_clean,
        "PORT": port,
        "FLASK_HOST": flask_host,
        "SOC_AUTH_CONFIGURED": True,
        "SOC_EVENTS_ENDPOINT": os.getenv("SOC_EVENTS_ENDPOINT") or f"{soc_url_clean}/api/events"
    }


def get_trusted_proxies() -> Set[str]:
    """Return configured set of trusted proxy IP addresses."""
    trusted_env = os.getenv("TRUSTED_PROXIES", "")
    env_proxies = {p.strip() for p in trusted_env.split(",") if p.strip()}
    trusted: Set[str] = {"127.0.0.1", "::1", "localhost"} | env_proxies
    server_ip = os.getenv("CN_SERVER_IP")
    if server_ip and server_ip.strip():
        trusted.add(server_ip.strip())
    return trusted


def get_client_ip(req, trusted_proxies: Optional[Set[str]] = None) -> str:
    """
    Extract authentic client IP accounting for trusted reverse-proxy configuration.
    Forwarding headers (X-Forwarded-For, X-Real-IP) are ONLY trusted if the direct peer
    (req.remote_addr) is an explicitly verified trusted proxy (e.g. Nginx on loopback).
    Never trusts arbitrary client-supplied forwarding headers from untrusted connections.
    """
    direct_remote = getattr(req, "remote_addr", None) or "127.0.0.1"

    allowed_proxies = trusted_proxies if trusted_proxies is not None else get_trusted_proxies()

    # If the direct peer is not an authorized trusted proxy, ignore all forwarding headers
    if direct_remote not in allowed_proxies:
        return direct_remote

    headers = getattr(req, "headers", {})

    # 1. Check X-Forwarded-For (standard header; leftmost IP is the original client)
    forwarded_for = headers.get("X-Forwarded-For")
    if forwarded_for:
        parts = [p.strip() for p in forwarded_for.split(",") if p.strip()]
        if parts:
            return parts[0]

    # 2. Check X-Real-IP (set by Nginx proxy_set_header X-Real-IP $remote_addr)
    real_ip = headers.get("X-Real-IP")
    if real_ip and real_ip.strip():
        return real_ip.strip()

    # 3. Fallback to direct TCP socket address
    return direct_remote


def redact_sensitive_data(val: Any) -> Any:
    """
    Recursively sanitize dictionaries, lists, and strings to redact credentials,
    passwords, bearer tokens, and API keys.
    """
    sensitive_keys = {
        "password", "pass", "pwd", "secret", "token", "api_key", "apikey",
        "soc_api_key", "soc_agent_token", "authorization", "auth", "cookie"
    }
    if isinstance(val, dict):
        sanitized = {}
        for k, v in val.items():
            if str(k).lower() in sensitive_keys:
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = redact_sensitive_data(v)
        return sanitized
    elif isinstance(val, (list, tuple, set)):
        sanitized_list = [redact_sensitive_data(item) for item in val]
        return type(val)(sanitized_list)
    elif isinstance(val, str):
        # Redact Bearer tokens in headers
        if "Bearer " in val:
            import re
            return re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer [REDACTED]", val)
        return val
    return val


# Automatically execute env loading upon module import
load_portal_env()
