from __future__ import annotations

import hashlib
import ipaddress
import logging
import socket
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict
from urllib.parse import urlparse


logger = logging.getLogger("mcp_server.security")


def redact_secret(secret: str) -> str:
    if len(secret) <= 6:
        return "***"
    return f"{secret[:3]}...{secret[-3:]}"


def secret_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",
    "100.100.100.200",
}


def _is_private_or_internal_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def validate_url_safety(endpoint: str) -> None:
    parsed = urlparse(endpoint)
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS endpoints are allowed")
    if parsed.hostname is None:
        raise ValueError("Invalid endpoint hostname")

    hostname = parsed.hostname.lower().strip(".")
    if hostname in BLOCKED_HOSTNAMES:
        raise ValueError("Blocked hostname")

    try:
        infos = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed: {exc}") from exc

    ips = {info[4][0] for info in infos}
    for ip in ips:
        if _is_private_or_internal_ip(ip):
            raise ValueError(f"Endpoint resolved to internal/private IP: {ip}")


@dataclass
class RateLimitConfig:
    requests: int = 60
    per_seconds: int = 60


class SlidingWindowRateLimiter:
    def __init__(self, config: RateLimitConfig | None = None) -> None:
        self.config = config or RateLimitConfig()
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        start = now - self.config.per_seconds
        with self._lock:
            q = self._hits[key]
            while q and q[0] < start:
                q.popleft()
            if len(q) >= self.config.requests:
                logger.warning("rate_limit_reject key=%s", key)
                return False
            q.append(now)
            return True
