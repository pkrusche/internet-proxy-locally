"""The ordered catalogue of every egress check."""

from __future__ import annotations

from . import (
    allowed_http,
    allowed_https,
    blocked_host_connect,
    blocked_host_http,
    concurrency_sanity,
    connect_raw_tunnel,
    connect_sni_mismatch,
    direct_ip_connect,
    dns_mixed,
    dns_private_v4,
    dns_private_v6,
    dns_rebind,
    link_local_ipv4,
    loopback_ipv4,
    loopback_ipv6,
    metadata_endpoint,
    private_ipv6,
    ptr_allowlist,
    rfc1918_ipv4,
)
from .models import Check

TESTS: list[Check] = [
    allowed_http.CHECK,
    allowed_https.CHECK,
    blocked_host_connect.CHECK,
    blocked_host_http.CHECK,
    direct_ip_connect.CHECK,
    loopback_ipv4.CHECK,
    rfc1918_ipv4.CHECK,
    link_local_ipv4.CHECK,
    metadata_endpoint.CHECK,
    loopback_ipv6.CHECK,
    private_ipv6.CHECK,
    dns_private_v4.CHECK,
    dns_private_v6.CHECK,
    dns_rebind.CHECK,
    dns_mixed.CHECK,
    ptr_allowlist.CHECK,
    connect_sni_mismatch.CHECK,
    connect_raw_tunnel.CHECK,
    concurrency_sanity.CHECK,
]

CHECKS_BY_NAME = {check.name: check for check in TESTS}


def check_purpose(name: str) -> str:
    check = CHECKS_BY_NAME.get(name)
    return check.purpose if check else ""
