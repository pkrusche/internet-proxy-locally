"""Probe hosts shared by more than one check.

A constant used by exactly one check lives in that check's own file; these
two are read by several (allowed-https/connect-sni-mismatch/
connect-raw-tunnel/concurrency-sanity, and blocked-host-connect/
blocked-host-http, respectively), so duplicating them per file would let
checks that are supposed to probe the same host silently drift apart.
"""

from __future__ import annotations

ALLOWED_HTTPS_HOST = "pypi.org"  # must be on the allowlist
BLOCKED_HOST = "example.com"  # must NOT be on the allowlist
