"""Tests for `internet_proxy_locally.checks.egress`, one file per check plus
a handful of files for shared infrastructure (transport, TLS decoding,
denial classification, fixture-log parsing, the suite runner,
the CLI). See tests/egress/support.py for the shared mock-proxy scaffolding.
"""

from __future__ import annotations
