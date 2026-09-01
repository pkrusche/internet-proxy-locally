"""annotate_tls_bytes() — decoding the exact alert bytes docs/findings.md
manually decoded."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import tls


class AnnotateTlsBytesTest(unittest.TestCase):
    def test_decodes_documented_alert_sequence(self) -> None:
        data = b"\x15\x03\x03\x00\x02\x02\x32" + b"\x15\x03\x03\x00\x02\x01\x00"
        result = tls.annotate_tls_bytes(data)
        self.assertIn("alert(21)", result)
        self.assertIn("fatal(2)", result)
        self.assertIn("decode_error(50)", result)
        self.assertIn("warning(1)", result)
        self.assertIn("close_notify(0)", result)

    def test_falls_back_for_non_tls_bytes(self) -> None:
        result = tls.annotate_tls_bytes(b"HTTP/1.1 400 Bad Request\r\n")
        self.assertIn("not a recognized TLS record", result)


if __name__ == "__main__":
    unittest.main()
