"""main() — the CLI entry point."""

from __future__ import annotations

import json
import unittest

from internet_proxy_locally.checks import egress
from tests import quiet
from tests.egress import support


@support.requires_openssl
class MainTest(unittest.TestCase):
    def test_exit_code_reflects_failures(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        with quiet() as printed:
            rc_ok = egress.main(
                [
                    "--proxy",
                    f"http://127.0.0.1:{port}",
                    "--engine",
                    "pipelock",
                    "--quick",
                    "--json",
                ]
            )
        self.assertEqual(rc_ok, 0)
        # --json means the envelope is the whole of stdout, so assert that
        # rather than letting it scroll past.
        self.assertEqual(json.loads(printed.out)["engine"], "pipelock")

    def test_tls_interception_flag_is_recorded(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        with quiet() as printed:
            rc = egress.main(
                [
                    "--proxy",
                    f"http://127.0.0.1:{port}",
                    "--engine",
                    "squid",
                    "--quick",
                    "--json",
                    "--tls-interception",
                ]
            )
        self.assertEqual(rc, 0)
        self.assertIs(json.loads(printed.out)["tls_interception"], True)

        with quiet() as printed:
            egress.main(
                [
                    "--proxy",
                    f"http://127.0.0.1:{port}",
                    "--engine",
                    "squid",
                    "--quick",
                    "--json",
                ]
            )
        self.assertIs(json.loads(printed.out)["tls_interception"], False)


if __name__ == "__main__":
    unittest.main()
