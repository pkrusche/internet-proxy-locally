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


if __name__ == "__main__":
    unittest.main()
