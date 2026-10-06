"""Failure recovery after creation, and deterministic startup polling."""

import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from internet_proxy_locally import lifecycle, net
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.spec import ServiceSpec
from tests import quiet


class StartupRecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = Mock(spec=Backend)
        self.backend.name = "docker"
        self.backend.image_present.return_value = True
        self.backend.container_state.return_value = "running"
        self.backend.container_labels.return_value = lifecycle.ownership_labels()
        self.backend.published_ports.return_value = [("127.0.0.1", 18080, 8888)]
        self.backend.tail_logs.return_value = "diagnostic evidence"
        self.backend.remove_container.return_value = True
        for target, value in (
            ("selected_container_names", []),
            ("port_listening", False),
        ):
            patcher = patch.object(lifecycle, target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def start(self, verdict=(False, "unhealthy proxy")) -> str:
        with (
            patch.object(lifecycle.net, "wait_until", return_value=verdict),
            self.assertRaises(Fail) as caught,
            quiet(),
        ):
            lifecycle.start_engine(
                self.backend,
                ServiceSpec.load("pipelock"),
                Path("config.yaml"),
                binding=("127.0.0.1", 18080),
            )
        return str(caught.exception)

    def test_log_failure_does_not_prevent_cleanup(self) -> None:
        self.backend.tail_logs.side_effect = Fail("log command timed out")
        message = self.start()
        self.backend.remove_container.assert_called_once()
        self.assertIn("unhealthy proxy", message)
        self.assertIn("log command timed out", message)
        self.assertIn("created container removed", message)

    def test_publication_inspection_failure_still_cleans_up(self) -> None:
        self.backend.published_ports.side_effect = Fail("inspect unavailable")
        message = self.start((True, "healthy"))
        self.backend.remove_container.assert_called_once()
        self.assertIn("inspect unavailable", message)

    def test_cleanup_failure_preserves_health_and_log_evidence(self) -> None:
        for failure in ("inspect", "remove"):
            with self.subTest(failure=failure):
                self.backend.container_state.side_effect = (
                    Fail("cleanup inspect failed") if failure == "inspect" else None
                )
                self.backend.remove_container.side_effect = Fail("removal failed")
                message = self.start()
                self.assertIn("unhealthy proxy", message)
                self.assertIn("cleanup also failed", message)
                self.assertIn("diagnostic evidence", message)

    def test_polling_inspection_failure_still_cleans_up(self) -> None:
        with (
            patch.object(
                lifecycle.net, "wait_until", side_effect=Fail("poll inspect failed")
            ),
            quiet(),
            self.assertRaisesRegex(
                Fail, "poll inspect failed.*created container removed"
            ),
        ):
            lifecycle.start_engine(
                self.backend,
                ServiceSpec.load("pipelock"),
                Path("config.yaml"),
                binding=("127.0.0.1", 18080),
            )
        self.backend.remove_container.assert_called_once()


class PollingTest(unittest.TestCase):
    def test_retries_only_undecided_probes(self) -> None:
        probe = Mock(side_effect=[None, None, (False, "decisive rejection")])
        with (
            patch.object(net.time, "monotonic", return_value=0),
            patch.object(net.time, "sleep") as sleep,
        ):
            self.assertEqual(net.wait_until(probe, 15), (False, "decisive rejection"))
        self.assertEqual(probe.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_stops_at_deadline_without_an_extra_sleep(self) -> None:
        probe = Mock(return_value=None)
        with (
            patch.object(net.time, "monotonic", side_effect=[0, 0, 15]),
            patch.object(net.time, "sleep") as sleep,
        ):
            self.assertIsNone(net.wait_until(probe, 15))
        self.assertEqual(probe.call_count, 2)
        sleep.assert_called_once_with(0.5)
