"""Mocked tests for config.setup_vici (A10). No real socket, service or
systemctl is touched: socket.socket, subprocess.run, time.sleep and the
vici/dbus modules are all replaced. Run: python3 -I tests/test_setup_vici.py
"""
import importlib.util
import io
import os
import subprocess
import sys
import types
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

CONFIG = Path(__file__).resolve().parent.parent / "python/vyatta/vpn/ipsec/config.py"


def load_config(vici_mod):
    for name, mod in (("vici", vici_mod), ("dbus", types.ModuleType("dbus"))):
        sys.modules[name] = mod
    spec = importlib.util.spec_from_file_location("ipsec_config_under_test", CONFIG)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class FakeSock:
    def __init__(self, outcome):
        self.outcome = outcome
        self.closed = False
        self.connected_to = None

    def connect(self, path):
        self.connected_to = path
        if self.outcome is not None:
            raise self.outcome

    def close(self):
        self.closed = True


class SetupViciTest(unittest.TestCase):
    def setUp(self):
        self.vici = types.ModuleType("vici")
        self.sessions = []
        self.vici.Session = lambda s: self.sessions.append(s) or ("session", s)
        self.cfg = load_config(self.vici)
        self.socks = []
        self.outcomes = []
        self.run_calls = []
        self.sleeps = []
        self.restart_result = subprocess.CompletedProcess([], 0, "", "")

        def make_socket(*a):
            sock = FakeSock(self.outcomes.pop(0))
            self.socks.append(sock)
            return sock

        def fake_run(argv, **kw):
            self.run_calls.append((argv, kw))
            if isinstance(self.restart_result, Exception):
                raise self.restart_result
            return self.restart_result

        patches = [
            mock.patch.object(self.cfg.socket, "socket", make_socket),
            mock.patch.object(self.cfg.subprocess, "run", fake_run),
            mock.patch.object(self.cfg.time, "sleep", self.sleeps.append),
            # the old code restarted via os.system: it must never be reached
            mock.patch.object(os, "system", side_effect=AssertionError("os.system called")),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def call(self):
        err = io.StringIO()
        with redirect_stderr(err):
            try:
                return self.cfg.setup_vici(), None, err.getvalue()
            except BaseException as e:   # noqa: B902 -- the exception is the result
                return None, e, err.getvalue()

    # -- success
    def test_success_first_try_no_restart(self):
        self.outcomes = [None]
        res, exc, _ = self.call()
        self.assertIsNone(exc)
        self.assertEqual(res, ("session", self.socks[0]))
        self.assertEqual(self.run_calls, [])
        self.assertEqual(self.sleeps, [])
        self.assertEqual(self.socks[0].connected_to, "/var/run/charon.vici")
        self.assertFalse(self.socks[0].closed)      # handed to the session

    # -- refused, then recovers
    def test_refused_restarts_the_right_unit_and_recovers_on_a_fresh_socket(self):
        self.outcomes = [ConnectionRefusedError("refused"), None]
        res, exc, _ = self.call()
        self.assertIsNone(exc)
        self.assertEqual(self.run_calls[0][0], ["systemctl", "restart", "strongswan-starter.service"])
        self.assertNotIn("shell", self.run_calls[0][1])          # argv list, no shell
        self.assertIn("timeout", self.run_calls[0][1])
        self.assertEqual(len(self.socks), 2)
        self.assertTrue(self.socks[0].closed)                     # failed socket closed
        self.assertIsNot(self.socks[0], self.socks[1])            # retry uses a new one
        self.assertEqual(res, ("session", self.socks[1]))
        self.assertEqual(self.sleeps, [self.cfg.VICI_RESTART_WAIT])

    # -- missing socket, then recovers
    def test_missing_socket_also_restarts_and_recovers(self):
        self.outcomes = [FileNotFoundError(2, "No such file or directory"), None]
        res, exc, _ = self.call()
        self.assertIsNone(exc)
        self.assertEqual(len(self.run_calls), 1)
        self.assertTrue(self.socks[0].closed)
        self.assertEqual(res, ("session", self.socks[1]))

    # -- restart failure
    def test_restart_nonzero_exit_is_reported_and_not_retried(self):
        self.outcomes = [ConnectionRefusedError("refused")]
        self.restart_result = subprocess.CompletedProcess([], 5, "", "Unit strongswan-starter.service not found.")
        res, exc, err = self.call()
        self.assertIsInstance(exc, ConnectionRefusedError)
        for needle in ("strongswan-starter.service", "restarting", "exit status 5", "not found", "/var/run/charon.vici"):
            self.assertIn(needle, str(exc))
        self.assertIn("restarting strongswan-starter.service failed", err)
        self.assertEqual(len(self.socks), 1)                      # no second connect attempt
        self.assertTrue(self.socks[0].closed)
        self.assertEqual(self.sleeps, [])
        self.assertIsInstance(exc.__cause__, ConnectionRefusedError)

    def test_restart_cannot_run_or_times_out_is_reported(self):
        for failure in (FileNotFoundError("systemctl: not found"),
                        subprocess.TimeoutExpired(["systemctl"], 60)):
            self.setUp()
            self.outcomes = [FileNotFoundError(2, "gone")]
            self.restart_result = failure
            res, exc, _ = self.call()
            self.assertIsInstance(exc, ConnectionRefusedError, failure)
            self.assertIn("restarting strongswan-starter.service failed", str(exc))
            self.assertEqual(len(self.socks), 1)
            self.assertTrue(self.socks[0].closed)

    # -- second connect failure
    def test_second_connect_failure_is_raised_with_context_and_sockets_closed(self):
        for first, second in ((ConnectionRefusedError("r1"), ConnectionRefusedError("r2")),
                              (FileNotFoundError(2, "f1"), FileNotFoundError(2, "f2")),
                              (ConnectionRefusedError("r1"), FileNotFoundError(2, "f2"))):
            self.setUp()
            self.outcomes = [first, second]
            res, exc, err = self.call()
            self.assertIs(exc, second)                            # the real, last error
            self.assertEqual(len(self.run_calls), 1)              # restarted only once
            self.assertEqual(len(self.socks), 2)
            self.assertTrue(all(s.closed for s in self.socks))
            self.assertIn("even after restarting strongswan-starter.service", err)
            self.assertEqual(self.sessions, [])

    # -- other errors are not swallowed or "fixed" by a restart
    def test_other_errors_propagate_without_restart_and_close_the_socket(self):
        self.outcomes = [PermissionError(13, "Permission denied")]
        res, exc, _ = self.call()
        self.assertIsInstance(exc, PermissionError)
        self.assertEqual(self.run_calls, [])
        self.assertTrue(self.socks[0].closed)

    def test_session_construction_failure_closes_the_socket(self):
        self.vici.Session = mock.Mock(side_effect=RuntimeError("bad session"))
        self.outcomes = [None]
        res, exc, _ = self.call()
        self.assertIsInstance(exc, RuntimeError)
        self.assertTrue(self.socks[0].closed)
        self.assertEqual(self.run_calls, [])

    def test_ordinary_error_closes_but_keyboard_interrupt_is_not_intercepted(self):
        self.outcomes = [RuntimeError("boom")]
        _, exc, _ = self.call()
        self.assertIsInstance(exc, RuntimeError)
        self.assertTrue(self.socks[0].closed)
        self.setUp()
        self.outcomes = [KeyboardInterrupt()]
        _, exc, _ = self.call()
        self.assertIsInstance(exc, KeyboardInterrupt)    # propagates untouched
        self.assertEqual(self.run_calls, [])             # and triggers no restart
        self.assertEqual(self.sessions, [])

    def test_never_uses_the_old_unit_name(self):
        self.outcomes = [ConnectionRefusedError("r"), None]
        self.call()
        flat = " ".join(" ".join(c[0]) for c in self.run_calls)
        self.assertNotIn("strongswan.service", flat)


if __name__ == "__main__":
    unittest.main()
