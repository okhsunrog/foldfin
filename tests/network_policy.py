#!/usr/bin/env python3
"""Real namespace policy acceptance, including failure rollback and host refusal."""
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from network_policy import NetworkPolicy


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.ns = 'ffpolicy-'+secrets.token_hex(4)
        self.root('ip', 'netns', 'add', self.ns)
        self.addCleanup(self.root, 'ip', 'netns', 'del', self.ns)
        self.root('ip', 'netns', 'exec', self.ns, 'ip', 'tuntap', 'add', 'dev', 'testtun', 'mode', 'tun')
        self.policy = NetworkPolicy(self.ns, 'testtun')
        self.policy.identity = self.policy.file_identity(self.policy.path)
        self.original = self.policy.wmem(), self.policy.link()['txqlen']

    def root(self, *command):
        return subprocess.check_output(['sudo', '-n', *command], text=True).strip()

    def assert_restored(self):
        self.assertEqual((self.policy.wmem(), self.policy.link()['txqlen']), self.original)

    def test_child_failure_restores_settings(self):
        with self.assertRaisesRegex(RuntimeError, 'child failed'):
            with self.policy:
                self.assertGreaterEqual(self.policy.wmem()[2], 33554432)
                self.assertEqual(self.policy.link()['txqlen'], 10000)
                raise RuntimeError('child failed')
        self.assert_restored()

    def test_partial_setup_rolls_back(self):
        original_command = self.policy.command
        def fail(*args):
            if args[:3] == ('sysctl', '-q', '-w') and '33554432' in args[3]:
                raise RuntimeError('injected sysctl failure')
            return original_command(*args)
        self.policy.command = fail
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            with self.policy:
                self.fail('setup should not succeed')
        self.assert_restored()

    def test_external_queue_change_is_preserved(self):
        with self.assertRaisesRegex(RuntimeError, 'changed externally'):
            with self.policy:
                self.policy.command('ip', 'link', 'set', 'testtun', 'txqueuelen', '1234')
        self.assertEqual(self.policy.link()['txqlen'], 1234)
        self.assertEqual(self.policy.wmem(), self.original[0])

    def test_host_namespace_is_refused(self):
        alias = 'ffhost-'+secrets.token_hex(4)
        self.root('ip', 'netns', 'attach', alias, str(os.getpid()))
        try:
            with self.assertRaisesRegex(RuntimeError, 'host network namespace'):
                with NetworkPolicy(alias):
                    self.fail('host should be refused')
        finally:
            self.root('ip', 'netns', 'del', alias)

    def test_wrapper_signal_stops_child_and_restores(self):
        script = Path(__file__).resolve().parents[1]/'scripts/network_policy.py'
        with tempfile.TemporaryDirectory(prefix='ffpolicy-signal-') as tmp:
            report = Path(tmp)/'report.json'
            child = subprocess.Popen([sys.executable, script, '--namespace', self.ns,
                                      '--tun', 'testtun', '--report', report, '--', 'sleep', '30'],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic()+5
                while not self.root('ip', 'netns', 'pids', self.ns):
                    if child.poll() is not None or time.monotonic() > deadline:
                        self.fail('wrapper did not launch child')
                    time.sleep(.05)
                child.terminate(); child.wait(timeout=10)
                self.assertNotEqual(child.returncode, 0)
                self.assert_restored()
                self.assertEqual(self.root('ip', 'netns', 'pids', self.ns), '')
                self.assertTrue(report.is_file())
            finally:
                if child.poll() is None: child.terminate(); child.wait(timeout=10)


if __name__ == '__main__':
    unittest.main()
