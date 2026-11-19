"""Regression contract for live strict EAP-TLS helper rendering.

Extract only the two target functions via AST to test safely on Windows.
The real helper imports FreeBSD-only modules and must not run on a client.
No file writes, configctl calls, FreeRADIUS HUPs, or network are performed.
"""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
import unittest


FILE = Path(__file__).parents[1] / "deploy/opnsense/bixcore-radius-user-toggle.py"
TARGETS = {"render_check_hup", "render_check_hup_vlan"}
TEMPLATE = ("/usr/local/sbin/configctl", "template", "reload", "OPNsense/Freeradius")
PREPARE = ("/usr/local/etc/rc.syshook.d/start/98-radius-eap-strict", "--prepare-only")
VALIDATE = ("/usr/local/sbin/radiusd", "-C")


def extract_functions():
    module = ast.parse(FILE.read_text(encoding="utf8"))
    nodes = [node for node in module.body
             if isinstance(node, ast.FunctionDef) and node.name in TARGETS]
    if {node.name for node in nodes} != TARGETS:
        raise AssertionError("Both target helper functions must exist")
    return compile(ast.Module(body=nodes, type_ignores=[]), str(FILE), "exec")


COMPILED = extract_functions()


class StrictEapHelperTests(unittest.TestCase):
    def make_env(self, template_stdout="OK", template_code=0, prepare_code=0):
        commands = []
        events = []
        def run(argv, **kwargs):
            command = tuple(argv)
            commands.append(command)
            if command == TEMPLATE:
                return SimpleNamespace(returncode=template_code, stdout=template_stdout)
            if command == PREPARE:
                return SimpleNamespace(returncode=prepare_code, stdout="")
            if command == VALIDATE:
                return SimpleNamespace(returncode=0, stdout="")
            raise AssertionError("Unexpected command: " + repr(command))
        def installed(username):
            events.append(("user", username))
            return True
        def vlan(username, desired):
            events.append(("vlan", username, desired))
            return True
        def get_pid():
            events.append(("pid",))
            return 4321
        def signal_pid(pid, sig):
            events.append(("hup", pid, sig))
        env = {
            "run": run,
            "present_in_authorize": installed,
            "vlan_in_authorize": vlan,
            "pid_of_radius": get_pid,
            "os": SimpleNamespace(kill=signal_pid),
            "signal": SimpleNamespace(SIGHUP=1),
            "time": SimpleNamespace(sleep=lambda _: events.append(("sleep",))),
        }
        exec(COMPILED, env)
        return env, commands, events

    def execute(self, kind, **config):
        env, commands, events = self.make_env(**config)
        if kind == "toggle":
            fn = lambda: env["render_check_hup"]("demo_phone15", True, 4321)
        elif kind == "vlan":
            fn = lambda: env["render_check_hup_vlan"]("demo_phone15", 10, True, 4321)
        else:
            raise AssertionError(kind)
        return fn, commands, events

    def test_successful_render_strict_prepare_validation_then_hup(self):
        for kind in ("toggle", "vlan"):
            with self.subTest(kind=kind):
                fn, commands, events = self.execute(kind)
                fn()
                self.assertEqual(commands, [TEMPLATE, PREPARE, VALIDATE])
                self.assertEqual(sum(e[0] == "hup" for e in events), 1)
                self.assertEqual(events[-1], ("pid",))

    def test_success_code_without_exact_ok_must_fail_closed(self):
        for kind in ("toggle", "vlan"):
            for response in ("", "ERROR", "OK\nunexpected", "NOT OK"):
                with self.subTest(kind=kind, response=response):
                    fn, commands, events = self.execute(kind, template_stdout=response)
                    with self.assertRaisesRegex(RuntimeError, "TEMPLATE_RENDER_FAILED"):
                        fn()
                    self.assertEqual(commands, [TEMPLATE])
                    self.assertFalse(any(e[0] == "hup" for e in events))

    def test_template_nonzero_rejected(self):
        for kind in ("toggle", "vlan"):
            with self.subTest(kind=kind):
                fn, commands, events = self.execute(kind, template_code=1)
                with self.assertRaisesRegex(RuntimeError, "TEMPLATE_RENDER_FAILED"):
                    fn()
                self.assertEqual(commands, [TEMPLATE])
                self.assertFalse(any(e[0] == "hup" for e in events))

    def test_prepare_failure_cannot_sighup(self):
        for kind in ("toggle", "vlan"):
            with self.subTest(kind=kind):
                fn, commands, events = self.execute(kind, prepare_code=1)
                with self.assertRaisesRegex(RuntimeError, "RADIUS_POLICY_PREPARE_FAILED"):
                    fn()
                self.assertEqual(commands, [TEMPLATE, PREPARE])
                self.assertFalse(any(e[0] == "hup" for e in events))


if __name__ == "__main__":
    unittest.main()
