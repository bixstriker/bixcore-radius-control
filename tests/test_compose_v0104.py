"""No-live-network regression tests for the v0.10.4 service separation."""
import json
import os
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from app import control_gateway, main, unifi_workflow
from app.logic import prepare_users
from fastapi.testclient import TestClient
from sync import compose_control, compose_sync, healthcheck


class GatewayBoundaryTests(unittest.TestCase):
    def test_web_rpc_returns_legacy_process_contract(self):
        with patch.object(control_gateway, "available", return_value=True), \
             patch.object(control_gateway.ap_control, "call",
                          return_value={"ok": True, "returncode": 0,
                                        "stdout": '{"result":"applied"}', "stderr": ""}) as invoke:
            out = control_gateway.execute("radius_user", '{"uuid":"abc"}')
        self.assertEqual(out.returncode, 0)
        self.assertIn("applied", out.stdout)
        self.assertEqual(invoke.call_args.args[0]["op"], "opnsense")
        self.assertEqual(invoke.call_args.args[0]["action"], "radius_user")

    def test_web_rpc_fails_closed_on_missing_socket(self):
        with patch.object(control_gateway, "available", return_value=False):
            with self.assertRaises(OSError):
                control_gateway.execute("disconnect", "{}")

    def test_web_rpc_rejects_bad_reply(self):
        with patch.object(control_gateway, "available", return_value=True), \
             patch.object(control_gateway.ap_control, "call", return_value={"ok": True}):
            with self.assertRaises(OSError):
                control_gateway.execute("disconnect", "{}")

    def test_web_rpc_rejects_oversized_payload(self):
        with patch.object(control_gateway, "available", return_value=True):
            with self.assertRaises(OSError):
                control_gateway.execute("disconnect", "x" * 1601)

    def test_web_image_is_keyless_but_legacy_image_can_rebuild(self):
        root = Path(__file__).resolve().parents[1]
        legacy = (root / "Dockerfile").read_text(encoding="utf-8")
        web = (root / "Dockerfile.web").read_text(encoding="utf-8")
        stage = (root / "compose.v0104.stage.yaml").read_text(encoding="utf-8")
        release = (root / "compose.v0104.release.yaml").read_text(encoding="utf-8")
        self.assertIn("openssh-client", legacy)
        self.assertNotIn("openssh-client", web)
        self.assertIn("dockerfile: Dockerfile.web", stage)
        self.assertIn("dockerfile: Dockerfile.web", release)
        self.assertIn("name: bixcore-radius-control", release)
        self.assertIn("bixcore_radius_npm", release)
        self.assertIn("127.0.0.1:18765:8765", release)
        self.assertIn("127.0.0.1:18766:8765", stage)
        self.assertIn("BIX_CONTROL_GATEWAY_ENABLED: \"1\"", release)
        self.assertNotIn("v0104-prod-state", stage)

    def test_release_web_has_no_control_secret_mounts(self):
        root = Path(__file__).resolve().parents[1]
        release = (root / "compose.v0104.release.yaml").read_text(encoding="utf-8")
        web = release.split("\n  sync:\n", 1)[0]
        for forbidden in ("unifi_disconnect_ed25519", "unifi_pmksa_ed25519",
                          "stale_close_ed25519", "radius_user_toggle_ed25519",
                          "pull_ed25519", "ap_service_ed25519"):
            self.assertNotIn(forbidden, web)
        self.assertIn("/run/bix-admin:rw", web)
        self.assertIn("BIX_ADMIN_AUTH_ENABLED: \"1\"", web)

    def test_stage_web_has_no_control_ssh_keys(self):
        source = (Path(__file__).resolve().parents[1] / "compose.v0104.stage.yaml").read_text()
        web = source.split("\n  sync:\n", 1)[0]
        self.assertIn("BIX_CONTROL_GATEWAY_ENABLED: \"1\"", web)
        self.assertNotIn("unifi_disconnect_ed25519", web)
        self.assertNotIn("radius_user_toggle_ed25519", web)
        self.assertNotIn("unifi_pmksa_ed25519", web)
        self.assertNotIn("stale_close_ed25519", web)
        self.assertNotIn("pull_ed25519", web)


class ControlWorkerTests(unittest.TestCase):
    def test_operation_allowlist_rejects_unlisted_command(self):
        with patch.object(compose_control.subprocess, "run") as spawn:
            response = compose_control.opnsense("bash", "id")
            self.assertFalse(response["ok"])
            spawn.assert_not_called()

    def test_known_action_uses_fixed_host_key_and_command(self):
        with tempfile.TemporaryDirectory() as temp:
            secrets = Path(temp)
            (secrets / "unifi_pmksa_key").write_text("test-dummy")
            (secrets / "bix_known_hosts").write_text("test-host")
            completed = subprocess.CompletedProcess([], 0, '{"ok":true,"result":"ack"}', "")
            with patch.object(compose_control, "SECRETS", secrets), \
                 patch.object(compose_control.subprocess, "run", return_value=completed) as spawn:
                result = compose_control.opnsense("pmksa", '{"op":"cache_pmk"}\n')
            self.assertEqual(result["returncode"], 0)
            args = spawn.call_args.args[0]
            self.assertIn("root@192.0.2.1", args)
            self.assertEqual(args[-1], "bixcore-unifi-pmksa-clean")
            self.assertIn("StrictHostKeyChecking=yes", args)
            self.assertNotIn("bash", args)

    def test_no_keys_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(compose_control, "SECRETS", Path(temp)), \
             patch.object(compose_control.subprocess, "run") as spawn:
            response = compose_control.opnsense("radius_user", '{"uuid":"x"}')
            self.assertEqual(response["error"], "CREDENTIALS_UNAVAILABLE")
            spawn.assert_not_called()

    def test_bounded_payload(self):
        with patch.object(compose_control.subprocess, "run") as spawn:
            response = compose_control.opnsense("disconnect", "a" * 2000)
            self.assertEqual(response["error"], "PAYLOAD_INVALID")
            spawn.assert_not_called()

    def test_unifi_scan_reuses_guarded_handler(self):
        with patch.object(compose_control.unifi_host, "handle",
                          return_value={"ok": True, "scanned": 2}) as scanner:
            result = compose_control.dispatch({"op": "scan", "mac": "02:00:00:00:00:13"})
        self.assertEqual(result["scanned"], 2)
        scanner.assert_called_once()


class EndpointGatewayTests(unittest.TestCase):
    """All operations here are simulated; no SSH command or production update is made."""

    @staticmethod
    def radius_fixture():
        raw = [{"uuid": "aaaaaaaa-aaaa-aaaa-aaaa-02000000001a",
                "username": "demo_phone11", "enabled": True, "vlan": 10}]
        snap = {"source": "sanitized_export",
                "as_of": datetime.now(timezone.utc).isoformat(),
                "sessions": [], "local_users": raw, "portal_sessions": [],
                "users_collected": True, "portal_collected": True}
        return snap, prepare_users(raw), [], []

    def test_user_toggle_flows_through_control_without_direct_ssh(self):
        body = {"uuid": "aaaaaaaa-aaaa-aaaa-aaaa-02000000001a",
                "username": "demo_phone11", "expected_enabled": True, "enabled": False}
        response = subprocess.CompletedProcess([], 0, json.dumps({"ok": True, "result": "applied", "enabled": False}), "")
        with patch.dict(os.environ, {"BIX_ADMIN_AUTH_ENABLED": "0"}), \
             patch.object(main, "bundle", return_value=self.radius_fixture()), \
             patch.object(main, "user_management_ready", return_value=True), \
             patch.object(control_gateway, "enabled", return_value=True), \
             patch.object(control_gateway, "execute", return_value=response) as gateway, \
             patch.object(main.subprocess, "run") as direct:
            with TestClient(main.app, base_url="https://radius.example.test") as client:
                r = client.post("/api/users/set-enabled", json=body)
        self.assertEqual(r.status_code, 200, r.text)
        direct.assert_not_called()
        self.assertEqual(gateway.call_args.args[0], "radius_user")
        self.assertEqual(json.loads(gateway.call_args.args[1]), body)

    def test_vlan_change_flows_through_control_without_direct_ssh(self):
        body = {"uuid": "aaaaaaaa-aaaa-aaaa-aaaa-02000000001a",
                "username": "demo_phone11", "expected_vlan": 10, "vlan": 20, "expected_enabled": True}
        response = subprocess.CompletedProcess([], 0,
            json.dumps({"ok": True, "result": "applied", "uuid": body["uuid"], "vlan": 20}), "")
        with patch.dict(os.environ, {"BIX_ADMIN_AUTH_ENABLED": "0"}), \
             patch.object(main, "bundle", return_value=self.radius_fixture()), \
             patch.object(main, "user_management_ready", return_value=True), \
             patch.object(control_gateway, "enabled", return_value=True), \
             patch.object(control_gateway, "execute", return_value=response) as gateway, \
             patch.object(main.subprocess, "run") as direct:
            with TestClient(main.app, base_url="https://radius.example.test") as client:
                r = client.post("/api/users/set-vlan", json=body)
        self.assertEqual(r.status_code, 200, r.text)
        direct.assert_not_called()
        self.assertEqual(gateway.call_args.args[0], "radius_user")
        self.assertEqual(json.loads(gateway.call_args.args[1]), {"action": "set_vlan", **body})

    def test_pmk_das_uses_control_without_direct_ssh(self):
        body = {"probe": True}
        proc = subprocess.CompletedProcess([], 0, '{"ok":true,"result":"ack"}', "")
        with patch.object(unifi_workflow, "pmksa_ready", return_value=True), \
             patch.object(control_gateway, "enabled", return_value=True), \
             patch.object(control_gateway, "execute", return_value=proc) as gateway, \
             patch.object(unifi_workflow.subprocess, "run") as direct:
            result = unifi_workflow.send_das(body)
        self.assertTrue(result["ok"])
        self.assertEqual(gateway.call_args.args[0], "pmksa")
        self.assertEqual(json.loads(gateway.call_args.args[1]), body)
        direct.assert_not_called()

    def test_active_disconnect_uses_control(self):
        proc = subprocess.CompletedProcess([], 0, '{"result":"ack"}', "")
        with patch.object(control_gateway, "enabled", return_value=True), \
             patch.object(control_gateway, "execute", return_value=proc) as gateway, \
             patch.object(main.subprocess, "run") as direct:
            result = main._active_disconnect_on_opnsense(
                {"nas_ip": "192.0.2.4", "session_id": "safe-test"}, "02:00:00:00:00:21")
        self.assertEqual(result, "ack")
        self.assertEqual(gateway.call_args.args[0], "disconnect")
        direct.assert_not_called()

    def test_portal_and_guest_helpers_are_prSecondaryed(self):
        portal = subprocess.CompletedProcess([], 0, '{"result":"applied"}', "")
        guest = subprocess.CompletedProcess([], 0, '{"result":"ack"}', "")
        with patch.object(control_gateway, "enabled", return_value=True), \
             patch.object(control_gateway, "execute", side_effect=[portal, guest]) as gateway, \
             patch.object(main.subprocess, "run") as direct:
            exitcode, outcome = main.portal_control_invoke({"action": "portal_enabled"}, "TEST")
            self.assertEqual(exitcode, 0)
            self.assertEqual(outcome["result"], "applied")
            result = main.disconnect_one_guest_unifi({
                "nas_ip": "192.0.2.4", "session_id": "sample", "mac": "020000000022"})
        self.assertEqual(result["result"], "ack")
        self.assertEqual([x.args[0] for x in gateway.call_args_list], ["radius_user", "disconnect"])
        direct.assert_not_called()

    def test_gateway_readiness_does_not_require_keys_in_web(self):
        with patch.dict(os.environ, {
            "BIX_UNIFI_DISCONNECT_ENABLED": "1",
            "BIX_RADIUS_USER_CONTROL_ENABLED": "1",
            "BIX_STALE_ACCOUNTING_CLOSE_ENABLED": "1",
            "BIX_UNIFI_PMKSA_ENABLED": "1",
        }), patch.object(control_gateway, "enabled", return_value=True), \
             patch.object(control_gateway, "available", return_value=True), \
             patch.object(unifi_workflow.ap_control, "available", return_value=True), \
             patch.object(main.Path, "is_file", side_effect=AssertionError("web must not read SSH secrets")):
            self.assertTrue(main.management_ready())
            self.assertTrue(main.user_management_ready())
            self.assertTrue(main.stale_close_ready())
            self.assertTrue(unifi_workflow.pmksa_ready())


class WorkerHealthTests(unittest.TestCase):
    def test_health_rejects_missing_socket(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertFalse(healthcheck.check(str(Path(temp) / "missing.sock")))

    def test_health_requires_valid_probe_response(self):
        class Fake:
            def __init__(self, reply):
                self.reply = reply
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def settimeout(self, val):
                pass
            def connect(self, val):
                pass
            def sendall(self, val):
                assert val == b'{"probe":true}\n'
            def shutdown(self, val):
                pass
            def makefile(self, mode):
                return BytesIO(self.reply)
        with patch.object(healthcheck.socket, "AF_UNIX", 1, create=True), \
             patch.object(healthcheck.socket, "socket",
                          return_value=Fake(b'{"ok":true,"result":"probe"}\n')):
            self.assertTrue(healthcheck.check(str(Path(tempfile.gettempdir()) / "test.sock")))
        with patch.object(healthcheck.socket, "AF_UNIX", 1, create=True), \
             patch.object(healthcheck.socket, "socket",
                          return_value=Fake(b'{"ok":false,"error":"failed"}\n')):
            self.assertFalse(healthcheck.check(str(Path(tempfile.gettempdir()) / "test.sock")))


class SyncWorkerTests(unittest.TestCase):
    def test_manual_pull_updates_isolated_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "current.json"
            target.write_text('{"source":"sanitized_export","as_of":"2026-11-17T20:00:00Z"}')
            before = target.stat().st_mtime_ns
            def fake_pull():
                target.write_text('{"source":"sanitized_export","as_of":"2026-11-17T20:01:00Z"}')
                os.utime(target, ns=(before + 1000000, before + 1000000))
                return 0
            with patch.object(compose_sync.pull_snapshot, "TARGET", target), \
                 patch.object(compose_sync.pull_snapshot, "main", side_effect=fake_pull):
                worker = compose_sync.SnapshotWorker()
                response = worker.dispatch({"op": "refresh"})
            self.assertTrue(response["ok"])
            self.assertEqual(response["as_of"], "2026-11-17T20:01:00Z")

    def test_overlapping_snapshot_pull_is_rejected(self):
        worker = compose_sync.SnapshotWorker()
        worker.lock.acquire()
        try:
            self.assertEqual(worker.dispatch({"op": "refresh"})["error"],
                             "PULL_ALREADY_RUNNING")
        finally:
            worker.lock.release()

    def test_unrecognized_sync_request_is_rejected(self):
        worker = compose_sync.SnapshotWorker()
        self.assertEqual(worker.dispatch({"op": "delete"})["error"], "INVALID_REQUEST")


if __name__ == "__main__":
    unittest.main()
