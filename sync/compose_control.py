"""Dedicated limited-capability OPNsense and UniFi SSH worker (no published port)."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
from . import unifi_host
from .compose_rpc import UnixRPCServer

CONTROL_SOCKET = "/run/bixcore-unifi/trigger.sock"
OPNSENSE = "root@192.0.2.1"
# Fixed OPNsense commands; never accept a command, address, key path, or SSH options from web.
ACTIONS = {
    "disconnect": ("bixcore-unifi-disconnect", "unifi_disconnect", 18),
    "pmksa": ("bixcore-unifi-pmksa-clean", "unifi_pmksa", 16),
    "stale_close": ("bixcore-accounting-close-stale", "stale_close", 16),
    "omada_disconnect": ("bixcore-omada-disconnect", "omada_disconnect", 45),
    "radius_user": ("bixcore-radius-user-toggle", "radius_user_toggle", 90),
}
SECRETS = Path("/run/secrets")


def opnsense(action: object, payload: object) -> dict:
    if not isinstance(action, str) or action not in ACTIONS:
        return {"ok": False, "error": "ACTION_NOT_ALLOWED"}
    if not isinstance(payload, str) or len(payload.encode("utf-8")) > 1600:
        return {"ok": False, "error": "PAYLOAD_INVALID"}
    forced, key_name, timeout = ACTIONS[action]
    key = SECRETS / (key_name + "_key")
    hosts = SECRETS / ("radius_user_hosts" if action == "radius_user" else "bix_known_hosts")
    if not key.is_file() or not hosts.is_file():
        return {"ok": False, "error": "CREDENTIALS_UNAVAILABLE"}
    cmd = [
        "/usr/bin/ssh", "-F", "/dev/null", "-T",
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + str(hosts),
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=6",
        "-i", str(key), OPNSENSE,
        forced,
    ]
    try:
        done = subprocess.run(
            cmd, input=payload, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "error": "SSH_TRANSPORT_FAILED"}
    if len(done.stdout) > 24000 or len(done.stderr) > 3000:
        return {"ok": False, "error": "SSH_REPLY_TOO_LARGE"}
    return {
        "ok": True,
        "returncode": int(done.returncode),
        "stdout": done.stdout,
        "stderr": done.stderr,
    }


def dispatch(request: object) -> dict:
    if request == {"probe": True}:
        return {"ok": True, "result": "probe"}
    if not isinstance(request, dict):
        return {"ok": False, "error": "INVALID_REQUEST"}
    if set(request) == {"op", "action", "payload"} and request["op"] == "opnsense":
        return opnsense(request["action"], request["payload"])
    # Existing scan and EAPOL_REAUTH logic validates AP, MAC, BSSID, and STA state.
    try:
        return unifi_host.handle(request)
    except unifi_host.Reject as exc:
        return {"ok": False, "error": str(exc)[:64]}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"ok": False, "error": "AP_RUNTIME_UNAVAILABLE"}


def main() -> None:
    unifi_host.KEY = SECRETS / "ap_service_key"
    unifi_host.KNOWN = SECRETS / "ap_known_hosts"
    socket_path = os.environ.get("BIX_UNIFI_CONTROL_SOCKET", CONTROL_SOCKET)
    with UnixRPCServer(socket_path, dispatch) as server:
        server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
