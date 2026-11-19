"""Targeted UniFi PMKSA cleanup orchestration after confirmed RADIUS Disconnect.

The restricted OPNsense helper sends one DAS packet for a proven cache entry.
Each target comes from a live read-only scan on both APs. A new authorized STA,
missing AP, missing authentication evidence or race immediately stops cleanup.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from . import ap_control, control_gateway

NAS = frozenset(("192.0.2.4", "192.0.2.5"))
MAX_TARGETS = 16


def pmksa_ready() -> bool:
    return (os.getenv("BIX_UNIFI_PMKSA_ENABLED") == "1"
            and ap_control.available()
            and (control_gateway.available() if control_gateway.enabled() else
                 (Path("/run/secrets/bix_unifi_pmksa_key").is_file()
                  and Path("/run/secrets/bix_known_hosts").is_file())))


class WorkflowError(Exception):
    pass


def send_das(body: dict) -> dict:
    if not pmksa_ready():
        raise WorkflowError("PMKSA_CONTROL_UNAVAILABLE")
    cmd = [
        "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes",
        "-o", "UserKnownHostsFile=/run/secrets/bix_known_hosts",
        "-i", "/run/secrets/bix_unifi_pmksa_key",
        "root@192.0.2.1", "bixcore-unifi-pmksa-clean",
    ]
    try:
        payload = json.dumps(body, separators=(",", ":")) + "\n"
        reply = (control_gateway.execute("pmksa", payload, timeout=20)
                 if control_gateway.enabled() else
                 subprocess.run(cmd, input=payload,
                                text=True, capture_output=True, timeout=16, check=False))
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise WorkflowError("PMKSA_EXECUTOR_UNREACHABLE") from exc
    if reply.returncode:
        raise WorkflowError("PMKSA_EXECUTOR_ERROR")
    try:
        data = json.loads(reply.stdout.strip())
    except (ValueError, TypeError) as exc:
        raise WorkflowError("PMKSA_EXECUTOR_BAD_RESPONSE") from exc
    if not isinstance(data, dict) or data.get("ok") is not True or data.get("result") != "ack":
        reason = str(data.get("reason", "PMKSA_DAS_NOT_ACKED")) if isinstance(data, dict) else "BAD_RESPONSE"
        raise WorkflowError(reason[:64])
    return data


def cache_key(row: dict) -> tuple:
    return row["nas_ip"], row["bss"], row["bssid"], row["pmkid"]


def cleanup(mac: str, username: str, source_nas: str, session_id: str) -> dict:
    if not pmksa_ready():
        raise WorkflowError("PMKSA_CONTROL_UNAVAILABLE")
    statuses = []
    try:
        before = ap_control.call({"op": "scan", "mac": mac})
    except ap_control.UnifiError as exc:
        return {"complete": False, "reason": exc.code, "cache": []}
    if before.get("scanned") != 2:
        return {"complete": False, "reason": "BOTH_APS_NOT_SCANNED", "cache": []}
    if before.get("authorized"):
        return {"complete": False, "reason": "CLIENT_CONNECTED_OR_RECONNECTED", "cache": []}
    targets = before.get("cache")
    if not isinstance(targets, list) or len(targets) > MAX_TARGETS:
        return {"complete": False, "reason": "TOO_MANY_CACHE_TARGETS", "cache": []}
    if not targets:
        return {"complete": True, "reason": "NO_PMKSA_FOUND", "cache": []}

    for target in sorted(targets, key=cache_key):
        label = {k: target[k] for k in ("nas_ip", "bss", "bssid")}
        try:
            if target["nas_ip"] not in NAS:
                raise WorkflowError("UNEXPECTED_AP")
            current = ap_control.call({"op": "scan", "mac": mac})
            if current.get("scanned") != 2 or current.get("authorized"):
                raise WorkflowError("CLIENT_MOVED_OR_RECONNECTED")
            if cache_key(target) not in {cache_key(x) for x in current["cache"]}:
                statuses.append({**label, "status": "already_gone"})
                continue
            send_das({
                "op": "cache_pmk", "nas_ip": target["nas_ip"],
                "source_nas": source_nas, "session_id": session_id,
                "username": username, "mac": mac,
                "bssid": target["bssid"], "pmkid": target["pmkid"],
            })
            after = ap_control.call({"op": "scan", "mac": mac})
            if after.get("scanned") != 2 or after.get("authorized"):
                raise WorkflowError("CLIENT_MOVED_OR_RECONNECTED")
            if cache_key(target) in {cache_key(x) for x in after["cache"]}:
                raise WorkflowError("OLD_PMKID_STILL_PRESENT")
            statuses.append({**label, "status": "removed"})
        except (WorkflowError, ap_control.UnifiError, KeyError, TypeError) as exc:
            name = exc.code if isinstance(exc, ap_control.UnifiError) else str(exc)
            statuses.append({**label, "status": "not_verified"})
            return {"complete": False, "reason": name[:64], "cache": statuses}

    try:
        final = ap_control.call({"op": "scan", "mac": mac})
        if final.get("scanned") != 2 or final.get("authorized"):
            return {"complete": False, "reason": "CLIENT_RECONNECTED", "cache": statuses}
        if final.get("cache"):
            return {"complete": False, "reason": "CACHE_STILL_PRESENT", "cache": statuses}
    except ap_control.UnifiError as exc:
        return {"complete": False, "reason": exc.code, "cache": statuses}
    return {"complete": True, "reason": "CACHE_VERIFIED_EMPTY_BOTH_APS", "cache": statuses}
