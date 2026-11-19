"""Bounded web-to-control RPC; no SSH credential or arbitrary command is exposed."""
from __future__ import annotations

import os
from subprocess import CompletedProcess
from . import ap_control


def enabled() -> bool:
    return os.getenv("BIX_CONTROL_GATEWAY_ENABLED") == "1"


def available() -> bool:
    return enabled() and ap_control.available()


def execute(action: str, payload: str, timeout: float = 95.0) -> CompletedProcess[str]:
    """Execute one allowlisted OPNsense helper via control, preserving legacy reply shape."""
    if not available():
        raise OSError("CONTROL_GATEWAY_UNAVAILABLE")
    if not isinstance(payload, str) or len(payload.encode("utf-8")) > 1600:
        raise OSError("CONTROL_PAYLOAD_INVALID")
    try:
        data = ap_control.call(
            {"op": "opnsense", "action": action, "payload": payload},
            timeout=timeout,
        )
    except ap_control.UnifiError as exc:
        raise OSError("CONTROL_GATEWAY_FAILED") from exc
    if (type(data.get("returncode")) is not int or
            not isinstance(data.get("stdout"), str) or
            not isinstance(data.get("stderr"), str)):
        raise OSError("CONTROL_RESPONSE_INVALID")
    return CompletedProcess(
        args=["control-gateway", action],
        returncode=data["returncode"],
        stdout=data["stdout"],
        stderr=data["stderr"],
    )
