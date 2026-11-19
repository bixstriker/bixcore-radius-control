"""Deliberately narrow pilot scope for the Omada wired Disconnect action."""
import os
import re

NAS_IP = "192.0.2.6"
# The switch itself is the only permitted Dynamic Authorization target.
# A particular wired MAC/port is selected from the authoritative Accounting DB.


def enabled() -> bool:
    return os.getenv("BIX_OMADA_WIRED_ENABLED") == "1"


def mac(raw: object) -> str:
    return re.sub(r"[^0-9a-f]", "", str(raw or "").lower())


def permitted_session(session: dict) -> bool:
    """The web may only offer the explicit pilot, never an arbitrary port."""
    age = session.get("age_minutes")
    return (
        session.get("nas_family") == "omada"
        and session.get("nas_ip") == NAS_IP
        and bool(str(session.get("username") or ""))
        and bool(re.fullmatch(r"[0-9a-f]{12}", mac(session.get("mac"))))
        and session.get("state") == "fresh"
        and type(age) in (int, float)
        and -1 <= age <= 10.9
        and bool(re.fullmatch(r"[0-9a-fA-F]{8}", str(session.get("session_id") or "")))
    )

def session_key(session: dict) -> tuple[str, str]:
    return str(session.get("nas_ip") or ""), mac(session.get("mac"))


def latest_sessions(sessions: list[dict]) -> dict[tuple[str, str], dict]:
    """Newest fresh session per MAC, not one session for the whole switch."""
    latest = {}
    # Include stale open rows in ordering: a stale older row must not
    # displace a newer fresh row, and a fresher row supersedes an old SID.
    for s in sessions:
        if not permitted_session(s):
            continue
        key = session_key(s)
        old = latest.get(key)
        score = (str(s.get("started_at") or ""),
                 str(s.get("updated_at") or ""), str(s.get("session_id") or ""))
        if old is None or score > (str(old.get("started_at") or ""),
                                   str(old.get("updated_at") or ""),
                                   str(old.get("session_id") or "")):
            latest[key] = s
    return latest


def latest_session(sessions: list[dict]) -> dict | None:
    """Compatibility helper for offline tests; API uses latest_sessions."""
    values = latest_sessions(sessions).values()
    return max(values, key=lambda x: (
        str(x.get("started_at") or ""),
        str(x.get("updated_at") or ""),
        str(x.get("session_id") or ""),
    ), default=None)
