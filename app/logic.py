"""BiXCore domain policy, with no production side effects.

Policy is distinct from capability: permitted_actions describe the agreed design,
not live enabled controls. Only two DC bootstrap identities are protected by name.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
import hashlib
import json
from typing import Any, Mapping

PROTECTED_BOOTSTRAP = re.compile(r"^host/LAB-DC0[12]\.ad\.example\.test$", re.IGNORECASE)
DEFAULT_FRESH_SECONDS = 15 * 60
NAS = {
    "192.0.2.4": {"name": "UniFi Primary", "family": "unifi", "kind": "wifi"},
    "192.0.2.5": {"name": "UniFi Secondary", "family": "unifi", "kind": "wifi"},
    "192.0.2.6": {"name": "Omada", "family": "omada", "kind": "wired"},
    "127.0.0.1": {"name": "Local Captive Portal RADIUS", "family": "local", "kind": "portal"},
}

ACTIONS = {
    "wifi_device": ("enable", "disable", "set_vlan", "disconnect_session"),
    "guest_wifi": ("enable", "disable", "disconnect_all_guests"),
    "portal_user": ("enable", "disable", "disconnect_portal"),
    "infrastructure": ("disconnect_session",),
    "other_local": (),
}


def timestamp(value: Any) -> datetime | None:
    """Read Unix epoch seconds or a timezone-aware ISO date; never guess TZ."""
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, ValueError, OSError):
            return None
    if isinstance(value, str):
        v = value.strip()
        if re.fullmatch(r"\d{9,12}(?:\.\d+)?", v):
            return timestamp(float(v))
        try:
            parsed = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo is not None else None
        except ValueError:
            return None
    return None


def iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


def normalize_vlan(value: Any) -> int | None:
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, int) and 1 <= value <= 4094:
        return value
    if isinstance(value, str) and value.isdecimal() and 1 <= int(value) <= 4094:
        return int(value)
    return None


def user_kind(username: str, vlan: int | None) -> str:
    """Classification agreed with owner on 13 Nov 2026.

    A missing VLAN is *a local account with portal-like semantics*, not proof
    that the portal authentication source used it. No blanket writable rights
    are given for unrecognized VLANs or inconsistent guestwlan settings.
    """
    if PROTECTED_BOOTSTRAP.fullmatch(username):
        return "infrastructure"
    if username.casefold() == "guestwlan":
        return "guest_wifi" if vlan == 30 else "other_local"
    # Any configured VLAN belongs to RADIUS users, including after a VLAN change.
    if vlan is not None:
        return "wifi_device"
    if vlan is None:
        return "portal_user"
    return "other_local"


def prepare_users(users: list[dict[str, Any]], allowlist: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    result = []
    for item in users:
        username = str(item.get("username") or "").strip()
        uuid = str(item.get("uuid") or "").strip()
        if not username:
            continue
        vlan = normalize_vlan(item.get("vlan"))
        kind = user_kind(username, vlan)
        result.append({
            "uuid": uuid,
            "username": username,
            "enabled": item.get("enabled") in (True, 1, "1", "true", "True"),
            "configured_vlan": vlan,
            "kind": kind,
            "protected": kind == "infrastructure",
            "permitted_actions": list(ACTIONS[kind]),
            "editable": False,  # Never advertise an actual write capability in this release.
            "management_available": False,
            "category_evidence": "local_user_vlan_and_exact_protected_identity",
        })
    order = {"guest_wifi": 0, "wifi_device": 1, "portal_user": 2, "infrastructure": 3, "other_local": 4}
    return sorted(result, key=lambda u: (order[u["kind"]], u["username"].casefold()))


def classify_source(username: str, users: list[dict[str, Any]]) -> str:
    if PROTECTED_BOOTSTRAP.fullmatch(username):
        return "infrastructure"
    matches = [u for u in users if u["username"] == username]
    return matches[0]["kind"] if len(matches) == 1 else "unknown"


def prepare_sessions(records: list[dict[str, Any]], users: list[dict[str, Any]],
                     as_of: datetime, fresh_seconds: int = DEFAULT_FRESH_SECONDS) -> list[dict[str, Any]]:
    result, seen = [], set()
    for rec in records:
        nas_ip = str(rec.get("nasipaddress") or "")
        username = str(rec.get("username") or "")
        sid = str(rec.get("acctsessionid") or "")
        mac = str(rec.get("callingstationid") or "")
        key = (nas_ip, sid, mac, username)
        if key in seen:
            continue
        seen.add(key)
        started = timestamp(rec.get("acctstarttime"))
        updated = timestamp(rec.get("acctupdatetime")) or started
        stopped = timestamp(rec.get("acctstoptime"))
        delta = (as_of - updated).total_seconds() if updated else None
        skew = delta is not None and delta < -60
        if stopped:
            state = "ended"
        elif delta is not None and -60 <= delta <= fresh_seconds:
            state = "fresh"
        else:
            state = "stale"
        nas = NAS.get(nas_ip, {"name": f"NAS {nas_ip or 'unknown'}", "family": "other", "kind": "other"})
        result.append({
            "username": username, "nas_ip": nas_ip, "nas_name": nas["name"],
            "nas_family": nas["family"], "network_kind": nas["kind"],
            "mac": mac, "session_id": sid, "started_at": iso(started),
            "updated_at": iso(updated), "stopped_at": iso(stopped),
            "age_minutes": round(delta/60, 1) if delta is not None else None,
            "clock_skew": skew, "state": state,
            "identity_kind": classify_source(username, users),
            "current_vlan": None,  # Accounting does not prove actual VLAN.
        })
    result.sort(key=lambda r: r["updated_at"] or "", reverse=True)
    return result


def prepare_portal_sessions(records: list[dict[str, Any]], as_of: datetime) -> list[dict[str, Any]]:
    """Project OPNsense configctl list_clients onto an approved nonsecret view.

    The portal's active-session list is authoritative for portal authorization;
    local FreeRADIUS radacct 127.0.0.1 is not a substitute for it.
    """
    result, seen = [], set()
    for row in records:
        sid = str(row.get("sessionId") or "")
        zone = str(row.get("zoneid") if row.get("zoneid") is not None else "")
        if not sid or not zone or (zone, sid) in seen:
            continue
        seen.add((zone, sid))
        ips = row.get("ipAddresses") or []
        ip = row.get("ipAddress") or (ips[0] if isinstance(ips, list) and ips else "")
        started = timestamp(row.get("startTime"))
        last = timestamp(row.get("last_accessed"))
        result.append({
            "session_id": sid,
            "zone_id": zone,
            "username": str(row.get("userName") or ""),
            "ip": str(ip or ""),
            "mac": str(row.get("macAddress") or ""),
            "started_at": iso(started),
            "last_activity_at": iso(last),
            "authenticated_via": str(row.get("authenticated_via") or ""),
            "state": "authorized",  # Present in the OPNsense active-client list.
            "seconds_active": max(0, int((as_of - started).total_seconds())) if started else None,
        })
    result.sort(key=lambda r: (r["started_at"] or "", r["session_id"]), reverse=True)
    return result



def prepare_portal_accounts(users: list[dict[str, Any]], portal_sessions: list[dict[str, Any]],
                            portal_available: bool, snapshot_stale: bool) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Join no-VLAN users to portal sessions by exact username, without assuming live state."""
    accounts=[u for u in users if u["kind"]=="portal_user"]
    names={u["username"] for u in accounts}
    matches={}
    unmatched=[]
    for session in portal_sessions:
        name=session["username"]
        if name in names:matches.setdefault(name,[]).append(session)
        else:unmatched.append(session)
    result=[]
    for user in accounts:
        sessions=matches.get(user["username"],[])
        if not portal_available:status="unknown"
        elif snapshot_stale:status="previously_authorized" if sessions else "not_confirmed"
        else:status="authorized" if sessions else "not_authorized"
        result.append({**user,"authorization_status":status,"session_count":len(sessions),"sessions":sessions})
    return result,unmatched

def guest_disconnect_plan(sessions: list[dict[str, Any]], portal_sessions: list[dict[str, Any]],
                         authorized_zone_ids: list[str]) -> dict[str, Any]:
    """Preview only. Fail closed if guest portal zones aren't explicitly scoped.

    No packet is sent. The builder shows a bounded list; execution in a future
    version will re-read live sessions, revalidate identities and require approval.
    """
    wifi = [s for s in sessions if s["username"].casefold() == "guestwlan"
            and s["nas_family"] == "unifi" and s["state"] == "fresh"]
    zones = set(authorized_zone_ids)
    portal = [p for p in portal_sessions if p["zone_id"] in zones]
    return {
        "action": "disconnect_all_guests", "execution_enabled": False,
        "wifi_count": len(wifi), "portal_count": len(portal),
        "wifi_targets": [{"nas": x["nas_ip"], "mac": x["mac"], "session_id": x["session_id"]} for x in wifi],
        "portal_targets": [{"zone_id": x["zone_id"], "username": x["username"],
                            "session_id": x["session_id"]} for x in portal],
        "zone_scope_verified": bool(zones),
        "warnings": ["Это только план: команды отключения не реализованы в данном релизе.",
                     "Перед реальным отключением обязательны повторное чтение, подтверждение и отчёт по каждой сессии."]
        + ([] if zones else ["ID зоны гостевого портала не задан: отключение портала должно быть заблокировано."]),
    }


def last_ended_per_device(sessions: list[dict[str, Any]], max_per_device: int = 2) -> list[dict[str, Any]]:
    """Last ended sessions per device across APs, sorted by Accounting Stop.

    A dedicated local Wi-Fi RADIUS account identifies one device even when
    its MAC changes between SSIDs. Shared guestwlan and unclassified accounts
    are instead grouped by MAC, so distinct guests are never merged.
    """
    if not 1 <= max_per_device <= 10:
        raise ValueError("Invalid history limit")
    def identity(s):
        name=str(s.get("username") or "").strip().casefold()
        if s.get("identity_kind")=="wifi_device" and name:
            return ("radius_device_account", name)
        raw=str(s.get("mac") or "").strip().lower()
        mac=re.sub(r"[^0-9a-f]", "", raw)
        if len(mac)==12 and mac!="020000000009":
            return ("mac", mac)
        nas=str(s.get("nas_ip") or "").strip()
        if name:
            return ("identity_nas",name,nas)
        return ("unknown_session",nas,str(s.get("session_id") or ""))
    ended=[s for s in sessions if s["state"]=="ended"]
    ended.sort(key=lambda s:(s.get("stopped_at") or s.get("updated_at") or "", s.get("session_id") or ""),reverse=True)
    result=[]
    counts={}
    for s in ended:
        key=identity(s)
        if counts.get(key,0)>=max_per_device:
            continue
        counts[key]=counts.get(key,0)+1
        result.append(s)
    return result

def summarize(sessions: list[dict[str, Any]]) -> dict[str, int]:
    return {"total":len(sessions), "fresh":sum(s["state"] == "fresh" for s in sessions),
            "stale":sum(s["state"] == "stale" for s in sessions),
            "ended":sum(s["state"] == "ended" for s in sessions)}


MAX_GUEST_WIFI_BATCH=24
GUEST_SID=re.compile(r"[A-Za-z0-9._:@/+=-]{1,64}")
GUEST_MAC=re.compile(r"[0-9a-f]{12}")


def build_guest_wifi_batch(sessions: list[dict[str,Any]], snapshot_as_of: str) -> dict[str,Any]:
    """Bounded, read-only UniFi guest session snapshot; never touch Captive Portal.

    Only the exact shared guestwlan account qualifies; no inference from VLAN30,
    IP subnet or portal individual usernames. Old/stale and roaming rows are
    excluded. Bulk executor re-checks username on RadiusGateway live accounting.
    """
    eligible=[]
    seen_macs=set()
    skipped_stale=0
    skipped_roaming=0
    skipped_invalid=0
    omada=0
    guests=[s for s in sessions if s.get("username")=="guestwlan"
            and s.get("identity_kind")=="guest_wifi" and not s.get("stopped_at")]
    ordered=sorted(sessions,key=lambda s:s.get("updated_at") or "",reverse=True)
    # A newer active session of the same MAC, including a non-guest session,
    # wins. Never Disconnect an older guest session after a device roamed.
    latest={}
    for row in ordered:
        raw=re.sub("[^0-9a-f]","",str(row.get("mac") or "").lower())
        if (raw and row.get("state")=="fresh" and not row.get("stopped_at")
                and row.get("nas_family")=="unifi" and raw not in latest):
            latest[raw]=row
    for s in sorted(guests,key=lambda r:r.get("updated_at") or "",reverse=True):
        if s.get("nas_family")!="unifi":
            if s.get("nas_family")=="omada":omada+=1
            continue
        mac=re.sub("[^0-9a-f]","",str(s.get("mac") or "").lower())
        sid=str(s.get("session_id") or "")
        if (s.get("nas_ip") not in ("192.0.2.4","192.0.2.5")
            or not GUEST_MAC.fullmatch(mac) or mac=="020000000009"
            or not GUEST_SID.fullmatch(sid)):
            skipped_invalid+=1
            continue
        if (s.get("state")!="fresh" or s.get("age_minutes") is None
                or not -1 <= s["age_minutes"] <= 10.9 or s.get("clock_skew")):
            skipped_stale+=1
            continue
        if latest.get(mac) is not s or mac in seen_macs:
            skipped_roaming+=1
            continue
        seen_macs.add(mac)
        eligible.append({"nas_ip":s["nas_ip"],"session_id":sid,"mac":mac})
    # Stable canonical order ensures preview and execution cannot silently
    # drift to a different AP or session while awaiting confirmation.
    eligible.sort(key=lambda x:(x["nas_ip"],x["session_id"],x["mac"]))
    fingerprint=hashlib.sha256(json.dumps(
        {"snapshot":snapshot_as_of,"targets":eligible},sort_keys=True,
        separators=(",",":")).encode("utf8")).hexdigest()
    return {
        "count":len(eligible),"targets":eligible,"fingerprint":fingerprint,
        "omada_unsupported":omada,"skipped_stale":skipped_stale,
        "skipped_roaming":skipped_roaming,"skipped_invalid":skipped_invalid,
        "limit":MAX_GUEST_WIFI_BATCH,"within_limit":len(eligible)<=MAX_GUEST_WIFI_BATCH,
        "portal_untouched":True,
    }
