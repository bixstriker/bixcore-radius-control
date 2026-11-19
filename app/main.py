"""Snapshot-driven BiXCore service with restricted per-session UniFi Disconnect."""
from __future__ import annotations

from datetime import datetime, timezone
import os
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .logic import PROTECTED_BOOTSTRAP, prepare_sessions, prepare_portal_sessions, prepare_portal_accounts, prepare_users, guest_disconnect_plan, build_guest_wifi_batch, last_ended_per_device, summarize, timestamp
from .source import load_bundle
from . import auth, refresh as manual_refresh, ap_control, unifi_workflow, control_gateway, audit, omada_wired

STATIC = Path(__file__).resolve().parent / "static"
app = FastAPI(title="BiXCore RADIUS Control 1.0.1 — UniFi PMKSA and EAPOL Reauth", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.middleware("http")
async def administrator_gate(request: Request, call_next):
    """Protect pages, data API and Disconnect before routes are evaluated."""
    if not auth.enabled():
        return await call_next(request)
    path = request.url.path
    if path == "/api/health":
        return await call_next(request)
    public = path in ("/login", "/static/style.css", "/static/login.js", "/static/ui.js", "/static/ui-theme.css", "/static/responsive.css", "/static/favicon.svg", "/api/auth/login")
    logged_in = auth.valid_cookie(request.cookies.get(auth.COOKIE_NAME))
    if path == "/login" and request.method == "GET" and logged_in:
        return RedirectResponse("/", status_code=303)
    if not public and not logged_in:
        if path == "/" and request.method == "GET":
            return RedirectResponse("/login", status_code=303)
        return JSONResponse({"detail": "Требуется вход администратора"}, status_code=401)
    if not public and request.method not in ("GET", "HEAD", "OPTIONS"):
        if request.headers.get("origin", "") != os.getenv("BIX_CONTROL_ORIGIN", "https://radius.example.test"):
            return JSONResponse({"detail": "Неверный источник запроса"}, status_code=403)
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    return response


def bundle():
    try:
        snap, allowlist = load_bundle()
        as_of = timestamp(snap["as_of"])
        users = prepare_users(snap["local_users"], allowlist)
        effective_time = as_of if snap["source"] == "demo" else datetime.now(timezone.utc)
        sessions = prepare_sessions(snap["sessions"], users, effective_time)
        portal = prepare_portal_sessions(snap.get("portal_sessions",[]), effective_time)
        return snap, users, sessions, portal
    except (ValueError, OSError, TypeError) as exc:
        raise HTTPException(503, detail="Источник данных недоступен или некорректен") from exc


def meta(snap):
    time = timestamp(snap["as_of"])
    age = max(0, int((datetime.now(timezone.utc)-time).total_seconds()))
    imported = snap["source"] == "sanitized_export"
    users_collected = bool(snap.get("users_collected",bool(snap["local_users"]) or not imported))
    portal_collected = bool(snap.get("portal_collected",bool(snap.get("portal_sessions")) or not imported))
    return {
        "mode":snap["source"], "as_of":snap["as_of"],
        "snapshot_age_seconds":age if imported else None,
        "snapshot_stale":imported and age>900,
        "freshness_minutes":15, "live":False,
        "users_available":users_collected, "portal_available":portal_collected,
        "management_enabled":management_ready(),
        "omada_wired_enabled":(omada_wired.enabled() and control_gateway.available()
                               and imported and age <= 180),
        "unifi_maintenance_enabled":unifi_workflow.pmksa_ready() and imported and age <=180,
        "manual_refresh_enabled":manual_refresh.available(),
        "stale_close_enabled":stale_close_ready() and imported and age <= 180 and users_collected,
        "user_management_enabled":user_management_ready() and imported and age<=180 and users_collected,
        "portal_management_enabled":user_management_ready() and imported and age<=180 and users_collected,
        "portal_disconnect_enabled":user_management_ready() and imported and age<=180 and users_collected and portal_collected,
        "guest_management_enabled":user_management_ready() and imported and age<=180 and users_collected,
        "guest_disconnect_enabled":management_ready() and imported and age<=180 and users_collected,
        "warnings":[
            "Демонстрационные данные." if not imported else "Снимок из файла: не автоматическое подключение к RadiusGateway.",
            "Источник устарел — обновите экспорт." if imported and age>900 else "Fresh основан на Accounting, не на ассоциации с точкой доступа.",
            "UniFi Disconnect доступен для свежих сессий." if management_ready() else "Команды управления пока недоступны.",
        ],
    }


@app.get("/")
def index():
    return FileResponse(STATIC/"index.html")


from pydantic import BaseModel, Field, StrictInt


class AdminLogin(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@app.get("/login")
def login_page():
    if not auth.enabled():
        return RedirectResponse("/", status_code=303)
    return FileResponse(STATIC/"login.html")


@app.post("/api/auth/login")
def administrator_login(body: AdminLogin, request: Request):
    if not auth.enabled():
        raise HTTPException(404, detail="Авторизация не включена")
    if request.headers.get("origin", "") != os.getenv("BIX_CONTROL_ORIGIN", "https://radius.example.test"):
        raise HTTPException(403, detail="Неверный источник запроса")
    if not auth.configured():
        raise HTTPException(503, detail="Учётная запись администратора ещё не настроена")
    remote = request.client.host if request.client else "unknown"
    if auth.failed_limit(remote):
        raise HTTPException(429, detail="Слишком много попыток. Повтори вход позже")
    if not auth.password_matches(body.username, body.password):
        auth.record_failed(remote)
        raise HTTPException(401, detail="Неверный логин или пароль")
    auth.clear_failures(remote)
    response = JSONResponse({"ok": True, "username": "admin"})
    response.set_cookie(key=auth.COOKIE_NAME, value=auth.create_cookie(), max_age=auth.SESSION_SECONDS,
                        secure=True, httponly=True, samesite="strict", path="/")
    logging.getLogger("uvicorn.error").info("ADMIN_LOGIN success")
    return response


@app.post("/api/auth/logout")
def administrator_logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(key=auth.COOKIE_NAME, path="/", secure=True, httponly=True, samesite="strict")
    logging.getLogger("uvicorn.error").info("ADMIN_LOGOUT")
    return response


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=16, max_length=256)
    confirm_password: str = Field(min_length=1, max_length=256)


@app.post("/api/auth/change-password")
def administrator_change_password(body: PasswordChange):
    try:
        auth.change_password(body.current_password, body.new_password, body.confirm_password)
    except ValueError as exc:
        reasons = {
            "CURRENT_INCORRECT": (403, "Неверный текущий пароль"),
            "CONFIRM_MISMATCH": (400, "Подтверждение нового пароля не совпадает"),
            "PASSWORD_LENGTH": (400, "Новый пароль должен содержать от 16 до 256 символов"),
            "PASSWORD_UNCHANGED": (400, "Новый пароль должен отличаться от текущего"),
        }
        code, message = reasons.get(str(exc), (400, "Невозможно изменить пароль"))
        raise HTTPException(code, detail=message) from None
    except OSError:
        ACTION_LOG.error("ADMIN_PASSWORD_CHANGE credential storage unavailable")
        raise HTTPException(503, detail="Не удалось сохранить новый пароль") from None
    ACTION_LOG.info("ADMIN_PASSWORD_CHANGED sessions_invalidated")
    response = JSONResponse({"ok": True, "message": "Пароль изменён. Войдите с новым паролем"})
    response.delete_cookie(key=auth.COOKIE_NAME, path="/", secure=True, httponly=True, samesite="strict")
    return response


@app.get("/api/overview")
def overview():
    snap, users, sessions, portal = bundle()
    wifi = [s for s in sessions if s["network_kind"] != "portal"]
    current=[s for s in wifi if s["state"]!="ended"]
    counts=summarize(current)
    counts["ended"]=len(last_ended_per_device(wifi))
    return {"meta":meta(snap), "sessions":counts,
            "users":{k:sum(u["kind"]==k for u in users) for k in
                     ("wifi_device","guest_wifi","portal_user","infrastructure","other_local")},
            "portal":len(portal), "local_users":len(users),
            "phones":sum(u["kind"]=="wifi_device" for u in users)}


@app.get("/api/sessions")
def get_sessions(
    state: str=Query("all",pattern="^(all|fresh|stale|ended)$"),
    nas: str=Query("all",max_length=64),
    query: str=Query("",max_length=128),
    include_portal:bool=False,
    limit:int=Query(100,ge=1,le=2000),offset:int=Query(0,ge=0),
):
    snap,_,sessions,_=bundle()
    # Never offer Offline cleanup on a roaming duplicate while the same MAC
    # already has a Fresh session on either UniFi access point.
    fresh_macs={re.sub(r"[^0-9a-f]", "", str(s["mac"]).lower()) for s in sessions
                if s["state"]=="fresh" and s["nas_family"]=="unifi"}
    newest_omada_by_mac = omada_wired.latest_sessions(sessions)
    for session in sessions:
        session["omada_wired_latest"] = (
            newest_omada_by_mac.get(omada_wired.session_key(session)) is session
        )
        normalized=re.sub(r"[^0-9a-f]", "", str(session["mac"]).lower())
        session["offline_disconnect_eligible"]=bool(
            session["state"] in ("ended","stale")
            and session["nas_family"]=="unifi"
            and session["identity_kind"]!="infrastructure"
            and normalized and normalized not in fresh_macs)
    if not include_portal: sessions=[s for s in sessions if s["network_kind"]!="portal"]
    if state=="ended":
        sessions=last_ended_per_device(sessions)
    else:
        sessions=[s for s in sessions if s["state"]!="ended"]
        if state!="all": sessions=[s for s in sessions if s["state"]==state]
    if nas!="all": sessions=[s for s in sessions if s["nas_ip"]==nas]
    if query.strip():
        needle=query.strip().casefold()
        sessions=[s for s in sessions if any(needle in str(s[k]).casefold() for k in
                  ("username","mac","nas_name","nas_ip","session_id"))]
    return {"meta":meta(snap),"total":len(sessions),"offset":offset,"limit":limit,"items":sessions[offset:offset+limit]}


@app.get("/api/users")
def get_users(category:str=Query("all",pattern="^(all|wifi_device|guest_wifi|portal_user|infrastructure|other_local)$"),
              query:str=Query("",max_length=128),limit:int=Query(200,ge=1,le=1000),offset:int=Query(0,ge=0)):
    snap,users,_,_=bundle()
    if category=="all": users=[u for u in users if u["kind"] not in ("guest_wifi","portal_user")]
    elif category=="portal_user": users=[]
    else: users=[u for u in users if u["kind"]==category]
    if query.strip():
        needle=query.strip().casefold()
        users=[u for u in users if needle in u["username"].casefold() or needle in u["uuid"].casefold()]
    m=meta(snap)
    for user in users:
        user["editable"]=bool(
            (m["user_management_enabled"] and user["kind"]=="wifi_device"
             and user["configured_vlan"] is not None and not user["protected"] and user["uuid"])
            or (m["guest_management_enabled"] and user["kind"]=="guest_wifi"
                and user["username"]=="guestwlan" and user["configured_vlan"]==30
                and bool(user["uuid"])))
        user["management_available"]=bool(user["editable"])
    return {"meta":m,"total":len(users),"offset":offset,"limit":limit,"items":users[offset:offset+limit]}


@app.get("/api/phones")
def get_phones(query:str=Query("",max_length=128),include_other:bool=False):
    """Deprecated compatibility path; returns configured-VLAN devices, not only phones."""
    snap,users,_,_=bundle()
    if not include_other: users=[u for u in users if u["kind"]=="wifi_device"]
    if query.strip():
        needle=query.strip().casefold()
        users=[u for u in users if needle in u["username"].casefold() or needle in u["uuid"].casefold()]
    return {"meta":meta(snap),"total":len(users),"items":users}


@app.get("/api/portal-users")
def get_portal_users(query: str=Query("",max_length=128),limit:int=Query(200,ge=1,le=1000),
                     offset:int=Query(0,ge=0)):
    snap,users,_,sessions=bundle()
    m=meta(snap)
    accounts,unmatched=prepare_portal_accounts(users,sessions,m["portal_available"],m["snapshot_stale"])
    for account in accounts:
        account["editable"]=bool(m["portal_management_enabled"] and account["uuid"]
                                 and account["kind"]=="portal_user" and not account["protected"])
        account["management_available"]=bool(account["editable"])
        account["disconnect_available"]=bool(m["portal_disconnect_enabled"] and account["editable"]
                                             and account["session_count"]>0)
    if query.strip():
        needle=query.strip().casefold()
        accounts=[u for u in accounts if needle in u["username"].casefold() or
                  needle in u["uuid"].casefold() or any(needle in str(p.get(key) or "").casefold()
                  for p in u["sessions"] for key in ("ip","mac","zone_id","session_id"))]
        unmatched=[p for p in unmatched if any(needle in str(p.get(key) or "").casefold()
                   for key in ("username","ip","mac","zone_id","session_id"))]
    return {"meta":m,"total":len(accounts),"offset":offset,"limit":limit,
            "active_session_count":len(sessions) if m["portal_available"] else None,
            "items":accounts[offset:offset+limit],"unmatched_sessions":unmatched,
            "unmatched_count":len(unmatched)}


@app.get("/api/portal-sessions")
def get_portal_sessions(zone:str=Query("all",max_length=24),query:str=Query("",max_length=128)):
    snap,_,_,sessions=bundle()
    if zone!="all": sessions=[s for s in sessions if s["zone_id"]==zone]
    if query.strip():
        q=query.strip().casefold()
        sessions=[s for s in sessions if any(q in s[key].casefold() for key in
                  ("username","ip","mac","session_id","zone_id"))]
    return {"meta":meta(snap),"total":len(sessions),"items":sessions}


@app.get("/api/audit")
def get_audit_log(limit: int = Query(default=50, ge=1, le=100),
                  offset: int = Query(default=0, ge=0, le=5000),
                  action: str | None = Query(default=None, max_length=40),
                  state: str | None = Query(default=None, max_length=20)):
    if not auth.enabled():
        raise HTTPException(503, detail="Требуется авторизация администратора")
    return audit.entries(limit=limit, offset=offset, action=action, state=state)


@app.get("/api/guest-disconnect-preview")
def get_guest_disconnect_preview():
    snap,users,sessions,portal=bundle()
    guest=[u for u in users if u["username"].casefold()=="guestwlan" and u["kind"]=="guest_wifi"]
    if len(guest)!=1: raise HTTPException(409,detail="Локальная запись guestwlan не подтверждена")
    if snap["source"]=="demo":
        allowed_zones=["1"]
    else:
        raw=os.getenv("BIX_RADIUS_GUEST_PORTAL_ZONES","")
        allowed_zones=[s for s in raw.split(",") if s.isdecimal() and len(s)<8]
    return {"meta":meta(snap),"plan":guest_disconnect_plan(sessions,portal,allowed_zones)}


_MANUAL_REFRESH_LOCK = threading.Lock()
_MANUAL_REFRESH_LAST = 0.0
_MANUAL_REFRESH_COOLDOWN = 15.0


@app.post("/api/snapshot/refresh")
def refresh_snapshot_now(request: Request):
    """Authenticated, origin-checked request for a new OPNsense export."""
    global _MANUAL_REFRESH_LAST
    if request.headers.get("origin", "") != os.getenv(
        "BIX_CONTROL_ORIGIN", "https://radius.example.test"
    ):
        raise HTTPException(403, detail="Неверный источник запроса")
    if not auth.enabled() or not manual_refresh.available():
        raise HTTPException(503, detail="Ручной экспорт с RadiusGateway пока недоступен")
    if not _MANUAL_REFRESH_LOCK.acquire(blocking=False):
        raise HTTPException(409, detail="Экспорт уже выполняется")
    try:
        now = time.monotonic()
        if now - _MANUAL_REFRESH_LAST < _MANUAL_REFRESH_COOLDOWN:
            raise HTTPException(429, detail="Повторный экспорт можно запускать не чаще одного раза в 15 секунд")
        _MANUAL_REFRESH_LAST = now
        try:
            exported_at = manual_refresh.trigger()
            snap, _, _, _ = bundle()
            age = (datetime.now(timezone.utc) - timestamp(snap["as_of"])).total_seconds()
            if snap["source"] != "sanitized_export" or abs(age) > 180:
                raise RuntimeError("REFRESH_UNEXPECTED_SNAPSHOT")
            if timestamp(snap["as_of"]) < timestamp(exported_at):
                raise RuntimeError("REFRESH_SNAPSHOT_NOT_VISIBLE")
        except (RuntimeError, OSError, ValueError, HTTPException) as exc:
            ACTION_LOG.error("MANUAL_REFRESH failed reason=%s", type(exc).__name__)
            raise HTTPException(503, detail="Не удалось получить новый экспорт с RadiusGateway") from None
        ACTION_LOG.info("MANUAL_REFRESH success")
        return {"ok": True, "as_of": snap["as_of"], "snapshot_age_seconds": max(0, int(age))}
    finally:
        _MANUAL_REFRESH_LOCK.release()


@app.get("/api/health")
def health():
    return {"status":"ok","kind":"snapshot-readonly","opnsense_connected":False,
            "management_enabled":management_ready(),
            "manual_refresh_enabled":manual_refresh.available(),
            "auth_enabled":auth.enabled(),"auth_configured":auth.configured() if auth.enabled() else False}


import json
import re
import subprocess

class DisconnectRequest(BaseModel):
    nas_ip: str=Field(max_length=16)
    session_id: str=Field(min_length=1,max_length=64)
    mac: str=Field(min_length=12,max_length=25)
    offline: bool=False

ACTION_LOG = logging.getLogger("uvicorn.error")

def management_ready():
    return (os.getenv("BIX_UNIFI_DISCONNECT_ENABLED")=="1"
      and (control_gateway.available() if control_gateway.enabled() else
           (Path("/run/secrets/bix_unifi_disconnect_key").is_file()
            and Path("/run/secrets/bix_known_hosts").is_file())))

_UNIFI_ACTION_LOCK = threading.Lock()
_UNIFI_LAST_REAUTH: dict[str, float] = {}


def _unifi_mac(raw: str) -> str:
    value = re.sub("[^0-9a-f]", "", raw.lower())
    if not re.fullmatch("[0-9a-f]{12}", value):
        raise HTTPException(400, detail="Некорректный MAC")
    return ":".join(value[i:i+2] for i in range(0, 12, 2))


def _unifi_target(body: DisconnectRequest, offline: bool = False):
    if body.nas_ip not in ("192.0.2.4", "192.0.2.5"):
        raise HTTPException(400, detail="Доступны только UniFi1 и UniFi2")
    if not re.fullmatch(r"[A-Za-z0-9._:@/+=-]{1,64}", body.session_id):
        raise HTTPException(400, detail="Некорректный Session ID")
    mac = _unifi_mac(body.mac)
    snap, _, sessions, _ = bundle()
    m = meta(snap)
    if m["mode"] != "sanitized_export" or m["snapshot_age_seconds"] is None or m["snapshot_age_seconds"] > 180:
        raise HTTPException(409, detail="Обновите снимок перед действием")
    candidates = [
        s for s in sessions
        if s["nas_family"] == "unifi" and s["nas_ip"] == body.nas_ip
        and s["session_id"] == body.session_id and _unifi_mac(s["mac"]) == mac
        and (s["state"] in ("ended", "stale") if offline else s["state"] == "fresh")
    ]
    if len(candidates) != 1:
        raise HTTPException(409, detail="Сессия изменилась: обновите список")
    s = candidates[0]
    if s["identity_kind"] == "infrastructure":
        raise HTTPException(403, detail="Системные учётные записи защищены")
    if offline:
        visible = last_ended_per_device(sessions) if s["state"] == "ended" else sessions
        if s not in visible:
            raise HTTPException(409, detail="Историческая сессия больше недоступна")
        if any(x["state"] == "fresh" and _unifi_mac(x["mac"]) == mac for x in sessions
               if x["nas_family"] == "unifi"):
            raise HTTPException(409, detail="У устройства есть активная сессия — используйте её Disconnect")
    elif s["age_minutes"] is None or not -1 <= s["age_minutes"] <= 10.9:
        raise HTTPException(409, detail="Accounting Update не подтверждает актуальную сессию")
    return s, mac


def _unifi_origin(request: Request):
    if request.headers.get("origin", "") != os.getenv(
        "BIX_CONTROL_ORIGIN", "https://radius.example.test"
    ):
        raise HTTPException(403, detail="Недопустимый Origin")


def _active_disconnect_on_opnsense(s: dict, mac: str) -> str:
    command = [
        "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes",
        "-o", "UserKnownHostsFile=/run/secrets/bix_known_hosts",
        "-i", "/run/secrets/bix_unifi_disconnect_key",
        "root@192.0.2.1", "bixcore-unifi-disconnect",
    ]
    payload = json.dumps({"nas_ip":s["nas_ip"],"session_id":s["session_id"],
                          "mac":mac.replace(":", "")}, separators=(",", ":"))
    try:
        reply = (control_gateway.execute("disconnect", payload, timeout=22)
                 if control_gateway.enabled() else
                 subprocess.run(command, input=payload, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=18, check=False))
        if reply.returncode:
            raise HTTPException(502, detail="OPNsense Disconnect-исполнитель недоступен")
        answer = json.loads(reply.stdout.strip())
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        raise HTTPException(502, detail="Не удалось получить ответ OPNsense") from None
    if not isinstance(answer, dict) or answer.get("result") not in ("ack", "nak", "error"):
        raise HTTPException(502, detail="Некорректный ответ OPNsense")
    if answer["result"] != "ack":
        raise HTTPException(409, detail="UniFi Disconnect не подтверждён: " +
                            str(answer.get("reason", answer["result"]))[:65])
    return "ack"


@app.post("/api/unifi/reauth")
def unifi_reauth(body: DisconnectRequest, request: Request):
    _unifi_origin(request)
    if body.offline:
        raise HTTPException(400, detail="Переавторизация доступна только Online")
    if not management_ready() or not unifi_workflow.pmksa_ready():
        raise HTTPException(503, detail="UniFi EAPOL_REAUTH недоступна")
    s, mac = _unifi_target(body)
    if not _UNIFI_ACTION_LOCK.acquire(blocking=False):
        raise HTTPException(409, detail="На UniFi уже выполняется операция")
    try:
        now = time.monotonic()
        if now - _UNIFI_LAST_REAUTH.get(mac, 0.0) < 20:
            raise HTTPException(429, detail="Повторная переавторизация доступна через 20 секунд")
        try:
            before = ap_control.call({"op":"scan","mac":mac})
            stations = before.get("authorized",[])
            if before.get("scanned") != 2 or len(stations) != 1 or stations[0]["nas_ip"] != s["nas_ip"]:
                raise HTTPException(409, detail="Клиент перешёл на другую AP или отключился")
            outcome = ap_control.call({"op":"reauth","mac":mac,"nas_ip":s["nas_ip"],
                                       "bssid":stations[0]["bssid"]})
        except ap_control.UnifiError as exc:
            raise HTTPException(409, detail="EAPOL_REAUTH не выполнена: "+exc.code) from None
        _UNIFI_LAST_REAUTH[mac] = now
        ACTION_LOG.info("UNIFI_REAUTH_REQUESTED nas=%s sid=%s",s["nas_ip"],s["session_id"])
        return {"ok":True,"result":"requested","nas_ip":s["nas_ip"],"bss":outcome["bss"],
                "message":"EAPOL_REAUTH принята точкой. Результат EAP следует проверять в FreeRADIUS."}
    finally:
        _UNIFI_ACTION_LOCK.release()


@app.post("/api/unifi/disconnect")
def unifi_disconnect(body: DisconnectRequest, request: Request):
    if not management_ready():
        raise HTTPException(503, detail="UniFi Disconnect недоступен")
    _unifi_origin(request)
    s, mac = _unifi_target(body, offline=body.offline)
    if not unifi_workflow.pmksa_ready():
        raise HTTPException(503, detail="Очистка PMKSA недоступна: Disconnect не запускался")
    if not _UNIFI_ACTION_LOCK.acquire(blocking=False):
        raise HTTPException(409, detail="На UniFi уже выполняется операция")
    try:
        try:
            prior = ap_control.call({"op":"scan","mac":mac})
        except ap_control.UnifiError as exc:
            raise HTTPException(503, detail="Не удалось проверить обе AP: "+exc.code) from None
        stations = prior.get("authorized",[])
        if prior.get("scanned") != 2 or len(stations)>1:
            raise HTTPException(503, detail="Обе точки не проверены")
        if body.offline and stations:
            raise HTTPException(409, detail="Клиент Online — используйте текущую сессию")
        if stations and stations[0]["nas_ip"] != s["nas_ip"]:
            raise HTTPException(409, detail="Клиент переместился на другую UniFi")
        if stations:
            _active_disconnect_on_opnsense(s,mac)
            ACTION_LOG.info("UNIFI_DISCONNECT ack nas=%s sid=%s",s["nas_ip"],s["session_id"])
        try:
            outcome = unifi_workflow.cleanup(mac,s["username"],s["nas_ip"],s["session_id"])
        except unifi_workflow.WorkflowError as exc:
            outcome = {"complete":False,"reason":str(exc)[:64],"cache":[]}
        partial = not outcome["complete"]
        ACTION_LOG.info("UNIFI_DISCONNECT_AND_PMKSA nas=%s sid=%s ack=%s complete=%s reason=%s",
                        s["nas_ip"],s["session_id"],bool(stations),not partial,outcome["reason"])
        return {"ok":not partial,"result":"partial" if partial else "complete",
                "disconnect_ack":bool(stations),"pmksa":outcome,
                "message":"Disconnect и проверка кеша выполнены" if not partial else
                          "Выполнено частично: проверьте состояние PMKSA"}
    finally:
        _UNIFI_ACTION_LOCK.release()


# The wired Disconnect pilot is deliberately limited to one workstation and
# one Omada switchport. The OPNsense forced-command helper independently checks
# every field against live FreeRADIUS Accounting before sending one datagram.
class OmadaWiredDisconnectRequest(BaseModel):
    nas_ip: str = Field(max_length=16)
    session_id: str = Field(min_length=8, max_length=64)
    mac: str = Field(min_length=12, max_length=25)


_OMADA_WIRED_LOCK = threading.Lock()
_OMADA_WIRED_LAST_ATTEMPT = 0.0


@app.post("/api/omada/disconnect")
def omada_wired_disconnect(body: OmadaWiredDisconnectRequest, request: Request):
    global _OMADA_WIRED_LAST_ATTEMPT
    _unifi_origin(request)
    if not omada_wired.enabled() or not control_gateway.available():
        raise HTTPException(503, detail="Omada Wired Disconnect пока не настроен")
    if (body.nas_ip != omada_wired.NAS_IP or
            not re.fullmatch(r"[0-9a-f]{12}", omada_wired.mac(body.mac)) or
            not re.fullmatch(r"[0-9A-Fa-f]{8}", body.session_id)):
        raise HTTPException(403, detail="Разрешён только пилотный клиент BiX на Tw1/0/2")
    snap, _, sessions, _ = bundle()
    m = meta(snap)
    if (m["mode"] != "sanitized_export" or m["snapshot_age_seconds"] is None
            or m["snapshot_age_seconds"] > 180):
        raise HTTPException(409, detail="Перед Disconnect необходим свежий снимок")
    latest = omada_wired.latest_sessions(sessions).get(
        (body.nas_ip, omada_wired.mac(body.mac)))
    if latest is None or latest["session_id"] != body.session_id:
        raise HTTPException(409, detail="Сессия BiX изменилась, обновите список")
    if not _OMADA_WIRED_LOCK.acquire(blocking=False):
        raise HTTPException(409, detail="Omada Disconnect уже выполняется")
    try:
        now = time.monotonic()
        if now - _OMADA_WIRED_LAST_ATTEMPT < 45:
            raise HTTPException(429, detail="Повторный Disconnect не ранее чем через 45 секунд")
        # Start cooldown before the network operation; an ambiguous timeout
        # must never trigger automatic or immediate repeat requests.
        _OMADA_WIRED_LAST_ATTEMPT = now
        payload = json.dumps({"nas_ip":body.nas_ip,
                              "session_id":body.session_id,
                              "mac":omada_wired.mac(body.mac)},
                             separators=(",", ":"))
        try:
            reply = control_gateway.execute("omada_disconnect", payload, timeout=52)
            if reply.returncode != 0:
                raise HTTPException(502, detail="Недоступен исполнитель Omada на RadiusGateway")
            response = json.loads(reply.stdout)
        except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
            # The request may have reached the switch: do not claim failure.
            ACTION_LOG.warning("OMADA_WIRED result=unknown sid=%s", body.session_id)
            return JSONResponse(status_code=202, content={
                "ok":False,"result":"unknown",
                "message":"Результат неизвестен. Проверьте Accounting; не повторяйте автоматически."})
        if not isinstance(response, dict) or response.get("result") not in (
                "ack", "nak", "unknown", "error"):
            raise HTTPException(502, detail="Некорректный ответ исполнителя Omada")
        result = response["result"]
        reason = str(response.get("reason", ""))[:65]
        ACTION_LOG.info("OMADA_WIRED result=%s reason=%s sid=%s",
                        result, reason, body.session_id)
        if result == "ack":
            cleanup = response.get("cleanup", "unknown")
            allowed = {
                "closed", "already_ended", "no_new_start", "old_session_changed",
                "old_interim_changed", "old_interim_after_start",
                "port_identity_changed", "ambiguous_successor", "storage_error",
                "unknown",
            }
            if cleanup not in allowed:
                cleanup = "unknown"
            successor = response.get("new_session_id")
            if not isinstance(successor, str) or not re.fullmatch(
                    r"[0-9A-Fa-f]{8}", successor):
                successor = None
            ACTION_LOG.info("OMADA_WIRED cleanup=%s successor=%s sid=%s",
                            cleanup, successor or "-", body.session_id)
            message = (
                "Проверенный Disconnect-ACK. Старая Accounting-запись закрыта после новой авторизации." if cleanup == "closed" else
                "Проверенный Disconnect-ACK. Новая Accounting-Start пока не подтверждена; старая запись не изменена." if cleanup == "no_new_start" else
                "Проверенный Disconnect-ACK. Старая Accounting-запись уже была завершена." if cleanup == "already_ended" else
                "Проверенный Disconnect-ACK. Автоматическая очистка не выполнена: условия безопасности не подтверждены."
            )
            return {"ok":True, "result":"ack", "session_id":body.session_id,
                    "cleanup":cleanup, "new_session_id":successor, "message":message}
        if result == "nak":
            cause = response.get("error_cause")
            if cause == 503:
                raise HTTPException(409, detail="Omada не нашла подходящую 802.1X-сессию (Error-Cause 503)")
            raise HTTPException(409, detail="Omada Disconnect-NAK" +
                                (f" (Error-Cause {cause})" if type(cause) is int else ""))
        if result == "unknown":
            return JSONResponse(status_code=202, content={
                "ok":False,"result":"unknown",
                "message":"Нет проверенного ACK. Сессия могла отключиться; проверьте Accounting."})
        raise HTTPException(503, detail="Omada Disconnect не отправлен: " + reason)
    finally:
        _OMADA_WIRED_LOCK.release()


# Closing a stale Accounting row is a database correction, NOT an AP Disconnect.
# A separate OPNsense forced-command key grants only this narrowly scoped action.
STALE_CLOSE_NAS = {"192.0.2.4", "192.0.2.5", "192.0.2.6"}


def stale_close_ready() -> bool:
    return (
        os.getenv("BIX_STALE_ACCOUNTING_CLOSE_ENABLED") == "1"
        and (control_gateway.available() if control_gateway.enabled() else
             (Path("/run/secrets/bix_stale_close_key").is_file()
              and Path("/run/secrets/bix_known_hosts").is_file()))
    )


class StaleCloseRequest(BaseModel):
    nas_ip: str = Field(min_length=7, max_length=16)
    session_id: str = Field(min_length=1, max_length=64)
    mac: str = Field(min_length=17, max_length=17)
    username: str = Field(min_length=1, max_length=128)
    started_at: str = Field(min_length=10, max_length=48)
    updated_at: str = Field(min_length=10, max_length=48)


@app.post("/api/accounting/close-stale")
def accounting_close_stale(body: StaleCloseRequest, request: Request):
    """Mark exactly one old SQLite radacct row ended; never touch a live Wi-Fi session."""
    if not auth.enabled() or not stale_close_ready():
        raise HTTPException(503, detail="Закрытие старых Accounting-сессий недоступно")
    if request.headers.get("origin", "") != os.getenv(
        "BIX_CONTROL_ORIGIN", "https://radius.example.test"
    ):
        raise HTTPException(403, detail="Недопустимый источник запроса")
    if (body.nas_ip not in STALE_CLOSE_NAS
            or not re.fullmatch(r"[A-Za-z0-9._:@/+=-]{1,64}", body.session_id)
            or not re.fullmatch(r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}", body.mac)
            or not re.fullmatch(r"[A-Za-z0-9._:/@+-]{1,128}", body.username)):
        raise HTTPException(400, detail="Недопустимый идентификатор сессии")
    start, updated = timestamp(body.started_at), timestamp(body.updated_at)
    if not start or not updated or int(start.timestamp()) > int(updated.timestamp()):
        raise HTTPException(400, detail="Некорректное время Accounting")
    snap, _, sessions, _ = bundle()
    m = meta(snap)
    if (m["mode"] != "sanitized_export" or m["snapshot_age_seconds"] is None
            or m["snapshot_age_seconds"] > 180):
        raise HTTPException(409, detail="Снимок устарел — обновите снимок и повторите")
    matches = [
        s for s in sessions
        if s["state"] == "stale" and not s["stopped_at"]
        and s["nas_ip"] == body.nas_ip and s["session_id"] == body.session_id
        and s["mac"] == body.mac and s["username"] == body.username
        and s["started_at"] == body.started_at and s["updated_at"] == body.updated_at
    ]
    if len(matches) != 1:
        raise HTTPException(409, detail="Сессия изменилась — обновите список")
    age = (datetime.now(timezone.utc) - updated).total_seconds()
    if age < 15 * 60 or age > 60 * 60 * 24 * 60:
        raise HTTPException(409, detail="Сессия больше не подходит для закрытия")
    payload = json.dumps({
        "nas_ip": body.nas_ip,
        "session_id": body.session_id,
        "mac": body.mac,
        "username": body.username,
        "started": int(start.timestamp()),
        "updated": int(updated.timestamp()),
    }, separators=(",", ":"))
    cmd = [
        "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6",
        "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes",
        "-o", "UserKnownHostsFile=/run/secrets/bix_known_hosts",
        "-i", "/run/secrets/bix_stale_close_key",
        "root@192.0.2.1", "bixcore-accounting-close-stale",
    ]
    try:
        done = (control_gateway.execute("stale_close", payload + "\n", timeout=20)
                if control_gateway.enabled() else
                subprocess.run(cmd, input=payload + "\n", text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=15, check=False))
        if done.returncode:
            raise HTTPException(502, detail="Нет связи с исполнителем OPNsense")
        answer = json.loads(done.stdout.strip())
        if not isinstance(answer, dict) or answer.get("result") not in ("closed", None):
            raise ValueError("Unexpected helper reply")
    except (subprocess.TimeoutExpired, OSError, ValueError, TypeError):
        raise HTTPException(502, detail="Не удалось проверить результат на OPNsense") from None
    if answer.get("ok") is not True or answer.get("result") != "closed":
        reason = str(answer.get("reason", "SESSION_CHANGED"))[:48]
        ACTION_LOG.info("STALE_ACCOUNTING_CLOSE rejected nas=%s sid=%s reason=%s",
                        body.nas_ip, body.session_id, reason)
        raise HTTPException(409, detail="Запись изменилась или обновилась: " + reason)
    ACTION_LOG.info("STALE_ACCOUNTING_CLOSED nas=%s sid=%s", body.nas_ip, body.session_id)
    return {"ok": True, "result": "closed",
            "message": "Старая Accounting-запись закрыта. Wi-Fi не отключался."}


# A distinct, forced-command SSH key is used for FreeRADIUS user toggles.
# The UniFi Disconnect key cannot perform these operations.
class UserEnabledRequest(BaseModel):
    uuid: str = Field(min_length=36, max_length=36)
    username: str = Field(min_length=1, max_length=128)
    expected_enabled: bool
    enabled: bool


USER_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
USER_NAME = re.compile(r"[A-Za-z0-9@._:/-]{1,128}")


def user_management_ready():
    return (os.getenv("BIX_RADIUS_USER_CONTROL_ENABLED")=="1"
            and (control_gateway.available() if control_gateway.enabled() else
                 (Path("/run/secrets/bix_radius_user_toggle_key").is_file()
                  and Path("/run/secrets/bix_radius_user_toggle_hosts").is_file())))


@app.post("/api/users/set-enabled")
def set_local_radius_user_enabled(body: UserEnabledRequest):
    if not user_management_ready():
        raise HTTPException(503, detail="Управление локальными пользователями недоступно")
    if (not USER_UUID.fullmatch(body.uuid) or not USER_NAME.fullmatch(body.username)
            or body.expected_enabled==body.enabled):
        raise HTTPException(400, detail="Некорректная команда изменения пользователя")
    if PROTECTED_BOOTSTRAP.fullmatch(body.username) or body.username.casefold()=="guestwlan":
        raise HTTPException(403, detail="Защищённая учётная запись")
    snap,users,_,_=bundle()
    m=meta(snap)
    if (m["mode"]!="sanitized_export" or not m["users_available"]
            or m["snapshot_age_seconds"] is None or m["snapshot_age_seconds"]>180):
        raise HTTPException(409, detail="Снимок Users устарел, дождись синхронизации")
    candidates=[u for u in users if u["uuid"]==body.uuid and u["username"]==body.username
                and u["kind"]=="wifi_device" and u["configured_vlan"] is not None
                and not u["protected"]]
    if len(candidates)!=1:
        raise HTTPException(403, detail="Пользователь не разрешён для ручного управления")
    if candidates[0]["enabled"] is not body.expected_enabled:
        raise HTTPException(409, detail="Состояние пользователя изменилось, обнови список")
    request_data=json.dumps({
        "uuid":body.uuid, "username":body.username,
        "expected_enabled":body.expected_enabled, "enabled":body.enabled
    },separators=(",",":"))
    cmd=["/usr/bin/ssh","-T","-o","BatchMode=yes","-o","ConnectTimeout=6",
         "-o","StrictHostKeyChecking=yes","-o","IdentitiesOnly=yes",
         "-o","UserKnownHostsFile=/run/secrets/bix_radius_user_toggle_hosts",
         "-i","/run/secrets/bix_radius_user_toggle_key",
         "root@192.0.2.1","bixcore-radius-user-toggle"]
    try:
        result=(control_gateway.execute("radius_user", request_data, timeout=96)
                if control_gateway.enabled() else
                subprocess.run(cmd,input=request_data,text=True,stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,timeout=90,check=False))
        reply=json.loads(result.stdout.strip())
        if not isinstance(reply,dict) or reply.get("result") not in ("applied","error"):
            raise ValueError("unexpected helper response")
    except (subprocess.TimeoutExpired,OSError,ValueError,json.JSONDecodeError):
        ACTION_LOG.error("RADIUS_USER_TOGGLE error user=%r reason=EXECUTOR_UNAVAILABLE",body.username)
        raise HTTPException(502,detail="Нет корректного ответа от RadiusGateway") from None
    if result.returncode==0 and reply.get("result")=="applied" and reply.get("enabled") is body.enabled:
        ACTION_LOG.info("RADIUS_USER_TOGGLE applied user=%r uuid=%s enabled=%s",
                        body.username,body.uuid,body.enabled)
        return {"ok":True,"result":"applied","username":body.username,"enabled":body.enabled,
                "message":"FreeRADIUS подтвердил изменение. Список обновится после следующего импорта."}
    reason=str(reply.get("reason","UNKNOWN"))[:80]
    ACTION_LOG.warning("RADIUS_USER_TOGGLE rejected user=%r uuid=%s reason=%s",body.username,body.uuid,reason)
    messages={
       "STATE_CHANGED":"Состояние пользователя уже изменилось. Обнови список.",
       "APPLY_FAILED_ROLLED_BACK":"Не удалось применить настройку; прежнее состояние восстановлено.",
       "APPLY_FAILED_MANUAL_RECOVERY_REQUIRED":"Не удалось подтвердить применение и откат. Проверь RadiusGateway.",
       "PROTECTED_USER":"Эту учётную запись запрещено изменять.",
       "IDENTITY_OR_VLAN_MISMATCH":"Изменился пользователь или VLAN. Обнови список.",
    }
    raise HTTPException(409,detail=messages.get(reason,"Изменение не подтверждено: "+reason))


class UserVlanRequest(BaseModel):
    uuid: str = Field(min_length=36, max_length=36)
    username: str = Field(min_length=1, max_length=128)
    expected_vlan: StrictInt = Field(ge=1, le=4094)
    vlan: StrictInt = Field(ge=1, le=4094)
    expected_enabled: bool


@app.post("/api/users/set-vlan")
def set_local_radius_user_vlan(body: UserVlanRequest):
    if not user_management_ready():
        raise HTTPException(503, detail="Управление VLAN сейчас недоступно")
    if (not USER_UUID.fullmatch(body.uuid) or not USER_NAME.fullmatch(body.username)
            or type(body.vlan) is not int or type(body.expected_vlan) is not int
            or body.vlan == body.expected_vlan):
        raise HTTPException(400, detail="Укажи новый VLAN, отличный от текущего")
    if PROTECTED_BOOTSTRAP.fullmatch(body.username) or body.username.casefold()=="guestwlan":
        raise HTTPException(403, detail="Защищённая учётная запись")
    snap, users, _, _ = bundle()
    m = meta(snap)
    if (m["mode"]!="sanitized_export" or not m["users_available"]
            or m["snapshot_age_seconds"] is None or m["snapshot_age_seconds"]>180):
        raise HTTPException(409, detail="Снимок Users устарел, дождись синхронизации")
    candidates = [u for u in users
        if u["uuid"] == body.uuid and u["username"] == body.username
        and u["kind"] == "wifi_device" and not u["protected"]
        and u["configured_vlan"] == body.expected_vlan]
    if len(candidates) != 1:
        raise HTTPException(403, detail="Изменение VLAN для этой записи запрещено или запись изменилась")
    if candidates[0]["enabled"] is not body.expected_enabled:
        raise HTTPException(409, detail="Enabled изменился, обнови список")
    data = json.dumps({
        "action":"set_vlan","uuid":body.uuid,"username":body.username,
        "expected_vlan":body.expected_vlan,"vlan":body.vlan,
        "expected_enabled":body.expected_enabled
    }, separators=(",",":"))
    cmd = ["/usr/bin/ssh","-T","-o","BatchMode=yes","-o","ConnectTimeout=6",
        "-o","StrictHostKeyChecking=yes","-o","IdentitiesOnly=yes",
        "-o","UserKnownHostsFile=/run/secrets/bix_radius_user_toggle_hosts",
        "-i","/run/secrets/bix_radius_user_toggle_key",
        "root@192.0.2.1","bixcore-radius-user-toggle"]
    try:
        result = (control_gateway.execute("radius_user", data, timeout=96)
                  if control_gateway.enabled() else
                  subprocess.run(cmd,input=data,text=True,stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,timeout=90,check=False))
        reply = json.loads(result.stdout.strip())
        if not isinstance(reply,dict) or reply.get("result") not in ("applied","error"):
            raise ValueError("unexpected helper response")
    except (subprocess.TimeoutExpired,OSError,ValueError,json.JSONDecodeError):
        ACTION_LOG.error("RADIUS_USER_VLAN error user=%r reason=EXECUTOR_UNAVAILABLE",body.username)
        raise HTTPException(502,detail="Нет корректного ответа от RadiusGateway; проверь состояние записи") from None
    if (result.returncode==0 and reply.get("result")=="applied"
            and reply.get("vlan") == body.vlan and reply.get("uuid")==body.uuid):
        ACTION_LOG.info("RADIUS_USER_VLAN applied user=%r uuid=%s vlan=%s->%s",
                        body.username,body.uuid,body.expected_vlan,body.vlan)
        return {"ok":True,"result":"applied","username":body.username,
                "vlan":body.vlan,
                "message":"VLAN применён на RadiusGateway. Для действующего Wi-Fi-подключения потребуется новая аутентификация."}
    reason = str(reply.get("reason","UNKNOWN"))[:80]
    ACTION_LOG.warning("RADIUS_USER_VLAN rejected user=%r uuid=%s reason=%s",body.username,body.uuid,reason)
    reasons = {
        "VLAN_CHANGED":"VLAN уже изменился. Обнови список.",
        "STATE_CHANGED":"Enabled изменился. Обнови список.",
        "IDENTITY_OR_VLAN_MISMATCH":"Пользователь или VLAN уже изменился.",
        "PROTECTED_USER":"Защищённая учётная запись.",
        "APPLY_FAILED_ROLLED_BACK":"Не удалось применить VLAN; прежняя настройка восстановлена.",
        "APPLY_FAILED_MANUAL_RECOVERY_REQUIRED":"Не удалось подтвердить применение и откат. Проверь RadiusGateway.",
    }
    raise HTTPException(409, detail=reasons.get(reason,"Изменение VLAN не подтверждено: "+reason))

# Additional v0.9.0 restricted operations.
# No portal VLAN assignments, timers, guestwlan changes, or arbitrary SSH commands.

class PortalEnabledRequest(BaseModel):
    uuid: str = Field(min_length=36,max_length=36)
    username: str = Field(min_length=1,max_length=128)
    expected_enabled: bool
    enabled: bool


PORTAL_SID = re.compile(r"[A-Za-z0-9._:@/+=-]{1,160}")
PORTAL_ZONE = re.compile(r"[0-9]{1,7}")


def portal_control_zones():
    raw=os.getenv("BIX_RADIUS_GUEST_PORTAL_ZONES","")
    return {zone for zone in raw.split(",") if PORTAL_ZONE.fullmatch(zone)}


def portal_control_invoke(payload, log_prefix):
    cmd=["/usr/bin/ssh","-T","-o","BatchMode=yes","-o","ConnectTimeout=6",
        "-o","StrictHostKeyChecking=yes","-o","IdentitiesOnly=yes",
        "-o","UserKnownHostsFile=/run/secrets/bix_radius_user_toggle_hosts",
        "-i","/run/secrets/bix_radius_user_toggle_key",
        "root@192.0.2.1","bixcore-radius-user-toggle"]
    try:
        request_data=json.dumps(payload,separators=(",",":"))
        result=(control_gateway.execute("radius_user", request_data, timeout=96)
                if control_gateway.enabled() else
                subprocess.run(cmd,input=request_data,text=True,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90,check=False))
        answer=json.loads(result.stdout.strip())
        if not isinstance(answer,dict) or answer.get("result") not in ("applied","disconnected","error"):
            raise ValueError("bad helper result")
        return result.returncode,answer
    except (OSError,ValueError,subprocess.TimeoutExpired):
        ACTION_LOG.error("%s executor unavailable",log_prefix)
        raise HTTPException(502,detail="Не удалось получить подтверждение от RadiusGateway") from None


def portal_management_snapshot(need_sessions=False):
    if not user_management_ready():
        raise HTTPException(503,detail="Управление Captive Portal недоступно")
    snap,users,_,portal=bundle()
    state=meta(snap)
    if (state["mode"]!="sanitized_export" or state["snapshot_age_seconds"] is None
        or state["snapshot_age_seconds"]>180 or not state["users_available"]
        or (need_sessions and not state["portal_available"])):
        raise HTTPException(409,detail="Данные портала устарели, дождись синхронизации")
    return users,portal


def portal_account(users,uuid,name,expected_enabled):
    if not USER_UUID.fullmatch(uuid) or not USER_NAME.fullmatch(name):
        raise HTTPException(400,detail="Некорректный пользователь")
    if PROTECTED_BOOTSTRAP.fullmatch(name) or name.casefold()=="guestwlan":
        raise HTTPException(403,detail="Защищённая учётная запись")
    matches=[u for u in users if u["uuid"]==uuid and u["username"]==name
             and u["kind"]=="portal_user" and u["configured_vlan"] is None
             and not u["protected"]]
    if len(matches)!=1 or sum(u["username"]==name for u in users)!=1:
        raise HTTPException(403,detail="Эта учётная запись не относится к Captive Portal")
    if matches[0]["enabled"] is not expected_enabled:
        raise HTTPException(409,detail="Enabled изменился, обнови список")
    return matches[0]


@app.post("/api/portal-users/set-enabled")
def set_portal_user_enabled(body:PortalEnabledRequest):
    if body.expected_enabled==body.enabled:
        raise HTTPException(400,detail="Состояние уже установлено")
    users,_=portal_management_snapshot()
    portal_account(users,body.uuid,body.username,body.expected_enabled)
    rc,answer=portal_control_invoke({
        "action":"portal_enabled","uuid":body.uuid,"username":body.username,
        "expected_enabled":body.expected_enabled,"enabled":body.enabled
    },"PORTAL_USER_TOGGLE")
    if (rc==0 and answer.get("result")=="applied" and
        answer.get("uuid")==body.uuid and answer.get("enabled") is body.enabled):
        ACTION_LOG.info("PORTAL_USER_TOGGLE applied user=%r uuid=%s enabled=%s",
                        body.username,body.uuid,body.enabled)
        return {"ok":True,"result":"applied","username":body.username,"enabled":body.enabled,
                "message":"Enabled изменён. Действующие сессии портала не разорваны."}
    reason=str(answer.get("reason","UNKNOWN"))[:75]
    ACTION_LOG.warning("PORTAL_USER_TOGGLE rejected user=%r reason=%s",body.username,reason)
    raise HTTPException(409,detail={
        "STATE_CHANGED":"Enabled уже изменился. Обнови список.",
        "APPLY_FAILED_ROLLED_BACK":"Не удалось применить; прежнее состояние восстановлено.",
        "APPLY_FAILED_MANUAL_RECOVERY_REQUIRED":"Проверить RadiusGateway: применение и откат не подтверждены.",
        "IDENTITY_OR_VLAN_MISMATCH":"Изменился пользователь или ему назначили VLAN.",
        "PROTECTED_USER":"Эту учётную запись менять нельзя.",
    }.get(reason,"Изменение не подтверждено: "+reason))


class PortalDisconnectRequest(BaseModel):
    uuid: str=Field(min_length=36,max_length=36)
    username: str=Field(min_length=1,max_length=128)
    expected_enabled: bool
    zone_id: str=Field(min_length=1,max_length=7)
    session_id: str=Field(min_length=1,max_length=160)
    ip: str=Field(max_length=64)
    mac: str=Field(max_length=64)


@app.post("/api/portal-sessions/disconnect")
def disconnect_portal_session(body:PortalDisconnectRequest):
    if not PORTAL_ZONE.fullmatch(body.zone_id) or not PORTAL_SID.fullmatch(body.session_id):
        raise HTTPException(400,detail="Некорректный идентификатор сессии")
    if body.zone_id not in portal_control_zones():
        raise HTTPException(403,detail="Управление этой зоной Captive Portal не разрешено")
    users,portal=portal_management_snapshot(need_sessions=True)
    portal_account(users,body.uuid,body.username,body.expected_enabled)
    matches=[s for s in portal if s["zone_id"]==body.zone_id
             and s["session_id"]==body.session_id
             and s["username"]==body.username
             and s["ip"]==body.ip and s["mac"]==body.mac]
    if len(matches)!=1 or sum(s["session_id"]==body.session_id for s in portal)!=1:
        raise HTTPException(409,detail="Сессия изменилась или неоднозначна. Обнови список")
    rc,answer=portal_control_invoke({
        "action":"portal_disconnect","zone_id":body.zone_id,
        "session_id":body.session_id,"username":body.username,
        "ip":body.ip,"mac":body.mac
    },"PORTAL_DISCONNECT")
    if (rc==0 and answer.get("result")=="disconnected"
            and answer.get("session_id")==body.session_id
            and answer.get("zone_id")==body.zone_id):
        ACTION_LOG.info("PORTAL_DISCONNECT confirmed user=%r zone=%s session=%r",
                        body.username,body.zone_id,body.session_id)
        return {"ok":True,"result":"disconnected",
                "message":"OPNsense подтвердил удаление выбранной сессии портала."}
    reason=str(answer.get("reason","UNKNOWN"))[:75]
    ACTION_LOG.warning("PORTAL_DISCONNECT rejected user=%r reason=%s",body.username,reason)
    raise HTTPException(409,detail={
        "SESSION_CHANGED":"Сессия изменилась или уже завершилась.",
        "SESSION_AMBIGUOUS":"Session ID неоднозначен.",
        "ZONE_NOT_ALLOWED":"Управление этой зоной запрещено.",
        "PORTAL_NOT_CONFIRMED":"OPNsense не подтвердил удаление сессии.",
    }.get(reason,"Disconnect не подтверждён: "+reason))


# v0.10.0 — shared guestwlan controls. No Captive Portal side effects.
class GuestEnabledRequest(BaseModel):
    uuid: str = Field(min_length=36,max_length=36)
    expected_enabled: bool
    enabled: bool


class GuestDisconnectAllRequest(BaseModel):
    uuid: str = Field(min_length=36,max_length=36)
    expected_enabled: bool
    fingerprint: str = Field(min_length=64,max_length=64)
    expected_count: StrictInt = Field(ge=1,le=24)
    confirmation: str = Field(min_length=1,max_length=64)


def guest_management_snapshot(*, require_disconnect=False):
    if not (management_ready() if require_disconnect else user_management_ready()):
        raise HTTPException(503,detail="Управление гостевым Wi-Fi недоступно")
    snap,users,sessions,portal=bundle()
    m=meta(snap)
    if (m["mode"]!="sanitized_export" or not m["users_available"]
            or m["snapshot_age_seconds"] is None or m["snapshot_age_seconds"]>180):
        raise HTTPException(409,detail="Снимок RADIUS устарел. Дождись синхронизации")
    guests=[u for u in users if u["kind"]=="guest_wifi" and u["username"]=="guestwlan"
            and u["configured_vlan"]==30 and u["uuid"]]
    if len(guests)!=1 or sum(u["username"].casefold()=="guestwlan" for u in users)!=1:
        raise HTTPException(409,detail="Единственная общая запись guestwlan VLAN30 не подтверждена")
    return snap,guests[0],sessions


@app.post("/api/guest-wifi/set-enabled")
def set_guest_wifi_enabled(body:GuestEnabledRequest):
    if not USER_UUID.fullmatch(body.uuid) or body.enabled is body.expected_enabled:
        raise HTTPException(400,detail="Некорректная команда")
    snap,guest,_=guest_management_snapshot()
    if guest["uuid"]!=body.uuid or guest["enabled"] is not body.expected_enabled:
        raise HTTPException(409,detail="guestwlan уже изменилась. Обнови список")
    rc,answer=portal_control_invoke({
        "action":"guest_enabled","uuid":body.uuid,"username":"guestwlan",
        "expected_enabled":body.expected_enabled,"enabled":body.enabled,
    },"GUEST_WIFI_ENABLED")
    if (rc==0 and answer.get("result")=="applied"
            and answer.get("uuid")==body.uuid and answer.get("enabled") is body.enabled
            and answer.get("username")=="guestwlan"):
        ACTION_LOG.info("GUEST_WIFI_ENABLED applied uuid=%s enabled=%s",body.uuid,body.enabled)
        return {"ok":True,"result":"applied","enabled":body.enabled,
                "message":"guestwlan изменён. Wi-Fi и Captive Portal сессии не отключались."}
    reason=str(answer.get("reason","UNKNOWN"))[:80]
    ACTION_LOG.warning("GUEST_WIFI_ENABLED rejected reason=%s",reason)
    raise HTTPException(409,detail={
        "STATE_CHANGED":"Enabled изменился. Обнови список.",
        "GUEST_IDENTITY_CHANGED":"guestwlan или VLAN 30 изменились. Действие заблокировано.",
        "IDENTITY_OR_VLAN_MISMATCH":"guestwlan или VLAN 30 изменились.",
        "APPLY_FAILED_ROLLED_BACK":"Ошибка применения. Прежнее Enabled восстановлено.",
        "APPLY_FAILED_MANUAL_RECOVERY_REQUIRED":"Применение и откат не подтверждены — проверь RadiusGateway.",
    }.get(reason,"Изменение guestwlan не подтверждено: "+reason))


@app.get("/api/guest-wifi/preview")
def guest_wifi_disconnect_preview():
    snap,guest,sessions=guest_management_snapshot(require_disconnect=True)
    plan=build_guest_wifi_batch(sessions,snap["as_of"])
    return {"meta":meta(snap),"guest":{"uuid":guest["uuid"],"enabled":guest["enabled"],"vlan":30},
            "plan":plan}


def disconnect_one_guest_unifi(target):
    """Existing NAS-specific SSH forced command; live helper pins username."""
    command=["/usr/bin/ssh","-T","-o","BatchMode=yes","-o","ConnectTimeout=5",
       "-o","StrictHostKeyChecking=yes","-o","IdentitiesOnly=yes",
       "-o","UserKnownHostsFile=/run/secrets/bix_known_hosts",
       "-i","/run/secrets/bix_unifi_disconnect_key",
       "root@192.0.2.1","bixcore-unifi-disconnect"]
    record={"nas_ip":target["nas_ip"],"session_id":target["session_id"],
            "mac":target["mac"],"result":"error","reason":"UNCONFIRMED"}
    payload={**target,"expected_username":"guestwlan"}
    try:
        request_data=json.dumps(payload,separators=(",",":"))
        response=(control_gateway.execute("disconnect", request_data, timeout=22)
                  if control_gateway.enabled() else
                  subprocess.run(command,input=request_data,
                                 text=True,capture_output=True,timeout=18,check=False))
        if response.returncode==0:
            report=json.loads(response.stdout.strip())
            if isinstance(report,dict) and report.get("result") in ("ack","nak","error"):
                record["result"]=report["result"]
                record["reason"]=str(report.get("reason") or "")[:80]
    except (OSError,ValueError,subprocess.TimeoutExpired):
        record["reason"]="EXECUTOR_UNAVAILABLE"
    return record


@app.post("/api/guest-wifi/disconnect-all")
def disconnect_all_guest_wifi(body:GuestDisconnectAllRequest):
    if (body.confirmation!="disconnect_guest_wifi"
            or not USER_UUID.fullmatch(body.uuid)
            or not re.fullmatch(r"[0-9a-f]{64}",body.fingerprint)):
        raise HTTPException(400,detail="Нужно явное подтверждение массового Disconnect")
    snap,guest,sessions=guest_management_snapshot(require_disconnect=True)
    if guest["uuid"]!=body.uuid or guest["enabled"] is not body.expected_enabled:
        raise HTTPException(409,detail="guestwlan изменилась. Обнови список")
    plan=build_guest_wifi_batch(sessions,snap["as_of"])
    if (not plan["within_limit"] or plan["count"]!=body.expected_count
            or plan["fingerprint"]!=body.fingerprint):
        raise HTTPException(409,detail="Состав гостевых сессий изменился или превышает лимит. Построй новый список")
    if not plan["targets"]:
        raise HTTPException(409,detail="Нет подтверждённых гостевых UniFi-сессий для отключения")
    # Each result is explicitly acknowledged; no automatic retry of NAK/error.
    targets=plan["targets"]
    outcomes=[]
    with ThreadPoolExecutor(max_workers=min(8,len(targets))) as executor:
        futures=[executor.submit(disconnect_one_guest_unifi,t) for t in targets]
        for f in as_completed(futures):
            try:outcomes.append(f.result())
            except Exception:
                outcomes.append({"result":"error","reason":"EXECUTION_EXCEPTION"})
    outcomes.sort(key=lambda x:(x.get("nas_ip",""),x.get("session_id","")))
    ack=sum(x["result"]=="ack" for x in outcomes)
    nak=sum(x["result"]=="nak" for x in outcomes)
    failed=len(outcomes)-ack-nak
    ACTION_LOG.info("GUEST_WIFI_DISCONNECT completed eligible=%s ack=%s nak=%s error=%s",
                    len(targets),ack,nak,failed)
    return {"ok":ack==len(targets),"result":"completed","requested":len(targets),
            "ack":ack,"nak":nak,"error":failed,"items":outcomes,
            "portal_sessions_untouched":True,
            "omada_unsupported":plan["omada_unsupported"],
            "message":"Disconnect подтверждён только для сессий с ACK; Captive Portal не изменялся."}


# Outermost ASGI guard: commit audit event before administrative POST.
app.add_middleware(audit.AuditMiddleware)
