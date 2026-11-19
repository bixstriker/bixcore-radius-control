#!/usr/local/bin/python3.13
"""Restricted FreeRADIUS forced-command for local user Enabled and VLAN.

No arbitrary commands, creation, passwords or protected DC/guest changes.
Executes a native OPNsense PHP model mutation, regenerates templates, checks
FreeRADIUS config, and sends HUP (never service stop/restart).
"""
from __future__ import annotations
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

PHP="/usr/local/sbin/bixcore-radius-user-toggle.php"
CONFIG=Path("/conf/config.xml")
AUTHORIZE=Path("/usr/local/etc/raddb/mods-config/files/authorize")
PID=Path("/var/run/radiusd/radiusd.pid")
LOCK=Path("/var/run/bixcore-radius-user-toggle.lock")
UUID=re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
USERNAME=re.compile(r"^[A-Za-z0-9@._:/-]{1,128}$")
PROTECTED=re.compile(r"^host/LAB-DC0[12]\.ad\.example\.test$", re.I)
MAX_INPUT=2048


def fail(reason):
    print(json.dumps({"ok":False,"result":"error","reason":reason},separators=(",",":")))
    sys.exit(1)


def run(argv, *, input_text=None, timeout=20):
    return subprocess.run(argv, input=input_text, capture_output=True, text=True, timeout=timeout, check=False)


def target_fields(uid,name):
    root=ET.parse(CONFIG).getroot()
    items=root.findall(".//OPNsense/freeradius/user/users/user")
    matches=[item for item in items if (item.get("uuid") or "")==uid]
    if len(matches)!=1:
        raise ValueError("USER_NOT_FOUND_OR_DUPLICATED")
    item=matches[0]
    live=(item.findtext("username") or "").strip()
    raw_vlan=(item.findtext("vlan") or "").strip()
    enabled=(item.findtext("enabled") or "0").strip()
    if (live!=name or not raw_vlan.isdecimal() or
            not 1<=int(raw_vlan)<=4094 or enabled not in ("0","1")):
        raise ValueError("IDENTITY_OR_VLAN_MISMATCH")
    if PROTECTED.fullmatch(name) or name.lower()=="guestwlan":
        raise ValueError("PROTECTED_USER")
    if sum((x.findtext("username") or "").strip()==name for x in items)!=1:
        raise ValueError("USERNAME_NOT_UNIQUE")
    return enabled=="1",int(raw_vlan)


def target_state(uid,name):
    return target_fields(uid,name)[0]


def present_in_authorize(username):
    # Only look for an exact username entry at the beginning of a RADIUS users line.
    prefix=re.compile(r'^'+re.escape(username)+r'(?=\s)')
    with AUTHORIZE.open("r",encoding="utf8",errors="replace") as f:
        return any(prefix.match(line) for line in f)


def pid_of_radius():
    data=PID.read_text(encoding="ascii").strip()
    if not data.isdecimal() or not (1<int(data)<1_000_000):
        raise RuntimeError("INVALID_RADIUS_PID")
    pid=int(data)
    r=run(["/bin/ps","-p",str(pid),"-o","comm="],timeout=6)
    if r.returncode or r.stdout.strip()!="radiusd":
        raise RuntimeError("RADIUS_NOT_RUNNING")
    return pid


def save_state(uuid,username,current,target):
    cmd={"uuid":uuid,"username":username,"expected_enabled":current,"enabled":target}
    result=run(["/usr/local/bin/php",PHP],input_text=json.dumps(cmd,separators=(",",":")),timeout=20)
    if result.returncode:
        reason=result.stderr.strip().splitlines()[0] if result.stderr.strip() else "OPNSENSE_SAVE_FAILED"
        if reason not in ("STATE_CHANGED","IDENTITY_OR_VLAN_MISMATCH","MODEL_VALIDATION_FAILED",
                          "PROTECTED_USER","USER_NOT_FOUND","STATE_ALREADY_REQUESTED"):
            reason="OPNSENSE_SAVE_FAILED"
        raise RuntimeError(reason)
    try:
        obj=json.loads(result.stdout)
        if obj.get("ok") is not True or obj.get("enabled") is not target:
            raise ValueError
    except (ValueError,TypeError):
        raise RuntimeError("OPNSENSE_UNEXPECTED_RESPONSE")
    if target_state(uuid,username) is not target:
        raise RuntimeError("OPNSENSE_VERIFY_FAILED")


def render_check_hup(username,desired,pid):
    reload_result=run(["/usr/local/sbin/configctl","template","reload","OPNsense/Freeradius"],timeout=35)
    if reload_result.returncode or reload_result.stdout.strip() != "OK":
        raise RuntimeError("TEMPLATE_RENDER_FAILED")
    prepared=run(["/usr/local/etc/rc.syshook.d/start/98-radius-eap-strict","--prepare-only"],timeout=35)
    if prepared.returncode:
        raise RuntimeError("RADIUS_POLICY_PREPARE_FAILED")
    if present_in_authorize(username) is not desired:
        raise RuntimeError("TEMPLATE_NOT_APPLIED")
    validated=run(["/usr/local/sbin/radiusd","-C"],timeout=25)
    if validated.returncode:
        raise RuntimeError("RADIUS_VALIDATION_FAILED")
    if pid_of_radius()!=pid:
        raise RuntimeError("RADIUS_PID_CHANGED")
    os.kill(pid,signal.SIGHUP)
    time.sleep(2)
    if pid_of_radius()!=pid:
        raise RuntimeError("RADIUS_PID_CHANGED_AFTER_HUP")



def vlan_in_authorize(username,desired):
    """Check the generated RADIUS reply attribute under exactly one user entry.

    Never print file content (it may contain password material).
    """
    prefix=re.compile(r"^"+re.escape(username)+r"\s")
    attribute=re.compile(r'^\s*Tunnel-Private-Group-Id\s*=\s*"?([0-9]{1,4})"?,?\s*$')
    blocks=[]
    block=None
    with AUTHORIZE.open("r",encoding="utf8",errors="replace") as file:
        for line in file:
            if prefix.match(line):
                if block is not None:blocks.append(block)
                block=[]
            elif block is not None and not line.strip():
                blocks.append(block)
                block=None
            elif block is not None:
                block.append(line)
    if block is not None:blocks.append(block)
    if len(blocks)!=1:return False
    matches=[int(m.group(1)) for line in blocks[0]
             if (m:=attribute.match(line))]
    return matches==[desired]


def save_vlan(uid,username,old_vlan,new_vlan,enabled):
    request={"action":"set_vlan","uuid":uid,"username":username,
             "expected_vlan":old_vlan,"vlan":new_vlan,"expected_enabled":enabled}
    result=run(["/usr/local/bin/php",PHP],
               input_text=json.dumps(request,separators=(",",":")),timeout=20)
    if result.returncode:
        reason=result.stderr.strip().splitlines()[0] if result.stderr.strip() else "OPNSENSE_SAVE_FAILED"
        if reason not in ("VLAN_CHANGED","STATE_CHANGED","MODEL_VALIDATION_FAILED",
                          "PROTECTED_USER","USER_NOT_FOUND","VLAN_ALREADY_REQUESTED",
                          "IDENTITY_OR_VLAN_MISMATCH"):
            reason="OPNSENSE_SAVE_FAILED"
        raise RuntimeError(reason)
    try:
        reply=json.loads(result.stdout)
        if reply.get("ok") is not True or reply.get("vlan")!=new_vlan or reply.get("uuid")!=uid:
            raise ValueError
    except (ValueError,TypeError):
        raise RuntimeError("OPNSENSE_UNEXPECTED_RESPONSE")
    if target_fields(uid,username)!=(enabled,new_vlan):
        raise RuntimeError("OPNSENSE_VERIFY_FAILED")


def render_check_hup_vlan(username,desired,enabled,pid):
    r=run(["/usr/local/sbin/configctl","template","reload","OPNsense/Freeradius"],timeout=35)
    if r.returncode or r.stdout.strip() != "OK":
        raise RuntimeError("TEMPLATE_RENDER_FAILED")
    prepared=run(["/usr/local/etc/rc.syshook.d/start/98-radius-eap-strict","--prepare-only"],timeout=35)
    if prepared.returncode:
        raise RuntimeError("RADIUS_POLICY_PREPARE_FAILED")
    if enabled and not vlan_in_authorize(username,desired):
        raise RuntimeError("TEMPLATE_VLAN_NOT_APPLIED")
    if not enabled and present_in_authorize(username):
        raise RuntimeError("DISABLED_USER_STILL_IN_AUTHORIZE")
    valid=run(["/usr/local/sbin/radiusd","-C"],timeout=25)
    if valid.returncode:raise RuntimeError("RADIUS_VALIDATION_FAILED")
    if pid_of_radius()!=pid:raise RuntimeError("RADIUS_PID_CHANGED")
    os.kill(pid,signal.SIGHUP)
    time.sleep(2)
    if pid_of_radius()!=pid:raise RuntimeError("RADIUS_PID_CHANGED_AFTER_HUP")


def execute_set_vlan(request):
    allowed={"action","uuid","username","expected_vlan","vlan","expected_enabled"}
    if set(request)!=allowed:fail("INVALID_REQUEST")
    uid,name=request["uuid"],request["username"]
    expected,new=request["expected_vlan"],request["vlan"]
    enabled=request["expected_enabled"]
    if (type(uid) is not str or not UUID.fullmatch(uid) or type(name) is not str
            or not USERNAME.fullmatch(name) or type(enabled) is not bool
            or type(expected) is not int or type(new) is not int
            or not 1<=expected<=4094 or not 1<=new<=4094 or new==expected):
        fail("INVALID_REQUEST")
    if PROTECTED.fullmatch(name) or name.lower()=="guestwlan":fail("PROTECTED_USER")
    with LOCK.open("a+") as mutex:
        fcntl.flock(mutex,fcntl.LOCK_EX)
        try:
            actual_enabled,actual_vlan=target_fields(uid,name)
            if actual_vlan!=expected:fail("VLAN_CHANGED")
            if actual_enabled!=enabled:fail("STATE_CHANGED")
            pid=pid_of_radius()
            save_vlan(uid,name,expected,new,enabled)
            try:
                render_check_hup_vlan(name,new,enabled,pid)
            except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):
                try:
                    if target_fields(uid,name)==(enabled,new):
                        save_vlan(uid,name,new,expected,enabled)
                    render_check_hup_vlan(name,expected,enabled,pid)
                except Exception:
                    fail("APPLY_FAILED_MANUAL_RECOVERY_REQUIRED")
                fail("APPLY_FAILED_ROLLED_BACK")
            print(json.dumps({"ok":True,"result":"applied","uuid":uid,"username":name,
                              "vlan":new,"radius_pid_unchanged":True},
                             separators=(",",":")))
        except ValueError as exc:
            reason=str(exc)
            fail(reason if reason in ("USER_NOT_FOUND_OR_DUPLICATED",
                 "IDENTITY_OR_VLAN_MISMATCH","PROTECTED_USER","USERNAME_NOT_UNIQUE")
                 else "INVALID_ACCOUNT_STATE")
        except (OSError,RuntimeError,subprocess.TimeoutExpired):
            fail("OPNSENSE_OPERATION_FAILED")

# v0.9.0 — portal actions through the same fixed, source-scoped SSH key.
# The existing Enabled/VLAN paths above remain unchanged.
PORTAL_ZONES=frozenset({"0"})
PORTAL_SID_RE=re.compile(r"^[A-Za-z0-9._:@/+=-]{1,160}$")
PORTAL_ZONE_RE=re.compile(r"^[0-9]{1,7}$")


def portal_enabled_state(uid,name):
    root=ET.parse(CONFIG).getroot()
    items=root.findall(".//OPNsense/freeradius/user/users/user")
    matches=[x for x in items if (x.get("uuid") or "")==uid]
    if len(matches)!=1:raise ValueError("USER_NOT_FOUND_OR_DUPLICATED")
    row=matches[0]
    live=(row.findtext("username") or "").strip()
    vlan=(row.findtext("vlan") or "").strip()
    state=(row.findtext("enabled") or "0").strip()
    if live!=name or vlan or state not in ("0","1"):
        raise ValueError("IDENTITY_OR_VLAN_MISMATCH")
    if PROTECTED.fullmatch(name) or name.casefold()=="guestwlan":
        raise ValueError("PROTECTED_USER")
    if sum((x.findtext("username") or "").strip()==name for x in items)!=1:
        raise ValueError("USERNAME_NOT_UNIQUE")
    return state=="1"


def save_portal_enabled(uid,name,expected,new):
    data={"action":"portal_enabled","uuid":uid,"username":name,
          "expected_enabled":expected,"enabled":new}
    result=run(["/usr/local/bin/php",PHP],
               input_text=json.dumps(data,separators=(",",":")),timeout=20)
    if result.returncode:
        reason=(result.stderr.strip().splitlines() or ["OPNSENSE_SAVE_FAILED"])[0]
        if reason not in ("STATE_CHANGED","IDENTITY_OR_VLAN_MISMATCH",
                          "MODEL_VALIDATION_FAILED","PROTECTED_USER",
                          "USER_NOT_FOUND","STATE_ALREADY_REQUESTED"):
            reason="OPNSENSE_SAVE_FAILED"
        raise RuntimeError(reason)
    try:
        obj=json.loads(result.stdout)
        if (obj.get("ok") is not True or obj.get("enabled") is not new
                or obj.get("uuid")!=uid):raise ValueError
    except (ValueError,TypeError):
        raise RuntimeError("OPNSENSE_UNEXPECTED_RESPONSE")
    if portal_enabled_state(uid,name) is not new:
        raise RuntimeError("OPNSENSE_VERIFY_FAILED")


def execute_portal_enabled(request):
    if set(request)!={"action","uuid","username","expected_enabled","enabled"}:
        fail("INVALID_REQUEST")
    uid,name=request["uuid"],request["username"]
    expected,wanted=request["expected_enabled"],request["enabled"]
    if (type(uid) is not str or not UUID.fullmatch(uid) or type(name) is not str
        or not USERNAME.fullmatch(name) or type(expected) is not bool
        or type(wanted) is not bool or expected is wanted):
        fail("INVALID_REQUEST")
    if PROTECTED.fullmatch(name) or name.casefold()=="guestwlan":fail("PROTECTED_USER")
    with LOCK.open("a+") as mutex:
        fcntl.flock(mutex,fcntl.LOCK_EX)
        try:
            live=portal_enabled_state(uid,name)
            if live is not expected:fail("STATE_CHANGED")
            pid=pid_of_radius()
            save_portal_enabled(uid,name,expected,wanted)
            try:
                render_check_hup(name,wanted,pid)
            except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):
                try:
                    if portal_enabled_state(uid,name) is wanted:
                        save_portal_enabled(uid,name,wanted,expected)
                    render_check_hup(name,expected,pid)
                except Exception:
                    fail("APPLY_FAILED_MANUAL_RECOVERY_REQUIRED")
                fail("APPLY_FAILED_ROLLED_BACK")
            print(json.dumps({"ok":True,"result":"applied","uuid":uid,
                              "username":name,"enabled":wanted,
                              "radius_pid_unchanged":True},separators=(",",":")))
        except ValueError as exc:
            reason=str(exc)
            fail(reason if reason in ("USER_NOT_FOUND_OR_DUPLICATED","IDENTITY_OR_VLAN_MISMATCH",
                 "PROTECTED_USER","USERNAME_NOT_UNIQUE") else "INVALID_ACCOUNT_STATE")
        except (OSError,RuntimeError,subprocess.TimeoutExpired):
            fail("OPNSENSE_OPERATION_FAILED")


def portal_live_sessions():
    response=run(["/usr/local/sbin/configctl","captiveportal","list_clients"],timeout=15)
    if response.returncode:raise RuntimeError("PORTAL_LIST_UNAVAILABLE")
    items=json.loads(response.stdout)
    if not isinstance(items,list):raise RuntimeError("PORTAL_LIST_INVALID")
    return items


def portal_session_matches(row,request):
    if not isinstance(row,dict):return False
    addresses=row.get("ipAddresses") or []
    ip=row.get("ipAddress") or (addresses[0] if isinstance(addresses,list) and addresses else "")
    return (str(row.get("sessionId") or "")==request["session_id"]
            and str(row.get("zoneid"))==request["zone_id"]
            and str(row.get("userName") or "")==request["username"]
            and str(ip or "")==request["ip"]
            and str(row.get("macAddress") or "")==request["mac"])


def execute_portal_disconnect(request):
    if set(request)!={"action","zone_id","session_id","username","ip","mac"}:
        fail("INVALID_REQUEST")
    zone,sid,name=request["zone_id"],request["session_id"],request["username"]
    ip,mac=request["ip"],request["mac"]
    if (type(zone) is not str or not PORTAL_ZONE_RE.fullmatch(zone)
            or type(sid) is not str or not PORTAL_SID_RE.fullmatch(sid)
            or type(name) is not str or not USERNAME.fullmatch(name)
            or type(ip) is not str or len(ip)>64
            or type(mac) is not str or len(mac)>64):
        fail("INVALID_REQUEST")
    if zone not in PORTAL_ZONES:fail("ZONE_NOT_ALLOWED")
    if PROTECTED.fullmatch(name) or name.casefold()=="guestwlan":fail("PROTECTED_USER")
    with LOCK.open("a+") as mutex:
        fcntl.flock(mutex,fcntl.LOCK_EX)
        try:
            # A portal account must still exist without VLAN; never disconnect
            # RADIUS/LDAP sessions merely because the username matches.
            root=ET.parse(CONFIG).getroot()
            accounts=root.findall(".//OPNsense/freeradius/user/users/user")
            local=[x for x in accounts if (x.findtext("username") or "").strip()==name
                   and not (x.findtext("vlan") or "").strip()]
            if len(local)!=1:fail("ACCOUNT_CHANGED")
            current=portal_live_sessions()
            if sum(str(x.get("sessionId") or "")==sid for x in current if isinstance(x,dict))!=1:
                fail("SESSION_AMBIGUOUS")
            targets=[x for x in current if portal_session_matches(x,request)]
            if len(targets)!=1:fail("SESSION_CHANGED")
            response=run(["/usr/local/sbin/configctl","captiveportal","disconnect",
                          sid,"Admin-Reset"],timeout=20)
            if response.returncode:fail("PORTAL_NOT_CONFIRMED")
            payload=json.loads(response.stdout)
            if not isinstance(payload,dict) or payload.get("terminateCause")!="Admin-Reset":
                fail("PORTAL_NOT_CONFIRMED")
            after=portal_live_sessions()
            if any(str(x.get("sessionId") or "")==sid for x in after if isinstance(x,dict)):
                fail("PORTAL_NOT_CONFIRMED")
            print(json.dumps({"ok":True,"result":"disconnected",
                              "session_id":sid,"zone_id":zone},
                             separators=(",",":")))
        except (OSError,RuntimeError,ValueError,subprocess.TimeoutExpired):
            fail("PORTAL_OPERATION_FAILED")




# v0.10.0: ONLY the shared Wi-Fi identity guestwlan at exactly VLAN 30.
# This action does not change individual Captive Portal users or sessions.
def guest_wifi_state(uid):
    tree=ET.parse(CONFIG).getroot()
    items=tree.findall(".//OPNsense/freeradius/user/users/user")
    matches=[x for x in items if (x.get("uuid") or "")==uid]
    guests=[x for x in items if (x.findtext("username") or "").strip()=="guestwlan"]
    if len(matches)!=1 or len(guests)!=1 or matches[0] is not guests[0]:
        raise ValueError("GUEST_IDENTITY_CHANGED")
    row=matches[0]
    name=(row.findtext("username") or "").strip()
    vlan=(row.findtext("vlan") or "").strip()
    state=(row.findtext("enabled") or "0").strip()
    if name!="guestwlan" or vlan!="30" or state not in ("0","1"):
        raise ValueError("GUEST_IDENTITY_CHANGED")
    return state=="1"


def save_guest_enabled(uid,expected,wanted):
    req={"action":"guest_enabled","uuid":uid,"username":"guestwlan",
         "expected_enabled":expected,"enabled":wanted}
    result=run(["/usr/local/bin/php",PHP],
               input_text=json.dumps(req,separators=(",",":")),timeout=20)
    if result.returncode:
        reason=(result.stderr.strip().splitlines() or ["OPNSENSE_SAVE_FAILED"])[0]
        if reason not in ("STATE_CHANGED","IDENTITY_OR_VLAN_MISMATCH",
                          "PROTECTED_USER","MODEL_VALIDATION_FAILED","USER_NOT_FOUND",
                          "STATE_ALREADY_REQUESTED"):
            reason="OPNSENSE_SAVE_FAILED"
        raise RuntimeError(reason)
    try:
        data=json.loads(result.stdout)
        if (data.get("ok") is not True or data.get("uuid")!=uid
            or data.get("username")!="guestwlan" or data.get("enabled") is not wanted):
            raise ValueError
    except (ValueError,TypeError):
        raise RuntimeError("OPNSENSE_UNEXPECTED_RESPONSE")
    if guest_wifi_state(uid) is not wanted:
        raise RuntimeError("OPNSENSE_VERIFY_FAILED")


def execute_guest_enabled(request):
    if set(request)!={"action","uuid","username","expected_enabled","enabled"}:
        fail("INVALID_REQUEST")
    uid=request["uuid"]
    if (type(uid) is not str or not UUID.fullmatch(uid)
        or request["username"]!="guestwlan"
        or type(request["expected_enabled"]) is not bool
        or type(request["enabled"]) is not bool
        or request["enabled"] is request["expected_enabled"]):
        fail("INVALID_REQUEST")
    expected,wanted=request["expected_enabled"],request["enabled"]
    with LOCK.open("a+") as mutex:
        fcntl.flock(mutex,fcntl.LOCK_EX)
        try:
            live=guest_wifi_state(uid)
            if live is not expected:fail("STATE_CHANGED")
            pid=pid_of_radius()
            save_guest_enabled(uid,expected,wanted)
            try:
                render_check_hup("guestwlan",wanted,pid)
            except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):
                try:
                    if guest_wifi_state(uid) is wanted:
                        save_guest_enabled(uid,wanted,expected)
                    render_check_hup("guestwlan",expected,pid)
                except Exception:
                    fail("APPLY_FAILED_MANUAL_RECOVERY_REQUIRED")
                fail("APPLY_FAILED_ROLLED_BACK")
            print(json.dumps({"ok":True,"result":"applied","uuid":uid,
                              "username":"guestwlan","enabled":wanted,
                              "radius_pid_unchanged":True},separators=(",",":")))
        except ValueError as exc:
            fail(str(exc) if str(exc)=="GUEST_IDENTITY_CHANGED" else "INVALID_ACCOUNT_STATE")
        except (OSError,RuntimeError,subprocess.TimeoutExpired):
            fail("OPNSENSE_OPERATION_FAILED")


def main():
    incoming=sys.stdin.buffer.read(MAX_INPUT+1)
    if len(incoming)>MAX_INPUT:fail("INPUT_TOO_LARGE")
    try:
        request=json.loads(incoming.decode("utf8"))
    except (UnicodeError,ValueError):
        fail("INVALID_JSON")
    if type(request) is not dict:
        fail("INVALID_REQUEST")
    if request=={"probe":True}:
        try:
            pid_of_radius()
            if not Path(PHP).is_file() or not CONFIG.is_file() or not AUTHORIZE.is_file():
                raise RuntimeError("COMPONENT_MISSING")
            print(json.dumps({"ok":True,"result":"probe","reason":"USER_TOGGLE_FORCED_COMMAND_READY"}))
        except (OSError,RuntimeError):
            fail("COMPONENT_MISSING")
        return
    if request.get("action")=="guest_enabled":
        execute_guest_enabled(request)
        return
    if request.get("action")=="portal_enabled":
        execute_portal_enabled(request)
        return
    if request.get("action")=="portal_disconnect":
        execute_portal_disconnect(request)
        return
    if type(request) is dict and request.get("action")=="set_vlan":
        execute_set_vlan(request)
        return
    if set(request)!={"uuid","username","expected_enabled","enabled"}:
        fail("INVALID_REQUEST")
    uid,name=request["uuid"],request["username"]
    expected,wanted=request["expected_enabled"],request["enabled"]
    if (type(uid) is not str or not UUID.fullmatch(uid)
            or type(name) is not str or not USERNAME.fullmatch(name)
            or type(expected) is not bool or type(wanted) is not bool):
        fail("INVALID_REQUEST")
    if wanted==expected:fail("NO_CHANGE")
    if PROTECTED.fullmatch(name) or name.lower()=="guestwlan":fail("PROTECTED_USER")
    with LOCK.open("a+") as mutex:
        fcntl.flock(mutex,fcntl.LOCK_EX)
        try:
            actual=target_state(uid,name)
            if actual is not expected:fail("STATE_CHANGED")
            pid=pid_of_radius()
            save_state(uid,name,expected,wanted)
            try:
                render_check_hup(name,wanted,pid)
            except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as exc:
                # Revert only this identity (leave all other users unchanged).
                try:
                    if target_state(uid,name) is wanted:
                        save_state(uid,name,wanted,expected)
                    render_check_hup(name,expected,pid)
                except Exception:
                    fail("APPLY_FAILED_MANUAL_RECOVERY_REQUIRED")
                fail("APPLY_FAILED_ROLLED_BACK")
            print(json.dumps({"ok":True,"result":"applied","uuid":uid,"username":name,
                              "enabled":wanted,"radius_pid_unchanged":True},
                             separators=(",",":")))
        except ValueError as exc:
            fail(str(exc) if str(exc) in
                 ("USER_NOT_FOUND_OR_DUPLICATED","IDENTITY_OR_VLAN_MISMATCH",
                  "PROTECTED_USER","USERNAME_NOT_UNIQUE") else "INVALID_ACCOUNT_STATE")
        except (OSError,RuntimeError,subprocess.TimeoutExpired):
            fail("OPNSENSE_OPERATION_FAILED")

if __name__=="__main__":
    main()
