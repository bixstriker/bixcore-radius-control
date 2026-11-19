"""One-shot, strictly read-only projection of a running OPNsense firewall.

Intended for use over *an independently reviewed* SSH forced command. It does
not provision accounts, install hooks, restart services, change FreeRADIUS
users, call mutating API routes or send Disconnect. By default writes JSON to
stdout, never stores the raw configuration or credentials in the snapshot.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import quote
from xml.etree import ElementTree as ET

SQL = """SELECT username,nasipaddress,callingstationid,acctsessionid,
       acctstarttime,acctupdatetime,acctstoptime
FROM radacct
WHERE acctstoptime IS NULL OR CAST(COALESCE(acctupdatetime,acctstarttime) AS INTEGER) >= CAST(strftime('%s','now') AS INTEGER) - 2592000
ORDER BY COALESCE(acctupdatetime,acctstarttime) DESC LIMIT ?"""
USER_PATH = ".//OPNsense/freeradius/user/users"
USER_KEYS = ("uuid", "username", "enabled", "vlan")
PORTAL_KEYS = ("sessionId", "zoneid", "userName", "ipAddress", "macAddress", "startTime", "last_accessed", "authenticated_via")


def read_accounting(db_path:Path,limit:int) -> list[dict]:
    # URI mode=ro prevents writes even if process has root privileges.
    uri="file:"+quote(str(db_path.resolve()),safe="/")+"?mode=ro"
    conn=sqlite3.connect(uri,uri=True,timeout=5)
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.row_factory=sqlite3.Row
        return [dict(x) for x in conn.execute(SQL,(limit,))]
    finally:
        conn.close()


def read_local_users(config_path:Path) -> list[dict]:
    # The XML can contain passwords/secrets. Never serialize the raw tree,
    # log unknown fields, or include descriptions (which may be sensitive).
    root=ET.parse(config_path).getroot()
    container=root.find(USER_PATH)
    if container is None:
        raise ValueError("FreeRADIUS users model not found in OPNsense config")
    result=[]
    for node in container.findall("./user"):
        name=(node.findtext("username") or "").strip()
        uid=node.get("uuid") or (node.findtext("uuid") or "")
        if not name or not uid:
            raise ValueError("FreeRADIUS user lacks UUID or username")
        raw_vlan=(node.findtext("vlan") or "").strip()
        vlan=int(raw_vlan) if raw_vlan else None
        result.append({"uuid":uid,"username":name,
                       "enabled":(node.findtext("enabled") or "0").strip()=="1",
                       "vlan":vlan})
    return result


def sanitize_portal(raw) -> list[dict]:
    if not isinstance(raw,list):
        raise ValueError("Captive Portal list_clients did not return a list")
    out=[]
    for row in raw:
        if not isinstance(row,dict):
            raise ValueError("Malformed Captive Portal item")
        sid=row.get("sessionId")
        zone=row.get("zoneid")
        if not sid or zone is None:
            raise ValueError("Captive Portal item lacks sessionId/zoneid")
        ips=row.get("ipAddresses")
        ip=row.get("ipAddress") or (ips[0] if isinstance(ips,list) and ips else "")
        out.append({"sessionId":str(sid),"zoneid":str(zone),
                    "userName":str(row.get("userName") or ""),
                    "ipAddress":str(ip or ""), "macAddress":str(row.get("macAddress") or ""),
                    "startTime":row.get("startTime"), "last_accessed":row.get("last_accessed"),
                    "authenticated_via":str(row.get("authenticated_via") or "")})
    return out


def read_portal(command:tuple[str,...]) -> list[dict]:
    proc=subprocess.run(command,capture_output=True,timeout=12,check=False)
    if proc.returncode != 0 or len(proc.stdout)>4*1024*1024:
        raise RuntimeError("Captive Portal query failed")
    return sanitize_portal(json.loads(proc.stdout))


def export(db:Path,config:Path,portal_json:Path|None=None,skip_portal=False,limit=10000)->dict:
    sessions=read_accounting(db,limit)
    users=read_local_users(config)
    if skip_portal:
        portal=[]
    elif portal_json is not None:
        portal=sanitize_portal(json.loads(portal_json.read_text(encoding="utf-8")))
    else:
        portal=read_portal(("/usr/local/sbin/configctl","captiveportal","list_clients"))
    return {"source":"sanitized_export",
            "as_of":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
            "sessions":sessions,"local_users":users,"users_collected":True,
            "portal_sessions":portal,"portal_collected":not skip_portal}


def main():
    parser=argparse.ArgumentParser(description="Read-only OPNsense Accounting + local users + portal sessions")
    parser.add_argument("--db",type=Path,default=Path("/usr/local/etc/raddb/freeradius.db"))
    parser.add_argument("--config",type=Path,default=Path("/conf/config.xml"))
    parser.add_argument("--portal-json",type=Path,help="OFFLINE testing: use an existing portal list_clients JSON")
    parser.add_argument("--skip-portal",action="store_true",help="Explicit partial export, portal unavailable")
    parser.add_argument("--limit",type=int,default=10000)
    args=parser.parse_args()
    if not 1<=args.limit<=10000:
        parser.error("--limit must be 1..10000")
    payload=export(args.db,args.config,args.portal_json,args.skip_portal,args.limit)
    # STDOUT ONLY. Consumer validates and atomically saves this sanitized JSON.
    print(json.dumps(payload,ensure_ascii=False,separators=(",",":")))


if __name__=="__main__":
    main()
