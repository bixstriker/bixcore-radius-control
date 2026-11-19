#!/usr/local/bin/python3.13
"""BiXCore restricted per-session UniFi Disconnect; only executed by forced SSH key."""
import datetime
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import time

DB="/usr/local/etc/raddb/freeradius.db"
CLIENTS="/usr/local/etc/raddb/clients.conf"
NAS={"192.0.2.4":"UniFi1","192.0.2.5":"UniFi2"}
SID=re.compile(r"^[A-Za-z0-9._:@/+=-]{1,64}$")
ATTR=re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*(.*?)\s*$")

def result(state,reason="",**extra):
    print(json.dumps({"result":state,"reason":reason,**extra},separators=(",",":")))

def normmac(value):
    return re.sub("[^0-9a-f]","",str(value or "").lower())

def request():
    body=sys.stdin.buffer.read(2049)
    if not body or len(body)>2048:raise ValueError("INVALID_REQUEST_SIZE")
    req=json.loads(body)
    if req=={"probe":True}:return None,None,None
    if not isinstance(req,dict) or set(req)!={"nas_ip","session_id","mac"}:
        raise ValueError("INVALID_REQUEST_FIELDS")
    nas=req["nas_ip"];sid=req["session_id"];mac=normmac(req["mac"])
    if nas not in NAS or not isinstance(sid,str) or not SID.fullmatch(sid):
        raise ValueError("INVALID_NAS_OR_SESSION")
    if not re.fullmatch("[0-9a-f]{12}",mac):
        raise ValueError("INVALID_MAC")
    return nas,sid,mac

def accounting(nas,sid,mac):
    db=sqlite3.connect("file:"+DB+"?mode=ro",uri=True,timeout=3)
    try:
        db.execute("PRAGMA query_only=ON")
        rows=db.execute("""SELECT radacctid,callingstationid,acctupdatetime,acctstarttime,acctstoptime
                           FROM radacct WHERE nasipaddress=? AND acctsessionid=?""",(nas,sid)).fetchall()
        matches=[r for r in rows if normmac(r[1])==mac and r[4] is None]
        if len(matches)!=1:raise ValueError("SESSION_NOT_OPEN_OR_AMBIGUOUS")
        row=matches[0];stamp=float(row[2] or row[3] or 0);age=time.time()-stamp
        if age>650 or age< -90:raise ValueError("ACCOUNTING_NOT_FRESH")
        newer=db.execute("""SELECT radacctid,callingstationid,acctupdatetime FROM radacct
            WHERE nasipaddress IN ('192.0.2.4','192.0.2.5') AND acctstoptime IS NULL
              AND acctupdatetime >= ?""",(int(time.time())-650,)).fetchall()
        active=[r for r in newer if normmac(r[1])==mac]
        if not active:raise ValueError("SESSION_MISSING")
        latest=max(active,key=lambda r:float(r[2] or 0))
        if latest[0]!=row[0] and float(latest[2] or 0)>float(row[2] or 0):
            raise ValueError("SESSION_CHANGED_BY_ROAMING")
    finally:db.close()

def identifier(nas,sid,mac):
    directory=Path("/var/log/radacct")/nas
    if not directory.is_dir():raise ValueError("ACCOUNTING_DETAIL_MISSING")
    for offset in (0,1):
        fn=directory/(datetime.datetime.now()-datetime.timedelta(days=offset)).strftime("detail-%Y%m%d")
        if not fn.is_file():continue
        size=fn.stat().st_size
        with fn.open("rb") as fh:
            fh.seek(max(0,size-8*1024*1024))
            if size>8*1024*1024:fh.readline()
            data=fh.read().decode("utf-8","replace")
        for block in reversed(re.split(r"\r?\n\s*\r?\n",data)):
            attrs={}
            for line in block.splitlines():
                m=ATTR.match(line)
                if m:
                    v=m.group(2).strip()
                    if v.startswith('"') and v.endswith('"'):v=v[1:-1]
                    attrs[m.group(1)]=v
            if attrs.get("Acct-Session-Id")!=sid or attrs.get("NAS-IP-Address")!=nas:
                continue
            if normmac(attrs.get("Calling-Station-Id"))!=mac:continue
            ident=attrs.get("NAS-Identifier","").strip()
            if ident and len(ident)<=64 and re.fullmatch("[A-Za-z0-9_.:-]+",ident):
                return ident
    raise ValueError("NAS_IDENTIFIER_NOT_FOUND")

def secret_for(nas):
    text=Path(CLIENTS).read_text(encoding="utf-8")
    name=NAS[nas]
    matches=re.findall(r"(?ms)^\s*client\s+[\"']?"+re.escape(name)+r"[\"']?\s*\{(.*?)^\s*\}",text)
    if len(matches)!=1:raise ValueError("NAS_CLIENT_MISSING")
    m=re.search(r"(?m)^\s*secret\s*=\s*(\S(?:.*\S)?)\s*$",matches[0])
    if not m:raise ValueError("NAS_SECRET_MISSING")
    secret=m.group(1).split(" #",1)[0].strip().strip("\"'")
    if not secret:raise ValueError("NAS_SECRET_EMPTY")
    return secret

def disconnect(nas,sid,mac):
    accounting(nas,sid,mac)
    nas_identifier=identifier(nas,sid,mac)
    secret=secret_for(nas)
    fd,tmp=tempfile.mkstemp(prefix="bixcore-coa-",dir="/tmp")
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"w") as f:f.write(secret+"\n")
        attributes=(f'Acct-Session-Id = "{sid}"\n'
                    f'NAS-IP-Address = {nas}\n'
                    f'NAS-Identifier = "{nas_identifier}"\n'
                    'Message-Authenticator = 0x00\n')
        p=subprocess.run(["/usr/local/bin/radclient","-x","-t","3","-r","1",
                          "-S",tmp,nas+":3799","disconnect"],
                         input=attributes,text=True,stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,timeout=9)
        feedback=(p.stdout or "")+"\n"+(p.stderr or "")
        if "Disconnect-ACK" in feedback:result("ack",nas_ip=nas,session_id=sid)
        elif "Disconnect-NAK" in feedback:result("nak","AP_REJECTED_SESSION")
        else:result("error","NO_DISCONNECT_ACK")
    finally:
        try:os.unlink(tmp)
        except FileNotFoundError:pass

def main():
    try:
        nas,sid,mac=request()
        if nas is None:result("probe","FORCED_COMMAND_REACHABLE")
        else:disconnect(nas,sid,mac)
    except (ValueError,TypeError,json.JSONDecodeError) as exc:
        result("error",str(exc)[:90])
    except (OSError,sqlite3.Error,subprocess.TimeoutExpired):
        result("error","SOURCE_OR_TRANSPORT_FAILURE")

if __name__=="__main__":main()
