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
# Allowlisted backend accounting sender for locally terminated RadSec; never search arbitrary dirs.
RADSEC_PROXY_SRC="192.0.2.1"
DETAIL_ROOT=Path("/var/log/radacct")
DETAIL_MAX_BYTES=8*1024*1024

def result(state,reason="",**extra):
    print(json.dumps({"result":state,"reason":reason,**extra},separators=(",",":")))

def normmac(value):
    return re.sub("[^0-9a-f]","",str(value or "").lower())

def request():
    body=sys.stdin.buffer.read(2049)
    if not body or len(body)>2048:raise ValueError("INVALID_REQUEST_SIZE")
    req=json.loads(body)
    if req=={"probe":True}:return None,None,None,None
    if not isinstance(req,dict):
        raise ValueError("INVALID_REQUEST_FIELDS")
    fields=set(req)
    if fields=={"nas_ip","session_id","mac"}:
        expected_user=None
    elif fields=={"nas_ip","session_id","mac","expected_username"} and req["expected_username"]=="guestwlan":
        expected_user="guestwlan"
    else:
        raise ValueError("INVALID_REQUEST_FIELDS")
    nas=req["nas_ip"];sid=req["session_id"];mac=normmac(req["mac"])
    if nas not in NAS or not isinstance(sid,str) or not SID.fullmatch(sid):
        raise ValueError("INVALID_NAS_OR_SESSION")
    if not re.fullmatch("[0-9a-f]{12}",mac):
        raise ValueError("INVALID_MAC")
    return nas,sid,mac,expected_user

def accounting(nas,sid,mac,expected_user=None):
    db=sqlite3.connect("file:"+DB+"?mode=ro",uri=True,timeout=3)
    try:
        db.execute("PRAGMA query_only=ON")
        rows=db.execute("""SELECT radacctid,callingstationid,acctupdatetime,acctstarttime,acctstoptime,username
                           FROM radacct WHERE nasipaddress=? AND acctsessionid=?""",(nas,sid)).fetchall()
        matches=[r for r in rows if normmac(r[1])==mac and r[4] is None]
        if len(matches)!=1:raise ValueError("SESSION_NOT_OPEN_OR_AMBIGUOUS")
        row=matches[0]
        # Bulk guest Disconnect must fail closed if the live accounting identity
        # differs from guestwlan. The existing individual command is unchanged.
        if expected_user is not None and row[5]!=expected_user:
            raise ValueError("ACCOUNTING_USERNAME_CHANGED")
        stamp=float(row[2] or row[3] or 0);age=time.time()-stamp
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

def _detail_identifiers(path,nas,sid,mac):
    """Return all identifiers matching one SQLite-validated identity in one bounded file."""
    if not path.is_file() or path.is_symlink():
        return set()
    size=path.stat().st_size
    with path.open("rb") as fh:
        fh.seek(max(0,size-DETAIL_MAX_BYTES))
        if size>DETAIL_MAX_BYTES:
            fh.readline()  # discard incomplete first record
        data=fh.read().decode("utf-8","replace")
    found=set()
    for block in re.split(r"\r?\n\s*\r?\n",data):
        attrs={}
        for line in block.splitlines():
            match=ATTR.match(line)
            if match:
                value=match.group(2).strip()
                if value.startswith('"') and value.endswith('"'):
                    value=value[1:-1]
                attrs[match.group(1)]=value
        if (attrs.get("Acct-Session-Id")!=sid or attrs.get("NAS-IP-Address")!=nas
                or normmac(attrs.get("Calling-Station-Id"))!=mac):
            continue
        ident=attrs.get("NAS-Identifier","").strip()
        if not ident or len(ident)>64 or not re.fullmatch(r"[A-Za-z0-9_.:-]+",ident):
            raise ValueError("NAS_IDENTIFIER_INVALID")
        found.add(ident)
    return found


def identifier(nas,sid,mac):
    """Resolve identifier only for a proven NAS/SID/MAC from direct UDP or RadSec.

    Both sender directories are a fixed allowlist; conflicting identifiers fail closed.
    Detail path must never be supplied by a caller. SQLite session validation precedes
    this call and is repeated by the forced-command entry point for every action.
    """
    if nas not in NAS or not isinstance(sid,str) or not SID.fullmatch(sid):
        raise ValueError("INVALID_NAS_OR_SESSION")
    if not re.fullmatch("[0-9a-f]{12}",mac):
        raise ValueError("INVALID_MAC")
    found=set()
    dirs=(nas,RADSEC_PROXY_SRC)
    saw_directory=False
    for sender in dirs:
        directory=DETAIL_ROOT/sender
        if directory.is_symlink():
            raise ValueError("ACCOUNTING_DETAIL_UNTRUSTED_PATH")
        if not directory.is_dir():
            continue
        saw_directory=True
        for offset in (0,1):
            fn=directory/(datetime.datetime.now()-datetime.timedelta(days=offset)).strftime("detail-%Y%m%d")
            found.update(_detail_identifiers(fn,nas,sid,mac))
            if len(found)>1:
                raise ValueError("NAS_IDENTIFIER_AMBIGUOUS")
    if not saw_directory:
        raise ValueError("ACCOUNTING_DETAIL_MISSING")
    if len(found)!=1:
        raise ValueError("NAS_IDENTIFIER_NOT_FOUND")
    return next(iter(found))

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

def disconnect(nas,sid,mac,expected_user=None):
    accounting(nas,sid,mac,expected_user)
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
        nas,sid,mac,expected_user=request()
        if nas is None:result("probe","FORCED_COMMAND_REACHABLE")
        else:disconnect(nas,sid,mac,expected_user)
    except (ValueError,TypeError,json.JSONDecodeError) as exc:
        result("error",str(exc)[:90])
    except (OSError,sqlite3.Error,subprocess.TimeoutExpired):
        result("error","SOURCE_OR_TRANSPORT_FAILURE")

if __name__=="__main__":main()
