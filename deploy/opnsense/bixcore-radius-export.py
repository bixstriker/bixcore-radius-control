#!/usr/local/bin/python3.13
import json,sqlite3,subprocess,xml.etree.ElementTree as ET
from datetime import datetime,timezone
DB='file:/usr/local/etc/raddb/freeradius.db?mode=ro'
con=sqlite3.connect(DB,uri=True,timeout=5)
con.execute('PRAGMA query_only=ON')
q="""SELECT username,nasipaddress,callingstationid,acctsessionid,acctstarttime,acctupdatetime,acctstoptime FROM radacct
WHERE acctstoptime IS NULL OR CAST(COALESCE(acctupdatetime,acctstarttime) AS INTEGER) >= CAST(strftime('%s','now') AS INTEGER)-2592000
ORDER BY COALESCE(acctupdatetime,acctstarttime) DESC LIMIT 10000"""
cols=('username','nasipaddress','callingstationid','acctsessionid','acctstarttime','acctupdatetime','acctstoptime')
rows=[dict(zip(cols,x)) for x in con.execute(q)]
con.close()
root=ET.parse('/conf/config.xml').getroot()
model=root.find('.//OPNsense/freeradius/user/users')
if model is None: raise RuntimeError('MISSING_USER_MODEL')
users=[]
for x in model.findall('user'):
 name=(x.findtext('username') or '').strip()
 uid=x.get('uuid') or (x.findtext('uuid') or '')
 if not name or not uid: raise RuntimeError('MISSING_USER_IDENTITY')
 vn=(x.findtext('vlan') or '').strip()
 users.append(dict(uuid=uid,username=name,enabled=(x.findtext('enabled') or '0').strip()=='1',vlan=int(vn) if vn else None))
r=subprocess.run(['/usr/local/sbin/configctl','captiveportal','list_clients'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12,check=True)
raw=json.loads(r.stdout)
if not isinstance(raw,list):raise RuntimeError('INVALID_PORTAL_LIST')
port=[]
for x in raw:
 if not isinstance(x,dict): raise RuntimeError('INVALID_PORTAL_ROW')
 sid=x.get('sessionId');zone=x.get('zoneid')
 if sid is None or zone is None:raise RuntimeError('MISSING_PORTAL_SESSION')
 ips=x.get('ipAddresses')
 ip=x.get('ipAddress') or (ips[0] if isinstance(ips,list) and ips else '')
 port.append(dict(sessionId=str(sid),zoneid=str(zone),userName=str(x.get('userName') or ''),ipAddress=str(ip),macAddress=str(x.get('macAddress') or ''),startTime=x.get('startTime'),last_accessed=x.get('last_accessed'),authenticated_via=str(x.get('authenticated_via') or '')))
out=dict(source='sanitized_export',as_of=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),sessions=rows,local_users=users,users_collected=True,portal_sessions=port,portal_collected=True)
print(json.dumps(out,separators=(',',':'),ensure_ascii=False))
