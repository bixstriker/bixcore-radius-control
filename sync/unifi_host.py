#!/usr/bin/env python3
"""Single-purpose root-owned NAS bridge for UniFi *read-only* inspection and EAPOL_REAUTH.

The unprivileged web container has only the UNIX socket, not the AP SSH key.
The handler cannot run arbitrary client-provided commands, change AP configuration,
flush whole PMKSA caches, or disconnect a client directly.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

KEY = Path("/root/.ssh/bixcore-unifi-service-ed25519")
KNOWN = Path("/root/.ssh/bixcore-unifi-aps-known_hosts")
APS = ("192.0.2.4", "192.0.2.5")
MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z")
BSSID = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z")
PMKID = re.compile(r"[0-9a-f]{32}\Z")
BSS = re.compile(r"wifi[0-9]+ap[0-9]+\Z")
MAX_RESPONSE = 12000

SCAN_SCRIPT = r"""set -eu
mac="__TARGET_MAC__"
for sock in /var/run/hostapd/wifi*; do
 [ -S "$sock" ] || continue
 iface=$(basename "$sock")
 case "$iface" in wifi[0-9]*ap[0-9]*) ;; *) continue;; esac
 info=$(/usr/sbin/wpa_cli -p /var/run/hostapd -i "$iface" raw STATUS)
 ssid=$(printf '%s\n' "$info" | sed -n 's/^ssid\[0\]=//p' | head -n 1)
 [ "$ssid" = "BiX" ] || continue
 bssid=$(printf '%s\n' "$info" | sed -n 's/^bssid\[0\]=//p' | head -n 1)
 [ -n "$bssid" ] || exit 14
 sta=$(/usr/sbin/wpa_cli -p /var/run/hostapd -i "$iface" raw STA "$mac")
 authorized=0
 case "$sta" in *"[AUTHORIZED]"*) authorized=1;; esac
 printf 'BSS\t%s\t%s\t%s\n' "$iface" "$bssid" "$authorized"
 pm=$(/usr/sbin/wpa_cli -p /var/run/hostapd -i "$iface" raw PMKSA)
 printf '%s\n' "$pm" | grep -q 'Index / SPA / PMKID' || exit 15
 printf '%s\n' "$pm" | awk -v mac="$mac" -v iface="$iface" -v bssid="$bssid" \
  '$2==mac {printf "CACHE\t%s\t%s\t%s\t%s\n",iface,bssid,$3,$4}'
done
"""

REAUTH_SCRIPT = r"""set -eu
mac="__TARGET_MAC__"
iface="__TARGET_IFACE__"
bssid="__TARGET_BSSID__"
info=$(/usr/sbin/wpa_cli -p /var/run/hostapd -i "$iface" raw STATUS)
ssid=$(printf '%s\n' "$info" | sed -n 's/^ssid\[0\]=//p' | head -n 1)
current=$(printf '%s\n' "$info" | sed -n 's/^bssid\[0\]=//p' | head -n 1)
[ "$ssid" = "BiX" ] && [ "$current" = "$bssid" ] || exit 26
sta=$(/usr/sbin/wpa_cli -p /var/run/hostapd -i "$iface" raw STA "$mac")
case "$sta" in *"[AUTHORIZED]"*) ;; *) exit 27;; esac
/usr/sbin/wpa_cli -p /var/run/hostapd -i "$iface" raw EAPOL_REAUTH "$mac"
"""


class Reject(Exception):
    pass


def validate_mac(value: object) -> str:
    if not isinstance(value, str):
        raise Reject("INVALID_MAC")
    result = value.lower().replace("-", ":")
    if not MAC.fullmatch(result):
        raise Reject("INVALID_MAC")
    return result


def ssh(ap: str, script: str, timeout: int = 22) -> str:
    if ap not in APS or not KEY.is_file() or not KNOWN.is_file():
        raise Reject("AP_TRANSPORT_UNAVAILABLE")
    result = subprocess.run(
        ["/usr/bin/ssh", "-F", "/dev/null", "-T",
         "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
         "-o", "StrictHostKeyChecking=yes",
         "-o", "UserKnownHostsFile=" + str(KNOWN),
         "-o", "ConnectTimeout=5", "-i", str(KEY),
         "laxey@" + ap, "sh -s"],
        input=script, text=True, capture_output=True,
        timeout=timeout, check=False,
    )
    if result.returncode:
        raise Reject("AP_INSPECTION_FAILED")
    if len(result.stdout) > MAX_RESPONSE or result.stderr.strip():
        # A noisy/changed remote script is not proof of a correct AP state.
        raise Reject("AP_UNEXPECTED_RESPONSE")
    return result.stdout


def scan_one(ap: str, mac: str) -> tuple[list[dict], list[dict]]:
    output = ssh(ap, SCAN_SCRIPT.replace("__TARGET_MAC__", mac))
    bss, cache = [], []
    known_bss = {}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[0] == "BSS":
            _, iface, bssid, auth = parts
            if not BSS.fullmatch(iface) or not BSSID.fullmatch(bssid) or auth not in ("0", "1"):
                raise Reject("AP_BAD_BSS")
            if iface in known_bss:
                raise Reject("AP_DUPLICATE_BSS")
            known_bss[iface] = bssid
            bss.append({"nas_ip": ap, "bss": iface, "bssid": bssid, "authorized": auth == "1"})
        elif len(parts) == 5 and parts[0] == "CACHE":
            _, iface, bssid, pmkid, ttl = parts
            if (not BSS.fullmatch(iface) or not BSSID.fullmatch(bssid)
                    or not PMKID.fullmatch(pmkid)
                    or not ttl.isdecimal() or int(ttl) > 604800):
                raise Reject("AP_BAD_CACHE")
            cache.append({"nas_ip": ap, "bss": iface, "bssid": bssid,
                          "pmkid": pmkid, "ttl": int(ttl)})
        else:
            raise Reject("AP_UNKNOWN_RESPONSE")
    if not bss or not all(c["bss"] in known_bss and
                          known_bss[c["bss"]] == c["bssid"] for c in cache):
        raise Reject("AP_BSS_DISCOVERY_INCOMPLETE")
    return bss, cache


def scan(mac: str) -> dict:
    bss, cache = [], []
    for ap in APS:
        discovered, entries = scan_one(ap, mac)
        bss.extend(discovered)
        cache.extend(entries)
    authorized = [{k: v for k, v in row.items() if k != "authorized"}
                  for row in bss if row["authorized"]]
    if len(authorized) > 1 or len({(x["nas_ip"], x["bss"], x["pmkid"]) for x in cache}) != len(cache):
        raise Reject("AMBIGUOUS_AP_STATE")
    return {"ok": True, "scanned": len(APS), "authorized": authorized, "cache": cache}


def reauth(mac: str, nas_ip: str, bssid: str) -> dict:
    if nas_ip not in APS or not BSSID.fullmatch(bssid):
        raise Reject("INVALID_TARGET")
    before = scan(mac)
    stations = before["authorized"]
    if len(stations) != 1 or (stations[0]["nas_ip"], stations[0]["bssid"]) != (nas_ip, bssid):
        raise Reject("CLIENT_MOVED_OR_OFFLINE")
    iface = stations[0]["bss"]
    script = (REAUTH_SCRIPT.replace("__TARGET_MAC__", mac)
             .replace("__TARGET_IFACE__", iface)
             .replace("__TARGET_BSSID__", bssid))
    result = ssh(nas_ip, script, timeout=12).strip()
    if result != "OK":
        raise Reject("EAPOL_REAUTH_REJECTED")
    return {"ok": True, "result": "requested", "nas_ip": nas_ip, "bss": iface}


def handle(request: object) -> dict:
    if request == {"probe": True}:
        return {"ok": True, "result": "probe"}
    if not isinstance(request, dict):
        raise Reject("INVALID_REQUEST")
    if set(request) == {"op", "mac"} and request["op"] == "scan":
        return scan(validate_mac(request["mac"]))
    if set(request) == {"op", "mac", "nas_ip", "bssid"} and request["op"] == "reauth":
        return reauth(validate_mac(request["mac"]), request["nas_ip"], request["bssid"])
    raise Reject("INVALID_REQUEST")


def main() -> None:
    try:
        raw = sys.stdin.buffer.readline(2049)
        if (os.geteuid() != 0 or len(raw) > 2048 or not raw.endswith(b"\n")
                or sys.stdin.buffer.read(1)):
            raise Reject("INVALID_TRANSPORT")
        reply = handle(json.loads(raw))
    except Reject as exc:
        reply = {"ok": False, "error": str(exc)}
    except (ValueError, OSError, subprocess.TimeoutExpired):
        reply = {"ok": False, "error": "AP_RUNTIME_UNAVAILABLE"}
    sys.stdout.write(json.dumps(reply, separators=(",", ":")) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
