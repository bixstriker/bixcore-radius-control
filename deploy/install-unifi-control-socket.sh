#!/bin/sh
# BiXCore v0.10.3: one-time NAS installation of restricted UniFi socket.
# Explicitly run by NAS administrator, not by the web container.
set -eu
if [ "$(id -u)" != "0" ]; then
 echo "ERROR: run as root (sudo sh ...)" >&2
 exit 1
fi
root=/srv/bixcore-radius-control
stage=$root/.stage-v0103
unitdir=/etc/systemd/system
socketdir=$root/private/unifi_socket
for p in "$stage/sync/unifi_host.py" \
 "$stage/deploy/bixcore-unifi-control.socket" \
 "$stage/deploy/bixcore-unifi-control@.service" \
 /root/.ssh/bixcore-unifi-service-ed25519 \
 /root/.ssh/bixcore-unifi-aps-known_hosts; do
 if [ ! -f "$p" ]; then echo "MISSING_FILE: $p" >&2; exit 1; fi
 if [ -L "$p" ]; then echo "UNEXPECTED_SYMLINK: $p" >&2; exit 1; fi
done
if [ -L "$socketdir" ]; then echo "UNEXPECTED_SOCKET_SYMLINK" >&2; exit 1; fi
mkdir -p "$socketdir"
chown 10001:10001 "$socketdir"
chmod 0700 "$socketdir"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
for name in bixcore-unifi-control.socket bixcore-unifi-control@.service; do
 if [ -f "$unitdir/$name" ]; then cp -p "$unitdir/$name" "$unitdir/$name.pre-v0103-$stamp"; fi
 install -o root -g root -m 0644 "$stage/deploy/$name" "$unitdir/$name"
done
if [ -f "$root/sync/unifi_host.py" ]; then
 cp -p "$root/sync/unifi_host.py" "$root/sync/unifi_host.py.pre-v0103-$stamp"
fi
install -o root -g root -m 0644 "$stage/sync/unifi_host.py" "$root/sync/unifi_host.py"
systemctl daemon-reload
systemctl enable --now bixcore-unifi-control.socket
systemctl is-active bixcore-unifi-control.socket
systemctl is-enabled bixcore-unifi-control.socket
stat -c 'SOCKET_DIRECTORY_UID=%u MODE=%a' "$socketdir"
echo 'UNIFI_HOST_SOCKET_READY'
echo 'No client sessions, PMKSA entries, or production Docker containers were changed.'
