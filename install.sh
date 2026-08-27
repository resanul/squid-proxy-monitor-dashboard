#!/usr/bin/env bash
# install.sh — install Squid Proxy Monitor as a service on the management host.
#
# Run this ON 10.50.0.11, as a normal user with sudo:
#     sudo ./install.sh
#
# What it sets up:
#   /opt/squid-monitor/            program files
#   /var/lib/squid-monitor/        history database (SQLite)
#   /etc/squid-monitor/            config, TLS cert, tokens
#   squid-monitor.service          systemd unit, starts on boot, restarts on crash
#   squiddash-admin / -operator / -view    Linux groups that decide who may do what
#
# Sign-in uses the LINUX ACCOUNTS ON THIS HOST. Group membership sets the role:
#   squiddash-admin     everything: policy, fleet push, squid.conf editing
#   squiddash-operator  policy and blocklist changes, no squid.conf editing
#   squiddash-view      read-only — can watch traffic, cannot change anything
#
# Re-running is safe: existing config, certificate and database are kept.
set -euo pipefail

APP_DIR=/opt/squid-monitor
DATA_DIR=/var/lib/squid-monitor
CONF_DIR=/etc/squid-monitor
SVC_USER="${SVC_USER:-squidmon}"
PORT="${PORT:-9977}"
DB_MAX_GB="${DB_MAX_GB:-5}"
ALLOW_NET="${ALLOW_NET:-}"
BIND="${BIND:-0.0.0.0}"

die() { printf '\n!! %s\n' "$*" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }

# `hostname` is a separate package and is genuinely absent on minimal RHEL
# installs. Under `set -e` a failed `HN=$(hostname)` aborted the whole script
# with status 127 and no message at all, so both of these fall back to tools
# from coreutils/iproute2 and always succeed.
host_name() {
  uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo squid-monitor
}
host_ip() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null \
         | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
    [ -n "$ip" ] || ip=$(ip -4 -o addr show scope global 2>/dev/null \
         | awk '{split($4,a,"/"); print a[1]; exit}')
  fi
  [ -n "$ip" ] || ip=$( (hostname -I 2>/dev/null || true) | awk '{print $1}' )
  printf '%s' "${ip:-127.0.0.1}"
}

[ "$(id -u)" = 0 ] || die "run with sudo: sudo ./install.sh"
SRC="$(cd "$(dirname "$0")" && pwd)"
for f in squid_dashboard.py squid-dash-auth squid-policy; do
  [ -f "$SRC/$f" ] || die "missing $f next to install.sh"
done

say "1. checking python3"
PY=$(command -v python3 || true)
[ -n "$PY" ] || die "python3 not found. Install it first: dnf install -y python3"
"$PY" - <<'EOF' || die "python 3.8+ is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 8) else 1)
EOF
echo "   $($PY -V)"

say "2. service account and role groups"
getent group squiddash-admin    >/dev/null || groupadd squiddash-admin
getent group squiddash-operator >/dev/null || groupadd squiddash-operator
getent group squiddash-view     >/dev/null || groupadd squiddash-view
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /var/lib/"$SVC_USER" \
          --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
  || useradd --system --create-home --home-dir /var/lib/"$SVC_USER" \
          --shell /sbin/nologin "$SVC_USER"
fi
echo "   service account: $SVC_USER"
echo "   groups: squiddash-admin, squiddash-operator, squiddash-view"

say "3. program files"
install -d -m 0755 "$APP_DIR" "$CONF_DIR"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR"
install -m 0755 "$SRC/squid_dashboard.py" "$APP_DIR/squid_dashboard.py"
install -o root -g root -m 0755 "$SRC/squid-dash-auth" /usr/local/sbin/squid-dash-auth
install -m 0755 "$SRC/squid-policy" "$APP_DIR/squid-policy"   # pushed to proxies
[ -f "$SRC/setup-proxy.sh" ] && install -m 0755 "$SRC/setup-proxy.sh" "$APP_DIR/setup-proxy.sh"
[ -f "$SRC/configure-proxies.sh" ] && install -m 0755 "$SRC/configure-proxies.sh" "$APP_DIR/configure-proxies.sh"
echo "   installed into $APP_DIR"

say "4. proxy list"
NEEDS_CONFIGURE=0
if [ -f "$CONF_DIR/proxies.json" ]; then
  echo "   keeping the existing $CONF_DIR/proxies.json"
else
  # Deliberately NOT shipping a starter file with example IPs here. An earlier
  # version wrote four fake-but-real-looking "PROD 10.x.x.x" entries, which is
  # exactly the kind of thing a new user mistakes for their own already-done
  # configuration instead of an example to replace — the dashboard then shows
  # a fleet that does not exist. configure-proxies.sh asks for the real
  # proxies instead and tests SSH to each one immediately.
  cat > "$CONF_DIR/proxies.json" <<'JSON'
{
  "_comment": "Empty on purpose. Run configure-proxies.sh to add your real proxies — it asks for each one's IP/hostname and tests SSH connectivity immediately, rather than you hand-editing this file.",
  "proxies": []
}
JSON
  echo "   wrote an EMPTY $CONF_DIR/proxies.json — no fleet yet"
  NEEDS_CONFIGURE=1
fi
chmod 0644 "$CONF_DIR/proxies.json"

say "5. SSH identity for reaching the proxies"
SSH_HOME="/var/lib/$SVC_USER/.ssh"
install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$SSH_HOME"
if [ ! -f "$SSH_HOME/id_ed25519" ]; then
  sudo -u "$SVC_USER" ssh-keygen -q -t ed25519 -N "" -f "$SSH_HOME/id_ed25519"
  echo "   generated a new key for $SVC_USER"
else
  echo "   keeping the existing key"
fi
echo
echo "   >>> install this public key on every proxy (as the SSH user in proxies.json):"
echo
sed 's/^/       /' "$SSH_HOME/id_ed25519.pub"

say "6. admin token"
if [ -f "$CONF_DIR/token" ]; then
  echo "   keeping the existing token"
else
  openssl rand -hex 20 > "$CONF_DIR/token" 2>/dev/null \
    || head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$CONF_DIR/token"
  echo >> "$CONF_DIR/token"
fi
chown root:"$SVC_USER" "$CONF_DIR/token"; chmod 0640 "$CONF_DIR/token"

say "7. TLS certificate"
if [ -f "$CONF_DIR/cert.pem" ] && [ -f "$CONF_DIR/key.pem" ]; then
  echo "   keeping the existing certificate"
else
  command -v openssl >/dev/null 2>&1 \
    || die "openssl is required to create the TLS certificate.
   Install it:  dnf install -y openssl
   (or drop your own cert.pem and key.pem into $CONF_DIR and re-run)"
  IP=$(host_ip); HN=$(host_name)
  # errors are shown, not swallowed: a silently missing certificate turns into
  # a service that will not start, diagnosed much later
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$CONF_DIR/key.pem" -out "$CONF_DIR/cert.pem" \
    -subj "/CN=$HN" -addext "subjectAltName=IP:$IP,DNS:$HN" 2>&1 \
    | sed 's/^/     /' || true
  [ -s "$CONF_DIR/cert.pem" ] && [ -s "$CONF_DIR/key.pem" ] \
    || die "certificate generation failed — see the openssl output above"
  echo "   self-signed certificate created for $IP ($HN)"
  echo "   (browsers warn once; replace with an internal-CA cert to remove that)"
fi
chown root:"$SVC_USER" "$CONF_DIR"/cert.pem "$CONF_DIR"/key.pem
chmod 0640 "$CONF_DIR"/key.pem; chmod 0644 "$CONF_DIR"/cert.pem

say "8. sudoers: the service may run the login helper, nothing else"
printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/squid-dash-auth\n' "$SVC_USER" > /tmp/sm-sudoers
visudo -cf /tmp/sm-sudoers >/dev/null || die "generated sudoers file is invalid"
install -o root -g root -m 0440 /tmp/sm-sudoers /etc/sudoers.d/squid-monitor
rm -f /tmp/sm-sudoers
echo "   installed /etc/sudoers.d/squid-monitor (validated before install)"
# A whole-system check is advisory only: it can fail because of a PRE-EXISTING
# problem elsewhere in sudoers, which is worth reporting but is not this
# installer's doing and must not abort it. The drop-in itself was validated
# with `visudo -cf` above, before being put in place.
if ! visudo -c >/dev/null 2>&1; then
  echo "   note: 'visudo -c' reports a problem somewhere in the system sudoers"
  echo "         configuration. Our drop-in validated cleanly; check the rest with:"
  echo "           sudo visudo -c"
fi

say "9. systemd unit"
HAVE_SYSTEMD=1
command -v systemctl >/dev/null 2>&1 || HAVE_SYSTEMD=0
install -d -m 0755 /etc/systemd/system
ALLOW_ARG=""
[ -n "$ALLOW_NET" ] && ALLOW_ARG="--allow-net $ALLOW_NET"
cat > /etc/systemd/system/squid-monitor.service <<UNIT
[Unit]
Description=Squid Proxy Monitor (fleet monitoring and policy control)
Documentation=file://$APP_DIR
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$APP_DIR
ExecStart=$PY $APP_DIR/squid_dashboard.py \\
  --proxies-config $CONF_DIR/proxies.json \\
  --db $DATA_DIR/history.db --db-max-gb $DB_MAX_GB \\
  --enable-policy --enable-blocklist \\
  --policy-helper /usr/local/sbin/squid-policy \\
  --login-linux --auth-helper /usr/local/sbin/squid-dash-auth \\
  --admin-token-file $CONF_DIR/token \\
  --tls-cert $CONF_DIR/cert.pem --tls-key $CONF_DIR/key.pem \\
  --ssh-key $SSH_HOME/id_ed25519 \\
  $ALLOW_ARG --host $BIND --port $PORT
Restart=always
RestartSec=5
# the service only needs its own data dir and the config it reads
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$DATA_DIR
NoNewPrivileges=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
echo "   wrote /etc/systemd/system/squid-monitor.service"
if [ "$HAVE_SYSTEMD" = 1 ]; then
  systemctl daemon-reload
  echo "   systemd reloaded"
else
  echo "   note: systemctl is not available on this host, so the unit was"
  echo "         written but not registered. Start it by hand with:"
  echo "           $PY $APP_DIR/squid_dashboard.py --proxies-config \\"
  echo "             $CONF_DIR/proxies.json --db $DATA_DIR/history.db ..."
fi

say "10. firewall"
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  if [ -n "$ALLOW_NET" ]; then
    firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$ALLOW_NET\" port port=\"$PORT\" protocol=\"tcp\" accept" >/dev/null
    echo "   allowed tcp/$PORT from $ALLOW_NET"
  else
    firewall-cmd --permanent --add-port="$PORT"/tcp >/dev/null
    echo "   allowed tcp/$PORT from anywhere — set ALLOW_NET to narrow this"
  fi
  firewall-cmd --reload >/dev/null
else
  echo "   firewalld not active; open tcp/$PORT yourself if a firewall is in play"
fi

cat <<DONE

============================================================
  installed
============================================================
  service     : squid-monitor
  URL         : https://$(host_ip):$PORT
  admin token : $(cat "$CONF_DIR/token")
  database    : $DATA_DIR/history.db  (cap ${DB_MAX_GB} GB)

  NEXT, in order:

  1. tell it which proxies to watch (asks for each IP, tests SSH right away):
       $APP_DIR/configure-proxies.sh

  2. give yourself a role (this is what login checks):
       sudo usermod -aG squiddash-admin <your-linux-user>
     read-only users:
       sudo usermod -aG squiddash-view <username>

  3. install the key printed in step 5 above on each proxy, then prepare them:
       $APP_DIR/setup-proxy.sh <proxy-ip>
     ...repeat per proxy. This installs the helper, sudoers, log ACL and the
     include line. It does not change how Squid handles traffic.

  4. start it:
       sudo systemctl enable --now squid-monitor
       sudo systemctl status squid-monitor --no-pager
       sudo journalctl -u squid-monitor -f

  Policy writes stay OFF for every proxy until you set "admin": true for it —
  re-run configure-proxies.sh, or edit $CONF_DIR/proxies.json, then restart.
  Enable one proxy first, confirm it, then the rest.
============================================================
DONE

if [ "$NEEDS_CONFIGURE" = 1 ] && [ -t 0 ] && [ -t 1 ]; then
  echo
  read -r -p "Run the proxy configuration wizard now? [Y/n]: " RUN_WIZ
  case "${RUN_WIZ:-y}" in
    [Nn]*) echo "Skipped — run $APP_DIR/configure-proxies.sh whenever you're ready." ;;
    *) [ -x "$APP_DIR/configure-proxies.sh" ] && "$APP_DIR/configure-proxies.sh" ;;
  esac
fi
