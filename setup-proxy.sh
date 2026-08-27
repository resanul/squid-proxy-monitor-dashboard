#!/usr/bin/env bash
# setup-proxy.sh — prepare ONE Squid proxy to be managed from the management host.
#
# Run this ON THE MANAGEMENT HOST (10.50.0.11), once per proxy:
#     ./setup-proxy.sh 10.50.0.12
#
# What it does on that proxy, all idempotent:
#   1. installs /usr/local/sbin/squid-policy (root-owned, 0755)
#   2. installs a sudoers drop-in so the dashboard can run it without a password
#   3. grants read access to access.log via ACL, including for FUTURE rotated
#      files (without the default ACL the dashboard breaks at the next rotation)
#   4. generates the first rules.conf (init alone does not create it)
#   5. adds the single `include` line to squid.conf, in the one position where
#      it can actually affect HTTPS, and verifies the config still parses
#   6. confirms BOTH the include line and rules.conf exist before declaring the
#      proxy ready — either one missing makes every later policy push a no-op
#
# It never restarts Squid. Step 5 validates with `squid -k parse` and reverts
# its own edit if that fails, so a bad run cannot leave the proxy unable to
# start.
set -euo pipefail

PROXY="${1:-}"
SSH_USER="${SSH_USER:-opsuser}"
HELPER_SRC="${HELPER_SRC:-$(dirname "$0")/squid-policy}"
LOG_PATH="${LOG_PATH:-/var/log/squid/access.log}"
POLICY_DIR="${POLICY_DIR:-/etc/squid/policy}"
SQUID_CONF="${SQUID_CONF:-/etc/squid/squid.conf}"
# Use the SAME key the dashboard uses, not the invoking user's default identity.
# The service account owns the key that was installed on the proxies; root
# usually has none, so checking with root's identity reported "cannot SSH
# without a password" even though the dashboard's own path worked fine.
# Verifying with this key also proves the dashboard will be able to connect.
SSH_KEY="${SSH_KEY:-/var/lib/squidmon/.ssh/id_ed25519}"

die() { printf '\n!! %s\n' "$*" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }

[ -n "$PROXY" ] || die "usage: $0 <proxy-ip>   (e.g. $0 10.50.0.12)"
[ -f "$HELPER_SRC" ] || die "cannot find the helper at $HELPER_SRC"

KEYOPT=()
if [ -f "$SSH_KEY" ]; then
  KEYOPT=(-i "$SSH_KEY")
  KEYNOTE="using $SSH_KEY (the dashboard's key)"
else
  KEYNOTE="no key at $SSH_KEY — falling back to this user's default SSH identity"
fi

R=(ssh "${KEYOPT[@]}" -o BatchMode=yes -o ConnectTimeout=8 "${SSH_USER}@${PROXY}")
# -tt because the privileged steps run sudo on the proxy, which may prompt
RT=(ssh "${KEYOPT[@]}" -tt -o ConnectTimeout=8 "${SSH_USER}@${PROXY}")

say "0. checking passwordless SSH to $PROXY"
echo "   $KEYNOTE"
"${R[@]}" "echo ok" >/dev/null 2>&1 \
  || die "cannot SSH to ${SSH_USER}@${PROXY} without a password.
   The dashboard uses BatchMode, so a password prompt fails instantly.

   Install the dashboard's public key on that proxy:
     cat ${SSH_KEY}.pub | ssh ${SSH_USER}@${PROXY} \\
       'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'

   Then re-run this script. To use a different key: SSH_KEY=/path/to/key $0 $PROXY"
echo "   ok"

say "1. copying the helper"
scp -q "${KEYOPT[@]}" -o BatchMode=yes "$HELPER_SRC" "${SSH_USER}@${PROXY}:/tmp/squid-policy"
"${RT[@]}" "sudo install -o root -g root -m 0755 /tmp/squid-policy /usr/local/sbin/squid-policy \
     && rm -f /tmp/squid-policy && echo '   installed:' \$(/usr/local/sbin/squid-policy --help 2>/dev/null | head -1 || echo ok)"

say "2. sudoers drop-in (validated before install, so a typo cannot break sudo)"
"${RT[@]}" "printf '${SSH_USER} ALL=(root) NOPASSWD: /usr/local/sbin/squid-policy\n' > /tmp/sq-sudoers \
     && sudo visudo -cf /tmp/sq-sudoers \
     && sudo install -o root -g root -m 0440 /tmp/sq-sudoers /etc/sudoers.d/squid-dashboard \
     && rm -f /tmp/sq-sudoers && sudo visudo -c >/dev/null && echo '   sudoers ok'"

say "3. read access to $LOG_PATH (now and after rotation)"
"${RT[@]}" "sudo setfacl -m u:${SSH_USER}:rx \$(dirname $LOG_PATH) \
     && sudo setfacl -m u:${SSH_USER}:r $LOG_PATH \
     && sudo setfacl -d -m u:${SSH_USER}:r \$(dirname $LOG_PATH) \
     && echo '   acl set'"
"${R[@]}" "tail -1 $LOG_PATH >/dev/null 2>&1 && echo '   log is readable' || echo '   !! still cannot read the log'"

say "4. policy directory + first generated config"
# `apply` MUST run before the include line goes in. init only creates the
# directory and the starter JSON; rules.conf does not exist until apply. Adding
# the include first made `squid -k parse` fail with "Unable to find
# configuration file: .../rules.conf", so the script correctly reverted its own
# edit — and the proxy was then left admin-enabled but with NO include line,
# meaning policy pushes would be written and silently never enforced.
"${RT[@]}" "sudo /usr/local/sbin/squid-policy init >/dev/null \
     && sudo /usr/local/sbin/squid-policy apply >/dev/null \
     && echo '   policy dir ready, rules.conf generated'"

say "5. the include line in squid.conf"

# The include has to sit ABOVE the line that allows all CONNECT traffic,
# otherwise every HTTPS request is allowed before any per-IP rule is consulted.
"${RT[@]}" "sudo python3 - <<'PYEOF'
import re, shutil, subprocess, sys, time
CONF = '${SQUID_CONF}'
INC  = 'include ${POLICY_DIR}/rules.conf'
src  = open(CONF).read()
if INC in src:
    print('   include line already present'); sys.exit(0)
lines = src.splitlines()
anchor = None
for i, l in enumerate(lines):
    if re.match(r'\s*http_access\s+allow\s+CONNECT\s+SSL_ports', l):
        anchor = i; break
if anchor is None:
    for i, l in enumerate(lines):
        if re.match(r'\s*http_access\s+allow\s+localnet', l):
            anchor = i; break
if anchor is None:
    print('   !! could not find a safe place to insert the include line.')
    print('      Add this by hand ABOVE your first http_access allow line:')
    print('        ' + INC)
    sys.exit(1)
bak = CONF + '.pre-policy.' + time.strftime('%Y%m%d-%H%M%S')
shutil.copy2(CONF, bak)
lines.insert(anchor, INC)
open(CONF, 'w').write('\n'.join(lines) + '\n')
r = subprocess.run(['squid', '-k', 'parse'], capture_output=True, text=True)
if r.returncode != 0:
    shutil.copy2(bak, CONF)
    bad = [x for x in (r.stderr or '').splitlines() if 'FATAL' in x or 'ERROR' in x]
    print('   !! squid rejected the edit — reverted. ' + (bad[0] if bad else ''))
    print()
    print('   THIS PROXY IS NOT READY. Do NOT set \"admin\": true for it yet:')
    print('   without the include line the dashboard would report policy')
    print('   changes as applied while Squid never reads them.')
    sys.exit(1)
print('   include line added above line %d, squid -k parse passed' % (anchor + 1))
print('   backup: ' + bak)
PYEOF"

say "6. verifying"
"${R[@]}" "sudo -n /usr/local/sbin/squid-policy show 2>&1 | head -4" | sed 's/^/   /'

# Confirm the two things that must BOTH be true for policy to be enforced.
# Either one missing is silent: pushes succeed and change nothing.
# The helper answers this, not grep: squid.conf is not world-readable and the
# sudoers grant covers only the helper, so `sudo grep` is not available and a
# plain grep returns "Permission denied" — which an earlier version of this
# check misread as "not ready" on a proxy that was in fact correctly set up.
READY_OUT="$("${R[@]}" "sudo -n /usr/local/sbin/squid-policy ready" 2>&1 || true)"
echo "$READY_OUT" | grep -q '"ok": true' \
  || die "$PROXY is NOT ready:
   $READY_OUT

   Do not set \"admin\": true for this proxy — policy changes would be
   reported as applied while Squid never reads them.
   Re-run this script; if it fails again, send the step 5 output."
echo "   include line present and rules.conf exists"

printf '\n== done: %s is ready to be managed from this host\n' "$PROXY"
printf '   Enable it in the dashboard by setting "admin": true for it in\n'
printf '   /etc/squid-monitor/proxies.json, then: systemctl restart squid-monitor\n'
