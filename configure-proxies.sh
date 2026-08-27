#!/usr/bin/env bash
# configure-proxies.sh — interactive wizard that builds proxies.json for you.
#
# This is the recommended first step, on your PC or on the management host:
#     ./configure-proxies.sh
#
# It asks how many Squid proxies you want to monitor, their IP/hostname, the
# SSH user, and the access.log path — then writes a ready-to-use proxies.json
# and tests SSH connectivity to each one immediately, so a typo or a missing
# SSH key is caught right here instead of showing up later as a silent blank
# dashboard.
#
# Re-run any time to add/remove proxies; it never touches anything else.
set -uo pipefail   # deliberately NOT -e: one bad answer must not kill the wizard

# ---- where to write the result -------------------------------------------- #
# On a management-host install (install.sh has been run) the dashboard reads
# /etc/squid-monitor/proxies.json. Otherwise this writes ./squid_proxies.json
# for direct use with `python3 squid_dashboard.py --proxies-config ...`.
MGMT_CONF=/etc/squid-monitor/proxies.json
if [ -d /etc/squid-monitor ] && [ "$(id -u)" = 0 ]; then
  OUT="$MGMT_CONF"
  MODE="management host (systemd service)"
  SSH_KEY_DEFAULT="/var/lib/squidmon/.ssh/id_ed25519"
else
  OUT="${1:-squid_proxies.json}"
  MODE="standalone dashboard (run with --proxies-config)"
  SSH_KEY_DEFAULT=""
fi

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; RED=$'\033[31m'; RST=$'\033[0m'
ok()   { printf "  ${GREEN}OK${RST}      %s\n" "$*"; }
bad()  { printf "  ${RED}FAILED${RST}  %s\n" "$*"; }
note() { printf "  ${DIM}%s${RST}\n" "$*"; }

ask() {   # ask VAR "prompt" "default"
  local __var="$1" __prompt="$2" __default="${3:-}" __reply
  if [ -n "$__default" ]; then
    read -r -p "$__prompt [$__default]: " __reply
    __reply="${__reply:-$__default}"
  else
    read -r -p "$__prompt: " __reply
  fi
  printf -v "$__var" '%s' "$__reply"
}

ask_yn() {   # ask_yn VAR "prompt" default(y|n)
  local __var="$1" __prompt="$2" __default="${3:-n}" __reply
  local __hint="y/N"; [ "$__default" = "y" ] && __hint="Y/n"
  read -r -p "$__prompt [$__hint]: " __reply
  __reply="${__reply:-$__default}"
  case "$__reply" in
    [Yy]*) printf -v "$__var" '1' ;;
    *)     printf -v "$__var" '0' ;;
  esac
}

echo "${BOLD}== Squid Proxy Monitor — configuration wizard ==${RST}"
echo "mode: $MODE"
echo "will write: $OUT"
echo

if [ -f "$OUT" ]; then
  echo "note: $OUT already exists."
  ask_yn OVERWRITE "Overwrite it with a fresh configuration built by this wizard?" n
  if [ "$OVERWRITE" != "1" ]; then
    echo "Nothing changed. Edit $OUT by hand, or re-run and choose to overwrite."
    exit 0
  fi
  cp "$OUT" "$OUT.bak.$(date +%Y%m%d-%H%M%S)"
  echo "  (previous file backed up alongside it)"
fi
echo

read -r -p "How many proxies do you want to monitor? : " N
case "$N" in ''|*[!0-9]*) echo "a number is required"; exit 1;; esac
if [ "$N" -lt 1 ]; then echo "nothing to configure"; exit 0; fi

echo
ask_yn SAME_USER "Same SSH user on every proxy?" y
if [ "$SAME_USER" = "1" ]; then
  ask COMMON_USER "  SSH username" "$(whoami)"
fi
ask_yn SAME_PATH "Same log path on every proxy?" y
if [ "$SAME_PATH" = "1" ]; then
  ask COMMON_PATH "  access.log path" "/var/log/squid/access.log"
fi
ask_yn SAME_KEY "Use one SSH key to test connectivity?" y
if [ "$SAME_KEY" = "1" ]; then
  ask TEST_KEY "  key path (blank = your default identity)" "$SSH_KEY_DEFAULT"
fi
echo

IDS=(); NAMES=(); SSHSPECS=(); ADMINS=(); STATUSES=()

for i in $(seq 1 "$N"); do
  echo "${BOLD}--- proxy $i / $N ---${RST}"
  ask HOST "  IP address or hostname" ""
  [ -n "$HOST" ] || { echo "  (skipped — empty)"; continue; }

  if [ "$SAME_USER" = "1" ]; then USER_="$COMMON_USER"
  else ask USER_ "  SSH username" "$(whoami)"; fi

  if [ "$SAME_PATH" = "1" ]; then LOGPATH="$COMMON_PATH"
  else ask LOGPATH "  access.log path" "/var/log/squid/access.log"; fi

  DEFAULT_ID="p$(echo "$HOST" | tr -c '0-9A-Za-z' '_' | sed 's/^_*//;s/_*$//' | tail -c 12)"
  [ -n "$DEFAULT_ID" ] || DEFAULT_ID="p$i"
  ask ID "  short id (used in URLs/alert tags)" "$DEFAULT_ID"
  ask NAME "  label shown in the dashboard dropdown" "PROD $HOST"
  ask_yn ADMIN "  allow POLICY CHANGES from the dashboard on this proxy? (unsafe default is no — start read-only, opt in later)" n

  KEYOPT=(); [ "$SAME_KEY" = "1" ] && [ -n "${TEST_KEY:-}" ] && KEYOPT=(-i "$TEST_KEY")
  [ "$SAME_KEY" != "1" ] && { ask THIS_KEY "  key for THIS proxy (blank = default identity)" ""; [ -n "$THIS_KEY" ] && KEYOPT=(-i "$THIS_KEY"); }

  printf "  testing SSH to %s@%s... " "$USER_" "$HOST"
  if RESULT=$(ssh "${KEYOPT[@]}" -o BatchMode=yes -o ConnectTimeout=6 \
                -o StrictHostKeyChecking=accept-new "${USER_}@${HOST}" \
                "tail -1 '$LOGPATH' >/dev/null 2>&1 && echo LOG_OK || echo LOG_UNREADABLE" 2>&1); then
    if [ "$RESULT" = "LOG_OK" ]; then
      echo; ok "connected, log is readable"
      STATUS="ok"
    else
      echo; bad "connected, but cannot read $LOGPATH"
      note "fix on that proxy: sudo setfacl -m u:${USER_}:rx \$(dirname $LOGPATH) && sudo setfacl -m u:${USER_}:r $LOGPATH && sudo setfacl -d -m u:${USER_}:r \$(dirname $LOGPATH)"
      STATUS="log-unreadable"
    fi
  else
    echo; bad "could not connect without a password"
    note "fix: cat ~/.ssh/id_ed25519.pub | ssh ${USER_}@${HOST} 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'"
    STATUS="unreachable"
  fi
  note "added anyway — this is just config; SSH access can be fixed later and re-tested by re-running this wizard"

  IDS+=("$ID"); NAMES+=("$NAME")
  SSHSPECS+=("${USER_}@${HOST}:${LOGPATH}")
  ADMINS+=("$ADMIN"); STATUSES+=("$STATUS")
  echo
done

if [ "${#IDS[@]}" -eq 0 ]; then
  echo "no proxies entered — nothing written"
  exit 0
fi

# ---- write the JSON, with a tiny Python helper for correct escaping ------- #
python3 - "$OUT" "${#IDS[@]}" "${IDS[@]}" -- "${NAMES[@]}" -- "${SSHSPECS[@]}" -- "${ADMINS[@]}" <<'PYEOF'
import json, sys
out = sys.argv[1]
n = int(sys.argv[2])
rest = sys.argv[3:]
def take(rest, n):
    vals = rest[:n]
    remainder = rest[n:]
    assert remainder and remainder[0] == "--", "internal arg-splitting error"
    return vals, remainder[1:]
ids, rest = take(rest, n)
names, rest = take(rest, n)
sshspecs, rest = take(rest, n)
admins = rest[:n]

proxies = []
for id_, name, sshspec, admin in zip(ids, names, sshspecs, admins):
    proxies.append({
        "id": id_, "name": name, "ssh": sshspec,
        "squid_host": sshspec.split("@", 1)[1].split(":", 1)[0],
        "admin": admin == "1", "enabled": True,
    })

doc = {
    "_comment": ("Generated by configure-proxies.sh — re-run that wizard to add, "
                "remove, or fix an entry rather than hand-editing this file. "
                "\"admin\": false means monitor-only; the dashboard refuses to "
                "write policy/blocklist changes to that proxy no matter what "
                "the UI is asked to do."),
    "proxies": proxies,
    "_fields": {
        "id": "short stable id used in URLs and alert tags",
        "name": "label shown in the dropdown",
        "ssh": "user@host:/path/to/access.log",
        "squid_host": "host to poll for cache-manager stats",
        "admin": "false = monitor only, the UI cannot change policy/blocklist on it",
        "enabled": "false to skip this proxy entirely",
    },
}
with open(out, "w") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
print(f"wrote {out} with {len(proxies)} proxy(ies)")
PYEOF

chmod 0644 "$OUT" 2>/dev/null || true

echo
echo "${BOLD}== summary ==${RST}"
for i in "${!IDS[@]}"; do
  case "${STATUSES[$i]}" in
    ok)             MARK="${GREEN}OK${RST}" ;;
    log-unreadable) MARK="${RED}LOG UNREADABLE${RST}" ;;
    *)              MARK="${RED}UNREACHABLE${RST}" ;;
  esac
  printf "  %-14s %-28s admin=%-5s  %b\n" "${IDS[$i]}" "${SSHSPECS[$i]}" \
    "$([ "${ADMINS[$i]}" = 1 ] && echo true || echo false)" "$MARK"
done

echo
if [ "$OUT" = "$MGMT_CONF" ]; then
  echo "Next: sudo systemctl restart squid-monitor"
else
  echo "Next: python3 squid_dashboard.py --proxies-config $OUT"
fi
echo "Anything marked UNREACHABLE or LOG UNREADABLE above still needs the fix"
echo "printed next to it — then re-run this wizard to re-test."
