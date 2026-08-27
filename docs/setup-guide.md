# Squid Proxy Monitor — Setup Guide

This walks through going from a fresh clone to a running dashboard watching a
real proxy fleet. Every command block says **where** to run it and what
**success looks like**, so a wrong step is obvious immediately instead of
surfacing later as a silent blank dashboard.

There are two paths:

- **Path A — quick look / single machine.** Run `squid_dashboard.py` directly
  on your own PC. Good for trying it out or watching one or two proxies.
- **Path B — always-on service.** Install it on a dedicated management host
  with `install.sh`, with systemd, TLS, and role-based login. This is the
  path for a real fleet.

---

## Step 0 — Get the code

```bash
git clone https://github.com/resanul/squid-proxy-monitor-dashboard.git
cd squid-proxy-monitor-dashboard
```

Requirements: Python 3.8+ on this machine, and on every proxy you plan to
manage policy on (monitoring-only proxies need nothing installed).

---

## Path A — quick look on your own machine

### A1. Try it with synthetic traffic first

```bash
python3 squid_dashboard.py --demo
```

✅ Open **http://127.0.0.1:8899** — you should see live (fake) traffic. Stop
with `Ctrl+C`.

### A2. Point it at one real proxy

```bash
python3 squid_dashboard.py --check --ssh youruser@PROXY_IP:/var/log/squid/access.log
```

✅ **`All good — starting the dashboard.`** This checks SSH connectivity and
log readability before actually starting.

If it fails, first make sure your SSH key is on that proxy:

```bash
cat ~/.ssh/id_ed25519.pub | ssh youruser@PROXY_IP \
  "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

### A3. Several proxies — use the wizard

```bash
./configure-proxies.sh
```

Answer its questions (how many proxies, SSH user, log path). It tests SSH to
each one immediately and writes `squid_proxies.json`.

```bash
python3 squid_dashboard.py --proxies-config squid_proxies.json
```

✅ The dropdown at the top of the page lists every proxy, plus **All
proxies**.

This monitoring-only path never touches Squid's configuration on any proxy —
it only reads `access.log` over SSH.

---

## Path B — install as a service (recommended for a real fleet)

### B1. Install on the management host

On the host that will run the dashboard permanently (not a proxy):

```bash
sudo ./install.sh
```

This sets up `/opt/squid-monitor`, a dedicated `squidmon` service account with
its own SSH key, a TLS certificate, the `squiddash-admin` /
`squiddash-operator` / `squiddash-view` Linux groups, and a systemd unit. The
fleet starts empty on purpose — no example IPs to mistake for real
configuration.

✅ At the end it prints an SSH public key and an admin token. Save both.

### B2. Tell it which proxies to watch

```bash
sudo /opt/squid-monitor/configure-proxies.sh
```

For each proxy it asks for the IP/hostname and tests SSH connectivity right
there, so a typo or a missing key is caught immediately.

✅ Summary table at the end shows `OK` for every proxy. Anything else prints
the exact fix command next to it.

### B3. Give yourself a login role

Sign-in uses the **management host's own Linux accounts** — there is no
separate password to set up.

```bash
sudo usermod -aG squiddash-admin <your-linux-username>
```

Read-only users: `squiddash-view`. Policy/blocklist without `squid.conf`
editing: `squiddash-operator`.

### B4. Start the service

```bash
sudo systemctl enable --now squid-monitor
sudo systemctl status squid-monitor --no-pager
```

✅ `active (running)`.

Open `https://<management-host>:9977`. The certificate is self-signed by
default (accept the one-time browser warning), and sign in with your Linux
username and password.

At this point monitoring works for every proxy you configured. **No proxy can
have its policy changed yet** — that's opt-in per proxy, next.

### B5. Enable policy control for one proxy

```bash
sudo /opt/squid-monitor/setup-proxy.sh <proxy-ip>
```

This installs the `squid-policy` helper, a narrowly-scoped `sudoers` entry,
read access to `access.log` (including after log rotation), and adds a single
`include` line to that proxy's `squid.conf`. It validates with
`squid -k parse` at every step and reverts its own edit if Squid rejects it —
the live Squid process is never disrupted, because `-k reconfigure` (the
actual reload) only ever runs after `-k parse` has already succeeded.

✅ Ends with `is ready to be managed from this host`.

Then flip that one proxy to writable:

```bash
sudo /opt/squid-monitor/configure-proxies.sh
```

(Re-run the wizard, or edit `/etc/squid-monitor/proxies.json` directly and
set `"admin": true` for that proxy.)

```bash
sudo systemctl restart squid-monitor
```

✅ In the dashboard, select that proxy in the dropdown (not "All proxies") and
open **🛡 Access policy** — it should unlock with your admin token instead of
showing "monitor-only".

Repeat B5 for each additional proxy you want to manage, one at a time.

---

## Using the policy panel

Four things you can do to any IP or group of IPs:

| You want | Group mode | What to enter |
|---|---|---|
| Block this IP from the internet entirely | `deny_all` | Just the IP |
| This IP can reach everything except some sites | `restricted` | IP + domains/URLs to deny |
| This IP has full access (still subject to the security tier) | `unrestricted` | Just the IP |
| This IP may reach ONLY a specific allowlist | `allowlist_only` | IP + the allowed domains |

Always **Validate (dry run)** before **Apply to proxy** — validation renders
the exact rules that would be written without touching Squid.

Once more than one proxy is writable, **⇉ Push to ALL proxies** becomes
available: it validates on every node first, and if any node rejects the
policy, nothing is applied anywhere. If a later node fails during the actual
apply, the nodes that already received it are rolled back automatically so
the fleet never ends up half-updated.

---

## If something goes wrong

| Situation | Fix |
|---|---|
| Applied the wrong policy | **Undo last apply** in the UI |
| UI won't load, need to revert on the proxy itself | `sudo /usr/local/sbin/squid-policy rollback` |
| Want to disable policy enforcement on one proxy entirely | Comment out the `include` line in that proxy's `squid.conf`, then `sudo squid -k reconfigure` |
| `squid.conf` itself is broken | Restore from the timestamped backup `setup-proxy.sh` made: `sudo cp /etc/squid/squid.conf.pre-policy.* /etc/squid/squid.conf && sudo squid -k parse && sudo squid -k reconfigure` |
| Don't want the dashboard changing this proxy anymore | Set `"admin": false` for it and restart the service — monitoring keeps working |

Squid itself is the backstop: every change runs `squid -k parse` first, and
if Squid objects, the previous configuration is restored automatically.

---

## Protected destinations

A fixed list of domains can never enter a deny list, in `squid-policy`'s
`PROTECTED` list — payment gateways, government portals, your own internal
domains, Windows Update, and so on. This is enforced in both directions:
blocking a domain that would protect one as a subdomain (e.g. blocking
`example.com` when `pay.example.com` is protected) is refused too. Edit that
list in `squid-policy` for your own critical domains before deploying to
proxies carrying real traffic.
