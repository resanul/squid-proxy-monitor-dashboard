# Squid Proxy Monitor

A zero-dependency Python toolkit for running, watching, and controlling a fleet of
[Squid](http://www.squid-cache.org/) proxies — real-time traffic monitoring, per-IP
access policy, role-based login, and safe fleet-wide config push, all from a single
web dashboard.

Everything runs on the Python 3 standard library. No `pip install`, no database
server, no frontend build step. `squid_dashboard.py` is one file; the SQLite history
store, the SSE live feed, and the whole UI are built in.

## Why

Squid itself has no web UI, no per-IP policy engine, and no built-in way to see
"what is this client actually doing right now" without grepping `access.log` by
hand. This project adds all three, without installing anything invasive on the
proxies themselves:

- **Live monitoring** for one proxy, several, or a merged "all proxies" view —
  request rate, cache hit ratio, denied/error breakdown, top clients/destinations,
  a live tailing feed, and click-through drill-down into any client or host.
- **Per-IP access policy** — blacklist an IP (no internet), deny specific
  domains/URLs for a group, whitelist a group (full internet, still subject to a
  non-negotiable security tier), or restrict a group to an allowlist only. Changes
  are validated (`squid -k parse`), applied, and rolled back automatically if Squid
  rejects them.
- **Fleet-wide control from one place** — a management host drives every proxy over
  SSH, so proxies stay untouched between changes (nothing runs there but a small
  root-owned helper). Push a policy to one proxy or to the whole fleet in one click;
  a fleet push validates on every node first and rolls back any node it already
  touched if a later node rejects the change.
- **Role-based login backed by the host's own Linux accounts** — no separate
  password database. Group membership decides the role: `squiddash-view` (read
  only), `squiddash-operator` (policy/blocklist writes), `squiddash-admin` (also raw
  `squid.conf` editing and fleet-wide push). Every change an operator makes is
  attributed to them by name in the proxy's own audit log.
- **History with a disk budget** — an optional SQLite store keeps full request
  detail up to a size you choose (oldest data pruned first) plus permanent hourly
  rollups, so alerts can show you the actual requests that triggered them, not just
  a count.
- **Client history that survives restarts** — a dedicated panel lists every
  client seen and how many are unique, over 1 hour up to 3 months (or a custom
  range), backed by the same hourly rollups — so it isn't reset by restarting
  the service and isn't limited by the raw-request disk budget.

## Architecture

```
                    ┌─────────────────────────────┐
   your browser --> │  squid_dashboard.py          │  <-- one process, one file
   (HTTPS/login)    │  (runs on a management host, │
                     │   never on a proxy)          │
                     └──────────────┬───────────────┘
                                     │ SSH (tail access.log,
                                     │      run squid-policy)
                     ┌───────────────┼───────────────┬───────────────┐
                     ▼               ▼               ▼               ▼
                  proxy A         proxy B         proxy C         proxy D
             (squid + squid-policy helper, nothing else installed)
```

The dashboard never edits `squid.conf` directly for policy changes. Each proxy gets
a *single* `include` line added once (by `setup-proxy.sh`), pointing at a generated
file that a small root-owned helper (`squid-policy`) regenerates from a JSON policy
document on every change — validate, write, `squid -k parse`, reload, and roll back
on any failure. The dashboard talks to that helper over SSH; it can also run
directly on a proxy (`--local-admin`) if you'd rather manage a single node from
itself.

## Quick start — try it without touching any real proxy

```bash
python3 squid_dashboard.py --demo
```

Open `http://127.0.0.1:8899`. This generates synthetic traffic so you can explore
the UI, alert rules, and drill-down before pointing it at anything real.

## Point it at a real proxy

For more than one proxy, don't hand-edit a config file — run the wizard. It asks
how many proxies you have, their IP/hostname and SSH details, and **tests SSH
connectivity to each one immediately**, so a typo or a missing key is caught right
there instead of showing up later as a dashboard with nothing in it:

```bash
./configure-proxies.sh
# -> writes squid_proxies.json, ready to use:
python3 squid_dashboard.py --proxies-config squid_proxies.json
```

For a single proxy, the flags work directly too:

```bash
# over SSH — no software installed on the proxy for monitoring
python3 squid_dashboard.py --ssh youruser@proxy-host:/var/log/squid/access.log

# a log file that's already local or mounted
python3 squid_dashboard.py --log /var/log/squid/access.log
```

See [`docs/dashboard-guide.md`](docs/dashboard-guide.md) for every flag (alerts,
blocklists, UDP/TCP log push, the history database, TLS, per-user login).

## Install as a service on a management host

For a fleet you manage centrally and want always-on with role-based login:

```bash
sudo ./install.sh
```

This sets up `/opt/squid-monitor`, a dedicated service account with its own SSH
key, TLS certificate, the `squiddash-*` Linux groups, and a systemd unit — starting
with an intentionally *empty* fleet, not example IPs that look like real ones. The
installer offers to run the configuration wizard right away; if you skip that, run
it yourself before starting the service:

```bash
/opt/squid-monitor/configure-proxies.sh
```

Then, once per proxy you want to manage (not just monitor):

```bash
/opt/squid-monitor/setup-proxy.sh <proxy-ip>
```

This installs the `squid-policy` helper, a narrowly-scoped `sudoers` entry, read
access to `access.log` (including after log rotation), and the one-line
`squid.conf` include — verifying at every step that Squid still parses cleanly, and
reverting its own edit if not. It never restarts Squid outside of the controlled
reload path.

Full walkthrough, including the reasoning behind each step:
[`docs/setup-guide.md`](docs/setup-guide.md).

## What's in this repo

| File | What it is |
|---|---|
| `squid_dashboard.py` | The dashboard: SSE live feed, SQLite history, alert engine, policy/blocklist admin UI, per-user login. Runs on your PC or a management host. |
| `squid-policy` | Root-owned helper installed **on each proxy**. Compiles a JSON policy document into Squid ACLs, validates, applies, rolls back on failure. Also handles raw `squid.conf` edits with the same safety gates. |
| `squid-dash-auth` | Root-owned helper for `--login-linux`: verifies a Linux account's password and reports its role from group membership. |
| `squid-blocklist` | Simpler standalone domain/IP/URL blocklist helper, independent of the per-IP policy engine. |
| `install.sh` | Installs the dashboard as a systemd service on a management host. |
| `configure-proxies.sh` | Interactive wizard: asks for your proxies' IPs and tests SSH to each one, then writes `proxies.json`. The recommended way to configure the fleet — run it before starting the service. |
| `setup-proxy.sh` | Prepares one proxy to be managed from that host. Idempotent — safe to re-run. |
| `squid_proxies.json` | Example multi-proxy config shape for `--proxies-config` — for reference; `configure-proxies.sh` generates a working one for you. |
| `squid_policy_baseline.json`, `squid_policy_example.json` | Example policy documents — an industry-baseline starting point and a worked example with real groups. |
| `squid_alerts.json`, `squid_alerts_bank.json` | Default and a heavier-traffic example alert ruleset. |
| `test_policy_sim.py`, `test_userconf_sim.py`, `test_bank_regex.py` | Test suites that simulate Squid's own ACL evaluation to catch policy-generation bugs before they reach a real proxy. |
| `check_ui_wiring.py` | Static check that every DOM id/class the dashboard's JS references actually exists in the HTML it generates. |

## Security model, briefly

- The dashboard never needs to be root, and is encouraged not to be — install.sh
  runs it as a dedicated unprivileged service account.
- Every privileged action on a proxy goes through `squid-policy`, which refuses to
  run if it isn't root-owned and non-writable by anyone else (a writable helper
  behind a `sudoers` grant is a root shell).
- A fixed list of destinations (payment/critical infrastructure domains you
  configure) can never enter a deny list, in either direction — blocking a domain
  that would *contain* a protected one as a subdomain is refused too.
- `url_regex` patterns are validated against Squid's actual regex dialect (POSIX
  ERE, not PCRE) before they're written, because Squid silently skips a pattern it
  can't compile rather than failing loudly.
- Every write is validated with `squid -k parse` before it touches the running
  config, and rolled back automatically — including the underlying ACL list files,
  not just the top-level generated config — if Squid rejects it or the reload
  fails.

## Requirements

Python 3.8+, stdlib only, on both the machine running the dashboard and each proxy
(for `squid-policy`/`squid-dash-auth`). Tested against Squid 5.x on RHEL/Rocky and
Debian/Ubuntu.

## License

MIT — see [`LICENSE`](LICENSE).
