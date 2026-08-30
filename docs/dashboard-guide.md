# squid_dashboard.py — Full Reference

`squid_dashboard.py` is a single Python file, standard library only. This is the
complete flag reference; for the guided install path see
[`setup-guide.md`](setup-guide.md).

## Two tabs, one theme toggle

The UI is split into two tabs, switched instantly (no page reload, no lost SSE
connection or polling state):

- **Overview** — KPIs, traffic rate, System health, Client history, top
  clients/destinations, denied/slow requests, alert log, blocklist admin.
- **Live feed** — just the raw request table, given the full page height
  instead of competing for space with everything above it. Bookmarkable as
  `#live` in the URL.

The 🌙/☀️ button in the header switches between dark and light. The choice is
remembered (`localStorage`) and re-applied before the page paints, so
reloading never flashes the wrong theme. This only covers the main dashboard
— the sign-in page is dark-only.

```
python3 squid_dashboard.py --help
```

always prints the authoritative list for the version you're running — this
document mirrors it with added explanation.

## Core

| Flag | Default | What it does |
|---|---|---|
| `--log LOG` | — | A local (or mounted) `access.log` path. |
| `--host HOST` | `127.0.0.1` | Bind address. See **Network exposure** below before changing this. |
| `--port PORT` | `8899` | Dashboard port. |
| `--squid-host HOST` | SSH host | Host to poll for cache-manager stats (hit ratio, memory). |
| `--squid-port PORT` | `3128` | Squid's proxy port, for the cache-manager poll. |
| `--squid-pass PASS` | — | Cache manager password, if `cachemgr_passwd` is configured. |
| `--no-cachemgr` | off | Disable cache-manager polling entirely. |
| `--backfill N` | `2000` | How many existing log lines to preload on start. |
| `--demo` | off | Generate synthetic traffic instead of reading a real log — no Squid needed. |
| `--demo-rate N` | `6` | Demo requests per second. |
| `--alerts-config FILE` | `./squid_alerts.json` | Alert rule definitions. |
| `--no-alerts` | off | Disable the alert engine. |
| `--no-sysinfo` | off | Disable the **System health** panel (CPU/memory/disk/network). |
| `--sysinfo-interval SECS` | `20` | How often to sample resource usage. For each SSH proxy this is one extra short-lived SSH command per interval. |

## Remote proxy over SSH (run this on your own PC or a management host)

No software is installed on the proxy for monitoring — this just tails
`access.log` over SSH.

| Flag | What it does |
|---|---|
| `--ssh USER@HOST:/PATH` | e.g. `--ssh root@10.20.0.5:/var/log/squid/access.log` |
| `--ssh-host`, `--ssh-user`, `--ssh-path`, `--ssh-port` | Same thing, as separate flags instead of one string. |
| `--ssh-key PATH` | Private key file, e.g. `~/.ssh/id_ed25519`. |
| `--ssh-sudo` | Run the remote `tail` via `sudo -n` (needs a NOPASSWD sudoers entry). |
| `--ssh-bin PATH` | SSH binary to use — e.g. `plink.exe` on Windows. |
| `--check` | Test SSH connectivity and log permissions, print the exact fix if something's wrong, then exit. Run this before the real thing. |

## Pushed logs instead of SSH

For proxies where you'd rather have Squid push lines to you than SSH in:

| Flag | What it does |
|---|---|
| `--udp-port PORT` | Listen for `access_log udp://THIS_PC:PORT squid` |
| `--tcp-port PORT` | Listen for `access_log tcp://THIS_PC:PORT squid` |
| `--listen-bind ADDR` | Bind address for the above (default `0.0.0.0`) |

## Multiple proxies

| Flag | What it does |
|---|---|
| `--proxy NAME=USER@HOST:/PATH` | Add one proxy; repeat per proxy. `NAME=` becomes the dropdown label. |
| `--proxies-config FILE` | JSON file listing every proxy — see `squid_proxies.json`, or generate one with `./configure-proxies.sh` instead of hand-editing. |

With more than one proxy the UI gets a dropdown plus an **All proxies** merged
view (combined KPIs, merged leaderboards, and a `p` label on every live-feed
row and alert showing which proxy it came from). Alert *rules* are shared
across all proxies; alert *state* (the rolling window each rule evaluates) is
tracked per proxy, so one busy proxy's traffic can't trigger a threshold
meant for another.

## History database (optional)

Without `--db` the dashboard is memory-only and forgets everything on
restart.

| Flag | Default | What it does |
|---|---|---|
| `--db PATH` | — | Keep history in this SQLite file. |
| `--db-max-gb N` | `5` | Disk budget. Oldest raw requests are pruned first; hourly rollups are kept regardless — they cost almost nothing and are what makes long-term trend charts possible even after raw detail ages out. |
| `--db-no-urls` | off | Store hostnames but not full URLs — roughly halves the per-request disk cost, and avoids retaining full browsing detail. |

### Client history panel

With `--db` enabled, the **Client history** card answers "who connected, and
how much did they do" over a selectable window: **1 hour, 1 day, 2 days,
7 days, 15 days, 1 month, 3 months, or a custom date/time range**, plus a
free-text filter on the client IP. For each client in the window it shows
total requests, bytes, denied/error counts, how many distinct destination
hosts it reached, and its first/last-seen time — exportable as CSV.

This is backed by the `rollup_hour` table, the same hourly aggregate used for
the long-term trend chart. Unlike the raw `requests` table (pruned to fit
`--db-max-gb`, oldest rows first), rollups are **never pruned by the disk
budget** — a few MB per month of traffic, so this is effectively unbounded
retention in practice. That also means:

- Restarting the dashboard (or the whole `squid-monitor` service) does not
  lose this data — it lives in the SQLite file on disk, not in memory.
- "How many unique clients in the last 3 months" stays answerable for as
  long as the database file exists, independent of how small `--db-max-gb`
  is set — a tight raw-request budget only affects how far back you can pull
  individual request-level detail (URLs, exact timestamps of one request).

The underlying endpoint is `GET /api/clients?range=7d` (or `since=<epoch>`
and optionally `until=<epoch>` for a custom window, plus `proxy=<id>` to
scope to one proxy) — useful if you want to pull the same numbers from a
script instead of the UI.

**Click any client row** to see every individual request it made in that
same window — not just the aggregate counts. This queries the raw
`requests` table (so it needs data still inside the `--db-max-gb` raw-detail
window, unlike the aggregate table above which survives indefinitely),
capped at 1000 rows with a note if more exist; narrow the time range or use
the modal's CSV export to get the rest. Backed by `GET /api/history?client=…`.

### System health panel

A separate concern from Squid traffic: **is the machine itself healthy**. A
proxy can look perfectly fine in the traffic view while its disk fills up or
it starts swapping — this panel catches that. Shown for:

- **the dashboard's own host** — read directly from `/proc`, no network
  round-trip.
- **every SSH-sourced proxy** — one short-lived read-only SSH command per
  polling interval (`/proc/stat`, `/proc/meminfo`, `df -kP /`,
  `/proc/loadavg`, `/proc/uptime`, `/proc/net/dev`). Nothing is installed on
  the proxy and nothing needs root — the same unprivileged account already
  used to tail `access.log` can read all of these.
- Sources with no real host to probe (`--demo`, `--udp-port`, `--tcp-port`)
  show "no SSH system probe for this source" instead of a fabricated number.

Each host card shows CPU/memory/disk as ring gauges (turning amber at ≥75%,
red at ≥90%), plus load average, uptime, and network throughput (measured
directly — not a synthetic "network health %", since a made-up score would
be less useful than the real send/receive rate and the SSH probe's own
round-trip latency, both of which are shown as-is).

Disable with `--no-sysinfo`, or slow the SSH polling down with
`--sysinfo-interval 60` on a fleet where the extra per-interval SSH command
matters. The underlying endpoint is `GET /api/sysinfo`.

### Denied/blocked and Slowest requests — up to 1000 retained

Both panels keep up to **1000** rows server-side per proxy (was 120). The
continuous live update (every ~2s over SSE) still only carries the newest
~40 of those, on purpose — pushing all 1000 rows on every tick to every
connected browser would cost real, ongoing bandwidth for data that mostly
doesn't change between ticks. Click **"load up to 1000"** on either panel to
pull the full retained history on demand (`GET /api/mini?kind=denied|slow`);
click it again to go back to the live 40-row view. Switching proxies resets
back to live automatically, since a frozen list belongs to whichever proxy
it was loaded for.

## Policy and blocklist admin

These let the dashboard write to a proxy, through the root-owned
`squid-policy` / `squid-blocklist` helpers — see the main
[README](../README.md) for the trust model.

| Flag | What it does |
|---|---|
| `--enable-policy` | Turn on the per-IP access policy panel. Needs `squid-policy` installed on the proxy. |
| `--policy-helper PATH` | Path to that helper on the proxy (default `/usr/local/sbin/squid-policy`). |
| `--policy-no-sudo` | Call the helper without `sudo` — only if the dashboard process is already root. |
| `--enable-blocklist` | Turn on the simpler domain/IP/URL blocklist panel. Needs `squid-blocklist` installed. |
| `--blocklist-helper PATH` | Path to that helper (default `/usr/local/sbin/squid-blocklist`). |
| `--blocklist-no-sudo` | Same idea as `--policy-no-sudo`. |
| `--admin-token TOKEN` | Required to use either write panel (auto-generated and printed at startup if omitted). |
| `--admin-token-file PATH` | Read the token from a file instead of the command line — always use this for a service unit, since a token on the command line is visible to every local user via `ps`. |
| `--local-admin` | The helper scripts are on *this* machine — call them directly instead of over SSH. Use this when the dashboard runs on the proxy itself. Pair with `--log` for the local `access.log`. |

Every write is validated with `squid -k parse` before it touches the live
config and rolled back automatically if Squid rejects it or the reload
fails — including the underlying ACL list files, not just the top-level
generated config.

## Network exposure

Binding anything other than `127.0.0.1` is refused unless you also pass
`--auth-token` or `--insecure-no-auth` — the traffic view discloses every URL
every client has visited plus their IP, so publishing it unauthenticated is
not something to opt into by accident.

| Flag | What it does |
|---|---|
| `--auth-token TOKEN` | Require this token for the *whole* dashboard, not just the write panels. |
| `--login-linux` | Sign in with Linux accounts on the host running the dashboard instead of a shared token. Roles come from group membership (`squiddash-admin` / `-operator` / `-view`), so granting or revoking access is just `usermod`. Needs `squid-dash-auth` installed and a matching `sudoers` entry — `install.sh` sets this up for you. |
| `--auth-helper PATH` | Path to that login helper (default `/usr/local/sbin/squid-dash-auth`). |
| `--tls-cert PATH`, `--tls-key PATH` | Enable HTTPS with this certificate/key pair. |
| `--allow-net CIDR` | Only accept connections from this network. Repeatable. |
| `--insecure-no-auth` | Explicitly allow a non-localhost bind with no authentication. Do not use this on a proxy carrying real traffic. |

### Role enforcement

With `--login-linux`, three roles come from three Linux groups:

- **`squiddash-view`** — read-only: traffic, alerts, drill-down. No writes of
  any kind, and the server refuses them even if a client tries — hiding a
  button in the UI is not the same as access control.
- **`squiddash-operator`** — everything a viewer can do, plus policy and
  blocklist writes. Cannot edit raw `squid.conf`.
- **`squiddash-admin`** — everything, including raw `squid.conf` editing and
  pushing a policy to every proxy at once.

Every write made through a logged-in session is attributed to that Linux
username in the proxy's own audit log, not to the service account the
dashboard runs as.

## Examples

```bash
# try it with no proxy at all
python3 squid_dashboard.py --demo

# one proxy over SSH, with alerting and 5 GB of history
python3 squid_dashboard.py --ssh svc@10.20.0.12:/var/log/squid/access.log --db squid.db

# a fleet, read-only, from a config file
python3 squid_dashboard.py --proxies-config squid_proxies.json

# a fleet with policy control, published over HTTPS with per-user login
python3 squid_dashboard.py --proxies-config squid_proxies.json \
  --enable-policy --enable-blocklist --login-linux \
  --tls-cert cert.pem --tls-key key.pem --allow-net 10.20.0.0/16 \
  --host 0.0.0.0 --port 9977
```

The last line is effectively what `install.sh` sets up for you as a systemd
service — see [`setup-guide.md`](setup-guide.md) for the guided path.
