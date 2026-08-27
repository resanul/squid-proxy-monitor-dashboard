# squid_dashboard.py — Full Reference

`squid_dashboard.py` is a single Python file, standard library only. This is the
complete flag reference; for the guided install path see
[`setup-guide.md`](setup-guide.md).

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
