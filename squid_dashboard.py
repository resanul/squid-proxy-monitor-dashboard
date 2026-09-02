#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Squid Proxy Live Dashboard
==========================
Zero-dependency (stdlib only) real-time web dashboard for Squid proxy.

Runs on YOUR machine — Squid can live on another host. Log lines are streamed
in continuously, parsed, aggregated in memory, checked against configurable
alert rules, and pushed to the browser over Server-Sent Events.

DATA SOURCES (pick one)
-----------------------
    --ssh user@proxy:/var/log/squid/access.log   remote tail over SSH
                                                 (nothing to install on proxy)
    --udp-port 5140      Squid pushes:  access_log udp://<YOUR_IP>:5140 squid
    --tcp-port 5141      Squid pushes:  access_log tcp://<YOUR_IP>:5141 squid
    --log /path/access.log                       local file or mounted share
    --demo                                       synthetic traffic, no Squid

MULTIPLE PROXIES
----------------
    --proxy "Edge=user@10.0.0.8:/var/log/squid/access.log" \
    --proxy "Core=user@10.0.0.7:/var/log/squid/access.log"
    ...or list them in squid_proxies.json and pass --proxies-config.
    The UI then shows a dropdown per proxy plus an "All proxies" merged view.

USAGE
-----
    python3 squid_dashboard.py --demo
    python3 squid_dashboard.py --ssh root@10.0.0.5:/var/log/squid/access.log
    python3 squid_dashboard.py --udp-port 5140
    python3 squid_dashboard.py --log /var/log/squid/access.log

Then open http://127.0.0.1:8899

REQUIREMENTS
------------
    Python 3.8+ on this machine. Nothing on the proxy.

SSH mode needs key-based login (BatchMode, so it never waits on a password):
    ssh-copy-id user@proxy
Reading the log may need group access on the proxy:
    sudo usermod -a -G squid <user>      # or use --ssh-sudo
"""

__version__ = "1.15.0"       # …1.7 policy editor · 1.8 monitor-only · 1.8.1 panel
                              # feedback fixes · 1.9 client-history panel
                              # (unique/connected clients over selectable time
                              # ranges, backed by the already-unbounded hourly
                              # rollup table so it survives restarts) · 1.10
                              # System health panel: CPU/memory/disk/network
                              # for the dashboard's own host and each SSH
                              # proxy, via /proc + df — no helper installed ·
                              # 1.11 Live feed moved to its own tab (no more
                              # page-length table crowding the overview), plus
                              # a dark/light theme toggle (persisted, no FOUC) ·
                              # 1.12 Denied/Slowest retain up to 1000 rows
                              # server-side (was 120); live SSE ticks still
                              # carry only ~40 for bandwidth, with a
                              # "load up to 1000" button for the full history ·
                              # 1.13 click a client in Client history to see
                              # its full request list for that window (up to
                              # 1000 rows, from the history database) · 1.14
                              # the client-history modal is now a standalone IP
                              # search (own range picker, 1h-3mo or custom, any
                              # IP typed in) with client-side status/host/
                              # outcome/action filters over the fetched rows ·
                              # 1.15 client-history request list now pages
                              # ("load older") through EVERY retained row for
                              # the window instead of stopping at the first
                              # 1000 — the real ceiling on "3 months of
                              # traffic" is --db-max-gb, not this UI cap

import argparse
import collections
import ipaddress
import json
import secrets
import os
import queue
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

# --------------------------------------------------------------------------- #
#  Configuration defaults
# --------------------------------------------------------------------------- #

DEFAULT_LOG_PATHS = [
    "/var/log/squid/access.log",
    "/var/log/squid3/access.log",
    "/usr/local/squid/var/logs/access.log",
    "/opt/homebrew/var/logs/access.log",
    "/usr/local/var/logs/access.log",
    "C:/Squid/var/log/squid/access.log",
]

MAX_RECENT = 1000         # rows kept for the live request table
MINI_RETAIN = 1000        # denied/slow rows RETAINED server-side (deque size)
MINI_LIVE_N = 40          # denied/slow rows pushed on every ~2s live tick —
                          # kept small on purpose: pushing all MINI_RETAIN rows
                          # on every tick to every connected browser would cost
                          # real bandwidth for data that rarely changes between
                          # ticks. The full up-to-MINI_RETAIN list is available
                          # on demand via /api/mini (see the panel's own
                          # "load full history" button).
TOP_N = 12                # size of "top talkers" style leaderboards
RATE_WINDOW = 120         # seconds of per-second history for the charts
SLOW_MS = 2000            # requests slower than this are flagged
WINDOW_EVENTS = 60000     # rolling events retained for alert-rule evaluation
ALERT_HISTORY = 250       # alerts kept for the history panel
DETAIL_ENTITIES = 4000    # max clients / hosts tracked for drill-down
DETAIL_RECENT = 15        # recent requests kept per entity
EVIDENCE_EVENTS = 4000    # requests retained so an alert can show its cause
EVIDENCE_SAMPLE = 40      # matching requests attached to one fired alert
EVIDENCE_URL_MAX = 300    # URLs truncated to this length in the evidence buffer
DETAIL_PEERS = 400        # max counterparties tracked per entity

# --------------------------------------------------------------------------- #
#  Log parsing
# --------------------------------------------------------------------------- #

# Squid native format:
# time elapsed client action/code size method url rfc931 hierarchy/from mimetype
NATIVE_RE = re.compile(
    r"^\s*(?P<ts>\d+\.\d+)\s+"
    r"(?P<elapsed>-?\d+)\s+"
    r"(?P<client>\S+)\s+"
    r"(?P<action>[A-Z_]+)/(?P<status>\d{3}|0)\s+"
    r"(?P<size>\d+)\s+"
    r"(?P<method>[A-Z]+)\s+"
    r"(?P<url>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<hier>[A-Z_]+)/(?P<peer>\S+)\s+"
    r"(?P<mime>\S+)\s*$"
)

# Common/combined (httpd_emulate) format:
# client ident user [date] "METHOD url proto" status size ACTION:HIER
COMMON_RE = re.compile(
    r"^\s*(?P<client>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+"
    r"\[(?P<date>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+(?P<proto>\S+))?"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
    r"(?:\s+(?P<action>[A-Z_]+):(?P<hier>\S+))?"
)

HIT_ACTIONS = ("HIT", "MEM_HIT", "REFRESH_HIT", "OFFLINE_HIT", "IMS_HIT",
               "REFRESH_UNMODIFIED", "REVALIDATION_HIT")
DENY_ACTIONS = ("DENIED", "TCP_DENIED", "TCP_DENIED_REPLY")


def _host_of(url: str) -> str:
    """Extract a hostname from either an absolute URL or a CONNECT target."""
    if not url or url == "-":
        return "-"
    if "://" in url:
        try:
            h = urlparse(url).hostname
            if h:
                return h.lower()
        except ValueError:
            pass
    # CONNECT host:443 style
    target = url.split("/")[0]
    if ":" in target:
        target = target.rsplit(":", 1)[0]
    return target.lower() or "-"


def _classify(action: str, status: int) -> str:
    """Bucket a request into hit / miss / denied / error."""
    a = (action or "").upper()
    if any(k in a for k in DENY_ACTIONS) or status in (403, 407):
        return "denied"
    if any(a.endswith(k) or k in a for k in HIT_ACTIONS):
        return "hit"
    if status >= 500 or status == 0:
        return "error"
    if status >= 400:
        return "error"
    return "miss"


def parse_line(line: str):
    """Parse one access.log line into a normalized dict, or None."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    m = NATIVE_RE.match(line)
    if m:
        g = m.groupdict()
        ts = float(g["ts"])
        status = int(g["status"])
        action = g["action"]
        elapsed = max(int(g["elapsed"]), 0)
        peer = g["peer"]
        mime = g["mime"]
        user = g["user"]
    else:
        m = COMMON_RE.match(line)
        if not m:
            return None
        g = m.groupdict()
        ts = time.time()
        try:
            # 17/Aug/2026:22:31:05 +0600
            dt = datetime.strptime(g["date"].split()[0], "%d/%b/%Y:%H:%M:%S")
            ts = dt.timestamp()
        except (ValueError, IndexError):
            pass
        status = int(g["status"])
        action = g.get("action") or "NONE"
        elapsed = 0
        peer = g.get("hier") or "-"
        mime = "-"
        user = g.get("user") or "-"

    size = g["size"]
    size = int(size) if size and size != "-" else 0
    url = g["url"]

    return {
        "ts": ts,
        "elapsed": elapsed,
        "client": g["client"],
        "user": user if user not in ("-", "") else "-",
        "action": action,
        "status": status,
        "size": size,
        "method": g["method"],
        "url": url,
        "host": _host_of(url),
        "peer": peer,
        "mime": mime,
        "kind": _classify(action, status),
    }


# --------------------------------------------------------------------------- #
#  Rolling statistics store
# --------------------------------------------------------------------------- #

class Stats:
    """Thread-safe aggregate of everything the dashboard displays.

    One instance per monitored proxy. `pid` is the proxy id, stamped onto every
    event this instance publishes so the browser can route it to the right view.
    """

    def __init__(self, pid="default"):
        self.pid = pid
        self.lock = threading.Lock()
        self.started = time.time()
        self.total = 0
        self.bytes = 0
        self.kinds = collections.Counter()
        self.status = collections.Counter()
        self.methods = collections.Counter()
        self.clients = collections.Counter()
        self.hosts = collections.Counter()
        self.users = collections.Counter()
        self.client_bytes = collections.Counter()
        self.host_bytes = collections.Counter()
        self.denied = collections.deque(maxlen=MINI_RETAIN)
        self.slow = collections.deque(maxlen=MINI_RETAIN)
        self.recent = collections.deque(maxlen=MAX_RECENT)
        # per-entity drill-down: client IP -> detail, destination host -> detail.
        # Bounded (see DETAIL_ENTITIES) so a long run can't grow without limit.
        self.cdetail = {}
        self.hdetail = {}
        self._prune_tick = 0
        # compact rolling event log used by the alert engine for windowed rules
        self.win = collections.deque(maxlen=WINDOW_EVENTS)
        # Full-ish records kept purely so a fired alert can show WHICH requests
        # caused it. `win` above holds no host or URL, and `recent` only keeps
        # MAX_RECENT rows (a few seconds at real traffic rates) while alert
        # windows are 60s+ — so without this buffer the requests behind an
        # alert are simply gone by the time anyone clicks on it.
        self.evidence = collections.deque(maxlen=EVIDENCE_EVENTS)
        self.per_sec = collections.deque(maxlen=RATE_WINDOW)   # (sec, req, bytes, hits)
        self._cur_sec = None
        self._cur = [0, 0, 0]
        self.latency_sum = 0
        self.latency_n = 0
        self.parse_errors = 0
        self.cache_mgr = {}
        self.last_event = 0.0
        # where traffic is coming from, and whether that link is currently up
        self.source = {"kind": "none", "target": "—", "connected": False,
                       "error": None, "reconnects": 0, "hint": None}

    # -- ingestion ---------------------------------------------------------- #
    def add(self, rec):
        with self.lock:
            self.total += 1
            self.bytes += rec["size"]
            self.kinds[rec["kind"]] += 1
            self.status[str(rec["status"])] += 1
            self.methods[rec["method"]] += 1
            self.clients[rec["client"]] += 1
            self.hosts[rec["host"]] += 1
            self.client_bytes[rec["client"]] += rec["size"]
            self.host_bytes[rec["host"]] += rec["size"]
            if rec["user"] != "-":
                self.users[rec["user"]] += 1
            if rec["elapsed"]:
                self.latency_sum += rec["elapsed"]
                self.latency_n += 1
            if rec["kind"] == "denied":
                self.denied.appendleft(rec)
            if rec["elapsed"] >= SLOW_MS:
                self.slow.appendleft(rec)
            self.recent.appendleft(rec)
            self.win.append((rec["ts"], rec["kind"], rec["client"], rec["size"],
                             rec["status"], rec["elapsed"]))
            self.evidence.append({
                "ts": rec["ts"], "client": rec["client"], "host": rec["host"],
                "method": rec["method"], "status": rec["status"],
                "size": rec["size"], "elapsed": rec["elapsed"],
                "kind": rec["kind"], "action": rec["action"],
                "url": (rec["url"] or "")[:EVIDENCE_URL_MAX],
            })
            self._track(self.cdetail, rec["client"], rec, peer=rec["host"])
            self._track(self.hdetail, rec["host"], rec, peer=rec["client"])
            self._prune_tick += 1
            if self._prune_tick >= 500:
                self._prune_tick = 0
                self._prune(self.cdetail)
                self._prune(self.hdetail)
            self.last_event = time.time()

            sec = int(rec["ts"])
            if self._cur_sec is None:
                self._cur_sec = sec
            if sec != self._cur_sec:
                self.per_sec.append((self._cur_sec, *self._cur))
                # fill gaps so the chart scrolls smoothly
                gap = sec - self._cur_sec - 1
                for i in range(1, min(gap, 30) + 1):
                    self.per_sec.append((self._cur_sec + i, 0, 0, 0))
                self._cur_sec = sec
                self._cur = [0, 0, 0]
            self._cur[0] += 1
            self._cur[1] += rec["size"]
            if rec["kind"] == "hit":
                self._cur[2] += 1

    # -- per-entity drill-down ---------------------------------------------- #
    @staticmethod
    def _track(store, key, rec, peer):
        """Accumulate one request into a client's or host's detail record."""
        d = store.get(key)
        if d is None:
            if len(store) >= DETAIL_ENTITIES * 2:
                return                      # hard ceiling until the next prune
            d = store[key] = {
                "n": 0, "bytes": 0, "first": rec["ts"], "last": rec["ts"],
                "kinds": collections.Counter(), "status": collections.Counter(),
                "methods": collections.Counter(), "peers": collections.Counter(),
                "users": collections.Counter(), "actions": collections.Counter(),
                "lat_sum": 0, "lat_n": 0, "lat_max": 0,
                "recent": collections.deque(maxlen=DETAIL_RECENT),
            }
        d["n"] += 1
        d["bytes"] += rec["size"]
        d["last"] = rec["ts"]
        if rec["ts"] < d["first"]:
            d["first"] = rec["ts"]
        d["kinds"][rec["kind"]] += 1
        d["status"][str(rec["status"])] += 1
        d["methods"][rec["method"]] += 1
        d["actions"][rec["action"]] += 1
        if rec["user"] != "-":
            d["users"][rec["user"]] += 1
        if len(d["peers"]) < DETAIL_PEERS or peer in d["peers"]:
            d["peers"][peer] += 1
        if rec["elapsed"]:
            d["lat_sum"] += rec["elapsed"]
            d["lat_n"] += 1
            d["lat_max"] = max(d["lat_max"], rec["elapsed"])
        d["recent"].appendleft({
            "ts": rec["ts"], "method": rec["method"], "status": rec["status"],
            "kind": rec["kind"], "size": rec["size"], "elapsed": rec["elapsed"],
            "peer": peer, "url": str(rec["url"])[:200], "user": rec["user"],
            "action": rec["action"],
        })

    @staticmethod
    def _prune(store):
        """Keep the busiest DETAIL_ENTITIES entries; drop the long tail."""
        if len(store) <= DETAIL_ENTITIES:
            return
        keep = sorted(store.items(), key=lambda kv: kv[1]["n"],
                      reverse=True)[:DETAIL_ENTITIES]
        store.clear()
        store.update(keep)

    def detail(self, kind, key):
        """Full drill-down for one client IP or destination host."""
        store = self.cdetail if kind == "client" else self.hdetail
        with self.lock:
            d = store.get(key)
            if not d:
                return None
            out = {
                "kind": kind, "key": key, "proxy": self.pid,
                "requests": d["n"], "bytes": d["bytes"],
                "first": d["first"], "last": d["last"],
                "avg_latency": round(d["lat_sum"] / d["lat_n"]) if d["lat_n"] else 0,
                "max_latency": d["lat_max"],
                "kinds": dict(d["kinds"]),
                "status": dict(d["status"].most_common(12)),
                "methods": dict(d["methods"].most_common(8)),
                "actions": dict(d["actions"].most_common(8)),
                "users": [{"key": k, "n": v} for k, v in d["users"].most_common(8)],
                "peers": [{"key": k, "n": v} for k, v in d["peers"].most_common(15)],
                "peer_total": len(d["peers"]),
                "recent": list(d["recent"]),
            }
        return out

    def note_parse_error(self):
        with self.lock:
            self.parse_errors += 1

    def window(self, seconds):
        """Events from the last N seconds: [(ts, kind, client, size, status, ms)]."""
        cutoff = time.time() - seconds
        with self.lock:
            # deque is append-ordered by arrival, so walk backwards and stop early
            out = []
            for ev in reversed(self.win):
                if ev[0] < cutoff:
                    break
                out.append(ev)
            return out

    def evidence_for(self, seconds, match=None, limit=EVIDENCE_SAMPLE):
        """The actual requests behind an alert, newest first, plus a summary.

        Called at fire time, not when someone clicks: by then the requests have
        aged out of every buffer. `match` is a predicate over one evidence row.
        """
        cutoff = time.time() - seconds
        rows, hosts, statuses, clients = [], collections.Counter(), \
            collections.Counter(), collections.Counter()
        total = 0
        with self.lock:
            for r in reversed(self.evidence):
                if r["ts"] < cutoff:
                    break
                if match and not match(r):
                    continue
                total += 1
                hosts[r["host"] or "—"] += 1
                statuses[r["status"]] += 1
                clients[r["client"]] += 1
                if len(rows) < limit:
                    rows.append(dict(r))
        return {
            "requests": rows,
            "matched": total,
            "shown": len(rows),
            "truncated": total > len(rows),
            "top_hosts": hosts.most_common(8),
            "top_clients": clients.most_common(8),
            "status_mix": sorted(statuses.items(), key=lambda x: -x[1])[:8],
            "window": seconds,
        }

    def set_cache_mgr(self, data):
        with self.lock:
            self.cache_mgr = data

    # -- data-source state -------------------------------------------------- #
    def set_source(self, kind, target, hint=None):
        with self.lock:
            self.source.update({"kind": kind, "target": target, "hint": hint})

    def source_up(self, note=None):
        with self.lock:
            was = self.source["connected"]
            self.source["connected"] = True
            self.source["error"] = None
        if not was:
            HUB.publish("source", {"p": self.pid, "connected": True,
                                   "note": note or "connected"})

    def source_down(self, err, count_retry=True):
        with self.lock:
            was = self.source["connected"]
            self.source["connected"] = False
            self.source["error"] = str(err)[:400]
            if count_retry:
                self.source["reconnects"] += 1
            snap = dict(self.source)
        if was or count_retry:
            HUB.publish("source", {"p": self.pid, "connected": False,
                                   "error": snap["error"],
                                   "reconnects": snap["reconnects"]})

    # -- output ------------------------------------------------------------- #
    def _series(self):
        pts = list(self.per_sec)
        if self._cur_sec is not None:
            pts.append((self._cur_sec, *self._cur))
        now = int(time.time())
        by_sec = {p[0]: p for p in pts}
        out = []
        for s in range(now - RATE_WINDOW + 1, now + 1):
            p = by_sec.get(s)
            out.append({
                "t": s,
                "req": p[1] if p else 0,
                "bytes": p[2] if p else 0,
                "hits": p[3] if p else 0,
            })
        return out

    def snapshot(self, recent_limit=120):
        with self.lock:
            uptime = max(time.time() - self.started, 1)
            hits = self.kinds["hit"]
            served = hits + self.kinds["miss"]
            series = self._series()
            last5 = series[-5:] or [{"req": 0, "bytes": 0}]
            out = {
                "meta": {
                    "source": dict(self.source),
                    "uptime": round(uptime),
                    "server_time": datetime.now().strftime("%H:%M:%S"),
                    "parse_errors": self.parse_errors,
                    "last_event_age": round(time.time() - self.last_event, 1)
                    if self.last_event else None,
                },
                "totals": {
                    "requests": self.total,
                    "bytes": self.bytes,
                    "rps": round(sum(p["req"] for p in last5) / len(last5), 2),
                    "bps": round(sum(p["bytes"] for p in last5) / len(last5)),
                    "hit_ratio": round(hits / served * 100, 1) if served else 0.0,
                    "avg_latency": round(self.latency_sum / self.latency_n)
                    if self.latency_n else 0,
                    "clients": len(self.clients),
                    "hosts": len(self.hosts),
                },
                "kinds": dict(self.kinds),
                "status": dict(self.status.most_common(14)),
                "methods": dict(self.methods.most_common(8)),
                "series": series,
                "top_clients": [
                    {"key": k, "n": v, "bytes": self.client_bytes[k]}
                    for k, v in self.clients.most_common(TOP_N)
                ],
                "top_hosts": [
                    {"key": k, "n": v, "bytes": self.host_bytes[k]}
                    for k, v in self.hosts.most_common(TOP_N)
                ],
                "top_users": [
                    {"key": k, "n": v} for k, v in self.users.most_common(TOP_N)
                ],
                "denied": list(self.denied)[:MINI_LIVE_N],
                "slow": list(self.slow)[:MINI_LIVE_N],
                "recent": list(self.recent)[:recent_limit],
                "cache_mgr": self.cache_mgr,
            }
        out["proxy"] = self.pid
        return out

    def mini(self, kind, limit=MINI_RETAIN):
        """The FULL retained denied/slow list (up to MINI_RETAIN), on demand.

        Separate from snapshot() so browsing deep history doesn't cost every
        live SSE tick — see MINI_LIVE_N.
        """
        with self.lock:
            src = self.denied if kind == "denied" else self.slow
            return list(src)[:max(1, min(int(limit), MINI_RETAIN))]


# --------------------------------------------------------------------------- #
#  Proxy registry — one context per monitored proxy
# --------------------------------------------------------------------------- #

class Store:
    """Optional SQLite history, so the dashboard remembers past traffic.

    Two tiers, because they answer different questions and cost wildly
    different amounts of disk:

      requests    every request in full (client, host, URL, status, bytes,
                  latency). This is what you need to investigate "what did
                  10.60.11.5 actually do at 14:20". At the user's observed
                  ~36 req/s this is roughly 0.55 GB/day, so a 5 GB budget
                  holds about nine days.
      rollup_hour one row per hour per proxy per client per host, counting
                  requests/bytes/denials. A few MB a month, so it can be kept
                  effectively forever and still answer "was this host busy
                  last quarter".

    The size budget is enforced by deleting the OLDEST raw requests first and
    then running an incremental vacuum — without the vacuum SQLite keeps the
    freed pages and the file never actually shrinks, which is the usual way a
    "capped" database quietly grows past its cap.

    Writes go through a queue and a single writer thread. The log tailers must
    never block on disk: a slow fsync would stall ingestion and the dashboard
    would silently fall behind the live log.
    """

    MIN_KEEP_ROWS = 20000     # never prune below this, whatever the budget

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS requests (
      id      INTEGER PRIMARY KEY AUTOINCREMENT,
      ts      REAL    NOT NULL,
      proxy   TEXT    NOT NULL,
      client  TEXT,
      host    TEXT,
      method  TEXT,
      url     TEXT,
      status  INTEGER,
      bytes   INTEGER,
      ms      INTEGER,
      kind    TEXT,
      action  TEXT,
      user    TEXT
    );
    CREATE INDEX IF NOT EXISTS ix_req_ts     ON requests(ts);
    CREATE INDEX IF NOT EXISTS ix_req_client ON requests(client, ts);
    CREATE INDEX IF NOT EXISTS ix_req_host   ON requests(host, ts);
    CREATE INDEX IF NOT EXISTS ix_req_kind   ON requests(kind, ts);

    CREATE TABLE IF NOT EXISTS rollup_hour (
      hour    INTEGER NOT NULL,
      proxy   TEXT    NOT NULL,
      client  TEXT    NOT NULL,
      host    TEXT    NOT NULL,
      reqs    INTEGER NOT NULL DEFAULT 0,
      bytes   INTEGER NOT NULL DEFAULT 0,
      denied  INTEGER NOT NULL DEFAULT 0,
      errors  INTEGER NOT NULL DEFAULT 0,
      ms_sum  INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (hour, proxy, client, host)
    );
    CREATE INDEX IF NOT EXISTS ix_roll_hour ON rollup_hour(hour);

    CREATE TABLE IF NOT EXISTS alerts (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      ts       REAL NOT NULL,
      proxy    TEXT,
      seq      TEXT,
      rule     TEXT,
      type     TEXT,
      severity TEXT,
      msg      TEXT,
      detail   TEXT
    );
    CREATE INDEX IF NOT EXISTS ix_alert_ts ON alerts(ts);
    """

    def __init__(self, path, max_bytes, keep_urls=True, batch=400,
                 flush_secs=2.0, check_secs=30.0, check_rows=100000):
        self.path = path
        self.max_bytes = max_bytes
        self.keep_urls = keep_urls
        self.batch, self.flush_secs, self.check_secs = batch, flush_secs, check_secs
        # Maintenance is also triggered by volume, not time alone: at a few
        # hundred requests a second a fixed interval lets the file sail well
        # past its budget between checks.
        self.check_rows = check_rows
        self.q = queue.Queue(maxsize=50000)
        self.stop_flag = threading.Event()
        self.dropped = 0            # records shed because the queue was full
        self.written = 0
        self.pruned = 0
        self.last_error = None
        self.last_size = 0
        self._roll = {}             # (hour, proxy, client, host) -> counters
        self._roll_lock = threading.Lock()
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        # auto_vacuum has to be set before any table exists, otherwise SQLite
        # ignores it and the file can only be shrunk by a full VACUUM
        self.db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        # Without a size limit the write-ahead log grows without bound and is
        # never truncated on checkpoint. It counts toward the disk budget but
        # cannot be shrunk by deleting rows, so an unbounded WAL made the prune
        # loop delete almost every row while the total size never moved.
        self.db.execute("PRAGMA journal_size_limit=%d" % (16 * 1024 * 1024))
        self.db.executescript(self.SCHEMA)
        self.db.commit()
        self.t = threading.Thread(target=self._run, daemon=True,
                                  name="store-writer")
        self.t.start()

    # -- ingest -------------------------------------------------------------- #
    def add(self, pid, rec):
        """Called on the ingest path — must never block."""
        try:
            self.q.put_nowait((pid, rec))
        except queue.Full:
            self.dropped += 1       # shedding beats stalling the log tailer

    def add_alert(self, alert):
        try:
            self.q.put_nowait(("__alert__", alert))
        except queue.Full:
            self.dropped += 1

    # -- writer -------------------------------------------------------------- #
    def _run(self):
        last_flush = last_check = time.time()
        last_written = 0
        rows, alerts = [], []
        while not self.stop_flag.is_set():
            timeout = max(0.1, self.flush_secs - (time.time() - last_flush))
            try:
                pid, rec = self.q.get(timeout=timeout)
                if pid == "__alert__":
                    alerts.append((rec.get("ts"), rec.get("p"), rec.get("seq"),
                                   rec.get("rule"), rec.get("type"),
                                   rec.get("severity"), rec.get("msg"),
                                   json.dumps(rec.get("detail") or {})))
                else:
                    rows.append((rec["ts"], pid, rec["client"], rec["host"],
                                 rec["method"],
                                 (rec["url"] or "") if self.keep_urls else "",
                                 rec["status"], rec["size"], rec["elapsed"],
                                 rec["kind"], rec["action"], rec.get("user")))
                    self._accumulate(pid, rec)
            except queue.Empty:
                pass
            now = time.time()
            if rows and (len(rows) >= self.batch
                         or now - last_flush >= self.flush_secs):
                self._flush(rows, alerts)
                rows, alerts = [], []
                last_flush = now
            elif alerts and now - last_flush >= self.flush_secs:
                self._flush([], alerts)
                alerts = []
                last_flush = now
            if (now - last_check >= self.check_secs
                    or self.written - last_written >= self.check_rows):
                self._flush_rollups()
                self._enforce_budget()
                last_check, last_written = now, self.written
        self._flush(rows, alerts)
        self._flush_rollups()
        try:
            self.db.commit()
            self.db.close()
        except sqlite3.Error:
            pass

    def _accumulate(self, pid, rec):
        hour = int(rec["ts"] // 3600) * 3600
        key = (hour, pid, rec["client"] or "-", rec["host"] or "-")
        with self._roll_lock:
            c = self._roll.get(key)
            if c is None:
                c = self._roll[key] = [0, 0, 0, 0, 0]
            c[0] += 1
            c[1] += rec["size"] or 0
            c[2] += 1 if rec["kind"] == "denied" else 0
            c[3] += 1 if rec["kind"] == "error" else 0
            c[4] += rec["elapsed"] or 0

    def _flush(self, rows, alerts):
        if not rows and not alerts:
            return
        try:
            with self.db:
                if rows:
                    self.db.executemany(
                        "INSERT INTO requests (ts,proxy,client,host,method,url,"
                        "status,bytes,ms,kind,action,user) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                if alerts:
                    self.db.executemany(
                        "INSERT INTO alerts (ts,proxy,seq,rule,type,severity,"
                        "msg,detail) VALUES (?,?,?,?,?,?,?,?)", alerts)
            self.written += len(rows)
            self.last_error = None
        except sqlite3.Error as e:
            self.last_error = f"write failed: {e}"

    def _flush_rollups(self):
        with self._roll_lock:
            pending, self._roll = self._roll, {}
        if not pending:
            return
        try:
            with self.db:
                self.db.executemany(
                    "INSERT INTO rollup_hour (hour,proxy,client,host,reqs,"
                    "bytes,denied,errors,ms_sum) VALUES (?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(hour,proxy,client,host) DO UPDATE SET "
                    "reqs=reqs+excluded.reqs, bytes=bytes+excluded.bytes, "
                    "denied=denied+excluded.denied, errors=errors+excluded.errors, "
                    "ms_sum=ms_sum+excluded.ms_sum",
                    [(h, p, c, ho, v[0], v[1], v[2], v[3], v[4])
                     for (h, p, c, ho), v in pending.items()])
        except sqlite3.Error as e:
            self.last_error = f"rollup failed: {e}"

    # -- retention ----------------------------------------------------------- #
    def size_bytes(self):
        try:
            pc = self.db.execute("PRAGMA page_count").fetchone()[0]
            ps = self.db.execute("PRAGMA page_size").fetchone()[0]
            total = pc * ps
            for suffix in ("-wal", "-shm"):
                try:
                    total += os.path.getsize(self.path + suffix)
                except OSError:
                    pass
            return total
        except sqlite3.Error:
            return 0

    def _enforce_budget(self):
        """Delete the oldest raw requests until the file fits the budget.

        Rollups are never pruned here — they are the cheap long-term record,
        and dropping them would throw away years of history to reclaim
        kilobytes.
        """
        self._reclaim()
        size = self.last_size = self.size_bytes()
        if not self.max_bytes or size <= self.max_bytes:
            return
        try:
            for _ in range(40):          # bounded, so one pass can't run away
                row = self.db.execute("SELECT MIN(id), COUNT(*) "
                                      "FROM requests").fetchone()
                lo, n = row if row else (None, 0)
                if not n or lo is None or n <= self.MIN_KEEP_ROWS:
                    # Refuse to empty the table chasing a budget it cannot
                    # meet. If the floor is reached the budget is simply too
                    # small for this traffic rate, and silently deleting
                    # everything would look like data loss rather than a
                    # configuration problem.
                    self.last_error = (
                        f"disk budget {self.max_bytes // 1048576} MB is too "
                        f"small for this traffic — keeping the most recent "
                        f"{n:,} requests. Raise --db-max-gb, or add "
                        f"--db-no-urls to roughly halve the per-request cost.")
                    break
                chunk = max(5000, n // 20)      # ~5% at a time
                with self.db:
                    cur = self.db.execute(
                        "DELETE FROM requests WHERE id < ?", (lo + chunk,))
                    self.pruned += cur.rowcount
                self._reclaim()
                before, size = size, self.size_bytes()
                if size <= self.max_bytes * 0.95:
                    self.last_error = None
                    break
                if size >= before - 4096:
                    # a pass that frees nothing means the space is not in the
                    # rows we are deleting; keep the remaining data rather than
                    # grinding the table away for no gain
                    self.last_error = (
                        f"could not shrink below the budget "
                        f"({size // 1048576} MB vs "
                        f"{self.max_bytes // 1048576} MB) — stopping so the "
                        f"remaining history is not deleted for nothing")
                    break
            self.last_size = size
        except sqlite3.Error as e:
            self.last_error = f"prune failed: {e}"

    def _reclaim(self):
        """Actually return freed space to the filesystem.

        Deleting rows only moves pages to SQLite's freelist; the file keeps its
        size until an incremental vacuum hands them back, and the WAL keeps its
        own copy until a checkpoint truncates it. Measuring the budget without
        doing both reads a size that deletions can never reduce.
        """
        try:
            self.db.commit()
            # Order matters, and so does .fetchall() on both pragmas:
            #  1. checkpoint first, so the freed pages from the DELETE are in
            #     the main file where the vacuum can see them
            #  2. incremental_vacuum — sqlite3 steps a PRAGMA once, and this
            #     one reclaims a SINGLE page per step, so an unfetched call
            #     frees 4 KB and looks like it did nothing (measured: 18.28 MB
            #     unchanged unfetched, 18.28 -> 4.59 MB fetched)
            #  3. checkpoint AGAIN — in WAL mode the vacuum's result lands in
            #     the WAL, so the file on disk only shrinks at the next
            #     checkpoint. Without this the page count drops while the file
            #     stays exactly the same size, and the prune loop concludes it
            #     is making no progress.
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
            self.db.execute("PRAGMA incremental_vacuum").fetchall()
            self.db.commit()
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        except sqlite3.Error as e:
            self.last_error = f"reclaim failed: {e}"

    # -- reads --------------------------------------------------------------- #
    def query(self, since=None, until=None, proxy=None, client=None, host=None,
              kind=None, q=None, limit=200):
        sql = ["SELECT ts,proxy,client,host,method,url,status,bytes,ms,kind,"
               "action FROM requests WHERE 1=1"]
        args = []
        for col, val in (("ts >= ?", since), ("ts <= ?", until),
                         ("proxy = ?", proxy), ("client = ?", client),
                         ("host = ?", host), ("kind = ?", kind)):
            if val not in (None, "", "all"):
                sql.append("AND " + col)
                args.append(val)
        if q:
            sql.append("AND (url LIKE ? OR host LIKE ? OR client LIKE ?)")
            args += [f"%{q}%"] * 3
        sql.append("ORDER BY ts DESC LIMIT ?")
        # 5000, not 2000: a single busy client can log >1000 requests/day
        # (seen in practice), and the UI now pages through this with a
        # "load older" button rather than being stuck at the first page
        args.append(max(1, min(int(limit), 5000)))
        cols = ["ts", "proxy", "client", "host", "method", "url", "status",
                "bytes", "ms", "kind", "action"]
        try:
            rows = self.db.execute(" ".join(sql), args).fetchall()
            return [dict(zip(cols, r)) for r in rows]
        except sqlite3.Error as e:
            self.last_error = f"query failed: {e}"
            return []

    def trend(self, hours=168, proxy=None, client=None, host=None):
        since = int((time.time() - hours * 3600) // 3600) * 3600
        sql = ["SELECT hour, SUM(reqs), SUM(bytes), SUM(denied), SUM(errors) "
               "FROM rollup_hour WHERE hour >= ?"]
        args = [since]
        for col, val in (("proxy = ?", proxy), ("client = ?", client),
                         ("host = ?", host)):
            if val not in (None, "", "all"):
                sql.append("AND " + col)
                args.append(val)
        sql.append("GROUP BY hour ORDER BY hour")
        try:
            return [{"hour": h, "reqs": r, "bytes": b, "denied": d,
                     "errors": e}
                    for h, r, b, d, e in self.db.execute(" ".join(sql), args)]
        except sqlite3.Error as e:
            self.last_error = f"trend failed: {e}"
            return []

    def clients(self, since, until=None, proxy=None, limit=1000):
        """Every client seen in [since, until), aggregated from rollup_hour.

        rollup_hour is never pruned by the disk budget (unlike the raw
        requests table), so this answers "who connected in the last N days"
        even months after the raw request detail for that period has aged
        out — and it survives a dashboard/service restart because it lives
        in the same SQLite file, not in memory.

        `since`/`until` are epoch seconds; hour buckets are truncated to the
        hour so a window edge can include a *little* more than asked for
        (at most 59 minutes), never less.
        """
        since_h = int(since // 3600) * 3600
        sql = ["SELECT client, SUM(reqs), SUM(bytes), SUM(denied), "
               "SUM(errors), MIN(hour), MAX(hour), COUNT(DISTINCT host) "
               "FROM rollup_hour WHERE hour >= ?"]
        args = [since_h]
        if until:
            sql.append("AND hour < ?")
            args.append(int(until // 3600) * 3600 + 3600)
        if proxy not in (None, "", "all"):
            sql.append("AND proxy = ?")
            args.append(proxy)
        # the true unique count must not depend on the display LIMIT below,
        # otherwise capping the list at e.g. 1000 rows for the UI would also
        # (silently, wrongly) cap the reported "unique clients" total
        count_sql = ["SELECT COUNT(DISTINCT client), SUM(reqs) "
                     "FROM rollup_hour WHERE hour >= ?"]
        count_args = [since_h]
        if until:
            count_sql.append("AND hour < ?")
            count_args.append(int(until // 3600) * 3600 + 3600)
        if proxy not in (None, "", "all"):
            count_sql.append("AND proxy = ?")
            count_args.append(proxy)
        sql.append("GROUP BY client ORDER BY SUM(reqs) DESC LIMIT ?")
        args.append(max(1, min(int(limit), 20000)))
        try:
            unique, total_reqs = self.db.execute(
                " ".join(count_sql), count_args).fetchone()
            rows = self.db.execute(" ".join(sql), args).fetchall()
            clients = [{"client": c or "-", "requests": r, "bytes": b,
                        "denied": d, "errors": e, "first_seen": fh,
                        "last_seen": lh + 3600, "hosts": h}
                       for c, r, b, d, e, fh, lh, h in rows]
            return {"clients": clients, "unique": unique or 0,
                    "total_requests": total_reqs or 0,
                    "truncated": (unique or 0) > len(clients)}
        except sqlite3.Error as e:
            self.last_error = f"clients query failed: {e}"
            return {"clients": [], "unique": 0, "total_requests": 0,
                    "truncated": False}

    def status(self):
        try:
            n = self.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            span = self.db.execute("SELECT MIN(ts), MAX(ts) FROM requests").fetchone()
            nroll = self.db.execute("SELECT COUNT(*) FROM rollup_hour").fetchone()[0]
        except sqlite3.Error:
            n, span, nroll = 0, (None, None), 0
        # measured fresh, not the value cached at the last prune: between
        # prunes the write-ahead log grows again, and reporting the stale
        # number understated real disk use by several MB
        size = self.size_bytes()
        return {"enabled": True, "path": os.path.abspath(self.path),
                "size": size, "max": self.max_bytes,
                "pct": round(size / self.max_bytes * 100, 1) if self.max_bytes else None,
                "requests": n, "rollup_rows": nroll,
                "oldest": span[0], "newest": span[1],
                "written": self.written, "pruned": self.pruned,
                "dropped": self.dropped, "queue": self.q.qsize(),
                "keep_urls": self.keep_urls, "error": self.last_error}

    def stop(self):
        self.stop_flag.set()


STORE = None               # a Store when --db is used


# --------------------------------------------------------------------------- #
#  System health — CPU / memory / disk / network for the dashboard's own
#  host and for each SSH-reachable proxy. Separate from Squid traffic stats:
#  this is "is the machine itself healthy", which traffic counters can't show
#  (a proxy can look fine in the traffic view while swapping itself to death).
# --------------------------------------------------------------------------- #

def _read_proc_stat_cpu(text):
    """The first 'cpu ' line of /proc/stat -> 8-tuple of jiffie counters."""
    for line in text.splitlines():
        if line.startswith("cpu "):
            parts = [int(x) for x in line.split()[1:9]]
            parts += [0] * (8 - len(parts))
            return tuple(parts[:8])
    return None


def _cpu_pct_from_deltas(prev, cur):
    """% busy between two /proc/stat samples. None until there are two."""
    if not prev or not cur:
        return None
    total_d = sum(cur) - sum(prev)
    if total_d <= 0:
        return None
    idle_d = (cur[3] + cur[4]) - (prev[3] + prev[4])   # idle + iowait
    return max(0.0, min(100.0, (total_d - idle_d) / total_d * 100))


def _read_meminfo(text):
    info = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        try:
            info[k.strip()] = int(v.strip().split()[0]) * 1024   # kB -> bytes
        except (ValueError, IndexError):
            pass
    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    used = max(0, total - avail)
    return {"total": total, "used": used,
            "pct": (used / total * 100) if total else None}


def _read_net_dev(text):
    """Sum rx/tx bytes across every interface except loopback."""
    rx = tx = 0
    for line in text.splitlines():
        if ":" not in line:
            continue
        iface, _, rest = line.partition(":")
        if iface.strip() in ("", "lo"):
            continue
        f = rest.split()
        if len(f) >= 9:
            try:
                rx += int(f[0]); tx += int(f[8])
            except ValueError:
                pass
    return rx, tx


def _parse_sys_blob(text):
    """Split the '---SECTION---' delimited output of the remote probe command."""
    sections, cur, buf = {}, None, []
    for line in text.splitlines():
        if line.startswith("---") and line.endswith("---") and len(line) > 6:
            if cur is not None:
                sections[cur] = "\n".join(buf)
            cur, buf = line.strip("-"), []
        else:
            buf.append(line)
    if cur is not None:
        sections[cur] = "\n".join(buf)
    return sections


SYS_PROBE_CMD = (
    "echo ---CPU---; cat /proc/stat 2>/dev/null | head -1; "
    "echo ---MEM---; cat /proc/meminfo 2>/dev/null; "
    "echo ---DISK---; df -kP / 2>/dev/null | tail -1; "
    "echo ---LOAD---; cat /proc/loadavg 2>/dev/null; "
    "echo ---UPTIME---; cat /proc/uptime 2>/dev/null; "
    "echo ---NET---; cat /proc/net/dev 2>/dev/null"
)


class SysCollector(threading.Thread):
    """Polls CPU/memory/disk/network for one host, on a background thread.

    mode="local"  reads /proc directly — the machine this dashboard process
                  runs on (the management host, or a proxy when the
                  dashboard runs there itself).
    mode="ssh"    runs ONE read-only command over SSH per interval: /proc and
                  df, all readable by an unprivileged account. This is the
                  same trust boundary already used to tail access.log — no
                  helper, no sudo, nothing installed on the proxy.
    """

    def __init__(self, pid, name, mode="local", host=None, user=None, port=22,
                 key=None, ssh_bin="ssh", interval=20):
        super().__init__(daemon=True, name=f"sysinfo-{pid}")
        self.pid, self.name, self.mode = pid, name, mode
        self.host, self.user, self.port, self.key = host, user, port, key
        self.ssh_bin, self.interval = ssh_bin, max(5, interval)
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()
        self._prev_cpu = None
        self._prev_net = None            # (rx, tx, ts)
        self.latest = {"ok": False, "kind": mode, "error": "not polled yet",
                       "ts": None}

    def snapshot(self):
        with self.lock:
            return dict(self.latest)

    def stop(self):
        self.stop_flag.set()

    def run(self):
        self._poll_once()
        while not self.stop_flag.wait(self.interval):
            self._poll_once()

    def _poll_once(self):
        t0 = time.time()
        try:
            raw = self._collect_local() if self.mode == "local" \
                  else self._collect_ssh()
        except Exception as e:                     # a bad host must not kill
            raw = {"ok": False, "error": str(e)[:200]}       # this thread
        raw["kind"] = self.mode
        raw["latency_ms"] = round((time.time() - t0) * 1000)
        raw["ts"] = time.time()
        raw.setdefault("ok", True)
        with self.lock:
            self.latest = raw

    def _net_delta(self, rx, tx, now):
        net_rx_bps = net_tx_bps = None
        if self._prev_net:
            prx, ptx, pts = self._prev_net
            dt = max(0.001, now - pts)
            if rx >= prx and tx >= ptx:
                net_rx_bps = (rx - prx) / dt
                net_tx_bps = (tx - ptx) / dt
        self._prev_net = (rx, tx, now)
        return net_rx_bps, net_tx_bps

    def _collect_local(self):
        try:
            with open("/proc/stat") as fh:
                cpu_now = _read_proc_stat_cpu(fh.read())
        except OSError:
            cpu_now = None
        cpu_pct = _cpu_pct_from_deltas(self._prev_cpu, cpu_now)
        self._prev_cpu = cpu_now
        try:
            with open("/proc/meminfo") as fh:
                mem = _read_meminfo(fh.read())
        except OSError:
            mem = {"total": 0, "used": 0, "pct": None}
        try:
            du = shutil.disk_usage("/")
            disk = {"total": du.total, "used": du.used,
                    "pct": (du.used / du.total * 100) if du.total else None}
        except OSError:
            disk = {"total": 0, "used": 0, "pct": None}
        try:
            load = list(os.getloadavg())
        except (OSError, AttributeError):
            load = None
        try:
            with open("/proc/uptime") as fh:
                uptime = float(fh.read().split()[0])
        except (OSError, ValueError, IndexError):
            uptime = None
        rx = tx = None
        try:
            with open("/proc/net/dev") as fh:
                rx, tx = _read_net_dev(fh.read())
        except OSError:
            pass
        net_rx_bps = net_tx_bps = None
        if rx is not None:
            net_rx_bps, net_tx_bps = self._net_delta(rx, tx, time.time())
        return {"ok": True, "cpu_pct": cpu_pct, "mem": mem, "disk": disk,
                "load": load, "uptime": uptime,
                "net_rx_bps": net_rx_bps, "net_tx_bps": net_tx_bps}

    def _collect_ssh(self):
        cmd = [self.ssh_bin, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
               "-o", "StrictHostKeyChecking=accept-new"]
        if self.key:
            cmd += ["-i", os.path.expanduser(self.key)]
        if self.port:
            cmd += ["-p", str(self.port)]
        cmd += [f"{self.user}@{self.host}" if self.user else self.host,
                SYS_PROBE_CMD]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        if p.returncode != 0:
            return {"ok": False,
                    "error": (p.stderr or "ssh probe failed").strip()[:200]}
        sec = _parse_sys_blob(p.stdout)
        cpu_now = _read_proc_stat_cpu(sec.get("CPU") or "")
        cpu_pct = _cpu_pct_from_deltas(self._prev_cpu, cpu_now)
        self._prev_cpu = cpu_now
        mem = _read_meminfo(sec.get("MEM") or "")
        disk = {"total": 0, "used": 0, "pct": None}
        disk_lines = (sec.get("DISK") or "").strip().splitlines()
        if disk_lines:
            f = disk_lines[-1].split()      # df -kP: fs 1024blks used avail cap% mnt
            if len(f) >= 3:
                try:
                    total_kb, used_kb = int(f[1]), int(f[2])
                    disk = {"total": total_kb * 1024, "used": used_kb * 1024,
                            "pct": (used_kb / total_kb * 100) if total_kb
                                   else None}
                except ValueError:
                    pass
        load_f = (sec.get("LOAD") or "").split()
        load = [float(x) for x in load_f[:3]] if len(load_f) >= 3 else None
        up_f = (sec.get("UPTIME") or "").split()
        uptime = float(up_f[0]) if up_f else None
        rx, tx = _read_net_dev(sec.get("NET") or "")
        net_rx_bps, net_tx_bps = self._net_delta(rx, tx, time.time())
        return {"ok": True, "cpu_pct": cpu_pct, "mem": mem, "disk": disk,
                "load": load, "uptime": uptime,
                "net_rx_bps": net_rx_bps, "net_tx_bps": net_tx_bps}


LOCAL_SYS = None            # a SysCollector for the dashboard's own host


class ProxyCtx:
    """Everything belonging to one monitored proxy: its own counters, its own
    alert engine (so windowed rules never mix traffic from two proxies), and
    the collector threads feeding it."""

    def __init__(self, pid, name, cfg=None):
        self.id = pid
        self.name = name or pid
        self.cfg = cfg or {}
        self.stats = Stats(pid)
        self.alerts = None          # AlertEngine, attached in main()
        self.sysinfo = None         # SysCollector, attached in main() for SSH proxies
        self.threads = []

    def stop(self):
        for t in self.threads:
            if hasattr(t, "stop"):
                t.stop()
            elif hasattr(t, "stop_flag"):
                t.stop_flag.set()

    def info(self):
        return {"id": self.id, "name": self.name,
                "source": dict(self.stats.source),
                "requests": self.stats.total,
                "alerts": len(self.alerts.history) if self.alerts else 0}


# insertion-ordered: the first proxy added is the default view
PROXIES = collections.OrderedDict()


def get_ctx(pid=None):
    """Resolve a proxy id to its context; falls back to the first proxy."""
    if pid and pid in PROXIES:
        return PROXIES[pid]
    return next(iter(PROXIES.values())) if PROXIES else None


# --------------------------------------------------------------------------- #
#  Alert rules
# --------------------------------------------------------------------------- #

DEFAULT_ALERT_RULES = [
    # NOTE: every token is anchored with \b. An unanchored "c2" matches the hex
    # digests in ordinary CDN URLs (ac2fd9b4, 8c2e1f4a...) and floods the SOC
    # with false criticals, so C2 is only matched as a hostname label.
    {"id": "blacklist", "name": "Blacklisted domain accessed", "type": "blacklist",
     "enabled": True, "severity": "critical", "cooldown": 30, "match": "host",
     "pattern": r"\b(?:malware|botnet|phish(?:ing)?|ransom(?:ware)?|"
                r"keylog(?:ger)?|trojan|warez|keygen|crack(?:ed)?|torrent)\b"
                r"|\.onion\b|\bc2\.[a-z0-9-]+\."},
    {"id": "denied-burst", "name": "Denied request burst", "type": "denied_rate",
     "enabled": True, "severity": "warning", "cooldown": 120,
     "window": 60, "threshold": 25},
    {"id": "bw-spike", "name": "Client bandwidth spike", "type": "bandwidth_spike",
     "enabled": True, "severity": "warning", "cooldown": 180,
     "window": 60, "threshold_mb": 50},
    {"id": "req-flood", "name": "Client request flood", "type": "client_request_rate",
     "enabled": True, "severity": "warning", "cooldown": 180,
     "window": 60, "threshold": 300},
    {"id": "error-rate", "name": "Upstream error rate high", "type": "error_rate",
     "enabled": True, "severity": "warning", "cooldown": 120,
     "window": 60, "threshold": 20},
    {"id": "slow-pileup", "name": "Slow request pileup", "type": "slow_rate",
     "enabled": False, "severity": "info", "cooldown": 300,
     "window": 120, "threshold": 10, "latency_ms": 3000},
    {"id": "hit-collapse", "name": "Cache hit ratio collapse", "type": "hit_ratio_low",
     "enabled": False, "severity": "info", "cooldown": 600,
     "window": 300, "threshold_pct": 20, "min_requests": 100},
]

RULE_TYPES = {
    "blacklist":           {"label": "Blacklisted domain (per request)",
                            "fields": ["pattern", "match"]},
    "denied_rate":         {"label": "Denied requests in window",
                            "fields": ["window", "threshold"]},
    "error_rate":          {"label": "Error responses in window",
                            "fields": ["window", "threshold"]},
    "bandwidth_spike":     {"label": "Single client bandwidth in window",
                            "fields": ["window", "threshold_mb"]},
    "client_request_rate": {"label": "Single client requests in window",
                            "fields": ["window", "threshold"]},
    "slow_rate":           {"label": "Slow requests in window",
                            "fields": ["window", "threshold", "latency_ms"]},
    "hit_ratio_low":       {"label": "Cache hit ratio below percent",
                            "fields": ["window", "threshold_pct", "min_requests"]},
    "status_code":         {"label": "Specific status code in window",
                            "fields": ["window", "threshold", "code"]},
}

SEVERITIES = ("info", "warning", "critical")


def _num(rule, key, default=0):
    try:
        return float(rule.get(key, default))
    except (TypeError, ValueError):
        return default


class AlertEngine:
    """Evaluates configurable rules against the live traffic window."""

    def __init__(self, config_path, pid="default", stats=None):
        self.lock = threading.Lock()
        self.config_path = config_path
        self.pid = pid                 # which proxy this engine watches
        self.stats = stats             # that proxy's counters
        self.rules = []
        self.history = collections.deque(maxlen=ALERT_HISTORY)
        # seq -> captured requests; bounded to the same depth as the history so
        # it cannot outgrow it (insertion-ordered, oldest evicted first)
        self._evidence_by_seq = collections.OrderedDict()
        self.fired = collections.Counter()
        self.last_fire = {}
        self._seq = 0
        self._blacklist_cache = {}
        self.load()

    # -- config ------------------------------------------------------------- #
    def load(self):
        rules = None
        if self.config_path and os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as fh:
                    data = json.load(fh)
                rules = data.get("rules") if isinstance(data, dict) else data
            except (OSError, ValueError) as e:
                print(f"!! could not read {self.config_path}: {e}", file=sys.stderr)
        with self.lock:
            self.rules = self._sanitize(rules if rules else DEFAULT_ALERT_RULES)
            self._blacklist_cache = {}
        if rules is None and self.config_path:
            self.save()

    def save(self):
        if not self.config_path:
            return
        try:
            with self.lock:
                payload = {"rules": self.rules}
            tmp = self.config_path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(tmp, self.config_path)
        except OSError as e:
            print(f"!! could not write {self.config_path}: {e}", file=sys.stderr)

    def _sanitize(self, rules):
        clean, seen = [], set()
        for i, r in enumerate(rules or []):
            if not isinstance(r, dict):
                continue
            rtype = str(r.get("type", "")).strip()
            if rtype not in RULE_TYPES:
                continue
            rid = str(r.get("id") or f"{rtype}-{i}").strip()[:60] or f"rule-{i}"
            while rid in seen:
                rid += "_2"
            seen.add(rid)
            sev = str(r.get("severity", "warning")).lower()
            out = {
                "id": rid,
                "name": str(r.get("name") or rid)[:90],
                "type": rtype,
                "enabled": bool(r.get("enabled", True)),
                "severity": sev if sev in SEVERITIES else "warning",
                "cooldown": max(int(_num(r, "cooldown", 120)), 5),
            }
            for f in RULE_TYPES[rtype]["fields"]:
                if f == "pattern":
                    pat = str(r.get("pattern", "")).strip()
                    try:
                        re.compile(pat or "(?!)", re.I)
                    except re.error:
                        pat = ""
                    out["pattern"] = pat
                elif f == "match":
                    # default to host: matching full URLs makes query strings and
                    # path hashes trigger false positives
                    m = str(r.get("match", "host")).strip().lower()
                    out["match"] = m if m in ("host", "url", "both") else "host"
                elif f == "window":
                    out["window"] = min(max(int(_num(r, "window", 60)), 5), 3600)
                elif f == "code":
                    out["code"] = int(_num(r, "code", 407))
                else:
                    out[f] = max(_num(r, f, 1), 0)
                    if f in ("threshold", "min_requests", "latency_ms"):
                        out[f] = int(out[f])
            clean.append(out)
        return clean

    def set_rules(self, rules):
        clean = self._sanitize(rules)
        with self.lock:
            self.rules = clean
            self._blacklist_cache = {}
        self.save()
        return clean

    def get_rules(self):
        with self.lock:
            return [dict(r) for r in self.rules]

    # -- firing ------------------------------------------------------------- #
    def _cooled(self, rule, key=None):
        """True when the rule (optionally per-subject) may fire again."""
        k = (rule["id"], key)
        now = time.time()
        last = self.last_fire.get(k, 0)
        if now - last < rule["cooldown"]:
            return False
        self.last_fire[k] = now
        return True

    def _evidence(self, rule, detail):
        """Capture the requests that caused this alert, at the moment it fires.

        Each rule type needs a different filter, because "the requests behind
        this alert" means something different for a per-client flood than for a
        fleet-wide denied burst.
        """
        if not self.stats:
            return None
        win = int(rule.get("window", 60)) or 60
        t = rule.get("type")
        d = detail or {}
        client = d.get("client")
        try:
            if t == "blacklist":
                # one specific request tripped this; present it in the same
                # shape as the windowed rules so the panel looks consistent
                return {"requests": [{
                            "ts": time.time(), "client": d.get("client", "—"),
                            "host": d.get("host", "—"), "method": "-",
                            "status": d.get("status", 0), "size": 0,
                            "elapsed": 0, "kind": "denied",
                            "action": d.get("action", ""),
                            "url": (d.get("url") or "")[:EVIDENCE_URL_MAX]}],
                        "matched": 1, "shown": 1, "truncated": False,
                        "top_hosts": [(d.get("host", "—"), 1)],
                        "top_clients": [(d.get("client", "—"), 1)],
                        "status_mix": [(d.get("status", 0), 1)],
                        "window": 0}
            if t == "denied_rate":
                m = lambda r: r["kind"] == "denied"
            elif t == "error_rate":
                m = lambda r: r["kind"] == "error"
            elif t == "slow_rate":
                lim = int(rule.get("latency_ms", 3000))
                m = lambda r: r["elapsed"] >= lim
            elif t == "status_code":
                code = int(rule.get("code", 0))
                m = lambda r: r["status"] == code
            elif t in ("client_request_rate", "bandwidth_spike"):
                m = (lambda r: r["client"] == client) if client else None
            elif t == "hit_ratio_low":
                m = lambda r: r["kind"] in ("hit", "miss")
            else:
                m = None
            return self.stats.evidence_for(win, m)
        except (ValueError, TypeError, KeyError):
            return None      # evidence is a nicety; never break alerting for it

    def _fire(self, rule, msg, detail=None):
        evidence = self._evidence(rule, detail)
        with self.lock:
            self._seq += 1
            alert = {
                "seq": f"{self.pid}:{self._seq}",
                "p": self.pid,
                "rule_id": rule["id"],
                "rule": rule["name"],
                "type": rule["type"],
                "severity": rule["severity"],
                "msg": msg,
                "ts": time.time(),
                "detail": detail or {},
            }
            if evidence:
                alert["has_evidence"] = evidence["matched"] > 0
                # kept server-side only: attaching request lists to every SSE
                # frame and every history listing would bloat both for data
                # almost nobody opens. Fetched on click via /api/alert.
                self._evidence_by_seq[alert["seq"]] = evidence
                while len(self._evidence_by_seq) > ALERT_HISTORY:
                    self._evidence_by_seq.pop(next(iter(self._evidence_by_seq)))
            self.history.appendleft(alert)
            self.fired[rule["id"]] += 1
        if STORE:
            STORE.add_alert(alert)
        HUB.publish("alert", alert)
        return alert

    def evidence(self, seq):
        with self.lock:
            return self._evidence_by_seq.get(seq)

    def test_fire(self):
        rule = {"id": "__test__", "name": "Test alert", "type": "blacklist",
                "severity": "info", "cooldown": 0}
        return self._fire(rule, "Test alert — notifications are wired up correctly.",
                          {"source": "manual test"})

    # -- evaluation --------------------------------------------------------- #
    def check_request(self, rec):
        """Per-request rules (blacklist). Called on the ingest path."""
        for rule in self.get_rules():
            if not rule["enabled"] or rule["type"] != "blacklist":
                continue
            pat = rule.get("pattern") or ""
            if not pat:
                continue
            rx = self._blacklist_cache.get(rule["id"])
            if rx is None:
                try:
                    rx = re.compile(pat, re.I)
                except re.error:
                    continue
                self._blacklist_cache[rule["id"]] = rx
            scope = rule.get("match", "host")
            if scope == "url":
                target = str(rec["url"])
            elif scope == "both":
                target = f"{rec['host']} {rec['url']}"
            else:
                target = str(rec["host"])
            if rx.search(target) and self._cooled(rule, rec["host"]):
                self._fire(rule,
                           f"{rec['client']} → {rec['host']} matched blacklist pattern",
                           {"client": rec["client"], "host": rec["host"],
                            "url": rec["url"], "status": rec["status"],
                            "action": rec["action"]})

    def evaluate(self):
        """Windowed rules. Called on a timer."""
        for rule in self.get_rules():
            if not rule["enabled"] or rule["type"] == "blacklist":
                continue
            t = rule["type"]
            win = int(rule.get("window", 60))
            evs = self.stats.window(win) if self.stats else []
            if t == "denied_rate":
                n = sum(1 for e in evs if e[1] == "denied")
                if n >= rule["threshold"] and self._cooled(rule):
                    self._fire(rule, f"{n} denied requests in the last {win}s "
                                     f"(threshold {rule['threshold']})",
                               {"count": n, "window": win})
            elif t == "error_rate":
                n = sum(1 for e in evs if e[1] == "error")
                if n >= rule["threshold"] and self._cooled(rule):
                    self._fire(rule, f"{n} error responses in the last {win}s "
                                     f"(threshold {rule['threshold']})",
                               {"count": n, "window": win})
            elif t == "slow_rate":
                lim = int(rule.get("latency_ms", 3000))
                n = sum(1 for e in evs if e[5] >= lim)
                if n >= rule["threshold"] and self._cooled(rule):
                    self._fire(rule, f"{n} requests slower than {lim}ms in the last {win}s",
                               {"count": n, "window": win, "latency_ms": lim})
            elif t == "status_code":
                code = int(rule.get("code", 0))
                n = sum(1 for e in evs if e[4] == code)
                if n >= rule["threshold"] and self._cooled(rule):
                    self._fire(rule, f"status {code} returned {n} times in the last {win}s",
                               {"count": n, "window": win, "code": code})
            elif t == "bandwidth_spike":
                limit = _num(rule, "threshold_mb", 50) * 1024 * 1024
                per = collections.Counter()
                for e in evs:
                    per[e[2]] += e[3]
                for client, byts in per.most_common(5):
                    if byts >= limit and self._cooled(rule, client):
                        self._fire(rule,
                                   f"{client} transferred {byts / 1048576:.1f} MB in "
                                   f"{win}s (threshold {rule['threshold_mb']:.0f} MB)",
                                   {"client": client, "bytes": byts, "window": win})
            elif t == "client_request_rate":
                per = collections.Counter(e[2] for e in evs)
                for client, n in per.most_common(5):
                    if n >= rule["threshold"] and self._cooled(rule, client):
                        self._fire(rule,
                                   f"{client} made {n} requests in {win}s "
                                   f"(threshold {rule['threshold']})",
                                   {"client": client, "count": n, "window": win})
            elif t == "hit_ratio_low":
                hits = sum(1 for e in evs if e[1] == "hit")
                served = hits + sum(1 for e in evs if e[1] == "miss")
                need = int(rule.get("min_requests", 100))
                if served >= need:
                    pct = hits / served * 100
                    if pct < _num(rule, "threshold_pct", 20) and self._cooled(rule):
                        self._fire(rule,
                                   f"cache hit ratio {pct:.1f}% over {win}s "
                                   f"(below {rule['threshold_pct']:.0f}%)",
                                   {"hit_ratio": round(pct, 1), "served": served})

    def snapshot(self):
        with self.lock:
            return {
                "rules": [dict(r) for r in self.rules],
                "history": list(self.history)[:60],
                "counts": dict(self.fired),
                "types": {k: v for k, v in RULE_TYPES.items()},
            }


def first_engine():
    """Any proxy's alert engine — they all share one ruleset on disk."""
    for c in PROXIES.values():
        if c.alerts:
            return c.alerts
    return None


def set_rules_everywhere(rules):
    """Apply a ruleset to every proxy's engine (persisted once per engine)."""
    saved = None
    for c in PROXIES.values():
        if c.alerts:
            saved = c.alerts.set_rules(rules)
    return saved or []


# --------------------------------------------------------------------------- #
#  Live event fan-out (SSE)
# --------------------------------------------------------------------------- #

class Hub:
    def __init__(self):
        self.lock = threading.Lock()
        self.subs = set()

    def subscribe(self):
        q = queue.Queue(maxsize=500)
        with self.lock:
            self.subs.add(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            self.subs.discard(q)

    def publish(self, event, payload):
        msg = f"event: {event}\ndata: {json.dumps(payload, default=str)}\n\n"
        with self.lock:
            dead = []
            for q in self.subs:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self.subs.discard(q)

    @property
    def count(self):
        with self.lock:
            return len(self.subs)


HUB = Hub()

# --------------------------------------------------------------------------- #
#  Continuous log tailer (handles rotation & truncation)
# --------------------------------------------------------------------------- #

class Tailer(threading.Thread):
    daemon = True

    FP_LEN = 96          # bytes used to fingerprint a file's identity

    def __init__(self, ctx, path, backfill=2000):
        super().__init__(name=f"tailer-{ctx.id}")
        self.ctx = ctx
        self.path = path
        self.backfill = backfill
        self.first_open = True
        self.partial = ""            # buffer for a line caught mid-write
        self.stop_flag = threading.Event()

    def _open(self):
        f = open(self.path, "r", errors="replace")
        return f, os.fstat(f.fileno()).st_ino

    def _fingerprint(self):
        """First N bytes of the file — changes whenever the file is replaced
        or truncated, which size/inode checks alone can miss (copytruncate
        where the new content is longer than our read offset)."""
        try:
            with open(self.path, "rb") as fh:
                return fh.read(self.FP_LEN)
        except OSError:
            return None

    def run(self):
        f = ino = None
        while not self.stop_flag.is_set():
            # (re)open loop
            if f is None:
                try:
                    f, ino = self._open()
                    self.ctx.stats.source_up()
                    if self.first_open:
                        # seed history with the tail of the pre-existing file,
                        # then follow from the end so we don't replay old traffic
                        if self.backfill:
                            try:
                                f.seek(0, os.SEEK_END)
                                size = f.tell()
                                f.seek(max(0, size - 512 * 1024))
                                if size > 512 * 1024:
                                    f.readline()
                                # counters only, deliberately not the history
                                # DB: backfill re-reads the same tail on every
                                # start, so persisting it would duplicate those
                                # rows once per restart
                                for ln in f.readlines()[-self.backfill:]:
                                    rec = parse_line(ln)
                                    if rec:
                                        self.ctx.stats.add(rec)
                            except OSError:
                                pass
                        f.seek(0, os.SEEK_END)
                        self.first_open = False
                    else:
                        # rotation/truncation: the new file is fresh, so read it
                        # from byte 0 or we'd lose whatever was already written
                        f.seek(0)
                        self.partial = ""
                    fp = self._fingerprint()
                except (OSError, IOError) as e:
                    self.ctx.stats.source_down(f"cannot read {self.path}: {e}")
                    time.sleep(3)
                    continue

            chunk = f.readline()
            if chunk:
                # Squid may be caught mid-write: a chunk without a trailing
                # newline is an incomplete line — hold it until the rest lands.
                if not chunk.endswith("\n"):
                    self.partial += chunk
                    time.sleep(0.05)
                    continue
                line = self.partial + chunk
                self.partial = ""
                ingest(self.ctx, line)
                continue

            # nothing new -> check for rotation / truncation
            time.sleep(0.25)
            try:
                st = os.stat(self.path)
                rotated = (st.st_ino != ino
                           or st.st_size < f.tell()
                           or (fp is not None and self._fingerprint() != fp))
                if rotated:
                    f.close()
                    f = None
            except OSError:
                f.close()
                f = None


# --------------------------------------------------------------------------- #
#  Remote source 1: SSH tail  (nothing to install on the proxy)
# --------------------------------------------------------------------------- #

def ingest(ctx, rec_line, quiet=False):
    """Parse a raw log line into `ctx` and push it everywhere.

    `quiet` suppresses the parse-error counter — used for the first of two
    attempts when a line may or may not be syslog-wrapped.
    """
    rec = parse_line(rec_line)
    if not rec:
        if not quiet:
            ctx.stats.note_parse_error()
        return False
    dispatch(ctx, rec)
    return True


def dispatch(ctx, rec):
    """The one path every parsed request takes: counters, history, feed, rules.

    The demo generator used to inline its own copy of these four steps, so
    adding the history database here silently did nothing in demo mode — the
    duplicate had to be found and fixed separately. One function now, so the
    next thing added to the ingest path cannot miss a caller.
    """
    ctx.stats.add(rec)
    if STORE:
        STORE.add(ctx.id, rec)
    rec = dict(rec, p=ctx.id)
    HUB.publish("req", rec)
    if ctx.alerts:
        ctx.alerts.check_request(rec)


class SSHTailer(threading.Thread):
    """Runs `tail -F` on the proxy over SSH and streams the output back.

    Requires only SSH access to the proxy — no agent, no config change.
    Reconnects automatically with backoff if the link drops.
    """
    daemon = True

    def __init__(self, ctx, host, path, user=None, port=22, key=None,
                 backfill=2000, use_sudo=False, ssh_bin="ssh", extra_opts=None):
        super().__init__(name=f"ssh-tailer-{ctx.id}")
        self.ctx = ctx
        self.host, self.path, self.user, self.port = host, path, user, port
        self.key, self.backfill, self.use_sudo = key, backfill, use_sudo
        self.ssh_bin = ssh_bin
        self.extra_opts = extra_opts or []
        self.proc = None
        self._streamed_once = False    # after a reconnect, don't replay history
        self._diag = None              # last remote diagnostic (missing file etc.)
        self.stop_flag = threading.Event()

    @property
    def target(self):
        u = f"{self.user}@" if self.user else ""
        p = f":{self.port}" if self.port and self.port != 22 else ""
        return f"ssh://{u}{self.host}{p}{self.path}"

    def _cmd(self):
        # only the first connection backfills; reconnects start at the end of
        # the file, otherwise every drop would re-ingest the same lines
        n = 0 if self._streamed_once else int(self.backfill)
        remote = f"tail -n {n} -F {shlex_quote(self.path)} 2>&1"
        if self.use_sudo:
            remote = f"sudo -n {remote}"
        cmd = [self.ssh_bin]
        # batch mode: never hang waiting for a password prompt
        cmd += ["-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                "-o", "ServerAliveInterval=15",
                "-o", "ServerAliveCountMax=3",
                "-o", "StrictHostKeyChecking=accept-new"]
        if self.key:
            cmd += ["-i", os.path.expanduser(self.key)]
        if self.port:
            cmd += ["-p", str(self.port)]
        cmd += self.extra_opts
        cmd += [f"{self.user}@{self.host}" if self.user else self.host, remote]
        return cmd

    def run(self):
        backoff = 2.0
        while not self.stop_flag.is_set():
            try:
                self.proc = subprocess.Popen(
                    self._cmd(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, errors="replace", bufsize=1)
            except (OSError, ValueError) as e:
                self.ctx.stats.source_down(f"cannot launch ssh: {e}")
                if self.stop_flag.wait(backoff):
                    return
                backoff = min(backoff * 1.6, 30)
                continue

            # A healthy-but-idle proxy sends nothing, so don't wait for the first
            # line to report "connected": if ssh is still alive after a few
            # seconds, auth succeeded (failures exit almost immediately).
            # reset per connection; set if the remote reports a real problem
            # (e.g. `tail -F` on a missing file stays alive but never streams)
            self._diag = None

            def _mark_alive(p):
                if self.stop_flag.wait(3.0):
                    return
                if p.poll() is None and not self._diag and not self.stop_flag.is_set():
                    self.ctx.stats.source_up(note="ssh connected")
            threading.Thread(target=_mark_alive, args=(self.proc,), daemon=True).start()

            got_any = False
            try:
                for line in self.proc.stdout:
                    if self.stop_flag.is_set():
                        break
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    # quiet: a failed parse may be an ssh/tail diagnostic rather
                    # than a malformed log line, so decide before counting it
                    if ingest(self.ctx, line, quiet=True):
                        if not got_any:
                            got_any = True
                            self._streamed_once = True
                            self.ctx.stats.source_up()
                            backoff = 2.0
                    else:
                        # tail/ssh diagnostics arrive on the same stream
                        low = line.lower()
                        if any(k in low for k in
                               ("no such file", "permission denied", "cannot open",
                                "not a tty", "sudo:", "command not found",
                                "tail:", "ssh:", "connection closed",
                                "host key verification")):
                            self._diag = line[:300]
                            self.ctx.stats.source_down(line[:300], count_retry=False)
                        else:
                            self.ctx.stats.note_parse_error()  # truly unparseable
            except (OSError, ValueError) as e:
                self.ctx.stats.source_down(f"ssh stream error: {e}")

            err = ""
            try:
                if self.proc.stderr:
                    err = (self.proc.stderr.read() or "").strip()
            except (OSError, ValueError):
                pass
            rc = self.proc.poll()
            self.proc = None
            if self.stop_flag.is_set():
                return
            msg = err.splitlines()[-1] if err else f"ssh exited (code {rc})"
            self.ctx.stats.source_down(msg[:300])
            if self.stop_flag.wait(backoff):
                return
            backoff = min(backoff * 1.6, 30)

    def stop(self):
        self.stop_flag.set()
        if self.proc:
            try:
                self.proc.terminate()
            except OSError:
                pass


def shlex_quote(s):
    """Minimal shell quoting for the remote command."""
    import shlex
    return shlex.quote(s)


def posix_dirname(path):
    """Parent directory of a REMOTE (always POSIX) path.

    os.path.dirname would use Windows semantics when the dashboard runs on
    Windows, so split on '/' explicitly.
    """
    p = (path or "").rstrip("/")
    if "/" not in p:
        return "."
    parent = p.rsplit("/", 1)[0]
    return parent or "/"


def key_is_encrypted(path):
    """True if a private key is passphrase-protected, None if undetermined.

    A passphrase-protected key cannot be used with BatchMode unless it has
    been loaded into an ssh-agent, so this is worth detecting up front.
    """
    try:
        with open(os.path.expanduser(path), "r", errors="replace") as fh:
            data = fh.read()
    except OSError:
        return None
    if "ENCRYPTED" in data:                       # classic PEM header
        return True
    if "BEGIN OPENSSH PRIVATE KEY" in data:       # modern format
        import base64
        import struct
        b64 = "".join(l for l in data.splitlines() if "-----" not in l)
        try:
            blob = base64.b64decode(b64)
        except Exception:                          # noqa: BLE001
            return None
        magic = b"openssh-key-v1\x00"
        if blob.startswith(magic):
            off = len(magic)
            try:
                n = struct.unpack(">I", blob[off:off + 4])[0]
                cipher = blob[off + 4:off + 4 + n].decode("ascii", "replace")
            except (struct.error, IndexError):
                return None
            return cipher != "none"
    return None


def agent_keys():
    """Number of keys currently loaded in an ssh-agent (-1 if no agent)."""
    try:
        p = subprocess.run(["ssh-add", "-l"], capture_output=True, text=True,
                           timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        return -1
    if p.returncode == 0:
        return len([l for l in (p.stdout or "").splitlines() if l.strip()])
    return 0 if "no identities" in (p.stdout + p.stderr).lower() else -1


def diagnose_key_auth(tailer):
    """Print advice for a failed key auth, detecting the passphrase case."""
    candidates = []
    if tailer.key:
        candidates.append(os.path.expanduser(tailer.key))
    else:
        home = os.path.expanduser("~")
        for n in ("id_ed25519", "id_rsa", "id_ecdsa"):
            p = os.path.join(home, ".ssh", n)
            if os.path.exists(p):
                candidates.append(p)

    encrypted = [p for p in candidates if key_is_encrypted(p) is True]
    loaded = agent_keys()

    if encrypted and loaded <= 0:
        key = encrypted[0]
        print("\n  >> Your key is PASSPHRASE-PROTECTED and no ssh-agent has it "
              "loaded.\n     BatchMode cannot type a passphrase, so auth fails.\n")
        print("  Fix A (recommended — keeps the passphrase). Windows PowerShell:")
        print("    Get-Service ssh-agent | Set-Service -StartupType Automatic")
        print("    Start-Service ssh-agent")
        print(f"    ssh-add {key}")
        print("    # Linux/macOS:  eval $(ssh-agent -s) && ssh-add " + key)
        print("\n  Fix B (simplest — removes the passphrase):")
        print(f"    ssh-keygen -p -f {key}")
        print("    # enter the old passphrase, then leave the new one EMPTY")
        return True
    return False


def ssh_preflight(tailer):
    """Diagnose an SSH setup before starting the dashboard.

    Checks key-based auth, then whether the log is readable, and prints the
    exact fix for whatever is broken. Returns True if streaming would work.
    """
    def run(remote_cmd, batch=True, timeout=20):
        cmd = [tailer.ssh_bin]
        if batch:
            cmd += ["-o", "BatchMode=yes"]
        cmd += ["-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]
        if tailer.key:
            cmd += ["-i", os.path.expanduser(tailer.key)]
        if tailer.port:
            cmd += ["-p", str(tailer.port)]
        host = f"{tailer.user}@{tailer.host}" if tailer.user else tailer.host
        cmd += [host, remote_cmd]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
        except subprocess.TimeoutExpired:
            return 124, "", "timed out"
        except OSError as e:
            return 127, "", str(e)

    line = "-" * 62
    print(f"\n{line}\n  SSH PREFLIGHT  →  {tailer.target}\n{line}")

    # 1. key-based auth
    rc, out, err = run("echo CONNECT_OK")
    if "CONNECT_OK" not in out:
        print("  [FAIL] key-based SSH login")
        if err:
            print(f"         {err.splitlines()[-1]}")
        if diagnose_key_auth(tailer):
            print(line + "\n")
            return False
        print("\n  The dashboard runs ssh in BatchMode, so a password prompt can"
              "\n  never be answered — you must install a key.\n")
        keyname = tailer.key or "$env:USERPROFILE\\.ssh\\id_ed25519"
        print("  Windows PowerShell:")
        print(f"    ssh-keygen -t ed25519          # press Enter at every prompt")
        print(f"    type {keyname}.pub | ssh {tailer.user or 'user'}@{tailer.host} "
              '"mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys"')
        print("  Linux/macOS:")
        print(f"    ssh-copy-id {tailer.user or 'user'}@{tailer.host}")
        print(f"\n  Already have a key elsewhere? point at it:  --ssh-key <path>")
        print(line + "\n")
        return False
    print("  [ OK ] key-based SSH login")

    # 2. can we read the log?
    rc, out, err = run(f"test -r {shlex_quote(tailer.path)} && echo READ_OK "
                       f"|| echo READ_FAIL")
    if "READ_OK" in out:
        print(f"  [ OK ] readable: {tailer.path}")
        rc, out, _ = run(f"wc -l < {shlex_quote(tailer.path)}")
        if out.isdigit():
            print(f"  [info] {int(out):,} lines currently in the log")
        print(f"{line}\n  All good — starting the dashboard.\n")
        return True

    # 3. figure out WHY it isn't readable.
    #    Careful: `test -e file` is FALSE when the parent directory is not
    #    traversable (no +x), which looks identical to "file missing" but needs
    #    the opposite fix. Probe the directory first.
    print(f"  [FAIL] cannot read: {tailer.path}")
    parent = posix_dirname(tailer.path)
    qp, qf = shlex_quote(parent), shlex_quote(tailer.path)
    rc, probe, _ = run(
        f'if [ ! -e {qp} ]; then echo NOPARENT; '
        f'elif [ ! -x {qp} ]; then echo NOTRAVERSE; '
        f'elif [ -e {qf} ]; then echo UNREADABLE; '
        f'else echo NOFILE; fi')
    verdict = probe.strip().splitlines()[-1] if probe.strip() else "UNKNOWN"

    if verdict == "NOPARENT":
        print(f"         the directory {parent} does not exist on this host.")
        rc, found, _ = run("ls -1d /var/log/squid* /var/log/squid3* "
                           "/usr/local/squid/var/logs 2>/dev/null | head -10")
        if found:
            print("         directories that DO exist:")
            for ln in found.splitlines():
                print(f"           {ln}")
        else:
            print("         (no standard Squid log directory found — is Squid "
                  "installed here?)")
        print(f"\n  Fix: point --ssh at the real path, e.g.")
        print(f"    --ssh {tailer.user or 'user'}@{tailer.host}:<correct>/access.log")
        print(line + "\n")
        return False

    if verdict == "NOFILE":
        print(f"         {parent} is readable, but access.log is not in it.")
        rc, found, _ = run(f"ls -1 {qp} 2>/dev/null | head -20")
        if found:
            print(f"         files in {parent}:")
            for ln in found.splitlines():
                print(f"           {ln}")
        print(f"\n  Fix: pass the right filename from the list above.")
        print(line + "\n")
        return False

    # UNREADABLE or NOTRAVERSE -> a permissions problem. `ls -ld` on the parent
    # still works (it only needs +x on /var/log), so we can name the group.
    if verdict == "NOTRAVERSE":
        print(f"         the file is there, but you cannot enter {parent} "
              f"(missing +x).")
    else:
        print(f"         the file exists but is not readable by you.")

    rc, owner, _ = run(f"ls -ld {qp} 2>/dev/null; ls -ld {qf} 2>/dev/null")
    if owner:
        print("         current permissions:")
        for ln in owner.splitlines():
            print(f"           {ln}")
    rc, whoami, _ = run("id")
    if whoami:
        print(f"         your identity:  {whoami}")

    # group that owns the directory (or the file, if we could stat it)
    grp = "proxy"
    if owner:
        for ln in owner.splitlines():
            parts = ln.split()
            if len(parts) >= 4 and parts[0].startswith(("d", "-")):
                grp = parts[3]
                if parts[0].startswith("-"):
                    break        # prefer the file's group when available

    rc, sudo_out, _ = run("sudo -n true 2>&1 && echo SUDO_OK || echo SUDO_NO")
    has_sudo = "SUDO_OK" in sudo_out

    py = "python" if os.name == "nt" else "python3"
    who = tailer.user or "<user>"
    n = 1
    print("\n  Fix — pick one (run on the PROXY server, needs sudo there):")

    # ACL first: least privilege, no group changes, survives log rotation.
    print(f"    {n}) grant just this user read access (recommended — least privilege):")
    print(f"         sudo setfacl -m u:{who}:rx {parent}")
    print(f"         sudo setfacl -m u:{who}:r  {tailer.path}")
    print(f"         sudo setfacl -d -m u:{who}:r {parent}   # rotated logs inherit it")
    n += 1

    # Joining the owning group only helps when that group isn't root.
    if grp and grp != "root":
        print(f"    {n}) or add yourself to the '{grp}' group, then reconnect:")
        print(f"         sudo usermod -a -G {grp} {who}")
        print(f"       (applies on the next SSH connection — no reboot needed)")
        n += 1
    else:
        print(f"    -- NOT advised here: the directory's group is 'root', so "
              f"'usermod -a -G root' would\n"
              f"       be needed — that grants far more than log access. Use the "
              f"ACL above instead.")

    if has_sudo:
        print(f"    {n}) passwordless sudo already works — just add --ssh-sudo:")
        print(f"         {py} squid_dashboard.py --ssh ... --ssh-sudo")
    else:
        print(f"    {n}) or allow passwordless sudo for just this tail, then "
              f"use --ssh-sudo:")
        print(f"         # /etc/sudoers.d/squiddash  (edit with: sudo visudo -f "
              f"/etc/sudoers.d/squiddash)")
        print(f"         {who} ALL=(root) NOPASSWD: /usr/bin/tail -n [0-9]* -F "
              f"{tailer.path}")
        print(f"         {py} squid_dashboard.py --ssh ... --ssh-sudo")
    n += 1
    print(f"    {n}) no permission to change anything? use push mode "
          f"(no log access needed):")
    print(f"         # in squid.conf:  access_log udp://<YOUR_PC_IP>:5140 squid")
    print(f"         {py} squid_dashboard.py --udp-port 5140")
    print(line + "\n")
    return False


# --------------------------------------------------------------------------- #
#  Remote source 2: UDP listener  (Squid pushes to us)
# --------------------------------------------------------------------------- #

# strip a syslog header if the line was forwarded through syslog/rsyslog
SYSLOG_PRI = re.compile(r"^<\d{1,3}>(?:\d\s+)?")
NATIVE_START = re.compile(r"\d{10}\.\d{1,3}\s+-?\d+\s")


def strip_syslog(line):
    """Return the Squid payload from a possibly syslog-wrapped line."""
    s = SYSLOG_PRI.sub("", line).strip()
    m = NATIVE_START.search(s)
    if m:
        return s[m.start():]
    if "]: " in s:
        return s.split("]: ", 1)[1]
    # 'Aug 17 23:31:05 host squid: <payload>'
    parts = s.split(": ", 1)
    return parts[1] if len(parts) == 2 else s


class UDPListener(threading.Thread):
    """Receives log lines pushed by Squid's `access_log udp://` module,
    or lines relayed by rsyslog. Handles both raw and syslog-wrapped."""
    daemon = True

    def __init__(self, ctx, bind="0.0.0.0", port=5140):
        super().__init__(name=f"udp-listener-{ctx.id}")
        self.ctx = ctx
        self.bind, self.port = bind, port
        self.sock = None
        self.stop_flag = threading.Event()

    @property
    def target(self):
        return f"udp://{self.bind}:{self.port}"

    def run(self):
        import socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            except OSError:
                pass
            self.sock.bind((self.bind, self.port))
            self.sock.settimeout(1.0)
        except OSError as e:
            self.ctx.stats.source_down(f"cannot bind {self.target}: {e}",
                                       count_retry=False)
            return
        self.ctx.stats.set_source("udp", self.target,
                         hint=f"on the proxy add:  access_log udp://<THIS_PC_IP>:{self.port} squid")
        while not self.stop_flag.is_set():
            try:
                data, _addr = self.sock.recvfrom(65535)
            except OSError:
                continue
            if not data:
                continue
            self.ctx.stats.source_up()
            for raw in data.decode("utf-8", "replace").splitlines():
                if not raw.strip():
                    continue
                if not ingest(self.ctx, raw, quiet=True):
                    ingest(self.ctx, strip_syslog(raw))

    def stop(self):
        self.stop_flag.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
#  Remote source 3: TCP listener  (Squid's tcp:// log module)
# --------------------------------------------------------------------------- #

class TCPListener(threading.Thread):
    """Accepts connections from Squid's `access_log tcp://` module and reads
    newline-delimited log lines off the stream."""
    daemon = True

    def __init__(self, ctx, bind="0.0.0.0", port=5141):
        super().__init__(name=f"tcp-listener-{ctx.id}")
        self.ctx = ctx
        self.bind, self.port = bind, port
        self.srv = None
        self.stop_flag = threading.Event()

    @property
    def target(self):
        return f"tcp://{self.bind}:{self.port}"

    def _client(self, conn, addr):
        with conn:
            conn.settimeout(2.0)
            buf = ""
            self.ctx.stats.source_up(note=f"{addr[0]} connected")
            while not self.stop_flag.is_set():
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk.decode("utf-8", "replace")
                *lines, buf = buf.split("\n")
                for raw in lines:
                    if raw.strip() and not ingest(self.ctx, raw, quiet=True):
                        ingest(self.ctx, strip_syslog(raw))
                if len(buf) > 65536:      # runaway line without a newline
                    buf = ""
        self.ctx.stats.source_down(f"{addr[0]} disconnected", count_retry=False)

    def run(self):
        import socket
        try:
            self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.srv.bind((self.bind, self.port))
            self.srv.listen(8)
            self.srv.settimeout(1.0)
        except OSError as e:
            self.ctx.stats.source_down(f"cannot bind {self.target}: {e}",
                                       count_retry=False)
            return
        self.ctx.stats.set_source("tcp", self.target,
                         hint=f"on the proxy add:  access_log tcp://<THIS_PC_IP>:{self.port} squid")
        while not self.stop_flag.is_set():
            try:
                conn, addr = self.srv.accept()
            except OSError:
                continue
            threading.Thread(target=self._client, args=(conn, addr),
                             daemon=True).start()

    def stop(self):
        self.stop_flag.set()
        if self.srv:
            try:
                self.srv.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
#  Cache manager poller (squidclient)
# --------------------------------------------------------------------------- #

INFO_KEYS = {
    "Number of clients accessing cache": "clients_accessing",
    "Number of HTTP requests received": "http_requests",
    "Request Hit Ratios": "hit_ratios",
    "Byte Hit Ratios": "byte_hit_ratios",
    "Storage Swap size": "swap_size",
    "Storage Mem size": "mem_size",
    "Maximum Resident Size": "max_rss",
    "Mean Object Size": "mean_object_size",
    "CPU Usage": "cpu_usage",
    "Number of file desc currently in use": "fds_in_use",
    "Available number of file descriptors": "fds_available",
    "Total accounted": "total_accounted",
    "Start Time": "start_time",
    "Current Time": "current_time",
}


class CacheMgr(threading.Thread):
    """Polls Squid's cache manager over the network.

    Speaks the cache-manager protocol directly on a socket, so it works against
    a remote proxy with nothing installed locally. Falls back to the
    `squidclient` binary only if the raw request fails and the binary exists.
    """
    daemon = True

    def __init__(self, ctx, host="127.0.0.1", port=3128, interval=15,
                 enabled=True, password=None, timeout=8):
        super().__init__(name=f"cachemgr-{ctx.id}")
        self.ctx = ctx
        self.host, self.port, self.interval = host, port, interval
        self.password, self.timeout = password, timeout
        self.enabled = enabled
        self.stop_flag = threading.Event()

    def _paths(self):
        pw = f"@{self.password}" if self.password else ""
        # newer Squid uses squid-internal-mgr; older uses cache_object://
        return [f"http://{self.host}:{self.port}/squid-internal-mgr/info{pw}",
                f"cache_object://{self.host}/info{pw}"]

    def _http(self, uri):
        """Send one cache-manager request. Returns (status_code, body)."""
        import socket
        req = (f"GET {uri} HTTP/1.0\r\n"
               f"Host: {self.host}\r\n"
               f"User-Agent: SquidDash/1.1\r\n"
               f"Accept: */*\r\n\r\n")
        with socket.create_connection((self.host, self.port), self.timeout) as s:
            s.settimeout(self.timeout)
            s.sendall(req.encode("ascii", "replace"))
            chunks = []
            while True:
                try:
                    b = s.recv(65536)
                except socket.timeout:
                    break
                if not b:
                    break
                chunks.append(b)
        raw = b"".join(chunks).decode("utf-8", "replace")
        if not raw:
            raise OSError("empty response")
        head, _, body = raw.partition("\r\n\r\n")
        if not body and "\n\n" in raw:
            head, _, body = raw.partition("\n\n")
        code = 0
        first = head.splitlines()[0] if head else ""
        parts = first.split()
        if len(parts) >= 2 and parts[1].isdigit():
            code = int(parts[1])
        return code, body

    @staticmethod
    def _parse(text):
        data = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            if k in INFO_KEYS and v:
                data[INFO_KEYS[k]] = v
        return data

    def _squidclient(self):
        if not shutil.which("squidclient"):
            return None
        cmd = ["squidclient", "-h", self.host, "-p", str(self.port)]
        if self.password:
            cmd += ["-w", self.password]
        cmd += ["mgr:info"]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=self.timeout).stdout
        except Exception:                                          # noqa: BLE001
            return None
        d = self._parse(out)
        return d or None

    def poll(self):
        last_err = None
        for uri in self._paths():
            try:
                code, body = self._http(uri)
            except OSError as e:
                last_err = str(e)
                continue
            if code in (401, 403):
                return {"available": False, "denied": True,
                        "note": "manager access denied — on the proxy allow this PC: "
                                "acl dash src <THIS_PC_IP>/32 + "
                                "http_access allow manager dash"}
            d = self._parse(body)
            if d:
                d["available"] = True
                d["via"] = "http"
                return d
            last_err = f"HTTP {code} without recognizable info body"
        d = self._squidclient()
        if d:
            d["available"] = True
            d["via"] = "squidclient"
            return d
        return {"available": False,
                "note": f"cache manager unreachable at {self.host}:{self.port}"
                        + (f" ({last_err})" if last_err else "")}

    def run(self):
        if not self.enabled:
            self.ctx.stats.set_cache_mgr({"available": False,
                                          "note": "cache manager disabled"})
            return
        while not self.stop_flag.is_set():
            d = self.poll()
            self.ctx.stats.set_cache_mgr(d)
            HUB.publish("cachemgr", dict(d, p=self.ctx.id))
            self.stop_flag.wait(self.interval)


# --------------------------------------------------------------------------- #
#  Demo traffic generator (for testing without Squid)
# --------------------------------------------------------------------------- #

class Demo(threading.Thread):
    daemon = True
    HOSTS = ["cdn.jsdelivr.net", "github.com", "api.stripe.com", "youtube.com",
             "facebook.com", "update.microsoft.com", "pypi.org", "docker.io",
             "malware-c2.example.ru", "torrent-tracker.example.net",
             "google.com", "slack.com", "grafana.local", "s3.amazonaws.com"]
    CLIENTS = [f"192.168.10.{i}" for i in (11, 12, 15, 22, 34, 41, 57, 88, 103)]
    USERS = ["opsuser", "ops.admin", "hr.rina", "dev.tanvir", "-"]
    ACTIONS = ["TCP_HIT", "TCP_MISS", "TCP_MEM_HIT", "TCP_REFRESH_HIT",
               "TCP_TUNNEL", "TCP_DENIED", "TCP_MISS"]

    def __init__(self, ctx, rate=6):
        super().__init__(name=f"demo-{ctx.id}")
        self.ctx = ctx
        self.rate = rate
        self.stop_flag = threading.Event()

    def run(self):
        while not self.stop_flag.is_set():
            n = max(1, int(random.gauss(self.rate, self.rate / 2)))
            for _ in range(n):
                action = random.choice(self.ACTIONS)
                denied = action == "TCP_DENIED"
                host = random.choice(self.HOSTS)
                if "malware" in host or "torrent" in host:
                    action, denied = "TCP_DENIED", True
                status = 403 if denied else random.choice([200] * 12 + [204, 301, 304, 404, 502])
                method = random.choice(["GET"] * 8 + ["POST", "CONNECT", "HEAD"])
                url = (f"{host}:443" if method == "CONNECT"
                       else f"https://{host}/{random.choice(['', 'api/v1/data', 'static/app.js', 'images/logo.png', 'download/pkg.tar.gz'])}")
                rec = {
                    "ts": time.time(),
                    "elapsed": random.choice([12, 45, 88, 130, 260, 640, 1500, 2600, 4100]),
                    "client": random.choice(self.CLIENTS),
                    "user": random.choice(self.USERS),
                    "action": action,
                    "status": status,
                    "size": 0 if denied else random.choice([512, 2048, 15000, 90000, 1200000]),
                    "method": method,
                    "url": url,
                    "host": host,
                    "peer": random.choice(["DIRECT/93.184.216.34", "HIER_NONE/-", "DEFAULT_PARENT/10.0.0.5"]),
                    "mime": random.choice(["text/html", "application/json", "image/png", "-"]),
                    "kind": _classify(action, status),
                }
                dispatch(self.ctx, rec)
            self.stop_flag.wait(1.0)


# --------------------------------------------------------------------------- #
#  Blocklist administration (optional, opt-in, token-protected)
# --------------------------------------------------------------------------- #

BLOCK_KINDS = ("domains", "ips", "urls", "allow")


class BlocklistAdmin:
    """Drives the `squid-blocklist` helper on the proxy over SSH.

    The dashboard never edits squid.conf. It calls a root-owned helper script
    that maintains dedicated ACL list files, validates with `squid -k parse`,
    reloads, and rolls back automatically if Squid objects. All privileged
    policy (protected domains, CIDR width limits) is enforced *in the helper*,
    because that is the component running as root — this class is only a
    convenience wrapper plus an access gate.
    """

    def __init__(self, host, user=None, port=22, key=None, ssh_bin="ssh",
                 helper="/usr/local/sbin/squid-blocklist", use_sudo=True,
                 token=None, timeout=30, max_writes_per_min=20, local=False):
        self.host, self.user, self.port, self.key = host, user, port, key
        self.ssh_bin, self.helper, self.use_sudo = ssh_bin, helper, use_sudo
        # local=True: dashboard runs ON the proxy — call the helper directly
        # rather than SSH-ing to ourselves. See PolicyAdmin for the rationale.
        self.local = local
        self.token = token
        self.describe_target = lambda: (
            f"this host (local helper: {self.helper})" if self.local
            else f"{self.user or ''}@{self.host}")
        self.timeout = timeout
        self.max_writes = max_writes_per_min
        self._writes = collections.deque(maxlen=200)
        self.lock = threading.Lock()
        self.last_error = None

    # -- access control ----------------------------------------------------- #
    def check_token(self, supplied):
        import hmac
        if not self.token:
            return False
        return hmac.compare_digest(str(supplied or ""), self.token)

    def _rate_ok(self):
        now = time.time()
        with self.lock:
            while self._writes and now - self._writes[0] > 60:
                self._writes.popleft()
            if len(self._writes) >= self.max_writes:
                return False
            self._writes.append(now)
            return True

    # -- transport ---------------------------------------------------------- #
    def _run(self, args):
        import shlex
        if self.local:
            cmd = ([] if not self.use_sudo else ["sudo", "-n"]) \
                  + [self.helper] + list(args)
        else:
            remote = " ".join(shlex.quote(a)
                              for a in ([self.helper] + list(args)))
            if self.use_sudo:
                remote = "sudo -n " + remote
            cmd = [self.ssh_bin, "-o", "BatchMode=yes",
                   "-o", "ConnectTimeout=10",
                   "-o", "StrictHostKeyChecking=accept-new"]
            if self.key:
                cmd += ["-i", os.path.expanduser(self.key)]
            if self.port:
                cmd += ["-p", str(self.port)]
            cmd += [f"{self.user}@{self.host}" if self.user else self.host,
                    remote]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=self.timeout)
            return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
        except subprocess.TimeoutExpired:
            where = "the helper" if self.local else "the proxy"
            return 124, "", f"timed out talking to {where}"
        except OSError as e:
            return 127, "", str(e)

    # -- operations --------------------------------------------------------- #
    def list_kind(self, kind):
        if kind not in BLOCK_KINDS:
            return None, "unknown list"
        rc, out, err = self._run(["list", kind])
        if rc != 0:
            return None, err or out or f"helper exited {rc}"
        return [l.strip() for l in out.splitlines() if l.strip()], None

    def snapshot(self):
        data, errors = {}, {}
        for k in BLOCK_KINDS:
            rows, err = self.list_kind(k)
            data[k] = rows or []
            if err:
                errors[k] = err
        rc, out, _ = self._run(["status"])
        status = {}
        if rc == 0:
            for line in out.splitlines():
                if "=" in line:
                    a, b = line.split("=", 1)
                    status[a.strip()] = b.strip()
        self.last_error = "; ".join(f"{k}: {v}" for k, v in errors.items()) or None
        return {"enabled": True, "target": self.describe_target(),
                "lists": data, "status": status, "errors": errors}

    def mutate(self, action, kind, entry=None):
        if action not in ("add", "del", "rollback"):
            return {"ok": False, "error": "unknown action"}
        if kind not in BLOCK_KINDS:
            return {"ok": False, "error": "unknown list"}
        if not self._rate_ok():
            return {"ok": False, "error": "rate limit reached "
                                          f"({self.max_writes} changes/min)"}
        args = [action, kind] + ([entry] if entry else [])
        rc, out, err = self._run(args)
        msg = (out or err or "").strip()
        ok = rc == 0
        result = {"ok": ok, "code": rc, "message": msg[:500],
                  "action": action, "kind": kind, "entry": entry}
        if not ok:
            # helper exit codes carry meaning; surface them plainly
            result["reason"] = {
                2: "validation failed",
                3: "Squid rejected the config — rolled back",
                4: "reload failed — rolled back",
                5: "refused (protected entry or unsafe range)",
                124: "timed out", 127: "cannot reach proxy",
            }.get(rc, f"helper exited {rc}")
        HUB.publish("blocklist", {"action": action, "kind": kind,
                                  "entry": entry, "ok": ok,
                                  "message": result.get("reason") or msg[:160]})
        return result


class PolicyAdmin:
    """Drives the `squid-policy` helper on one proxy over SSH.

    The dashboard only ever ships a whole policy document; the helper on the
    proxy validates it, compiles the ACLs, asks Squid to parse them, reloads,
    and rolls back on failure. All the dangerous decisions stay on the box
    running as root, which is the only component that can be trusted to make
    them.
    """

    def __init__(self, host, user=None, port=22, key=None, ssh_bin="ssh",
                 helper="/usr/local/sbin/squid-policy", use_sudo=True,
                 token=None, timeout=30, local=False):
        self.host, self.user, self.port, self.key = host, user, port, key
        self.ssh_bin, self.helper, self.use_sudo = ssh_bin, helper, use_sudo
        self.token, self.timeout = token, timeout
        # local=True: this dashboard runs ON the proxy, so invoke the helper
        # directly instead of over SSH. SSH-ing to your own machine adds a key,
        # a BatchMode requirement and a connection timeout for no benefit — and
        # was the single most common cause of the panel hanging.
        self.local = local

    def describe_target(self):
        """What the UI shows as 'where changes are being written'.

        In local mode there is no SSH user or remote host, so the SSH-style
        "user@host" label would read as a bare "@127.0.0.1" — which looks like
        a bug and tells the operator nothing about what is actually being
        configured.
        """
        if self.local:
            return f"this host (local helper: {self.helper})"
        return f"{self.user or ''}@{self.host}"

    def check_token(self, supplied):
        import hmac
        return bool(self.token) and hmac.compare_digest(str(supplied or ""),
                                                       self.token)

    def _run(self, args, stdin_data=None, acting=None):
        """Run the helper. `acting` names the signed-in operator for the audit.

        The operator is passed as ARGUMENTS. An earlier version prefixed
        environment variables (`sudo -n VAR=x helper ...`), which sudo rejects
        outright — "you are not allowed to set the following environment
        variables" — because the sudoers rule carries no SETENV: tag. Adding
        SETENV: would have been worse than the bug: the helper is a Python
        script, so the caller could then set PYTHONPATH and run their own code
        as root.
        """
        import shlex
        who = []
        if acting:
            if acting.get("user"):
                who += ["--acting-user", str(acting["user"])]
            if acting.get("from"):
                who += ["--acting-from", str(acting["from"])]
        argv = [self.helper] + who + list(args)
        if self.local:
            cmd = (["sudo", "-n"] if self.use_sudo else []) + argv
        else:
            remote = " ".join(shlex.quote(a) for a in argv)
            if self.use_sudo:
                remote = "sudo -n " + remote
            cmd = [self.ssh_bin, "-o", "BatchMode=yes",
                   "-o", "ConnectTimeout=10",
                   "-o", "StrictHostKeyChecking=accept-new"]
            if self.key:
                cmd += ["-i", os.path.expanduser(self.key)]
            if self.port:
                cmd += ["-p", str(self.port)]
            cmd += [f"{self.user}@{self.host}" if self.user else self.host,
                    remote]
        try:
            p = subprocess.run(cmd, input=stdin_data, capture_output=True,
                               text=True, timeout=self.timeout)
            return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
        except subprocess.TimeoutExpired:
            where = "the helper" if self.local else "the proxy"
            return 124, "", f"timed out talking to {where}"
        except OSError as e:
            return 127, "", str(e)

    @property
    def REASONS(self):
        cannot = ("helper not found or not executable" if self.local
                  else "cannot reach proxy")
        return {2: "validation failed",
                3: "Squid rejected the config (rolled back)",
                4: "reload failed (rolled back)",
                5: "refused — unsafe or protected entry",
                124: "timed out", 127: cannot}

    def get_policy(self):
        rc, out, err = self._run(["get"])
        if rc != 0:
            return {"ok": False, "error": err or out or f"helper exited {rc}",
                    "reason": self.REASONS.get(rc, f"exit {rc}")}
        try:
            return {"ok": True, "policy": json.loads(out)}
        except ValueError as e:
            return {"ok": False, "error": f"helper returned invalid JSON: {e}"}

    def summary(self):
        rc, out, _ = self._run(["show"])
        return out if rc == 0 else ""

    # -- raw squid.conf ------------------------------------------------------ #
    def conf_get(self, acting=None):
        rc, out, err = self._run(["conf-get"], acting=acting)
        if rc != 0:
            return {"ok": False, "error": err or out or f"helper exited {rc}",
                    "reason": self.REASONS.get(rc, f"exit {rc}")}
        try:
            return json.loads(out)
        except ValueError:
            return {"ok": False, "error": "helper returned unreadable output"}

    def conf_check(self, text, acting=None):
        rc, out, err = self._run(["conf-check"], stdin_data=text, acting=acting)
        try:
            res = json.loads(out or err)
        except ValueError:
            return {"ok": False, "error": (err or out or "")[:800]}
        res.setdefault("ok", rc == 0)
        return res

    def conf_save(self, text, force=False, acting=None):
        args = ["conf-save"] + (["--force"] if force else [])
        rc, out, err = self._run(args, stdin_data=text, acting=acting)
        if rc != 0:
            return {"ok": False, "code": rc,
                    "reason": self.REASONS.get(rc, f"helper exited {rc}"),
                    "error": (err or out or "").strip()[:1500]}
        try:
            return json.loads(out.splitlines()[-1])
        except (ValueError, IndexError):
            return {"ok": True, "message": out[:800]}

    def conf_backups(self, acting=None):
        rc, out, err = self._run(["conf-backups"], acting=acting)
        try:
            return json.loads(out)
        except ValueError:
            return {"ok": False, "error": (err or out or "")[:400]}

    def conf_restore(self, name, acting=None):
        rc, out, err = self._run(["conf-restore", str(name)], acting=acting)
        if rc != 0:
            return {"ok": False, "code": rc,
                    "reason": self.REASONS.get(rc, f"helper exited {rc}"),
                    "error": (err or out or "").strip()[:1500]}
        try:
            return json.loads(out.splitlines()[-1])
        except (ValueError, IndexError):
            return {"ok": True, "message": out[:400]}

    def push(self, policy, dry_run=False, acting=None):
        args = ["set"] + (["--dry-run"] if dry_run else [])
        rc, out, err = self._run(args, stdin_data=json.dumps(policy),
                                 acting=acting)
        if rc != 0:
            return {"ok": False, "code": rc,
                    "reason": self.REASONS.get(rc, f"helper exited {rc}"),
                    "error": (err or out or "").strip()[:800]}
        # the helper may print human notes ("squid is not running…") before its
        # JSON result, so take the last line that actually parses as an object
        res = None
        for line in reversed([l for l in out.splitlines() if l.strip()]):
            try:
                cand = json.loads(line)
            except ValueError:
                continue
            if isinstance(cand, dict):
                res = cand
                break
        if res is None:
            try:
                res = json.loads(out)
            except ValueError:
                res = {"message": out[:800]}
        notes = [l for l in out.splitlines()
                 if l.strip() and not l.lstrip().startswith(("{", "["))]
        if notes:
            res.setdefault("note", " ".join(notes)[:300])
        res["ok"] = True
        res["code"] = 0
        if not dry_run:
            HUB.publish("policy", {"host": self.host,
                                   "applied": res.get("applied")})
        return res

    def rollback(self):
        rc, out, err = self._run(["rollback"])
        return {"ok": rc == 0, "code": rc, "message": (out or err)[:500],
                "reason": None if rc == 0 else self.REASONS.get(rc, f"exit {rc}")}


def readonly_note(pid, what):
    """Explain refusals precisely: monitor-only proxy vs feature switched off."""
    ctx = get_ctx(pid)
    if ctx and ctx.cfg.get("admin", True) is False:
        return (f"{ctx.name} is configured as monitor-only (admin:false in the "
                f"proxies config), so {what} changes are refused here. Switch the "
                f"dropdown to a proxy with admin access, or set "
                f'"admin": true for it and restart.')
    return f"{what} admin is disabled — start the dashboard with --enable-{what}"


def get_policy_admin(pid=None):
    ctx = get_ctx(pid)
    return getattr(ctx, "policy", None) if ctx else None


def writable_proxies():
    """Proxies this dashboard may push policy to, in config order."""
    return [c for c in PROXIES.values() if getattr(c, "policy", None)]


def fleet_push(policy, acting=None, dry_run=False):
    """Push one policy to every writable proxy.

    Two phases on purpose. A fleet-wide change that is valid on three nodes and
    rejected by the fourth must not leave the fleet in two different states, so
    every node validates first and nothing is applied unless all of them pass.
    Even then the apply is sequential and stops at the first failure — that
    node has already rolled itself back, and the report names exactly which
    nodes changed and which were left alone, so the operator is never guessing.
    """
    targets = writable_proxies()
    if not targets:
        return {"ok": False, "error": "no proxy in this configuration accepts "
                                      "policy changes (all are admin:false)"}
    checked = []
    for c in targets:
        r = c.policy.push(policy, dry_run=True, acting=acting)
        checked.append({"proxy": c.id, "name": c.name,
                        "ok": bool(r.get("ok")),
                        "error": r.get("error") or r.get("reason") or ""})
    failed = [x for x in checked if not x["ok"]]
    if failed or dry_run:
        return {"ok": not failed, "phase": "validate", "dry_run": True,
                "results": checked,
                "applied": [], "skipped": [x["proxy"] for x in checked],
                "error": (f"{len(failed)} of {len(checked)} proxies rejected "
                          f"this policy — nothing was applied"
                          if failed else None)}

    # Snapshot what each node holds now, so a failure part-way through can be
    # undone. Validation alone is not enough: `set --dry-run` checks the policy
    # without writing the ACL list files, so a proxy that only objects to the
    # rendered result passes the check and then fails on apply. Half the fleet
    # on the new policy and half on the old one is the worst possible outcome,
    # so the push is made all-or-nothing here instead of merely reported.
    before = {}
    for c in targets:
        snap = c.policy.get_policy()
        before[c.id] = snap.get("policy") if snap.get("ok") else None

    applied, results = [], []
    for i, c in enumerate(targets):
        r = c.policy.push(policy, dry_run=False, acting=acting)
        ok = bool(r.get("ok"))
        results.append({"proxy": c.id, "name": c.name, "ok": ok,
                        "error": r.get("error") or r.get("reason") or ""})
        if ok:
            applied.append(c.id)
            continue

        skipped = [t.id for t in targets[i + 1:]]
        reverted, revert_failed, still_new = [], [], []
        for t in targets[:i]:
            prev = before.get(t.id)
            if prev is None:
                revert_failed.append(f"{t.name} (its previous policy could not "
                                     f"be read before the push)")
                still_new.append(t.id)
                continue
            back = t.policy.push(prev, dry_run=False, acting=acting)
            if back.get("ok"):
                reverted.append(t.name)
            else:
                revert_failed.append(t.name)
                still_new.append(t.id)
        note = f"{c.name} rejected the policy and rolled itself back. "
        if reverted:
            note += (f"Reverted {', '.join(reverted)} to the previous policy, "
                     f"so the fleet is consistent again. ")
        if revert_failed:
            note += (f"COULD NOT revert {', '.join(revert_failed)} — "
                     f"those nodes still hold the new policy and need "
                     f"attention. ")
        if not reverted and not revert_failed:
            note += "No other node had been changed yet. "
        note += f"{len(skipped)} node(s) were never touched."
        return {"ok": False, "phase": "apply", "results": results,
                "applied": still_new, "reverted": reverted,
                "revert_failed": revert_failed, "skipped": skipped,
                "error": note}
    return {"ok": True, "phase": "apply", "results": results,
            "applied": applied, "skipped": [], "reverted": [],
            "revert_failed": [], "error": None}


def fleet_compare():
    """Is the stored policy the same on every writable proxy?"""
    import hashlib
    rows = []
    for c in writable_proxies():
        r = c.policy.get_policy()
        if not r.get("ok"):
            rows.append({"proxy": c.id, "name": c.name, "ok": False,
                         "error": r.get("error") or r.get("reason")})
            continue
        pol = r.get("policy") or {}
        canon = json.dumps(pol, sort_keys=True, separators=(",", ":"))
        rows.append({
            "proxy": c.id, "name": c.name, "ok": True,
            "fingerprint": hashlib.sha256(canon.encode()).hexdigest()[:12],
            "groups": len(pol.get("groups") or []),
            "ips": sum(len(g.get("ips") or []) for g in (pol.get("groups") or [])),
            "security_domains": len((pol.get("security_block") or {}).get("domains") or []),
            "policy_domains": len((pol.get("policy_block") or {}).get("domains") or []),
        })
    prints = {r["fingerprint"] for r in rows if r.get("ok")}
    return {"identical": len(prints) <= 1, "distinct": len(prints),
            "proxies": rows}


def get_blocklist(pid=None):
    """The blocklist admin for a specific proxy (never a different one)."""
    ctx = get_ctx(pid)
    return getattr(ctx, "blocklist", None) if ctx else None


def any_blocklist():
    for c in PROXIES.values():
        if getattr(c, "blocklist", None):
            return c.blocklist
    return None


# --------------------------------------------------------------------------- #
#  Broadcaster: pushes an aggregated snapshot on a fixed cadence
# --------------------------------------------------------------------------- #

def snapshot_of(ctx, recent_limit=120):
    """One proxy's snapshot, with its own alert state attached."""
    out = ctx.stats.snapshot(recent_limit=recent_limit)
    out["alerts"] = (ctx.alerts.snapshot() if ctx.alerts
                     else {"rules": [], "history": [], "counts": {}, "types": {}})
    out["proxy_name"] = ctx.name
    return out


def snapshot_all(recent_limit=120):
    """Merged view across every proxy — for the 'All proxies' selection.

    Counters are summed, leaderboards re-merged by key, the rate series lined up
    by timestamp, and the request/alert feeds interleaved newest-first.
    """
    ctxs = list(PROXIES.values())
    if not ctxs:
        return {"meta": {"source": {"kind": "none", "target": "—",
                                    "connected": False, "reconnects": 0},
                         "uptime": 0,
                         "server_time": datetime.now().strftime("%H:%M:%S"),
                         "parse_errors": 0},
                "totals": {}, "kinds": {}, "status": {}, "methods": {},
                "series": [], "top_clients": [], "top_hosts": [], "top_users": [],
                "denied": [], "slow": [], "recent": [], "cache_mgr": {},
                "alerts": {"rules": [], "history": []}, "proxy": "all"}

    snaps = [snapshot_of(c, recent_limit=recent_limit) for c in ctxs]

    def merge_counter(key):
        acc = collections.Counter()
        for s in snaps:
            acc.update(s.get(key) or {})
        return dict(acc.most_common(14))

    def merge_top(key):
        n, b = collections.Counter(), collections.Counter()
        for s in snaps:
            for row in s.get(key) or []:
                n[row["key"]] += row.get("n", 0)
                b[row["key"]] += row.get("bytes", 0)
        return [{"key": k, "n": v, "bytes": b[k]} for k, v in n.most_common(TOP_N)]

    tot = collections.Counter()
    for s in snaps:
        for k, v in (s.get("totals") or {}).items():
            tot[k] += v or 0
    hits = sum(s["kinds"].get("hit", 0) for s in snaps)
    served = hits + sum(s["kinds"].get("miss", 0) for s in snaps)
    lat_n = sum(1 for s in snaps if s["totals"].get("avg_latency"))

    by_t = collections.defaultdict(lambda: {"req": 0, "bytes": 0, "hits": 0})
    for s in snaps:
        for pt in s.get("series") or []:
            d = by_t[pt["t"]]
            d["req"] += pt["req"]; d["bytes"] += pt["bytes"]; d["hits"] += pt["hits"]
    series = [dict(t=t, **by_t[t]) for t in sorted(by_t)]

    def merge_rows(key, limit):
        rows = []
        for s, c in zip(snaps, ctxs):
            for r in s.get(key) or []:
                rows.append(dict(r, p=c.id))
        rows.sort(key=lambda r: r.get("ts", 0), reverse=True)
        return rows[:limit]

    alert_hist = []
    for s, c in zip(snaps, ctxs):
        for a in (s.get("alerts") or {}).get("history") or []:
            alert_hist.append(dict(a, p=a.get("p", c.id)))
    alert_hist.sort(key=lambda a: a.get("ts", 0), reverse=True)

    up = sum(1 for c in ctxs if c.stats.source["connected"])
    first_alerts = next((c.alerts for c in ctxs if c.alerts), None)

    return {
        "meta": {
            "source": {"kind": "multi",
                       "target": f"{len(ctxs)} proxies · {up} up",
                       "connected": up > 0,
                       "error": None if up == len(ctxs)
                       else f"{len(ctxs) - up} proxy(s) down",
                       "reconnects": sum(c.stats.source["reconnects"] for c in ctxs),
                       "hint": None},
            "uptime": max((s["meta"]["uptime"] for s in snaps), default=0),
            "server_time": datetime.now().strftime("%H:%M:%S"),
            "parse_errors": sum(s["meta"]["parse_errors"] for s in snaps),
        },
        "totals": {
            "requests": tot["requests"], "bytes": tot["bytes"],
            "rps": round(tot["rps"], 2), "bps": round(tot["bps"]),
            "hit_ratio": round(hits / served * 100, 1) if served else 0.0,
            "avg_latency": round(tot["avg_latency"] / lat_n) if lat_n else 0,
            "clients": tot["clients"], "hosts": tot["hosts"],
        },
        "kinds": merge_counter("kinds"),
        "status": merge_counter("status"),
        "methods": merge_counter("methods"),
        "series": series[-RATE_WINDOW:],
        "top_clients": merge_top("top_clients"),
        "top_hosts": merge_top("top_hosts"),
        "top_users": merge_top("top_users"),
        "denied": merge_rows("denied", MINI_LIVE_N),
        "slow": merge_rows("slow", MINI_LIVE_N),
        "recent": merge_rows("recent", recent_limit),
        "cache_mgr": {"available": False,
                      "note": "select a single proxy for cache manager stats"},
        "alerts": {"rules": first_alerts.get_rules() if first_alerts else [],
                   "history": alert_hist[:60], "counts": {}, "types": RULE_TYPES},
        "proxy": "all", "proxy_name": "All proxies",
    }


def detail_of(pid, kind, key):
    """Drill-down for one entity, on one proxy or merged across all of them."""
    if pid == "all":
        parts = []
        for c in PROXIES.values():
            d = c.stats.detail(kind, key)
            if d:
                d["proxy_name"] = c.name
                parts.append(d)
        if not parts:
            return None
        if len(parts) == 1:
            return parts[0]
        out = {"kind": kind, "key": key, "proxy": "all",
               "requests": sum(p["requests"] for p in parts),
               "bytes": sum(p["bytes"] for p in parts),
               "first": min(p["first"] for p in parts),
               "last": max(p["last"] for p in parts),
               "max_latency": max(p["max_latency"] for p in parts),
               "peer_total": sum(p["peer_total"] for p in parts),
               "seen_on": [{"proxy": p["proxy"], "name": p.get("proxy_name"),
                            "requests": p["requests"]} for p in parts]}
        lat = [p["avg_latency"] * p["requests"] for p in parts]
        out["avg_latency"] = round(sum(lat) / out["requests"]) if out["requests"] else 0
        for f in ("kinds", "status", "methods", "actions"):
            acc = collections.Counter()
            for p in parts:
                acc.update(p[f])
            out[f] = dict(acc.most_common(12))
        for f in ("peers", "users"):
            acc = collections.Counter()
            for p in parts:
                for row in p[f]:
                    acc[row["key"]] += row["n"]
            out[f] = [{"key": k, "n": v} for k, v in acc.most_common(15)]
        rows = []
        for p in parts:
            for r in p["recent"]:
                rows.append(dict(r, p=p["proxy"]))
        rows.sort(key=lambda r: r.get("ts", 0), reverse=True)
        out["recent"] = rows[:DETAIL_RECENT * 2]
        return out
    ctx = get_ctx(pid)
    if not ctx:
        return None
    d = ctx.stats.detail(kind, key)
    if d:
        d["proxy_name"] = ctx.name
    return d


class AlertRunner(threading.Thread):
    """Periodically evaluates the windowed alert rules."""
    daemon = True

    def __init__(self, interval=5.0):
        super().__init__(name="alerts")
        self.interval = interval
        self.stop_flag = threading.Event()

    def run(self):
        while not self.stop_flag.is_set():
            for ctx in list(PROXIES.values()):
                if not ctx.alerts:
                    continue
                try:
                    ctx.alerts.evaluate()
                except Exception as e:                             # noqa: BLE001
                    print(f"!! alert evaluation error [{ctx.id}]: {e}",
                          file=sys.stderr)
            self.stop_flag.wait(self.interval)


class Broadcaster(threading.Thread):
    daemon = True

    def __init__(self, interval=2.0):
        super().__init__(name="broadcaster")
        self.interval = interval
        self.stop_flag = threading.Event()

    def run(self):
        while not self.stop_flag.is_set():
            if HUB.count:
                for ctx in list(PROXIES.values()):
                    HUB.publish("stats", snapshot_of(ctx, recent_limit=0))
            self.stop_flag.wait(self.interval)


# --------------------------------------------------------------------------- #
#  HTTP layer
# --------------------------------------------------------------------------- #

class Access:
    """Front-door access control, for when the dashboard is exposed on a network.

    Bound to 127.0.0.1 the dashboard needs no gate — you already have to be on
    the box. Published on a network interface it needs one, because the traffic
    view alone discloses every URL every employee visited, along with their IP.
    That is the most sensitive data on the proxy, and it was previously served
    to anyone who could reach the port. The admin token only ever protected the
    write endpoints, never the traffic view.

    Deliberately simple: one shared token, an HttpOnly cookie so the browser
    stops re-sending it in URLs, per-source-IP lockout so the token cannot be
    guessed at speed, and an optional network allowlist in front of all of it.
    """

    COOKIE = "sqdash_auth"

    def __init__(self, token=None, allow_nets=(), max_fails=8, window=300,
                 lockout=900, secure_cookie=False):
        self.token = token or None
        self.allow_nets = list(allow_nets)
        self.max_fails, self.window, self.lockout = max_fails, window, lockout
        self.secure_cookie = secure_cookie
        self._fails = collections.defaultdict(list)   # ip -> [timestamps]
        self._locked = {}                             # ip -> unlock time
        self.lock = threading.Lock()

    @property
    def enabled(self):
        return bool(self.token)

    def net_ok(self, ip):
        if not self.allow_nets:
            return True
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.allow_nets)

    def locked_for(self, ip):
        """Seconds remaining on a lockout, or 0."""
        with self.lock:
            until = self._locked.get(ip, 0)
            left = until - time.time()
            if left <= 0:
                self._locked.pop(ip, None)
                return 0
            return int(left)

    def record_fail(self, ip):
        now = time.time()
        with self.lock:
            f = [t for t in self._fails[ip] if now - t < self.window]
            f.append(now)
            self._fails[ip] = f
            if len(f) >= self.max_fails:
                self._locked[ip] = now + self.lockout
                self._fails[ip] = []
                return True
        return False

    def clear(self, ip):
        with self.lock:
            self._fails.pop(ip, None)
            self._locked.pop(ip, None)

    def check(self, supplied):
        import hmac
        return bool(self.token) and hmac.compare_digest(str(supplied or ""),
                                                        self.token)

    def cookie_header(self, token):
        bits = [f"{self.COOKIE}={token}", "Path=/", "HttpOnly",
                "SameSite=Strict", "Max-Age=43200"]
        if self.secure_cookie:
            bits.append("Secure")
        return "; ".join(bits)

    def expire_header(self):
        return f"{self.COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"


class LinuxAuth:
    """Signs users in with their Linux account on the proxy, via squid-dash-auth.

    The dashboard is unprivileged and cannot read /etc/shadow, so the root-owned
    helper does the verification and returns a role derived from the user's
    Linux groups. That keeps every credential decision in the one component
    that is allowed to make it, and means access is granted or revoked with
    usermod rather than by editing anything here.
    """

    ROLES = {"viewer": 0, "operator": 1, "admin": 2}

    def __init__(self, helper="/usr/local/sbin/squid-dash-auth", use_sudo=True,
                 local=True, host=None, user=None, port=22, key=None,
                 ssh_bin="ssh", timeout=20):
        self.helper, self.use_sudo, self.local = helper, use_sudo, local
        self.host, self.user, self.port, self.key = host, user, port, key
        self.ssh_bin, self.timeout = ssh_bin, timeout
        self.sessions = {}                 # sid -> {user, role, expires}
        self.lock = threading.Lock()

    def _run(self, args, stdin_data):
        import shlex
        if self.local:
            cmd = (["sudo", "-n"] if self.use_sudo else []) \
                  + [self.helper] + list(args)
        else:
            remote = " ".join(shlex.quote(a)
                              for a in ([self.helper] + list(args)))
            if self.use_sudo:
                remote = "sudo -n " + remote
            cmd = [self.ssh_bin, "-o", "BatchMode=yes",
                   "-o", "ConnectTimeout=10",
                   "-o", "StrictHostKeyChecking=accept-new"]
            if self.key:
                cmd += ["-i", os.path.expanduser(self.key)]
            if self.port:
                cmd += ["-p", str(self.port)]
            cmd += [f"{self.user}@{self.host}" if self.user else self.host,
                    remote]
        try:
            p = subprocess.run(cmd, input=stdin_data, capture_output=True,
                               text=True, timeout=self.timeout)
            return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
        except subprocess.TimeoutExpired:
            return 124, "", "the login helper timed out"
        except OSError as e:
            return 127, "", str(e)

    def login(self, user, password, from_ip="-"):
        """Return (session_id, info) or (None, error_message)."""
        payload = json.dumps({"user": user, "password": password,
                              "from": from_ip})
        rc, out, err = self._run(["login"], payload)
        if rc != 0:
            msg = err or out or f"login helper exited {rc}"
            try:
                msg = json.loads(err or out).get("error", msg)
            except (ValueError, AttributeError):
                pass
            if rc == 127:
                msg = (f"{msg} — is squid-dash-auth installed at "
                       f"{self.helper}?")
            return None, msg
        try:
            info = json.loads(out)
        except ValueError:
            return None, "login helper returned unreadable output"
        if not info.get("ok") or info.get("role") not in self.ROLES:
            return None, info.get("error") or "not authorised"
        sid = secrets.token_urlsafe(32)
        with self.lock:
            self._reap()
            self.sessions[sid] = {"user": info["user"], "role": info["role"],
                                  "groups": info.get("groups", []),
                                  "from": from_ip,
                                  "expires": time.time() + 12 * 3600}
        return sid, info

    def _reap(self):
        now = time.time()
        for sid in [s for s, v in self.sessions.items() if v["expires"] < now]:
            self.sessions.pop(sid, None)

    def session(self, sid):
        if not sid:
            return None
        with self.lock:
            s = self.sessions.get(sid)
            if not s:
                return None
            if s["expires"] < time.time():
                self.sessions.pop(sid, None)
                return None
            return dict(s)

    def logout(self, sid):
        with self.lock:
            self.sessions.pop(sid, None)

    def allows(self, sess, need):
        """Is this session's role at least `need`?"""
        if not sess:
            return False
        return self.ROLES.get(sess.get("role"), -1) >= self.ROLES.get(need, 99)


LOGIN = None               # a LinuxAuth when --login-linux is used
ACCESS = Access()          # replaced in main() when a token is configured


LOGIN_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>Squid dashboard — sign in</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{color-scheme:dark}
body{margin:0;height:100vh;display:grid;place-items:center;background:#0b0f17;
 color:#e6edf7;font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
.card{width:min(92vw,380px);background:#121826;border:1px solid #1f2937;
 border-radius:12px;padding:26px 24px}
h1{margin:0 0 4px;font-size:15px;letter-spacing:.02em}
p{margin:0 0 18px;color:#8b98ad;font-size:12.5px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;
 border:1px solid #253046;background:#0b111d;color:#e6edf7;font:inherit}
button{margin-top:12px;width:100%;padding:10px;border:0;border-radius:8px;
 background:#3b82f6;color:#fff;font:inherit;font-weight:600;cursor:pointer}
button:hover{background:#2f6fdd}
.err{margin-top:12px;color:#f87171;font-size:12.5px;min-height:1.2em}
</style></head><body>
<form class="card" method="POST" action="/login">
  <h1>&#128272; Squid dashboard</h1>
  <p>This dashboard shows proxied traffic. Sign in to continue.</p>
  <input type="password" name="token" placeholder="access token" autofocus
         autocomplete="current-password">
  <button type="submit">Sign in</button>
  <div class="err">__ERR__</div>
</form></body></html>"""


LOGIN_USER_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>Squid dashboard — sign in</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{color-scheme:dark}
body{margin:0;height:100vh;display:grid;place-items:center;background:#0b0f17;
 color:#e6edf7;font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
.card{width:min(92vw,400px);background:#121826;border:1px solid #1f2937;
 border-radius:12px;padding:26px 24px}
h1{margin:0 0 4px;font-size:15px;letter-spacing:.02em}
p{margin:0 0 18px;color:#8b98ad;font-size:12.5px}
label{display:block;margin:0 0 4px;color:#8b98ad;font-size:12px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;
 border:1px solid #253046;background:#0b111d;color:#e6edf7;font:inherit;
 margin-bottom:12px}
button{width:100%;padding:10px;border:0;border-radius:8px;background:#3b82f6;
 color:#fff;font:inherit;font-weight:600;cursor:pointer}
button:hover{background:#2f6fdd}
.err{margin-top:12px;color:#f87171;font-size:12.5px;min-height:1.2em;
 word-break:break-word}
.host{margin-top:16px;padding-top:12px;border-top:1px solid #1f2937;
 color:#5f6b7f;font-size:11.5px}
</style></head><body>
<form class="card" method="POST" action="/login">
  <h1>&#128272; Squid dashboard</h1>
  <p>Sign in with your account on the proxy server.</p>
  <label for="u">username</label>
  <input id="u" type="text" name="user" autofocus autocomplete="username"
         autocapitalize="off" spellcheck="false">
  <label for="p">password</label>
  <input id="p" type="password" name="password" autocomplete="current-password">
  <button type="submit">Sign in</button>
  <div class="err">__ERR__</div>
  <div class="host">__HOST__</div>
</form></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "SquidDash/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):        # silence per-request noise
        pass

    # -- front door ---------------------------------------------------------- #
    def _client_ip(self):
        return self.client_address[0] if self.client_address else "?"

    def _cookie_token(self):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == Access.COOKIE:
                return v
        return None

    def _session(self):
        """The signed-in Linux user's session, when --login-linux is in use."""
        return LOGIN.session(self._cookie_token()) if LOGIN else None

    def _acting(self):
        """Who to record in the proxy-side audit log for this request."""
        s = self._session()
        if not s:
            return {"user": "token-auth", "from": self._client_ip()}
        return {"user": s.get("user", "?"), "from": self._client_ip()}

    def _admin_token_ok(self, admin, body):
        """Second factor for write endpoints; replies 403 itself when wrong.

        Kept even with per-user login: the login proves who you are, this
        proves you meant to change the proxy. With --login-linux the role check
        in _gate() has already run, so this is defence in depth rather than the
        only gate.
        """
        tok = self.headers.get("X-Admin-Token") or (
            body.get("token") if isinstance(body, dict) else None)
        if admin.check_token(tok):
            return True
        self._json({"error": "invalid or missing admin token"}, 403)
        return False

    def _authed(self):
        if LOGIN:
            return self._session() is not None
        if not ACCESS.enabled:
            return True
        return (ACCESS.check(self._cookie_token())
                or ACCESS.check(self.headers.get("X-Auth-Token")))

    def _login_page(self, err="", code=401, extra=None):
        if LOGIN:
            who = getattr(self.server, "login_hint", "") or ""
            body = (LOGIN_USER_HTML.replace("__ERR__", err)
                                   .replace("__HOST__", who))
        else:
            body = LOGIN_HTML.replace("__ERR__", err)
        self._send(code, body, "text/html; charset=utf-8", extra)

    def _wants_html(self):
        return (self.headers.get("Accept") or "").find("text/html") >= 0

    def _gate(self, need=None):
        """True when the request may proceed; otherwise the reply is sent here.

        `need` is the minimum role for this route ("viewer"/"operator"/"admin").
        With --login-linux a viewer can read the traffic view but must not reach
        the write endpoints, so authorisation is checked here rather than being
        left to the UI — hiding a button is not access control.
        """
        ip = self._client_ip()
        if not ACCESS.net_ok(ip):
            self._send(403, "forbidden network\n", "text/plain; charset=utf-8")
            return False
        if not (LOGIN or ACCESS.enabled):
            return True
        if self._authed():
            if need and LOGIN:
                sess = self._session()
                if not LOGIN.allows(sess, need):
                    self._json({"error": f"your role ({sess['role']}) may not "
                                         f"do this — {need} is required",
                                "role": sess["role"], "need": need}, 403)
                    return False
            return True
        left = ACCESS.locked_for(ip)
        if left:
            self._send(429, f"too many failed attempts — locked for {left}s\n",
                       "text/plain; charset=utf-8", {"Retry-After": str(left)})
            return False
        # a browser gets the sign-in form; anything else gets a clean 401
        if self.command == "GET" and self._wants_html():
            self._login_page()
        else:
            self._json({"error": "authentication required"}, 401)
        return False

    def _do_login(self):
        ip = self._client_ip()
        left = ACCESS.locked_for(ip)
        if left:
            self._login_page(f"locked for {left}s after too many attempts",
                             429, {"Retry-After": str(left)})
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 8192:                    # a login form is never this big
                self._login_page("request too large", 413)
                return
            raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        except OSError:
            raw = ""
        fields = {}
        for part in raw.split("&"):
            k, _, v = part.partition("=")
            if k:
                fields[unquote_plus(k)] = unquote_plus(v)

        if LOGIN:
            user = (fields.get("user") or "").strip()
            password = fields.get("password") or ""
            if not user or not password:
                self._login_page("enter both a username and a password")
                return
            sid, info = LOGIN.login(user, password, ip)
            if sid:
                ACCESS.clear(ip)
                self._send(303, b"", "text/plain; charset=utf-8",
                           {"Location": "/",
                            "Set-Cookie": ACCESS.cookie_header(sid)})
                return
            ACCESS.record_fail(ip)
            time.sleep(0.4)
            self._login_page(str(info))
            return

        supplied = fields.get("token") or ""
        if ACCESS.check(supplied):
            ACCESS.clear(ip)
            self._send(303, b"", "text/plain",
                       {"Location": "/",
                        "Set-Cookie": ACCESS.cookie_header(supplied)})
            return
        now_locked = ACCESS.record_fail(ip)
        # a wrong token and a locked-out client get the same shaped reply, so
        # the form cannot be used to probe whether an IP is still unlocked
        time.sleep(0.4)
        msg = ("too many failed attempts — locked out"
               if now_locked else "wrong token")
        self._send(401, LOGIN_HTML.replace("__ERR__", msg),
                   "text/html; charset=utf-8")

    # -- helpers ------------------------------------------------------------ #
    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, default=str), )

    # -- routes ------------------------------------------------------------- #
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        route = u.path.rstrip("/") or "/"

        if route == "/logout":
            if LOGIN:
                LOGIN.logout(self._cookie_token())
            self._send(303, b"", "text/plain; charset=utf-8",
                       {"Location": "/", "Set-Cookie": ACCESS.expire_header()})
            return
        # every other route, including the traffic view and the SSE stream,
        # goes through the gate — the traffic view is the sensitive part.
        # Reading squid.conf needs the admin role even though it is a GET: the
        # file exposes peer topology and internal addresses, so "view only"
        # users must not be able to fetch it.
        if not self._gate("admin" if route.startswith("/api/config") else None):
            return

        if route == "/api/whoami":
            sess = self._session()
            self._json({"login": bool(LOGIN),
                        "user": (sess or {}).get("user"),
                        "role": (sess or {}).get("role"),
                        "can_write": LOGIN.allows(sess, "operator") if LOGIN
                                     else True,
                        "can_edit_config": LOGIN.allows(sess, "admin") if LOGIN
                                            else True})
        elif route == "/":
            self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        elif route == "/api/proxies":
            self._json({"proxies": [c.info() for c in PROXIES.values()],
                        "default": next(iter(PROXIES), None)})
        elif route == "/api/stats":
            limit = int(q.get("recent", ["120"])[0])
            pid = q.get("proxy", [""])[0]
            if pid == "all":
                self._json(snapshot_all(recent_limit=limit))
            else:
                ctx = get_ctx(pid)
                self._json(snapshot_of(ctx, recent_limit=limit) if ctx
                           else {"error": "no proxies configured"})
        elif route == "/api/recent":
            limit = int(q.get("limit", ["200"])[0])
            pid = q.get("proxy", [""])[0]
            if pid == "all":
                self._json({"rows": snapshot_all(recent_limit=limit)["recent"]})
            else:
                ctx = get_ctx(pid)
                if not ctx:
                    self._json({"rows": []})
                else:
                    with ctx.stats.lock:
                        rows = list(ctx.stats.recent)[:limit]
                    self._json({"rows": rows})
        elif route == "/api/detail":
            kind = q.get("kind", ["client"])[0]
            key = q.get("key", [""])[0]
            pid = q.get("proxy", [""])[0] or None
            if kind not in ("client", "host") or not key:
                self._json({"error": "need kind=client|host and key=<value>"}, 400)
            else:
                d = detail_of(pid or next(iter(PROXIES), None), kind, key)
                if not d:
                    self._json({"error": f"no data for {kind} {key}"}, 404)
                else:
                    # alerts that mention this entity
                    hits = []
                    for c in PROXIES.values():
                        if not c.alerts or (pid and pid != "all" and c.id != pid):
                            continue
                        for a in c.alerts.snapshot()["history"]:
                            det = a.get("detail") or {}
                            if det.get(kind) == key or det.get("host") == key \
                                    or det.get("client") == key:
                                hits.append(dict(a, p=c.id))
                    hits.sort(key=lambda a: a.get("ts", 0), reverse=True)
                    d["alerts"] = hits[:12]
                    self._json(d)
        elif route == "/api/health":
            self._json({"ok": True,
                        "proxies": [c.info() for c in PROXIES.values()],
                        "subscribers": HUB.count,
                        "requests_seen": sum(c.stats.total
                                             for c in PROXIES.values())})
        elif route == "/api/export":
            self._export()
        elif route == "/api/history":
            if not STORE:
                self._json({"enabled": False,
                            "note": "history is off — restart with --db PATH"})
            else:
                def f(k):
                    v = q.get(k, [""])[0]
                    return v or None
                since = f("since")
                until = f("until")
                self._json({"enabled": True, "rows": STORE.query(
                    since=float(since) if since else None,
                    until=float(until) if until else None,
                    proxy=f("proxy"), client=f("client"), host=f("host"),
                    kind=f("kind"), q=f("q"),
                    limit=int(q.get("limit", ["200"])[0]))})
        elif route == "/api/trend":
            if not STORE:
                self._json({"enabled": False})
            else:
                self._json({"enabled": True, "points": STORE.trend(
                    hours=int(q.get("hours", ["168"])[0]),
                    proxy=q.get("proxy", [""])[0] or None,
                    client=q.get("client", [""])[0] or None,
                    host=q.get("host", [""])[0] or None)})
        elif route == "/api/clients":
            if not STORE:
                self._json({"enabled": False,
                            "note": "client history needs --db PATH — without "
                                    "it, clients are only visible while "
                                    "currently active and are forgotten on "
                                    "restart"})
            else:
                RANGE_HOURS = {"1h": 1, "1d": 24, "2d": 48, "7d": 168,
                               "15d": 360, "30d": 720, "90d": 2160}
                rng = q.get("range", ["1d"])[0]
                now = time.time()
                since_raw = q.get("since", [""])[0]
                until_raw = q.get("until", [""])[0]
                if since_raw:
                    since = float(since_raw)
                    until = float(until_raw) if until_raw else now
                else:
                    since = now - RANGE_HOURS.get(rng, 24) * 3600
                    until = now
                res = STORE.clients(
                    since=since, until=until,
                    proxy=q.get("proxy", [""])[0] or None,
                    limit=int(q.get("limit", ["1000"])[0]))
                res["enabled"] = True
                res["range"] = rng if not since_raw else "custom"
                res["since"] = since
                res["until"] = until
                self._json(res)
        elif route == "/api/sysinfo":
            def host_row(pid, name, coll):
                if coll is None:
                    return {"id": pid, "name": name, "available": False}
                snap = coll.snapshot()
                snap["id"] = pid
                snap["name"] = name
                snap["available"] = True
                return snap
            self._json({
                "enabled": not (LOCAL_SYS is None
                                and all(c.sysinfo is None
                                        for c in PROXIES.values())),
                "host": host_row("_local", "dashboard host", LOCAL_SYS),
                "proxies": [host_row(c.id, c.name, c.sysinfo)
                           for c in PROXIES.values()],
            })
        elif route == "/api/mini":
            # the FULL retained Denied/Slowest history (up to MINI_RETAIN),
            # fetched on demand — the live SSE ticks only carry MINI_LIVE_N
            # rows each, to keep the continuous push cheap (see MINI_LIVE_N)
            kind = q.get("kind", [""])[0]
            pid = q.get("proxy", [""])[0]
            limit = int(q.get("limit", [str(MINI_RETAIN)])[0])
            if kind not in ("denied", "slow"):
                self._json({"error": "need kind=denied|slow"}, 400)
            elif pid == "all":
                rows = []
                for c in PROXIES.values():
                    rows += [dict(r, p=c.id) for r in c.stats.mini(kind, limit)]
                rows.sort(key=lambda r: r.get("ts", 0), reverse=True)
                self._json({"rows": rows[:limit], "retained": MINI_RETAIN})
            else:
                ctx = get_ctx(pid or None)
                if not ctx:
                    self._json({"rows": [], "retained": MINI_RETAIN})
                else:
                    self._json({"rows": ctx.stats.mini(kind, limit),
                               "retained": MINI_RETAIN})
        elif route == "/api/config":
            pid = q.get("proxy", [""])[0]
            pa = get_policy_admin(None if pid in ("", "all") else pid)
            if not pa:
                self._json({"error": readonly_note(pid or None, "policy"),
                            "read_only": True}, 403)
            else:
                res = pa.conf_get(acting=self._acting())
                if res.get("ok"):
                    res["backups"] = (pa.conf_backups(acting=self._acting())
                                      .get("backups") or [])
                self._json(res)
        elif route == "/api/fleet":
            self._json({"writable": [{"id": c.id, "name": c.name}
                                     for c in writable_proxies()],
                        "monitor_only": [{"id": c.id, "name": c.name}
                                         for c in PROXIES.values()
                                         if not getattr(c, "policy", None)]})
        elif route == "/api/fleet/compare":
            if not writable_proxies():
                self._json({"error": "no proxy accepts policy changes"}, 403)
            else:
                self._json(fleet_compare())
        elif route == "/api/db":
            self._json(STORE.status() if STORE else
                       {"enabled": False,
                        "note": "history is off — restart with --db PATH"})
        elif route == "/api/alert":
            # the requests behind one fired alert, captured when it fired
            seq = q.get("seq", [""])[0]
            pid = seq.split(":", 1)[0] if ":" in seq else ""
            ctx = PROXIES.get(pid)
            ev = ctx.alerts.evidence(seq) if (ctx and ctx.alerts) else None
            alert = None
            for c in ([ctx] if ctx else PROXIES.values()):
                if not c or not c.alerts:
                    continue
                for a in c.alerts.history:
                    if a["seq"] == seq:
                        alert = a
                        break
                if alert:
                    break
            if not alert:
                self._json({"error": "no such alert — it may have aged out of "
                                     "the history"}, 404)
            else:
                self._json({"alert": alert, "evidence": ev,
                            "proxy": alert.get("p"),
                            "proxy_name": (PROXIES[alert["p"]].name
                                           if alert.get("p") in PROXIES
                                           else alert.get("p"))})
        elif route == "/api/alerts":
            eng = first_engine()
            self._json({"rules": eng.get_rules() if eng else [],
                        "types": RULE_TYPES, "severities": list(SEVERITIES)})
        elif route == "/api/alerts/history":
            pid = q.get("proxy", [""])[0]
            if pid == "all" or not pid:
                hist, counts = [], collections.Counter()
                for c in PROXIES.values():
                    if not c.alerts:
                        continue
                    sn = c.alerts.snapshot()
                    hist += [dict(a, p=c.id) for a in sn["history"]]
                    counts.update(sn.get("counts", {}))
                hist.sort(key=lambda a: a.get("ts", 0), reverse=True)
                self._json({"history": hist[:120], "counts": dict(counts)})
            else:
                ctx = get_ctx(pid)
                sn = (ctx.alerts.snapshot() if ctx and ctx.alerts
                      else {"history": [], "counts": {}})
                self._json({"history": sn["history"],
                            "counts": sn.get("counts", {})})
        elif route == "/api/blocklist":
            pid = q.get("proxy", [""])[0]
            bl = get_blocklist(None if pid in ("", "all") else pid)
            if not bl:
                ctx = get_ctx(None if pid in ("", "all") else pid)
                self._json({"enabled": False,
                            "read_only": bool(ctx and
                                              ctx.cfg.get("admin", True) is False),
                            "note": readonly_note(
                                None if pid in ("", "all") else pid, "blocklist")})
            elif not bl.check_token(self.headers.get("X-Admin-Token")):
                self._json({"error": "invalid or missing admin token"}, 403)
            else:
                snap = bl.snapshot()
                snap["proxy"] = pid or next(iter(PROXIES), None)
                self._json(snap)
        elif route == "/api/policy":
            pid = q.get("proxy", [""])[0]
            pa = get_policy_admin(None if pid in ("", "all") else pid)
            if not pa:
                ctx = get_ctx(None if pid in ("", "all") else pid)
                ro = bool(ctx and ctx.cfg.get("admin", True) is False)
                self._json({"enabled": False, "read_only": ro,
                            "note": ("this proxy is configured as monitor-only "
                                     "(admin:false in the proxies config) — "
                                     "policy changes are blocked here on purpose"
                                     if ro else
                                     "policy admin is off — start the dashboard "
                                     "with --enable-policy")})
            elif not pa.check_token(self.headers.get("X-Admin-Token")):
                self._json({"error": "invalid or missing admin token"}, 403)
            else:
                res = pa.get_policy()
                res["enabled"] = True
                res["target"] = pa.describe_target()
                res["proxy"] = pid or next(iter(PROXIES), None)
                # only spend a second SSH round-trip on the summary if the
                # first call actually worked
                res["summary"] = pa.summary() if res.get("ok") else ""
                if not res.get("ok") and "command not found" in (res.get("error") or ""):
                    res["hint"] = ("squid-policy is not installed on this proxy — "
                                   "run part B of SETUP.md on it first")
                self._json(res)
        elif route == "/events":
            self._sse()
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        route = urlparse(self.path).path.rstrip("/")

        # /login is the only unauthenticated POST — it IS the authentication
        if route == "/login":
            if (LOGIN or ACCESS.enabled) and ACCESS.net_ok(self._client_ip()):
                self._do_login()
            else:
                self._send(404, "not found\n", "text/plain; charset=utf-8")
            return
        # writes need at least the operator role; raw config needs admin
        need = "admin" if route.startswith("/api/config") else "operator"
        if not self._gate(need):
            return

        try:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b"{}"
            body = json.loads(raw or b"{}")
        except (ValueError, OSError):
            self._json({"error": "invalid JSON body"}, 400)
            return

        # ---- blocklist admin (token-gated, opt-in) ------------------------- #
        acting = self._acting()

        # ---- raw squid.conf editing (admin role only) ---------------------- #
        if route.startswith("/api/config"):
            pid = (body or {}).get("proxy")
            pa = get_policy_admin(None if pid in ("", "all", None) else pid)
            if not pa:
                self._json({"error": readonly_note(pid, "policy"),
                            "read_only": True}, 403)
                return
            if not self._admin_token_ok(pa, body):
                return
            if route == "/api/config/check":
                text = (body or {}).get("text")
                if not isinstance(text, str) or not text.strip():
                    self._json({"error": "expected {\"text\": \"...\"}"}, 400)
                    return
                self._json(pa.conf_check(text, acting=acting))
            elif route == "/api/config/save":
                text = (body or {}).get("text")
                if not isinstance(text, str) or not text.strip():
                    self._json({"error": "expected {\"text\": \"...\"}"}, 400)
                    return
                self._json(pa.conf_save(text, force=bool((body or {}).get("force")),
                                        acting=acting))
            elif route == "/api/config/restore":
                name = (body or {}).get("name")
                if not name:
                    self._json({"error": "expected {\"name\": \"...\"}"}, 400)
                    return
                self._json(pa.conf_restore(name, acting=acting))
            else:
                self._json({"error": "not found"}, 404)
            return

        if route.startswith("/api/policy"):
            pid = (body or {}).get("proxy")
            fleet = pid in ("all", "*", "fleet")

            # ---- fleet-wide push ------------------------------------------- #
            if fleet and route in ("/api/policy/validate", "/api/policy/apply"):
                if LOGIN and not LOGIN.allows(self._session(), "admin"):
                    self._json({"error": "pushing to every proxy at once "
                                         "requires the admin role"}, 403)
                    return
                first = next(iter(writable_proxies()), None)
                if not first:
                    self._json({"error": "no proxy in this configuration "
                                         "accepts policy changes"}, 403)
                    return
                if not self._admin_token_ok(first.policy, body):
                    return
                pol = (body or {}).get("policy")
                if not isinstance(pol, dict):
                    self._json({"error": "expected {\"policy\": {...}}"}, 400)
                    return
                self._json(fleet_push(pol, acting=acting,
                                      dry_run=route.endswith("validate")))
                return

            pa = get_policy_admin(None if pid in ("", "all", None) else pid)
            if not pa:
                self._json({"error": readonly_note(pid, "policy"),
                            "read_only": True}, 403)
                return
            if not self._admin_token_ok(pa, body):
                return
            if route == "/api/policy/rollback":
                self._json(pa.rollback())
                return
            pol = (body or {}).get("policy")
            if not isinstance(pol, dict):
                self._json({"error": "expected {\"policy\": {...}}"}, 400)
                return
            if route == "/api/policy/validate":
                self._json(pa.push(pol, dry_run=True, acting=acting))
            elif route == "/api/policy/apply":
                self._json(pa.push(pol, dry_run=False, acting=acting))
            else:
                self._json({"error": "not found"}, 404)
            return

        if route.startswith("/api/blocklist"):
            pid = (body or {}).get("proxy")
            if pid in ("", "all", None):
                pid = None
            bl = get_blocklist(pid)
            if not bl:
                self._json({"error": readonly_note(pid, "blocklist"),
                            "read_only": True}, 403)
                return
            tok = self.headers.get("X-Admin-Token") or (
                body.get("token") if isinstance(body, dict) else None)
            if not bl.check_token(tok):
                self._json({"error": "invalid or missing admin token"}, 403)
                return
            kind = (body or {}).get("kind")
            entry = (body or {}).get("entry")
            if route == "/api/blocklist/add":
                self._json(bl.mutate("add", kind, entry))
            elif route == "/api/blocklist/remove":
                self._json(bl.mutate("del", kind, entry))
            elif route == "/api/blocklist/rollback":
                self._json(bl.mutate("rollback", kind))
            else:
                self._json({"error": "not found"}, 404)
            return

        eng = first_engine()
        if not eng:
            self._json({"error": "alert engine unavailable"}, 503)
            return

        if route == "/api/alerts":
            rules = body.get("rules") if isinstance(body, dict) else body
            if not isinstance(rules, list):
                self._json({"error": "expected {\"rules\": [...]}"}, 400)
                return
            saved = set_rules_everywhere(rules)
            HUB.publish("rules", {"rules": saved})
            self._json({"ok": True, "saved": len(saved), "rules": saved,
                        "config": eng.config_path})
        elif route == "/api/alerts/test":
            pid = (body or {}).get("proxy")
            ctx = get_ctx(pid if pid and pid != "all" else None)
            self._json({"ok": True, "alert": ctx.alerts.test_fire()})
        elif route == "/api/alerts/reset":
            saved = set_rules_everywhere(DEFAULT_ALERT_RULES)
            HUB.publish("rules", {"rules": saved})
            self._json({"ok": True, "rules": saved})
        else:
            self._json({"error": "not found"}, 404)

    def _export(self):
        pid = parse_qs(urlparse(self.path).query).get("proxy", [""])[0]
        snap = (snapshot_all(recent_limit=MAX_RECENT) if pid == "all"
                else snapshot_of(get_ctx(pid), recent_limit=MAX_RECENT)
                if get_ctx(pid) else {"recent": []})
        rows = ["ts,datetime,client,user,method,status,action,kind,bytes,ms,host,url"]
        for r in snap["recent"]:
            dt = datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S")
            url = str(r["url"]).replace('"', "'")
            rows.append(f'{r["ts"]:.3f},{dt},{r["client"]},{r["user"]},{r["method"]},'
                        f'{r["status"]},{r["action"]},{r["kind"]},{r["size"]},'
                        f'{r["elapsed"]},{r["host"]},"{url}"')
        name = f"squid_requests_{datetime.now():%Y%m%d_%H%M%S}.csv"
        self._send(200, "\n".join(rows), "text/csv; charset=utf-8",
                   {"Content-Disposition": f'attachment; filename="{name}"'})

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        q = HUB.subscribe()
        try:
            # prime the client with a full snapshot immediately
            for c in PROXIES.values():
                first = snapshot_of(c, recent_limit=150)
                self.wfile.write(
                    f"event: stats\ndata: {json.dumps(first, default=str)}\n\n"
                    .encode("utf-8"))
            self.wfile.flush()
            last_ping = time.time()
            while True:
                try:
                    msg = q.get(timeout=1.0)
                    self.wfile.write(msg.encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    if time.time() - last_ping > 12:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        last_ping = time.time()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            HUB.unsubscribe(q)


# --------------------------------------------------------------------------- #
#  Front-end (single embedded page)
# --------------------------------------------------------------------------- #

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<script>try{document.documentElement.dataset.theme=localStorage.getItem('sqm_theme')||'dark'}catch(e){}</script>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Squid Proxy · Live Monitor</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0a0e14; --panel:#111823; --panel2:#151d2b; --line:#1f2a3a;
  --txt:#dbe4f0; --dim:#7b8ca6; --faint:#4e5f78;
  --hit:#2dd4a7; --miss:#4a9eff; --deny:#ff4d6d; --err:#ffa726;
  --accent:#4a9eff;
  --mono:'JetBrains Mono',ui-monospace,Menlo,monospace;
  color-scheme:dark;
}
html[data-theme="light"]{
  --bg:#f4f6fa; --panel:#ffffff; --panel2:#eef1f6; --line:#dde3ec;
  --txt:#1a2233; --dim:#5b6b82; --faint:#8b98ac;
  --hit:#0f9d76; --miss:#2b7fd6; --deny:#d63754; --err:#c9780a;
  --accent:#2b7fd6;
  color-scheme:light;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font-family:Inter,system-ui,sans-serif;
  font-size:13px;-webkit-font-smoothing:antialiased;transition:background .2s,color .2s}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(1100px 500px at 12% -12%,rgba(74,158,255,.10),transparent 60%),
             radial-gradient(900px 480px at 92% 0%,rgba(45,212,167,.07),transparent 62%)}
html[data-theme="light"] body::before{
  background:radial-gradient(1100px 500px at 12% -12%,rgba(43,127,214,.06),transparent 60%),
             radial-gradient(900px 480px at 92% 0%,rgba(15,157,118,.05),transparent 62%)}
.wrap{position:relative;z-index:1;max-width:1680px;margin:0 auto;padding:18px 22px 40px}

/* ---------- header ---------- */
header{display:flex;align-items:center;gap:18px;flex-wrap:wrap;
  padding-bottom:14px;border-bottom:1px solid var(--line);margin-bottom:18px}
.brand{display:flex;align-items:baseline;gap:10px}
.brand h1{margin:0;font-size:19px;font-weight:700;letter-spacing:-.02em}
.brand span{font-family:var(--mono);font-size:10.5px;color:var(--faint);
  text-transform:uppercase;letter-spacing:.16em}
.spacer{flex:1}
.pill{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border-radius:999px;
  background:var(--panel);border:1px solid var(--line);font-family:var(--mono);font-size:11px;color:var(--dim)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--faint)}
.dot.on{background:var(--hit);box-shadow:0 0 0 3px rgba(45,212,167,.18);animation:pulse 2s infinite}
.dot.off{background:var(--deny);box-shadow:0 0 0 3px rgba(255,77,109,.18)}
@keyframes pulse{50%{opacity:.45}}
button,.btn{font:inherit;font-size:11.5px;padding:6px 12px;border-radius:7px;cursor:pointer;
  background:var(--panel);color:var(--dim);border:1px solid var(--line);text-decoration:none;
  transition:.15s}
button:hover,.btn:hover{color:var(--txt);border-color:var(--accent)}
button.act{color:var(--bg);background:var(--accent);border-color:var(--accent);font-weight:600}

/* ---------- view tabs ---------- */
.tabs{display:flex;gap:6px;margin-bottom:16px;border-bottom:1px solid var(--line);padding-bottom:0}
.tabbtn{font:inherit;font-size:12.5px;font-weight:600;padding:9px 16px;border:0;background:none;
  color:var(--dim);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;
  transition:.15s}
.tabbtn:hover{color:var(--txt)}
.tabbtn.act{color:var(--accent);border-bottom-color:var(--accent)}
.tabbtn .tag{font-family:var(--mono);font-weight:400}

/* ---------- kpi ---------- */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:11px;margin-bottom:16px}
.kpi{background:linear-gradient(160deg,var(--panel2),var(--panel));border:1px solid var(--line);
  border-radius:11px;padding:13px 15px;position:relative;overflow:hidden}
.kpi::after{content:'';position:absolute;left:0;top:0;bottom:0;width:2.5px;background:var(--accent);opacity:.65}
.kpi.g::after{background:var(--hit)} .kpi.r::after{background:var(--deny)}
.kpi.o::after{background:var(--err)} .kpi.b::after{background:var(--miss)}
.kpi .lbl{font-family:var(--mono);font-size:9.5px;text-transform:uppercase;letter-spacing:.13em;color:var(--faint)}
.kpi .val{font-family:var(--mono);font-size:25px;font-weight:700;letter-spacing:-.02em;margin-top:5px;
  font-variant-numeric:tabular-nums}
.kpi .sub{font-size:10.5px;color:var(--dim);margin-top:2px}

/* ---------- layout ---------- */
.grid{display:grid;gap:13px}
.g3{grid-template-columns:1.55fr 1fr 1fr}
.g2{grid-template-columns:1fr 1fr}
@media(max-width:1180px){.g3,.g2{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden;
  display:flex;flex-direction:column;margin-bottom:13px}
.card>h2{margin:0;padding:11px 15px;font-size:11px;font-weight:600;text-transform:uppercase;
  letter-spacing:.11em;color:var(--dim);border-bottom:1px solid var(--line);
  display:flex;align-items:center;gap:9px;background:rgba(255,255,255,.012)}
.card>h2 .tag{margin-left:auto;font-family:var(--mono);font-size:10px;color:var(--faint);
  text-transform:none;letter-spacing:0}
.body{padding:13px 15px}
.body.flush{padding:0}

/* ---------- charts ---------- */
.chart{width:100%;display:block}
.legend{display:flex;gap:15px;padding:0 15px 11px;font-family:var(--mono);font-size:10px;color:var(--dim)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:-1px}

/* ---------- bars ---------- */
.bars{display:flex;flex-direction:column;gap:8px}
.bar{display:grid;grid-template-columns:1fr auto;gap:4px;font-size:12px}
.bar .top{display:flex;justify-content:space-between;gap:10px;grid-column:1/-1}
.bar .nm{font-family:var(--mono);font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar .ct{font-family:var(--mono);font-size:11px;color:var(--dim);flex-shrink:0}
.bar .track{grid-column:1/-1;height:4px;background:var(--panel2);border-radius:3px;overflow:hidden}
.bar .fill{height:100%;background:linear-gradient(90deg,var(--accent),#7b6cff);border-radius:3px;
  transition:width .5s cubic-bezier(.2,.8,.2,1)}
.bar.warn .fill{background:linear-gradient(90deg,var(--deny),#ff8a5b)}

/* ---------- system health ---------- */
.syshost{background:var(--panel2);border:1px solid var(--line);border-radius:10px;
  padding:14px;min-width:280px;flex:1 1 280px}
.syshost .hname{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--txt);
  display:flex;align-items:center;gap:7px;margin-bottom:10px}
.syshost .hname .dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.syshost .dot.on{background:var(--hit)} .syshost .dot.off{background:var(--deny)}
.gauges{display:flex;gap:12px;justify-content:space-between}
.gauge{display:flex;flex-direction:column;align-items:center;gap:2px}
.gauge svg{display:block}
.gauge .gv{font-family:var(--mono);font-size:13px;font-weight:700;fill:var(--txt)}
.gauge .gl{font-family:var(--mono);font-size:8.5px;letter-spacing:.08em;color:var(--faint);
  text-transform:uppercase;margin-top:2px}
.sysmeta{margin-top:12px;padding-top:10px;border-top:1px solid var(--line);
  font-family:var(--mono);font-size:10.5px;color:var(--dim);display:grid;
  grid-template-columns:1fr 1fr;gap:4px 10px}
.sysmeta .k{color:var(--faint)}
.syshost.err{border-color:var(--deny)}
.syshost .errmsg{font-family:var(--mono);font-size:11px;color:var(--deny);margin-top:6px}

/* ---------- tables ---------- */
.scroll{max-height:430px;overflow:auto}
.scroll::-webkit-scrollbar{width:8px;height:8px}
.scroll::-webkit-scrollbar-thumb{background:#233145;border-radius:4px}
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px}
th{position:sticky;top:0;background:var(--panel2);color:var(--faint);text-align:left;
  padding:8px 10px;font-size:9.5px;text-transform:uppercase;letter-spacing:.1em;font-weight:600;
  border-bottom:1px solid var(--line);z-index:2;white-space:nowrap}
td{padding:6px 10px;border-bottom:1px solid rgba(31,42,58,.5);white-space:nowrap;
  max-width:340px;overflow:hidden;text-overflow:ellipsis}
tbody tr:hover{background:rgba(74,158,255,.055)}
tr.fresh{animation:flash 1.1s ease-out}
@keyframes flash{from{background:rgba(74,158,255,.20)}to{background:transparent}}
.k{display:inline-block;padding:1px 6px;border-radius:4px;font-size:9.5px;font-weight:700;
  text-transform:uppercase;letter-spacing:.06em}
.k.hit{background:rgba(45,212,167,.15);color:var(--hit)}
.k.miss{background:rgba(74,158,255,.15);color:var(--miss)}
.k.denied{background:rgba(255,77,109,.15);color:var(--deny)}
.k.error{background:rgba(255,167,38,.15);color:var(--err)}
.s2{color:var(--hit)} .s3{color:var(--miss)} .s4{color:var(--deny)} .s5{color:var(--err)}
.dimc{color:var(--dim)}
.slowc{color:var(--err);font-weight:700}
.filters{display:flex;gap:8px;padding:10px 15px;border-bottom:1px solid var(--line);flex-wrap:wrap}
input[type=text],input[type=datetime-local],select{font:inherit;font-family:var(--mono);font-size:11px;padding:5px 9px;
  background:var(--bg);color:var(--txt);border:1px solid var(--line);border-radius:6px;outline:none}
input[type=text]{flex:1;min-width:150px}
input[type=text]:focus,select:focus{border-color:var(--accent)}
.empty{padding:26px 15px;text-align:center;color:var(--faint);font-family:var(--mono);font-size:11px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-family:var(--mono);font-size:11.5px}
.kv dt{color:var(--faint)} .kv dd{margin:0;text-align:right}
.banner{background:rgba(255,77,109,.10);border:1px solid rgba(255,77,109,.32);color:#ffb3c0;
  padding:10px 14px;border-radius:9px;font-family:var(--mono);font-size:11.5px;margin-bottom:14px;display:none}
footer{margin-top:22px;color:var(--faint);font-family:var(--mono);font-size:10.5px;text-align:center}

/* ---------- alerts: toasts ---------- */
#toasts{position:fixed;top:14px;right:14px;z-index:200;display:flex;flex-direction:column;
  gap:9px;width:372px;max-width:calc(100vw - 28px);pointer-events:none}
.toast{pointer-events:auto;background:var(--panel2);border:1px solid var(--line);
  border-left:3px solid var(--miss);border-radius:9px;padding:11px 13px;
  box-shadow:0 12px 34px rgba(0,0,0,.5);animation:slidein .28s cubic-bezier(.2,.9,.3,1)}
.toast.warning{border-left-color:var(--err)}
.toast.critical{border-left-color:var(--deny);background:linear-gradient(180deg,rgba(255,77,109,.12),var(--panel2))}
.toast.info{border-left-color:var(--miss)}
.toast.out{animation:slideout .25s ease-in forwards}
@keyframes slidein{from{transform:translateX(115%);opacity:0}to{transform:none;opacity:1}}
@keyframes slideout{to{transform:translateX(115%);opacity:0}}
.toast .th{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.toast .sev{font-family:var(--mono);font-size:9px;font-weight:700;text-transform:uppercase;
  letter-spacing:.11em;padding:2px 6px;border-radius:4px}
.toast.critical .sev{background:rgba(255,77,109,.2);color:var(--deny)}
.toast.warning .sev{background:rgba(255,167,38,.2);color:var(--err)}
.toast.info .sev{background:rgba(74,158,255,.2);color:var(--miss)}
.toast .rn{font-size:12px;font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.toast .x{cursor:pointer;color:var(--faint);font-size:15px;line-height:1;padding:0 2px}
.toast .x:hover{color:var(--txt)}
.toast .tm{font-family:var(--mono);font-size:11px;color:var(--dim);line-height:1.45}
.toast .tt{font-family:var(--mono);font-size:9.5px;color:var(--faint);margin-top:4px}

/* ---------- alerts: header bell ---------- */
.bell{position:relative}
.badge{position:absolute;top:-5px;right:-5px;min-width:16px;height:16px;border-radius:9px;
  background:var(--deny);color:#fff;font-family:var(--mono);font-size:9.5px;font-weight:700;
  display:none;align-items:center;justify-content:center;padding:0 4px}
.badge.on{display:flex}
.sev-dot{width:6px;height:6px;border-radius:50%;display:inline-block;margin-right:6px}
.sev-dot.critical{background:var(--deny)} .sev-dot.warning{background:var(--err)}
.sev-dot.info{background:var(--miss)}

/* ---------- alerts: modal ---------- */
.mask{position:fixed;inset:0;background:rgba(4,7,11,.78);z-index:300;display:none;
  align-items:flex-start;justify-content:center;padding:34px 16px;overflow:auto}
.mask.on{display:flex}
.modal{background:var(--panel);border:1px solid var(--line);border-radius:13px;width:100%;
  max-width:1000px;box-shadow:0 24px 70px rgba(0,0,0,.6)}
.modal h3{margin:0;padding:15px 19px;font-size:13px;font-weight:600;border-bottom:1px solid var(--line);
  display:flex;align-items:center;gap:11px}
.modal h3 .x{margin-left:auto;cursor:pointer;color:var(--faint);font-size:19px;line-height:1}
.modal h3 .x:hover{color:var(--txt)}
.mbody{padding:15px 19px;max-height:62vh;overflow:auto}
.mfoot{padding:13px 19px;border-top:1px solid var(--line);display:flex;gap:9px;align-items:center}
.mfoot .note{font-family:var(--mono);font-size:10.5px;color:var(--faint);flex:1}
.rule{border:1px solid var(--line);border-radius:9px;padding:12px 13px;margin-bottom:10px;
  background:var(--panel2)}
.rule.off{opacity:.55}
.rhead{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.rhead input[type=text].rname{flex:1;font-family:Inter,sans-serif;font-size:12.5px;font-weight:600}
.rgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:9px}
.fld{display:flex;flex-direction:column;gap:4px}
.fld label{font-family:var(--mono);font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:var(--faint)}
.fld input,.fld select{width:100%}
.sw{position:relative;width:34px;height:19px;flex-shrink:0;cursor:pointer}
.sw input{opacity:0;width:0;height:0;position:absolute}
.sw .tr{position:absolute;inset:0;background:#26324a;border-radius:19px;transition:.2s}
.sw .tr:before{content:'';position:absolute;width:13px;height:13px;left:3px;top:3px;
  background:var(--faint);border-radius:50%;transition:.2s}
.sw input:checked+.tr{background:rgba(45,212,167,.28)}
.sw input:checked+.tr:before{transform:translateX(15px);background:var(--hit)}
.del{cursor:pointer;color:var(--faint);font-size:11px;font-family:var(--mono);padding:3px 7px;
  border:1px solid var(--line);border-radius:6px;background:transparent}
.del:hover{color:var(--deny);border-color:var(--deny)}
.rtype{font-family:var(--mono);font-size:10px;color:var(--dim)}

/* ---------- blocklist panel ---------- */
.lblx{font-family:var(--mono);font-size:9px;text-transform:uppercase;letter-spacing:.11em;
  color:var(--faint);margin-bottom:7px}
.bllist{border:1px solid var(--line);border-radius:8px;background:var(--panel2);
  max-height:210px;overflow:auto;padding:5px}
.blrow{display:flex;align-items:center;gap:8px;padding:4px 7px;border-radius:5px;
  font-family:var(--mono);font-size:11px}
.blrow:hover{background:rgba(74,158,255,.07)}
.blrow span{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.blrow button{padding:1px 6px;font-size:10px;line-height:1.5}
.blrow.ph{opacity:.45}
.blempty{padding:14px;text-align:center;color:var(--faint);font-family:var(--mono);font-size:10.5px}
.blok{color:var(--hit)} .blerr{color:var(--deny)}
#proxy_sel{font-family:var(--mono);font-size:11.5px;padding:5px 9px;min-width:170px}
#pstrip{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.pchip{display:inline-flex;align-items:center;gap:7px;padding:4px 10px;border-radius:999px;
  background:var(--panel);border:1px solid var(--line);font-family:var(--mono);
  font-size:10.5px;color:var(--dim);cursor:pointer}
.pchip:hover{border-color:var(--accent);color:var(--txt)}
.pchip.sel{border-color:var(--accent);color:var(--txt);background:var(--panel2)}
.pchip .n{color:var(--faint)}
/* ---------- policy editor ---------- */
.pmodal{max-width:1120px}
.pgrp{border:1px solid var(--line);border-radius:10px;background:var(--panel2);
  padding:12px 13px;margin-bottom:11px}
.pgrp.off{opacity:.5}
.pgrp .ph{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-bottom:10px}
.pgrp .ph input.gn{flex:1;min-width:150px;font-weight:600;font-size:12.5px}
.mode{font-family:var(--mono);font-size:9px;font-weight:700;text-transform:uppercase;
  letter-spacing:.09em;padding:2px 7px;border-radius:5px;white-space:nowrap}
.mode.deny_all{background:rgba(255,77,109,.18);color:var(--deny)}
.mode.unrestricted{background:rgba(45,212,167,.16);color:var(--hit)}
.mode.allowlist_only{background:rgba(255,167,38,.16);color:var(--err)}
.mode.restricted{background:rgba(74,158,255,.16);color:var(--miss)}
.chips{display:flex;flex-wrap:wrap;gap:5px;align-items:center;margin-top:4px}
.chip{display:inline-flex;align-items:center;gap:5px;background:var(--bg);
  border:1px solid var(--line);border-radius:999px;padding:2px 8px;
  font-family:var(--mono);font-size:10.5px}
.chip b{cursor:pointer;color:var(--faint);font-weight:400}
.chip b:hover{color:var(--deny)}
.chip.lock{opacity:.6}
.chips input{width:150px;font-family:var(--mono);font-size:10.5px;padding:3px 7px}
.pfield{margin-top:9px}
.pfield .lbl2{font-family:var(--mono);font-size:9px;text-transform:uppercase;
  letter-spacing:.1em;color:var(--faint)}
.tierbox{border:1px solid var(--line);border-radius:9px;padding:11px 12px;
  background:var(--panel2);margin-bottom:10px}
.pout{font-family:var(--mono);font-size:11px;white-space:pre-wrap;max-height:200px;
  overflow:auto;background:var(--bg);border:1px solid var(--line);border-radius:8px;
  padding:9px;margin-top:9px;display:none}
.ptag{display:inline-block;padding:1px 5px;border-radius:4px;background:rgba(74,158,255,.13);
  color:var(--miss);font-size:9.5px;font-weight:600;letter-spacing:.03em}

/* ---------- drill-down ---------- */
.bar.clik{cursor:pointer;border-radius:6px;padding:2px 4px;margin:-2px -4px;transition:.12s}
.bar.clik:hover{background:rgba(74,158,255,.09)}
.bar.clik:hover .nm{color:var(--accent)}
td.clik{cursor:pointer} td.clik:hover{color:var(--accent);text-decoration:underline}
tr.clik{cursor:pointer;transition:.12s} tr.clik:hover{background:rgba(74,158,255,.09)}
.dmodal{max-width:1080px}
.dkpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:9px;margin-bottom:14px}
.dk{background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:9px 11px}
.dk .l{font-family:var(--mono);font-size:9px;text-transform:uppercase;letter-spacing:.11em;color:var(--faint)}
.dk .v{font-family:var(--mono);font-size:17px;font-weight:700;margin-top:3px}
.dgrid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:900px){.dgrid{grid-template-columns:1fr}}
.dsec{margin-bottom:15px}
.dsec h4{margin:0 0 8px;font-size:10px;font-weight:600;text-transform:uppercase;
  letter-spacing:.11em;color:var(--dim)}
.dwhen{font-family:var(--mono);font-size:11px;color:var(--dim);margin-bottom:12px}
.dacts{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.blockbtn{cursor:pointer;background:transparent;border:1px solid var(--line);color:var(--faint);
  border-radius:5px;font-size:9.5px;padding:1px 5px;font-family:var(--mono)}
.blockbtn:hover{color:var(--deny);border-color:var(--deny)}
/* alert -> "which requests caused this" */
tr.arow{cursor:pointer}
tr.arow:hover{background:var(--rowhov,rgba(255,255,255,.035))}
.evcue{font-family:var(--mono);font-size:9.5px;color:var(--faint);
  border:1px solid var(--line);border-radius:5px;padding:1px 5px;margin-left:6px;
  white-space:nowrap}
tr.arow:hover .evcue{color:var(--accent,#3b82f6);border-color:var(--accent,#3b82f6)}
.evhead{margin-bottom:12px;line-height:1.55}
.evhead .dim{font-family:var(--mono);font-size:11px;color:var(--dim)}
.evsum{margin:0 0 14px;padding:10px 12px;border:1px solid var(--line);
  border-radius:8px;display:grid;gap:7px}
.evrow{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap;
  font-family:var(--mono);font-size:11px}
.evlbl{min-width:86px;color:var(--dim);text-transform:uppercase;
  letter-spacing:.05em;font-size:9.5px}
.evchip{border:1px solid var(--line);border-radius:5px;padding:1px 6px}
.evchip b{margin-left:5px;color:var(--faint);font-weight:600}
.evtab{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px}
.evtab th{text-align:left;padding:5px 8px;color:var(--dim);font-weight:500;
  text-transform:uppercase;letter-spacing:.05em;font-size:9.5px;
  border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--panel,#121826)}
.evtab td{padding:4px 8px;border-bottom:1px solid rgba(255,255,255,.04);
  vertical-align:top}
.evurl{max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  color:var(--dim)}
.evlink{color:inherit;text-decoration:none;border-bottom:1px dotted var(--line)}
.evlink:hover{color:var(--accent,#3b82f6)}
</style></head><body><div class="wrap">

<header>
  <div class="brand"><h1>Squid Proxy Monitor</h1><span>live · sse</span></div>
  <select id="proxy_sel" title="which proxy to view"></select>
  <div class="spacer"></div>
  <span class="pill"><i class="dot" id="dot"></i><span id="conn">connecting…</span></span>
  <span class="pill" id="logpill">log: —</span>
  <span class="pill" id="clock">--:--:--</span>
  <button id="theme_btn" title="Switch between dark and light theme">🌙 Dark</button>
  <button id="notif" title="Enable desktop notifications">🔔 Notify: off</button>
  <button id="sound" title="Alert sound">🔈 Sound: off</button>
  <button id="rules_btn" class="bell">⚙ Alert rules<span class="badge" id="badge">0</span></button>
  <button id="pol_btn">🛡 Access policy</button>
  <button id="cfg_btn" title="edit squid.conf on the selected proxy">🧾 squid.conf</button>
  <button id="pause">⏸ Pause feed</button>
  <a class="btn" id="csv_link" href="/api/export">⤓ CSV</a>
  <span class="pill" id="who_badge" style="display:none"></span>
  <a class="btn" id="logout_link" href="/logout" style="display:none">sign out</a>
</header>

<div class="banner" id="banner"></div>
<div id="pstrip"></div>
<div id="toasts"></div>

<nav class="tabs" id="view_tabs">
  <button class="tabbtn act" data-view="overview">Overview</button>
  <button class="tabbtn" data-view="live">Live feed<span class="tag" id="tab_feed_n" style="margin-left:6px"></span></button>
</nav>

<div id="view_overview">
<div class="kpis">
  <div class="kpi"><div class="lbl">Requests</div><div class="val" id="k_req">0</div><div class="sub" id="k_req_s">total seen</div></div>
  <div class="kpi b"><div class="lbl">Req / sec</div><div class="val" id="k_rps">0</div><div class="sub">5s rolling avg</div></div>
  <div class="kpi g"><div class="lbl">Cache hit ratio</div><div class="val" id="k_hit">0%</div><div class="sub" id="k_hit_s">hit ÷ served</div></div>
  <div class="kpi"><div class="lbl">Throughput</div><div class="val" id="k_bw">0</div><div class="sub" id="k_bw_s">total transferred</div></div>
  <div class="kpi o"><div class="lbl">Avg latency</div><div class="val" id="k_lat">0</div><div class="sub">ms per request</div></div>
  <div class="kpi r"><div class="lbl">Denied</div><div class="val" id="k_den">0</div><div class="sub">policy blocks</div></div>
  <div class="kpi"><div class="lbl">Clients</div><div class="val" id="k_cli">0</div><div class="sub" id="k_cli_s">unique IPs</div></div>
  <div class="kpi"><div class="lbl">Uptime</div><div class="val" id="k_up">0s</div><div class="sub" id="k_up_s">monitoring</div></div>
</div>

<div class="card" id="sys_card">
  <h2>System health <span class="tag" id="sys_tag">CPU · memory · disk · network</span>
    <button id="sys_refresh" style="margin-left:10px">refresh</button></h2>
  <div class="body" id="sys_body" style="display:flex;gap:14px;flex-wrap:wrap;padding:16px"></div>
  <div class="empty" id="sys_empty" style="display:none"></div>
</div>

<div class="grid g3">
  <div class="card">
    <h2>Traffic rate <span class="tag" id="rate_tag">last 120s</span></h2>
    <div class="body flush"><svg class="chart" id="c_rate" viewBox="0 0 700 190" preserveAspectRatio="none" height="190"></svg></div>
    <div class="legend"><span><i style="background:#4a9eff"></i>requests/s</span><span><i style="background:#2dd4a7"></i>cache hits/s</span><span><i style="background:#7b6cff"></i>bytes/s</span></div>
  </div>
  <div class="card">
    <h2>Outcome mix</h2>
    <div class="body"><svg class="chart" id="c_donut" viewBox="0 0 220 150" height="150"></svg>
      <div class="bars" id="kind_bars" style="margin-top:6px"></div></div>
  </div>
  <div class="card">
    <h2>Status codes</h2>
    <div class="body"><div class="bars" id="status_bars"></div></div>
  </div>
</div>

<div class="grid g3">
  <div class="card"><h2>Top clients <span class="tag">by requests</span></h2><div class="body"><div class="bars" id="cli_bars"></div></div></div>
  <div class="card"><h2>Top destinations</h2><div class="body"><div class="bars" id="host_bars"></div></div></div>
  <div class="card"><h2>Methods &amp; proxy info</h2><div class="body"><div class="bars" id="meth_bars"></div>
    <dl class="kv" id="mgr" style="margin-top:14px;padding-top:12px;border-top:1px solid var(--line)"></dl></div></div>
</div>
</div><!-- /view_overview (part 1 — live feed sits on its own tab) -->

<div id="view_live" style="display:none">
<div class="card">
  <h2>Live request stream <span class="tag" id="feed_tag">0 rows</span></h2>
  <div class="filters">
    <input type="text" id="f_q" placeholder="filter: host, client, url, user…">
    <select id="f_kind"><option value="">all outcomes</option><option value="hit">hit</option>
      <option value="miss">miss</option><option value="denied">denied</option><option value="error">error</option></select>
    <select id="f_meth"><option value="">all methods</option></select>
    <button id="clear">clear</button>
  </div>
  <div class="scroll" style="max-height:calc(100vh - 260px)"><table><thead><tr>
    <th>time</th><th class="pcol">proxy</th><th>client</th><th>user</th><th>m</th>
    <th>st</th><th>outcome</th><th>action</th><th>bytes</th><th>ms</th>
    <th>host</th><th>url</th>
  </tr></thead><tbody id="feed"></tbody></table></div>
  <div class="empty" id="feed_empty">waiting for traffic…</div>
</div>
</div><!-- /view_live -->

<div id="view_overview2">
<div class="card" id="clients_card">
  <h2>Client history <span class="tag" id="cli_range_tag">last 24h</span>
    <button id="cli_refresh" style="margin-left:10px">refresh</button></h2>
  <div class="filters">
    <div id="cli_ranges" style="display:flex;gap:8px;flex-wrap:wrap">
      <span class="pchip" data-r="1h">1 hour</span>
      <span class="pchip sel" data-r="1d">1 day</span>
      <span class="pchip" data-r="2d">2 days</span>
      <span class="pchip" data-r="7d">7 days</span>
      <span class="pchip" data-r="15d">15 days</span>
      <span class="pchip" data-r="30d">1 month</span>
      <span class="pchip" data-r="90d">3 months</span>
      <span class="pchip" data-r="custom">custom…</span>
    </div>
    <span id="cli_custom_wrap" style="display:none;gap:6px;align-items:center">
      <input type="datetime-local" id="cli_since" style="max-width:190px">
      <span class="dimc">to</span>
      <input type="datetime-local" id="cli_until" style="max-width:190px">
      <button id="cli_apply">apply</button>
    </span>
    <input type="text" id="cli_q" placeholder="filter by client IP…" style="max-width:200px">
    <button id="cli_csv">⤓ CSV</button>
  </div>
  <div id="cli_summary" style="padding:2px 15px 12px;font-size:13px;color:var(--faint)"></div>
  <div class="scroll" style="max-height:380px"><table><thead><tr>
    <th>client</th><th>requests</th><th>bytes</th><th>denied</th><th>errors</th>
    <th>hosts reached</th><th>first seen</th><th>last seen</th>
  </tr></thead><tbody id="cli_t"></tbody></table></div>
  <div class="empty" id="cli_empty" style="display:none"></div>
</div>

<div class="grid g2">
  <div class="card"><h2>Denied / blocked <span class="tag" id="deny_tag">policy violations</span>
    <button id="deny_full" style="margin-left:10px" title="load the full retained history (up to 1000)">⤓ load up to 1000</button></h2>
    <div class="scroll" style="max-height:290px"><table><thead><tr><th>time</th><th>client</th><th>st</th><th>host</th><th>url</th></tr></thead>
    <tbody id="deny_t"></tbody></table></div><div class="empty" id="deny_e">none — clean</div></div>
  <div class="card"><h2>Slowest requests <span class="tag" id="slow_tag">&gt; 2000 ms</span>
    <button id="slow_full" style="margin-left:10px" title="load the full retained history (up to 1000)">⤓ load up to 1000</button></h2>
    <div class="scroll" style="max-height:290px"><table><thead><tr><th>time</th><th>ms</th><th>client</th><th>host</th><th>url</th></tr></thead>
    <tbody id="slow_t"></tbody></table></div><div class="empty" id="slow_e">none — all fast</div></div>
</div>

<div class="card">
  <h2>Alert log <span class="tag" id="alert_tag">0 alerts</span>
    <button id="clear_alerts" style="margin-left:10px">clear</button></h2>
  <div class="scroll" style="max-height:300px"><table><thead><tr>
    <th>time</th><th class="pcol">proxy</th><th>severity</th><th>rule</th>
    <th>detail</th></tr></thead>
    <tbody id="alert_t"></tbody></table></div>
  <div class="empty" id="alert_e">no alerts — all rules within threshold</div>
</div>

<div class="card" id="bl_card">
  <h2>⛔ Squid blocklist <span class="tag" id="bl_tag">locked</span>
    <button id="bl_refresh" style="margin-left:10px">refresh</button></h2>
  <div class="body">
    <div id="bl_lock">
      <div class="dimc" style="font-family:var(--mono);font-size:11.5px;margin-bottom:9px"
        id="bl_hint">Enter the admin token printed in the server console to manage block/allow lists.</div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input type="password" id="bl_token" placeholder="admin token" style="min-width:230px">
        <button id="bl_unlock" class="act">Unlock</button>
        <span class="dimc" id="bl_msg" style="font-family:var(--mono);font-size:11px"></span>
      </div>
    </div>
    <div id="bl_panel" style="display:none">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px">
        <select id="bl_kind">
          <option value="domains">block domain (HTTP + HTTPS)</option>
          <option value="ips">block source IP</option>
          <option value="urls">block URL pattern (HTTP only)</option>
          <option value="allow">allowlist domain</option>
        </select>
        <input type="text" id="bl_entry" placeholder="pastebin.com  ·  .anydesk.com  ·  10.20.30.7"
          style="flex:1;min-width:200px">
        <button id="bl_add" class="act">Add</button>
        <button id="bl_rollback">Undo last change</button>
      </div>
      <div id="bl_status" class="dimc" style="font-family:var(--mono);font-size:10.5px;margin-bottom:9px"></div>
      <div id="bl_out" style="font-family:var(--mono);font-size:11px;margin-bottom:11px"></div>
      <div class="grid" style="gap:11px;grid-template-columns:repeat(auto-fit,minmax(215px,1fr))">
        <div><div class="lblx">blocked domains</div><div class="bllist" id="bl_l_domains"></div></div>
        <div><div class="lblx">blocked source IPs</div><div class="bllist" id="bl_l_ips"></div></div>
        <div><div class="lblx">blocked URL patterns <span class="dimc">(http only)</span></div>
          <div class="bllist" id="bl_l_urls"></div></div>
        <div><div class="lblx">allowlisted domains</div><div class="bllist" id="bl_l_allow"></div></div>
      </div>
    </div>
  </div>
</div>
</div><!-- /view_overview (part 2) -->

<footer>Squid Proxy Monitor · stdlib Python + SSE · reading <span id="foot_log">—</span></footer>

<div class="mask" id="pmask"><div class="modal pmodal">
  <h3>🛡 Per-IP access policy <span class="rtype" id="pol_sub"></span>
    <span class="x" id="pol_close">×</span></h3>
  <div class="mbody" id="pol_body">
    <div id="pol_lock">
      <div class="dimc" style="font-family:var(--mono);font-size:11.5px;margin-bottom:9px"
        id="pol_hint">Enter the admin token from the server console.</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <input type="password" id="pol_token" placeholder="admin token" style="min-width:230px">
        <button id="pol_unlock" class="act">Unlock</button>
        <span class="dimc" id="pol_msg" style="font-family:var(--mono);font-size:11px"></span>
      </div>
    </div>
    <div id="pol_panel" style="display:none">
      <div class="dimc" style="font-family:var(--mono);font-size:10.5px;margin-bottom:11px"
        id="pol_status"></div>
      <div class="dsec"><h4>groups — an IP may belong to exactly one group</h4>
        <div id="pol_groups"></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px">
          <select id="pol_newmode">
            <option value="deny_all">no internet at all</option>
            <option value="restricted">normal minus some destinations</option>
            <option value="allowlist_only">only listed destinations</option>
            <option value="unrestricted">full internet</option>
          </select>
          <input type="text" id="pol_newname" placeholder="group name" style="min-width:170px">
          <button id="pol_addgrp">+ Add group</button>
        </div>
      </div>
      <div class="dgrid">
        <div class="tierbox"><div class="lbl2">security tier — applies to EVERYONE,
          even unrestricted groups</div>
          <div class="pfield"><div class="lbl2">domains</div><div class="chips" id="t_secdom"></div></div>
          <div class="pfield"><div class="lbl2">url patterns</div><div class="chips" id="t_securl"></div></div>
        </div>
        <div class="tierbox"><div class="lbl2">policy tier — unrestricted groups bypass this</div>
          <div class="pfield"><div class="lbl2">domains</div><div class="chips" id="t_poldom"></div></div>
          <div class="pfield"><div class="lbl2">url patterns</div><div class="chips" id="t_polurl"></div></div>
        </div>
      </div>
      <div class="tierbox"><div class="lbl2">never blocked — curated exceptions (wins over every block)</div>
        <div class="chips" id="t_allow"></div></div>
      <div class="tierbox"><div class="lbl2">options</div>
        <div class="chips" style="gap:14px">
          <label class="dimc" style="font-family:var(--mono);font-size:11px">
            <input type="checkbox" id="o_drop"> drop connection (TCP reset) instead of a 403 page</label>
          <label class="dimc" style="font-family:var(--mono);font-size:11px">
            <input type="checkbox" id="o_rawip"> block raw public-IP URLs</label>
          <label class="dimc" style="font-family:var(--mono);font-size:11px">
            <input type="checkbox" id="o_exe"> block executable downloads</label>
        </div></div>
      <div class="pout" id="pol_out"></div>
    </div>
  </div>
  <div class="mfoot"><span class="note" id="pol_note"></span>
    <button id="pol_reload">Reload from proxy</button>
    <button id="pol_undo">Undo last apply</button>
    <button id="pol_check">Validate (dry run)</button>
    <button id="pol_apply" class="act">Apply to proxy</button>
    <button id="pol_fleet" class="act" title="validate on every proxy, then apply node by node">⇉ Push to ALL proxies</button>
  </div>
</div></div>

<div class="mask" id="cmask"><div class="modal dmodal">
  <h3>🧾 squid.conf <span class="rtype" id="cfg_proxy"></span>
    <span class="x" id="cfg_close">×</span></h3>
  <div class="mbody">
    <div class="dimc" style="font-family:var(--mono);font-size:11px;margin-bottom:8px"
      id="cfg_meta">not loaded</div>
    <textarea id="cfg_text" spellcheck="false"
      style="width:100%;box-sizing:border-box;height:46vh;font-family:var(--mono);
             font-size:11.5px;line-height:1.5;background:#0b111d;color:#e6edf7;
             border:1px solid var(--line);border-radius:8px;padding:10px"></textarea>
    <div class="pout" id="cfg_out" style="margin-top:10px"></div>
    <div style="margin-top:10px">
      <div class="evlbl" style="margin-bottom:5px">BACKUPS</div>
      <select id="cfg_baks" style="min-width:260px"></select>
      <button id="cfg_restore">Restore this backup</button>
    </div>
  </div>
  <div class="mfoot"><span class="note" id="cfg_note">validated with `squid -k parse`
    before anything is written; rolled back automatically if Squid objects</span>
    <label style="font-family:var(--mono);font-size:11px;display:flex;gap:5px;align-items:center">
      <input type="checkbox" id="cfg_force"> force (override safety guards)</label>
    <button id="cfg_reload">Reload from proxy</button>
    <button id="cfg_check">Validate</button>
    <button id="cfg_save" class="act">Save &amp; reload Squid</button>
  </div>
</div></div>

<div class="mask" id="dmask"><div class="modal dmodal">
  <h3><span id="d_title">details</span>
    <span class="rtype" id="d_sub"></span><span class="x" id="d_close">×</span></h3>
  <div class="mbody" id="d_body"></div>
  <div class="mfoot"><span class="note" id="d_note"></span>
    <button id="d_filter">Filter live feed to this</button>
    <button id="d_block">⛔ Block on proxy</button></div>
</div></div>

<div class="mask" id="chmask"><div class="modal dmodal">
  <h3>🖧 <span id="ch_ip">client</span>
    <span class="rtype" id="ch_sub"></span><span class="x" id="ch_close">×</span></h3>
  <div class="mbody">
    <div class="filters" style="padding:0 0 10px;border-bottom:1px solid var(--line);margin-bottom:10px">
      <input type="text" id="ch_search_ip" placeholder="search a different IP…" style="min-width:160px">
      <button id="ch_go">Search</button>
      <div id="ch_ranges" style="display:flex;gap:6px;flex-wrap:wrap">
        <span class="pchip" data-r="1h">1h</span>
        <span class="pchip sel" data-r="1d">1d</span>
        <span class="pchip" data-r="2d">2d</span>
        <span class="pchip" data-r="7d">7d</span>
        <span class="pchip" data-r="15d">15d</span>
        <span class="pchip" data-r="30d">1mo</span>
        <span class="pchip" data-r="90d">3mo</span>
        <span class="pchip" data-r="custom">custom…</span>
      </div>
      <span id="ch_custom_wrap" style="display:none;gap:6px;align-items:center">
        <input type="datetime-local" id="ch_since_in" style="max-width:190px">
        <span class="dimc">to</span>
        <input type="datetime-local" id="ch_until_in" style="max-width:190px">
        <button id="ch_apply">apply</button>
      </span>
    </div>
    <div class="filters" style="padding:0 0 10px">
      <input type="text" id="ch_f_status" placeholder="status (e.g. 403 or 4)" style="max-width:150px">
      <input type="text" id="ch_f_host" placeholder="host contains…" style="max-width:200px">
      <select id="ch_f_kind"><option value="">all outcomes</option><option value="hit">hit</option>
        <option value="miss">miss</option><option value="denied">denied</option><option value="error">error</option></select>
      <input type="text" id="ch_f_action" placeholder="action contains…" style="max-width:170px">
      <button id="ch_f_clear">clear filters</button>
    </div>
    <div id="ch_summary" class="dimc" style="font-family:var(--mono);font-size:11.5px;margin-bottom:10px"></div>
    <div class="scroll" style="max-height:50vh"><table><thead><tr>
      <th>time</th><th class="pcol">proxy</th><th>m</th><th>st</th><th>outcome</th>
      <th>action</th><th>bytes</th><th>ms</th><th>host</th><th>url</th>
    </tr></thead><tbody id="ch_t"></tbody></table></div>
    <div class="empty" id="ch_empty" style="display:none"></div>
    <div style="text-align:center;margin-top:8px">
      <button id="ch_more" style="display:none">⤓ load older</button>
    </div>
  </div>
  <div class="mfoot"><span class="note" id="ch_note">note: full per-request detail only goes back as far as
    --db-max-gb keeps raw rows (often 1-3 weeks) — the aggregate counts in the
    Client history table behind this go back the full 3 months regardless</span>
    <button id="ch_csv">⤓ CSV</button></div>
</div></div>

<div class="mask" id="evmask"><div class="modal dmodal">
  <h3>⚠ <span id="ev_title">alert detail</span><span class="x" id="ev_close">×</span></h3>
  <div class="mbody" id="ev_body"></div>
  <div class="mfoot"><span class="note">requests captured at the moment the alert
    fired — click a client or destination to drill in further</span></div>
</div></div>

<div class="mask" id="mask"><div class="modal">
  <h3>⚙ Alert rules <span class="rtype" id="cfg_path"></span><span class="x" id="m_close">×</span></h3>
  <div class="mbody"><div id="rule_list"></div>
    <button id="add_rule">+ Add rule</button></div>
  <div class="mfoot">
    <span class="note" id="save_note">changes are saved to the JSON config on disk</span>
    <button id="test_alert">Send test alert</button>
    <button id="reset_rules">Reset defaults</button>
    <button id="save_rules" class="act">Save rules</button>
  </div>
</div></div>
</div>
<script>
/* ------------------------------------------------------------------ utils */
const $=id=>document.getElementById(id);
const fmtN=n=>n>=1e9?(n/1e9).toFixed(2)+'B':n>=1e6?(n/1e6).toFixed(2)+'M':n>=1e3?(n/1e3).toFixed(1)+'k':String(n);
const fmtB=b=>{const u=['B','KB','MB','GB','TB'];let i=0;b=b||0;while(b>=1024&&i<4){b/=1024;i++}return b.toFixed(i?1:0)+' '+u[i]};
const fmtT=s=>{s=Math.round(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  return d?`${d}d ${h}h`:h?`${h}h ${m}m`:m?`${m}m ${s%60}s`:`${s}s`};
const hhmmss=ts=>new Date(ts*1000).toTimeString().slice(0,8);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sclass=s=>'s'+String(s).charAt(0);

/* ------------------------------------------------------------------ state */
let paused=false, rows=[], methodsSeen=new Set(), lastStats=null;
let deniedFull=null, slowFull=null;   // frozen full history once "load up to 1000" is used
const MAXROWS=1000;
/* multi-proxy: '' = default (first proxy), 'all' = merged view */
let selProxy=sessionStorage.getItem('proxy')||'', proxyList=[], proxyName={};
const isAll=()=>selProxy==='all';
const curProxy=()=>selProxy||(proxyList[0]&&proxyList[0].id)||'';
let cliRange='1d', cliSinceEpoch=null, cliUntilEpoch=null, cliRows=[];
let cliWindow={since:null, until:null};   // the window currently shown in Client history

/* ------------------------------------------------------------------ charts */
function lineChart(el,series){
  const W=700,H=190,P={t:12,r:8,b:16,l:34};
  const n=series.length; if(!n){el.innerHTML='';return}
  const maxR=Math.max(1,...series.map(p=>p.req));
  const maxB=Math.max(1,...series.map(p=>p.bytes));
  const x=i=>P.l+i*(W-P.l-P.r)/Math.max(1,n-1);
  const y=(v,m)=>P.t+(1-v/m)*(H-P.t-P.b);
  const path=(key,m)=>series.map((p,i)=>`${i?'L':'M'}${x(i).toFixed(1)},${y(p[key],m).toFixed(1)}`).join('');
  const area=(key,m)=>`${path(key,m)}L${x(n-1).toFixed(1)},${H-P.b}L${P.l},${H-P.b}Z`;
  let g='';
  for(let i=0;i<=4;i++){const yy=P.t+i*(H-P.t-P.b)/4;
    g+=`<line x1="${P.l}" y1="${yy}" x2="${W-P.r}" y2="${yy}" stroke="#1f2a3a" stroke-width="1"/>`;
    g+=`<text x="${P.l-6}" y="${yy+3}" fill="#4e5f78" font-size="8" font-family="monospace" text-anchor="end">${fmtN(Math.round(maxR*(1-i/4)))}</text>`}
  el.innerHTML=`<defs>
      <linearGradient id="gr" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#4a9eff" stop-opacity=".38"/><stop offset="100%" stop-color="#4a9eff" stop-opacity="0"/></linearGradient>
      <linearGradient id="gh" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#2dd4a7" stop-opacity=".30"/><stop offset="100%" stop-color="#2dd4a7" stop-opacity="0"/></linearGradient>
    </defs>${g}
    <path d="${area('bytes',maxB)}" fill="none" stroke="#7b6cff" stroke-width="1" stroke-dasharray="3 3" opacity=".65"/>
    <path d="${area('req',maxR)}" fill="url(#gr)" stroke="none"/>
    <path d="${area('hits',maxR)}" fill="url(#gh)" stroke="none"/>
    <path d="${path('hits',maxR)}" fill="none" stroke="#2dd4a7" stroke-width="1.6"/>
    <path d="${path('req',maxR)}" fill="none" stroke="#4a9eff" stroke-width="1.9"/>`;
}
function donut(el,kinds){
  const order=[['hit','#2dd4a7'],['miss','#4a9eff'],['denied','#ff4d6d'],['error','#ffa726']];
  const tot=order.reduce((a,[k])=>a+(kinds[k]||0),0);
  const cx=75,cy=75,r=52,sw=17;
  if(!tot){el.innerHTML=`<text x="75" y="79" fill="#4e5f78" font-size="10" font-family="monospace" text-anchor="middle">no data</text>`;return}
  let ang=-Math.PI/2,seg='';
  order.forEach(([k,c])=>{const v=kinds[k]||0;if(!v)return;
    const a2=ang+v/tot*Math.PI*2, large=(a2-ang)>Math.PI?1:0;
    const p=(a,rr)=>[cx+rr*Math.cos(a),cy+rr*Math.sin(a)];
    const[x1,y1]=p(ang,r),[x2,y2]=p(a2,r);
    seg+=`<path d="M${x1},${y1} A${r},${r} 0 ${large} 1 ${x2},${y2}" fill="none" stroke="${c}" stroke-width="${sw}" stroke-linecap="butt"/>`;
    ang=a2});
  const hp=Math.round((kinds.hit||0)/Math.max(1,(kinds.hit||0)+(kinds.miss||0))*100);
  el.innerHTML=seg+
    `<text x="${cx}" y="${cy-2}" fill="#dbe4f0" font-size="21" font-weight="700" font-family="monospace" text-anchor="middle">${hp}%</text>
     <text x="${cx}" y="${cy+13}" fill="#4e5f78" font-size="8" font-family="monospace" text-anchor="middle" letter-spacing="1">HIT RATE</text>`;
}
function bars(el,items,opt={}){
  if(!items||!items.length){el.innerHTML='<div class="empty">no data</div>';return}
  const max=Math.max(...items.map(i=>i.n));
  const dk=opt.drill;                       // 'client' | 'host' -> clickable
  el.innerHTML=items.map(i=>{
    const w=(i.n/max*100).toFixed(1);
    const warnCls=opt.warn&&opt.warn(i)?' warn':'';
    const right=opt.right?opt.right(i):fmtN(i.n);
    const ck=dk?` clik" data-dk="${dk}" data-dv="${esc(i.key)}` : '';
    const tip=dk?' title="click for details"':` title="${esc(i.key)}"`;
    return `<div class="bar${warnCls}${ck}"${tip}><div class="top">
      <span class="nm">${esc(i.key)}</span>
      <span class="ct">${right}</span></div><div class="track"><div class="fill" style="width:${w}%"></div></div></div>`}).join('');
  if(dk) el.querySelectorAll('.bar.clik').forEach(b=>
    b.onclick=()=>openDetail(b.dataset.dk,b.dataset.dv));
}

/* ------------------------------------------------------------- system health */
function gaugeColor(pct){
  if(pct==null)return '#3a4658';
  return pct>=90?'#ff4d6d':pct>=75?'#ffa726':'#2dd4a7';
}
function gaugeSVG(pct,label){
  const r=26,sw=6,cx=32,cy=32,C=2*Math.PI*r;
  const has=pct!=null&&!isNaN(pct);
  const frac=has?Math.max(0,Math.min(100,pct))/100:0;
  const col=gaugeColor(has?pct:null);
  const txt=has?Math.round(pct)+'%':'—';
  return `<div class="gauge"><svg width="64" height="64" viewBox="0 0 64 64">
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#1f2a3a" stroke-width="${sw}"/>
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${col}" stroke-width="${sw}"
      stroke-linecap="round" stroke-dasharray="${(C*frac).toFixed(1)} ${C.toFixed(1)}"
      transform="rotate(-90 ${cx} ${cy})"/>
    <text x="${cx}" y="${cy+4}" text-anchor="middle" class="gv">${txt}</text>
  </svg><div class="gl">${esc(label)}</div></div>`;
}
function fmtBps(n){ return n==null?'—':fmtB(n)+'/s' }
function fmtUptime(s){ return s==null?'—':fmtT(s) }
function sysHostCard(h){
  const nm=h.name||h.id;
  if(h.available===false){
    return `<div class="syshost"><div class="hname"><i class="dot off"></i>${esc(nm)}</div>
      <div class="dimc" style="font-size:11px">no SSH system probe for this source
      (demo/UDP/TCP feeds have no host to poll)</div></div>`;
  }
  if(!h.ok){
    return `<div class="syshost err"><div class="hname"><i class="dot off"></i>${esc(nm)}</div>
      <div class="errmsg">${esc(h.error||'probe failed')}</div></div>`;
  }
  const mem=h.mem||{}, disk=h.disk||{};
  const load=(h.load||[]).map(x=>x.toFixed(2)).join(' / ')||'—';
  const age=h.ts?Math.max(0,Math.round(Date.now()/1000-h.ts)):null;
  return `<div class="syshost"><div class="hname"><i class="dot on"></i>${esc(nm)}
      <span class="dimc" style="font-weight:400;margin-left:auto;font-size:10px">${h.kind==='ssh'?'via SSH':'this host'}</span></div>
    <div class="gauges">
      ${gaugeSVG(h.cpu_pct,'CPU')}
      ${gaugeSVG(mem.pct,'Memory')}
      ${gaugeSVG(disk.pct,'Disk')}
    </div>
    <div class="sysmeta">
      <div><span class="k">mem</span> ${fmtB(mem.used)} / ${fmtB(mem.total)}</div>
      <div><span class="k">disk</span> ${fmtB(disk.used)} / ${fmtB(disk.total)}</div>
      <div><span class="k">load</span> ${load}</div>
      <div><span class="k">uptime</span> ${fmtUptime(h.uptime)}</div>
      <div><span class="k">net ↓/↑</span> ${fmtBps(h.net_rx_bps)} / ${fmtBps(h.net_tx_bps)}</div>
      <div><span class="k">checked</span> ${age==null?'—':age+'s ago'} (${h.latency_ms??'—'}ms)</div>
    </div></div>`;
}
async function loadSysInfo(){
  try{
    const d=await (await fetch('/api/sysinfo')).json();
    if(!d.enabled){
      $('sys_body').innerHTML='';
      $('sys_empty').style.display='block';
      $('sys_empty').textContent='system health is disabled (started with --no-sysinfo)';
      return;
    }
    $('sys_empty').style.display='none';
    const cards=[sysHostCard(d.host)]
      .concat((d.proxies||[]).map(sysHostCard));
    $('sys_body').innerHTML=cards.join('');
  }catch(e){
    $('sys_empty').style.display='block';
    $('sys_empty').textContent='could not load system health';
  }
}
$('sys_refresh').onclick=loadSysInfo;
setInterval(loadSysInfo, 20000);
loadSysInfo();

/* --------------------------------------------------- denied/slow full history */
/* Live ticks only carry the newest ~40 rows (MINI_LIVE_N) to keep the SSE
   push cheap. "load up to 1000" fetches the full server-retained history on
   demand and freezes the panel on it until toggled back to live. */
async function loadMiniFull(kind){
  const p=isAll()?'all':curProxy();
  try{
    const d=await (await fetch(`/api/mini?kind=${kind}&proxy=${encodeURIComponent(p)}`)).json();
    return d.rows||[];
  }catch(e){ return null; }
}
function wireMiniFull(btnId,tagId,getFull,setFull,liveLabel){
  $(btnId).onclick=async()=>{
    if(getFull()){
      setFull(null);
      $(btnId).textContent='⤓ load up to 1000';
      $(tagId).textContent=liveLabel;
      if(lastStats) renderStats(lastStats);
      return;
    }
    $(btnId).textContent='loading…';
    const rows=await loadMiniFull(btnId==='deny_full'?'denied':'slow');
    if(rows===null){ $(btnId).textContent='⤓ load up to 1000'; return; }
    setFull(rows);
    $(btnId).textContent='↺ back to live';
    $(tagId).textContent=`showing ${fmtN(rows.length)} of up to 1000 retained`;
    if(lastStats) renderStats(lastStats);
  };
}
wireMiniFull('deny_full','deny_tag',()=>deniedFull,v=>deniedFull=v,'policy violations');
wireMiniFull('slow_full','slow_tag',()=>slowFull,v=>slowFull=v,'> 2000 ms');

/* ------------------------------------------------------------------ render */
function renderStats(s){
  lastStats=s;
  const t=s.totals;
  $('k_req').textContent=fmtN(t.requests);
  $('k_rps').textContent=t.rps.toFixed(1);
  $('k_hit').textContent=t.hit_ratio+'%';
  $('k_bw').textContent=fmtB(t.bytes);
  $('k_bw_s').textContent=fmtB(t.bps)+'/s now';
  $('k_lat').textContent=fmtN(t.avg_latency);
  $('k_den').textContent=fmtN(s.kinds.denied||0);
  $('k_cli').textContent=t.clients;
  $('k_cli_s').textContent=t.hosts+' unique hosts';
  $('k_up').textContent=fmtT(s.meta.uptime);
  $('k_up_s').textContent=s.meta.parse_errors?(s.meta.parse_errors+' unparsed lines'):'monitoring';
  $('k_hit_s').textContent=(s.kinds.hit||0)+' hits / '+(s.kinds.miss||0)+' miss';
  $('clock').textContent=s.meta.server_time;

  // data-source state: which proxy link we're pulling from, and whether it's up
  const src=s.meta.source||{kind:'?',target:'—',connected:false};
  const ICON={ssh:'🔗',udp:'📡',tcp:'🔌',file:'📄',demo:'🧪'}[src.kind]||'•';
  $('logpill').innerHTML=`<i class="dot ${src.connected?'on':'off'}"></i>`+
    esc(ICON+' '+src.target)+(src.reconnects?` <span class="dimc">· ${src.reconnects} reconnect${src.reconnects>1?'s':''}</span>`:'');
  $('logpill').title=src.connected?'source connected':(src.error||'source down');
  $('foot_log').textContent=src.target+' ('+src.kind+')';
  $('csv_link').href='/api/export?proxy='+encodeURIComponent(isAll()?'all':curProxy());
  if(!src.connected){
    $('banner').style.display='block';
    $('banner').innerHTML='⚠ <b>'+esc(src.kind)+' source down</b> — '+esc(src.error||'not connected yet')+
      (src.hint?'<br><span class="dimc">'+esc(src.hint)+'</span>':'');
  } else $('banner').style.display='none';

  lineChart($('c_rate'),s.series);
  donut($('c_donut'),s.kinds);
  bars($('kind_bars'),['hit','miss','denied','error'].map(k=>({key:k,n:s.kinds[k]||0})),
       {warn:i=>i.key==='denied'||i.key==='error'});
  bars($('status_bars'),Object.entries(s.status).map(([k,v])=>({key:k,n:v})),
       {warn:i=>+i.key>=400});
  bars($('cli_bars'),s.top_clients,{right:i=>fmtN(i.n)+' · '+fmtB(i.bytes),drill:'client'});
  bars($('host_bars'),s.top_hosts,{right:i=>fmtN(i.n)+' · '+fmtB(i.bytes),drill:'host',
       warn:i=>/malware|torrent|c2|phish/i.test(i.key)});
  bars($('meth_bars'),Object.entries(s.methods).map(([k,v])=>({key:k,n:v})));

  Object.keys(s.methods).forEach(m=>{if(!methodsSeen.has(m)){methodsSeen.add(m);
    const o=document.createElement('option');o.value=o.textContent=m;$('f_meth').appendChild(o)}});

  const mgr=s.cache_mgr||{}, kv=[];
  if(mgr.available){
    const map={http_requests:'HTTP requests',clients_accessing:'Clients',hit_ratios:'Hit ratio',
      byte_hit_ratios:'Byte hit ratio',swap_size:'Swap size',mem_size:'Mem size',
      cpu_usage:'CPU usage',fds_in_use:'FDs in use',mean_object_size:'Mean obj size',start_time:'Squid start'};
    for(const k in map) if(mgr[k]) kv.push([map[k],mgr[k]]);
    if(mgr.via) kv.push(['polled via',mgr.via]);
  } else { kv.push(['cache mgr',mgr.note||mgr.error||'unavailable']); }
  kv.push(['source',src.kind+(src.connected?' · up':' · down')]);
  kv.push(['unique clients',s.totals.clients]);
  kv.push(['SSE feed',paused?'paused':'live']);
  $('mgr').innerHTML=kv.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');


  if(s.recent && s.recent.length && !rows.length){ rows=s.recent.slice(); drawFeed(); }

  // seed alert history + rule types on first snapshot (survives page reload)
  const al=s.alerts||{};
  if(al.types&&!Object.keys(ruleTypes).length) ruleTypes=al.types;
  if(al.history&&!alertHist.length&&al.history.length){
    al.history.slice().reverse().forEach(a=>onAlert(a,false));
  }
  drawMini('deny_t','deny_e',deniedFull||s.denied,r=>
    `<td class="dimc">${hhmmss(r.ts)}</td><td>${esc(r.client)}</td><td class="${sclass(r.status)}">${r.status}</td>
     <td>${esc(r.host)}</td><td class="dimc" title="${esc(r.url)}">${esc(r.url)}</td>`);
  drawMini('slow_t','slow_e',slowFull||s.slow,r=>
    `<td class="dimc">${hhmmss(r.ts)}</td><td class="slowc">${fmtN(r.elapsed)}</td><td>${esc(r.client)}</td>
     <td>${esc(r.host)}</td><td class="dimc" title="${esc(r.url)}">${esc(r.url)}</td>`);
}
function drawMini(tb,em,list,fn){
  list=list||[]; $(tb).innerHTML=list.map(r=>`<tr>${fn(r)}</tr>`).join('');
  $(em).style.display=list.length?'none':'block';
}

/* ------------------------------------------------------------------ feed */
function pass(r){
  const q=$('f_q').value.trim().toLowerCase(), k=$('f_kind').value, m=$('f_meth').value;
  if(k&&r.kind!==k)return false;
  if(m&&r.method!==m)return false;
  if(q&&!((r.host+' '+r.client+' '+r.url+' '+r.user+' '+r.action).toLowerCase().includes(q)))return false;
  return true;
}
function rowHtml(r,fresh){
  const pc=isAll()?`<td class="pcol"><span class="ptag">${esc(proxyName[r.p]||r.p||'-')}</span></td>`
                  :'<td class="pcol" style="display:none"></td>';
  return `<tr class="${fresh?'fresh':''}">
    <td class="dimc">${hhmmss(r.ts)}</td>${pc}
    <td class="clik" data-dk="client" data-dv="${esc(r.client)}">${esc(r.client)}</td>
    <td class="dimc">${esc(r.user)}</td>
    <td>${esc(r.method)}</td><td class="${sclass(r.status)}">${r.status}</td>
    <td><span class="k ${r.kind}">${r.kind}</span></td><td class="dimc">${esc(r.action)}</td>
    <td>${fmtB(r.size)}</td><td class="${r.elapsed>=2000?'slowc':'dimc'}">${r.elapsed||'-'}</td>
    <td class="clik" data-dk="host" data-dv="${esc(r.host)}">${esc(r.host)}</td>
    <td class="dimc" title="${esc(r.url)}">${esc(r.url)}</td></tr>`;
}
function drawFeed(){
  const vis=rows.filter(pass);
  $('feed').innerHTML=vis.slice(0,MAXROWS).map(r=>rowHtml(r,false)).join('');
  $('feed_tag').textContent=vis.length+' rows'+(rows.length!==vis.length?' / '+rows.length:'');
  $('feed_empty').style.display=vis.length?'none':'block';
  $('tab_feed_n').textContent=vis.length?fmtN(vis.length):'';
}
function pushRow(r){
  rows.unshift(r); if(rows.length>MAXROWS+120) rows.length=MAXROWS+120;
  if(paused||!pass(r)) return;
  const tb=$('feed'); tb.insertAdjacentHTML('afterbegin',rowHtml(r,true));
  while(tb.rows.length>MAXROWS) tb.deleteRow(tb.rows.length-1);
  $('feed_empty').style.display='none';
  $('feed_tag').textContent=tb.rows.length+' rows';
  $('tab_feed_n').textContent=fmtN(tb.rows.length);
}

/* ------------------------------------------------------------------ alerts */
let alertHist=[], unseen=0, notifOn=false, soundOn=false, ruleTypes={}, ruleDraft=[], seenSeq=new Set();
const SEV_ICON={critical:'🚨',warning:'⚠️',info:'ℹ️'};

function beep(sev){
  if(!soundOn)return;
  try{
    const C=window.AudioContext||window.webkitAudioContext; if(!C)return;
    const ctx=new C(), t=ctx.currentTime;
    const tones=sev==='critical'?[880,1180,880]:sev==='warning'?[720,900]:[540];
    tones.forEach((f,i)=>{const o=ctx.createOscillator(),g=ctx.createGain();
      o.type='sine';o.frequency.value=f;o.connect(g);g.connect(ctx.destination);
      const s=t+i*0.16;g.gain.setValueAtTime(0.0001,s);
      g.gain.exponentialRampToValueAtTime(0.16,s+0.02);
      g.gain.exponentialRampToValueAtTime(0.0001,s+0.15);
      o.start(s);o.stop(s+0.16)});
    setTimeout(()=>ctx.close(),900);
  }catch(e){}
}
function notify(a){
  if(!notifOn||!('Notification' in window)||Notification.permission!=='granted')return;
  try{const n=new Notification(`${SEV_ICON[a.severity]||''} ${a.rule}`,
      {body:a.msg,tag:a.rule_id+'-'+Math.floor(a.ts/10),silent:true});
    n.onclick=()=>{window.focus();n.close()};
    if(a.severity!=='critical')setTimeout(()=>n.close(),9000);
  }catch(e){}
}
function toast(a){
  const el=document.createElement('div');
  el.className='toast '+a.severity;
  const plab=(a.p&&proxyList.length>1)?`<span class="ptag">${esc(proxyName[a.p]||a.p)}</span> `:'';
  el.innerHTML=`<div class="th"><span class="sev">${esc(a.severity)}</span>
      <span class="rn">${plab}${esc(a.rule)}</span><span class="x">×</span></div>
    <div class="tm">${esc(a.msg)}</div>
    <div class="tt">${hhmmss(a.ts)}</div>`;
  const kill=()=>{el.classList.add('out');setTimeout(()=>el.remove(),260)};
  el.querySelector('.x').onclick=kill;
  $('toasts').appendChild(el);
  while($('toasts').children.length>5) $('toasts').firstChild.remove();
  if(a.severity!=='critical') setTimeout(kill,a.severity==='warning'?11000:7000);
}
function onAlert(a,live){
  if(a.seq&&seenSeq.has(a.seq))return; if(a.seq)seenSeq.add(a.seq);
  if(a.p&&proxyList.length>1&&!a._lbl){a.rule=a.rule; a._lbl=1;}
  alertHist.unshift(a); if(alertHist.length>250)alertHist.length=250;
  drawAlerts();
  if(live){toast(a);notify(a);beep(a.severity);
    unseen++;$('badge').textContent=unseen>99?'99+':unseen;$('badge').classList.add('on');
    if(a.severity==='critical'){document.title='🚨 '+a.rule+' · Squid Monitor';
      setTimeout(()=>document.title='Squid Proxy · Live Monitor',12000)}}
}
function drawAlerts(){
  $('alert_tag').textContent=alertHist.length+(alertHist.length===1?' alert':' alerts');
  $('alert_e').style.display=alertHist.length?'none':'block';
  $('alert_t').innerHTML=alertHist.slice(0,120).map(a=>{
    const d=a.detail||{};
    const extra=Object.keys(d).length?Object.entries(d).slice(0,4)
      .map(([k,v])=>`${k}=${typeof v==='number'&&k==='bytes'?fmtB(v):v}`).join('  '):'';
    const h=d.host&&d.host!=='-'?d.host:'';
    const pc=isAll()?`<td class="pcol"><span class="ptag">${esc(proxyName[a.p]||a.p||'-')}</span></td>`
                    :'<td class="pcol" style="display:none"></td>';
    const clickable=a.seq?' arow':'';
    const cue=a.has_evidence?'<span class="evcue" title="click to see the requests behind this alert">▸ requests</span>':'';
    return `<tr class="${clickable}" data-seq="${esc(a.seq||'')}"><td class="dimc">${hhmmss(a.ts)}</td>${pc}
      <td><span class="sev-dot ${esc(a.severity)}"></span>${esc(a.severity)}</td>
      <td>${esc(a.rule)}</td>
      <td class="dimc" title="${esc(a.msg)}">${esc(a.msg)}${extra?'  ·  '+esc(extra):''} ${cue}
      ${h?` <button class="blockbtn" data-host="${esc(h)}" title="block this domain on the proxy">⛔ block</button>`:''}</td></tr>`}).join('');
}

/* ------------------------------------------- what caused an alert */
async function openAlert(seq){
  const m=$('evmask'); m.classList.add('on');
  $('ev_title').textContent='alert detail';
  $('ev_body').innerHTML='<div class="dim">loading…</div>';
  let r;
  try{ r=await (await fetch('/api/alert?seq='+encodeURIComponent(seq))).json(); }
  catch(e){ $('ev_body').innerHTML='<div class="dim">could not load: '+esc(e.message)+'</div>'; return; }
  if(r.error){ $('ev_body').innerHTML='<div class="dim">'+esc(r.error)+'</div>'; return; }
  const a=r.alert||{}, ev=r.evidence, d=a.detail||{};
  $('ev_title').textContent=a.rule||'alert';
  let h=`<div class="evhead">
     <div><b>${esc(a.msg||'')}</b></div>
     <div class="dim">${hhmmss(a.ts)} · ${esc(r.proxy_name||'')} · severity ${esc(a.severity||'')}</div>`;
  if(Object.keys(d).length)
    h+=`<div class="dim">${Object.entries(d).map(([k,v])=>esc(k)+'='+esc(String(v))).join(' · ')}</div>`;
  h+='</div>';
  if(!ev||!ev.requests||!ev.requests.length){
    h+=`<div class="dim" style="padding:10px 0">No individual requests were captured for
        this alert. Blacklist matches show the offending request above; alerts that fired
        before this build has been running have no captured evidence.</div>`;
    $('ev_body').innerHTML=h; return;
  }
  const chips=(arr,fmt)=>arr.map(([k,v])=>`<span class="evchip">${esc(String(k))}<b>${fmt?fmt(v):v}</b></span>`).join('');
  h+=`<div class="evsum">
      <div class="evrow"><span class="evlbl">matched</span>${ev.matched} request(s) in ${ev.window}s`
      +(ev.truncated?` <span class="dim">— showing the ${ev.shown} most recent</span>`:'')+`</div>
      <div class="evrow"><span class="evlbl">destinations</span>${chips(ev.top_hosts)}</div>
      <div class="evrow"><span class="evlbl">clients</span>${chips(ev.top_clients)}</div>
      <div class="evrow"><span class="evlbl">status</span>${chips(ev.status_mix)}</div>
    </div>
    <table class="evtab"><thead><tr><th>time</th><th>client</th><th>destination</th>
      <th>status</th><th>bytes</th><th>ms</th><th>URL</th></tr></thead><tbody>`;
  h+=ev.requests.map(q=>`<tr>
      <td class="dimc">${hhmmss(q.ts)}</td>
      <td><a href="#" class="evlink" data-kind="client" data-key="${esc(q.client)}">${esc(q.client)}</a></td>
      <td><a href="#" class="evlink" data-kind="host" data-key="${esc(q.host||'')}">${esc(q.host||'—')}</a></td>
      <td>${esc(String(q.status))} <span class="dim">${esc(q.action||'')}</span></td>
      <td class="dimc">${fmtB(q.size)}</td>
      <td class="dimc">${q.elapsed}</td>
      <td class="evurl" title="${esc(q.url||'')}">${esc(q.url||'')}</td></tr>`).join('');
  h+='</tbody></table>';
  $('ev_body').innerHTML=h;
  $('ev_body').querySelectorAll('.evlink').forEach(el=>el.onclick=e=>{
    e.preventDefault(); $('evmask').classList.remove('on');
    openDetail(el.dataset.kind, el.dataset.key);
  });
}

/* ---------------------------------------------------------- rule editor */
const FLD_LABEL={window:'window (s)',threshold:'threshold',threshold_mb:'threshold (MB)',
  threshold_pct:'below (%)',min_requests:'min requests',latency_ms:'slower than (ms)',
  code:'status code',pattern:'regex pattern'};

function ruleRow(r,i){
  const spec=ruleTypes[r.type]||{fields:[],label:r.type};
  const flds=(spec.fields||[]).map(f=>{
    const wide=f==='pattern';
    if(f==='match'){
      const cur=r.match||'host';
      const opts=[['host','hostname only (safest)'],['url','full URL only'],
                  ['both','hostname + URL']].map(([v,l])=>
        `<option value="${v}" ${v===cur?'selected':''}>${l}</option>`).join('');
      return `<div class="fld"><label>match against</label>
        <select data-i="${i}" data-f="match">${opts}</select></div>`;
    }
    return `<div class="fld" ${wide?'style="grid-column:1/-1"':''}>
      <label>${FLD_LABEL[f]||f}</label>
      <input type="text" data-i="${i}" data-f="${f}" value="${esc(r[f]!==undefined?r[f]:'')}"
        placeholder="${wide?'malware|torrent|\\.onion':''}"></div>`}).join('');
  const opts=Object.entries(ruleTypes).map(([k,v])=>
    `<option value="${k}" ${k===r.type?'selected':''}>${esc(v.label||k)}</option>`).join('');
  const sevs=['info','warning','critical'].map(s=>
    `<option value="${s}" ${s===r.severity?'selected':''}>${s}</option>`).join('');
  return `<div class="rule ${r.enabled?'':'off'}">
    <div class="rhead">
      <label class="sw"><input type="checkbox" data-i="${i}" data-f="enabled" ${r.enabled?'checked':''}><span class="tr"></span></label>
      <input type="text" class="rname" data-i="${i}" data-f="name" value="${esc(r.name)}">
      <button class="del" data-del="${i}">remove</button>
    </div>
    <div class="rgrid">
      <div class="fld" style="grid-column:span 2"><label>condition</label>
        <select data-i="${i}" data-f="type">${opts}</select></div>
      <div class="fld"><label>severity</label><select data-i="${i}" data-f="severity">${sevs}</select></div>
      <div class="fld"><label>cooldown (s)</label>
        <input type="text" data-i="${i}" data-f="cooldown" value="${esc(r.cooldown)}"></div>
      ${flds}
    </div></div>`;
}
function drawRules(){
  $('rule_list').innerHTML=ruleDraft.map(ruleRow).join('')||'<div class="empty">no rules — add one</div>';
  $('rule_list').querySelectorAll('[data-f]').forEach(el=>{
    const h=()=>{const i=+el.dataset.i,f=el.dataset.f;
      ruleDraft[i][f]=el.type==='checkbox'?el.checked:el.value;
      if(f==='type'||f==='enabled')drawRules()};
    el.addEventListener(el.tagName==='SELECT'||el.type==='checkbox'?'change':'input',h)});
  $('rule_list').querySelectorAll('[data-del]').forEach(b=>
    b.onclick=()=>{ruleDraft.splice(+b.dataset.del,1);drawRules()});
}
async function openRules(){
  try{const r=await fetch('/api/alerts'),d=await r.json();
    ruleTypes=d.types||{};ruleDraft=(d.rules||[]).map(x=>({...x}));
    drawRules();$('mask').classList.add('on');
  }catch(e){$('save_note').textContent='could not load rules: '+e}
}
async function saveRules(){
  $('save_note').textContent='saving…';
  try{
    const r=await fetch('/api/alerts',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({rules:ruleDraft})});
    const d=await r.json();
    if(d.error){$('save_note').textContent='error: '+d.error;return}
    ruleDraft=d.rules.map(x=>({...x}));drawRules();
    $('cfg_path').textContent=d.config||'';
    $('save_note').textContent=`saved ${d.saved} rule(s) to disk`;
    setTimeout(()=>$('mask').classList.remove('on'),650);
  }catch(e){$('save_note').textContent='save failed: '+e}
}

/* -------------------------------------------------------------- blocklist */
let blToken=sessionStorage.getItem('bl_token')||'', blUnlocked=false;

function blHeaders(){return{'Content-Type':'application/json','X-Admin-Token':blToken}}
function blSay(el,msg,ok){const e=$(el);e.innerHTML=msg;e.className=ok===undefined?'dimc':(ok?'blok':'blerr')}

async function blLoad(){
  if(!blToken)return;
  try{
    const r=await fetch('/api/blocklist?proxy='+encodeURIComponent(isAll()?'':curProxy()),
      {headers:blHeaders()});
    const d=await r.json();
    if(d.enabled===false){
      $('bl_tag').textContent='disabled';
      blSay('bl_hint','Blocklist admin is off. Restart the dashboard with '+
        '<b>--enable-blocklist</b> to turn it on.');
      $('bl_unlock').style.display='none';$('bl_token').style.display='none';return;
    }
    if(d.error){blUnlocked=false;$('bl_tag').textContent='locked';
      blSay('bl_msg',d.error,false);return}
    blUnlocked=true;sessionStorage.setItem('bl_token',blToken);
    $('bl_lock').style.display='none';$('bl_panel').style.display='block';
    $('bl_tag').textContent='unlocked · '+esc(d.target||'')+
      (proxyList.length>1?'  ['+esc(proxyName[d.proxy]||d.proxy||'')+']':'');
    const st=d.status||{};
    $('bl_status').textContent=`proxy squid running: ${st.squid_running||'?'} · `+
      `domains ${st.domains||0} · ips ${st.ips||0} · allow ${st.allow||0} · `+
      `backups ${st.backups||0} · protected ${st.protected||0}`;
    ['domains','ips','urls','allow'].forEach(k=>blRender(k,(d.lists||{})[k]||[],(d.errors||{})[k]));
  }catch(e){blSay('bl_msg','load failed: '+e,false)}
}
function blRender(kind,rows,err){
  const el=$('bl_l_'+kind);
  if(err){el.innerHTML=`<div class="blempty blerr">${esc(err)}</div>`;return}
  if(!rows.length){el.innerHTML='<div class="blempty">empty</div>';return}
  el.innerHTML=rows.map(v=>{
    const ph=(v==='blocked.invalid'||v==='192.0.2.1'||v==='^https?://blocked\\.invalid/');
    return `<div class="blrow${ph?' ph':''}"><span title="${esc(v)}">${esc(v)}</span>`+
      (ph?'<span class="dimc" style="flex:0">placeholder</span>':
          `<button class="del" data-k="${kind}" data-v="${esc(v)}">remove</button>`)+
      `</div>`}).join('');
  el.querySelectorAll('button[data-v]').forEach(b=>b.onclick=()=>
    blMutate('remove',b.dataset.k,b.dataset.v));
}
async function blMutate(action,kind,entry){
  const on=proxyList.length>1?` on ${proxyName[curProxy()]||curProxy()}`:'';
  if(action==='add'&&!confirm(`Add "${entry}" to ${kind}${on}?`))return;
  if(action==='remove'&&!confirm(`Remove "${entry}" from ${kind}${on}?`))return;
  if(action==='rollback'&&!confirm(`Undo the last change to ${kind}${on}?`))return;
  blSay('bl_out','working…');
  try{
    const r=await fetch('/api/blocklist/'+(action==='add'?'add':action==='remove'?'remove':'rollback'),
      {method:'POST',headers:blHeaders(),
       body:JSON.stringify({kind,entry,proxy:isAll()?'':curProxy()})});
    const d=await r.json();
    if(d.ok){blSay('bl_out','✓ '+esc(d.message||'done'),true);$('bl_entry').value=''}
    else blSay('bl_out','✗ '+esc(d.reason||d.error||'failed')+
      (d.message?' — '+esc(d.message):''),false);
    blLoad();
  }catch(e){blSay('bl_out','✗ '+e,false)}
}
// one-click block straight from an alert or a top-host row
function blQuickBlock(host){
  if(!blUnlocked){alert('Unlock the blocklist panel first (admin token).');
    $('bl_card').scrollIntoView({behavior:'smooth',block:'center'});return}
  if(!confirm(`Block "${host}" on the proxy now?`))return;
  blMutate('add','domains',host);
}

/* ---------------------------------------------------------- access policy */
let polToken=sessionStorage.getItem('bl_token')||'', pol=null, polOpen=false;
const MODE_LABEL={deny_all:'no internet',restricted:'normal minus',
  allowlist_only:'only listed',unrestricted:'full internet'};

function polHeaders(){return{'Content-Type':'application/json','X-Admin-Token':polToken}}
function polSay(msg,cls){const e=$('pol_note');e.innerHTML=msg;e.className='note '+(cls||'')}

/* editable chip list bound to an array */
function chips(el,arr,ph,onchange,locked){
  const box=$(el); if(!box)return;
  box.innerHTML=(arr||[]).map((v,i)=>
    `<span class="chip"><span>${esc(v)}</span><b data-i="${i}" title="remove">×</b></span>`).join('')
    +(locked?'':`<input type="text" placeholder="${esc(ph||'add…')}">`);
  box.querySelectorAll('b[data-i]').forEach(b=>b.onclick=()=>{
    arr.splice(+b.dataset.i,1); onchange&&onchange(); });
  const inp=box.querySelector('input');
  if(inp) inp.onkeydown=e=>{
    if(e.key!=='Enter')return;
    const v=inp.value.trim(); if(!v)return;
    if(!arr.includes(v))arr.push(v);
    inp.value=''; onchange&&onchange();
  };
}

function drawPolicy(){
  if(!pol)return;
  const gs=pol.groups||[];
  $('pol_groups').innerHTML=gs.map((g,i)=>`
    <div class="pgrp ${g.enabled===false?'off':''}" data-gi="${i}">
      <div class="ph">
        <label class="sw"><input type="checkbox" data-gi="${i}" class="g_en"
          ${g.enabled===false?'':'checked'}><span class="tr"></span></label>
        <span class="mode ${esc(g.mode)}">${esc(MODE_LABEL[g.mode]||g.mode)}</span>
        <input type="text" class="gn" data-gi="${i}" value="${esc(g.name||g.id)}">
        <span class="rtype">${esc(g.id)}</span>
        <button class="del g_del" data-gi="${i}">remove</button>
      </div>
      <div class="pfield"><div class="lbl2">client IPs / CIDRs</div>
        <div class="chips" id="g${i}_ips"></div></div>
      ${(g.mode==='restricted')?`
        <div class="pfield"><div class="lbl2">blocked domains for this group</div>
          <div class="chips" id="g${i}_dd"></div></div>
        <div class="pfield"><div class="lbl2">blocked url patterns (http only)</div>
          <div class="chips" id="g${i}_du"></div></div>`:''}
      ${(g.mode==='allowlist_only')?`
        <div class="pfield"><div class="lbl2">permitted domains — everything else denied
          <span class="dimc">(payment rails &amp; Windows Update are added automatically)</span></div>
          <div class="chips" id="g${i}_ad"></div></div>`:''}
      ${(g.mode==='deny_all')?`<div class="dimc" style="font-family:var(--mono);font-size:10.5px">
          these clients get no internet at all</div>`:''}
      ${(g.mode==='unrestricted')?`<div class="dimc" style="font-family:var(--mono);font-size:10.5px">
          full internet, but the security tier below still applies</div>`:''}
    </div>`).join('')||'<div class="empty">no groups yet</div>';

  gs.forEach((g,i)=>{
    g.ips=g.ips||[]; g.deny_domains=g.deny_domains||[]; g.deny_urls=g.deny_urls||[];
    g.allow_domains=g.allow_domains||[];
    chips(`g${i}_ips`,g.ips,'10.60.11.58 or 10.60.11.0/24',drawPolicy);
    if(g.mode==='restricted'){
      chips(`g${i}_dd`,g.deny_domains,'facebook.com',drawPolicy);
      chips(`g${i}_du`,g.deny_urls,'\\.exe(\\?|$)',drawPolicy);
    }
    if(g.mode==='allowlist_only') chips(`g${i}_ad`,g.allow_domains,'cb.example.gov',drawPolicy);
  });
  $('pol_groups').querySelectorAll('.g_en').forEach(c=>c.onchange=()=>{
    pol.groups[+c.dataset.gi].enabled=c.checked; drawPolicy()});
  $('pol_groups').querySelectorAll('.gn').forEach(c=>c.oninput=()=>{
    pol.groups[+c.dataset.gi].name=c.value});
  $('pol_groups').querySelectorAll('.g_del').forEach(b=>b.onclick=()=>{
    const g=pol.groups[+b.dataset.gi];
    if(confirm(`Remove group "${g.name||g.id}"?`)){pol.groups.splice(+b.dataset.gi,1);drawPolicy()}});

  pol.security_block=pol.security_block||{domains:[],urls:[]};
  pol.policy_block=pol.policy_block||{domains:[],urls:[]};
  pol.global_allow=pol.global_allow||{domains:[]};
  pol.options=pol.options||{};
  chips('t_secdom',pol.security_block.domains,'anydesk.com',drawPolicy);
  chips('t_securl',pol.security_block.urls,'\\.onion/',drawPolicy);
  chips('t_poldom',pol.policy_block.domains,'dropbox.com',drawPolicy);
  chips('t_polurl',pol.policy_block.urls,'\\.torrent(\\?|$)',drawPolicy);
  chips('t_allow',pol.global_allow.domains,'cdn.example.com',drawPolicy);
  $('o_drop').checked=!!pol.options.drop_connection;
  $('o_rawip').checked=pol.options.deny_raw_ip_urls!==false;
  $('o_exe').checked=!!pol.options.deny_executables;
  const n=gs.filter(g=>g.enabled!==false&&(g.ips||[]).length).length;
  polSay(`${n} active group(s) · ${gs.length} defined — nothing reaches the proxy `+
         `until you press <b>Apply</b>`);
}

async function polLoad(){
  if(!polToken){$('pol_msg').textContent='enter the admin token first';
    $('pol_msg').className='blerr';return}
  // the dashboard has to SSH to the proxy for this, which can take a few
  // seconds — say so immediately instead of looking dead
  $('pol_msg').textContent='contacting the proxy over SSH…';
  $('pol_msg').className='dimc';
  const t0=Date.now();
  const slow=setTimeout(()=>{$('pol_msg').textContent=
    'still waiting for the proxy… (SSH or the helper may be slow)';},4000);
  const giveUp=setTimeout(()=>{
    $('pol_msg').innerHTML='no answer from the proxy after 45s — check that '+
      '<code>squid-policy</code> is installed there and that sudo needs no password';
    $('pol_msg').className='blerr';},45000);
  const done=()=>{clearTimeout(slow);clearTimeout(giveUp)};
  try{
    const q=encodeURIComponent(isAll()?'':curProxy());
    const d=await (await fetch('/api/policy?proxy='+q,{headers:polHeaders()})).json();
    done();
    if(d.enabled===false){$('pol_msg').textContent='';
      $('pol_hint').innerHTML=d.read_only
      ? '🔒 <b>'+esc(proxyName[curProxy()]||curProxy())+'</b> is monitor-only '+
        '(<code>admin:false</code>). Switch the dropdown to a proxy with admin '+
        'access, or set <code>"admin": true</code> for it in squid_proxies.json.'
      : 'Policy admin is off. Restart the dashboard with <b>--enable-policy</b>.';
      $('pol_unlock').style.display='none';$('pol_token').style.display='none';return}
    if(d.error){polSay('');$('pol_msg').textContent=d.error;
      $('pol_msg').className='blerr';return}
    if(!d.ok){
      // BUG 2 was here: with neither reason nor error this printed a bare
      // space, so the panel looked like it had silently done nothing
      const why=[d.reason,d.error,d.hint].filter(Boolean).join(' — ')||
        'the proxy did not return a policy (unexpected response shape)';
      $('pol_msg').textContent=why; $('pol_msg').className='blerr'; return}
    polToken&&sessionStorage.setItem('bl_token',polToken);
    $('pol_msg').textContent='';
    pol=d.policy||{};
    $('pol_lock').style.display='none';$('pol_panel').style.display='block';
    $('pol_sub').textContent=(d.target||'')+(proxyList.length>1?
      '  ['+(proxyName[d.proxy]||d.proxy||'')+']':'');
    $('pol_status').textContent=(d.summary||'').split('\n').slice(0,3).join('  ·  ');
    drawPolicy();
  }catch(e){done();$('pol_msg').textContent=''+e;$('pol_msg').className='blerr'}
}

async function polPush(kind){
  if(!pol)return;
  if(kind==='apply'&&!confirm(
     'Apply this policy to '+(proxyName[curProxy()]||curProxy())+' now?\n\n'+
     'The proxy validates it, reloads Squid, and rolls back automatically if '+
     'Squid rejects it.'))return;
  polSay(kind==='apply'?'applying…':'validating…');
  $('pol_out').style.display='none';
  try{
    const r=await fetch('/api/policy/'+kind,{method:'POST',headers:polHeaders(),
      body:JSON.stringify({policy:pol,proxy:isAll()?'':curProxy()})});
    const d=await r.json();
    if(!d.ok){
      polSay('✗ '+esc(d.reason||d.error||'failed'),'blerr');
      $('pol_out').style.display='block';
      $('pol_out').textContent=(d.error||d.message||'').trim();
      return;
    }
    if(kind==='validate'){
      polSay('✓ valid — '+(d.groups||[]).length+' active group(s)'+
        ((d.skipped||[]).length?', '+d.skipped.length+' empty placeholder(s) skipped':''),'blok');
      $('pol_out').style.display='block';
      $('pol_out').textContent=(d.rules||[]).join('\n');
    } else {
      polSay('✓ applied — '+d.applied+' group(s), '+d.ips+' IP(s) live on the proxy'+
        (d.note?' <span class="dimc">('+esc(d.note)+')</span>':''),'blok');
      polLoad();
    }
  }catch(e){polSay('✗ '+e,'blerr')}
}

/* ------------------------------------------- push one policy to every proxy */
async function polFleet(){
  if(!pol)return;
  let fl;
  try{ fl=await (await fetch('/api/fleet')).json(); }
  catch(e){ polSay('✗ '+e,'blerr'); return; }
  const names=(fl.writable||[]).map(x=>x.name);
  if(!names.length){ polSay('✗ no proxy accepts policy changes','blerr'); return; }
  if(!confirm('Push this policy to ALL '+names.length+' proxies?\n\n'+
      names.join('\n')+'\n\n'+
      'Every proxy validates first. Nothing is applied unless all of them '+
      'pass, and the apply then runs one node at a time, stopping at the '+
      'first failure.'))return;
  polSay('validating on '+names.length+' proxies…');
  $('pol_out').style.display='none';
  try{
    const r=await fetch('/api/policy/apply',{method:'POST',headers:polHeaders(),
      body:JSON.stringify({policy:pol,proxy:'all'})});
    const d=await r.json();
    const lines=(d.results||[]).map(x=>
      (x.ok?'  ok      ':'  FAILED  ')+x.name+(x.error?'   '+x.error:'')).join('\n');
    $('pol_out').style.display='block';
    $('pol_out').textContent=
      (d.phase==='validate'?'validation only — nothing was applied\n\n':'')+lines+
      (d.applied&&d.applied.length?'\n\napplied to: '+d.applied.join(', '):'')+
      (d.skipped&&d.skipped.length?'\nnot touched: '+d.skipped.join(', '):'');
    if(d.ok) polSay('✓ pushed to all '+(d.applied||[]).length+' proxies','blok');
    else     polSay('✗ '+esc(d.error||'failed'),'blerr');
  }catch(e){polSay('✗ '+e,'blerr')}
}

/* ------------------------------------------------------ raw squid.conf edit */
function cfgSay(html,cls){const e=$('cfg_note');e.innerHTML=html;e.className='note '+(cls||'')}
async function cfgLoad(){
  cfgSay('loading squid.conf over SSH…');
  $('cfg_out').style.display='none';
  try{
    const d=await (await fetch('/api/config?proxy='+
      encodeURIComponent(isAll()?'':curProxy()))).json();
    if(!d.ok){cfgSay('✗ '+esc(d.error||d.reason||'failed'),'blerr');return}
    $('cfg_text').value=d.text||'';
    $('cfg_meta').textContent=d.path+'  ·  '+(d.bytes||0)+' bytes  ·  modified '+
      (d.mtime?new Date(d.mtime*1000).toLocaleString():'?');
    $('cfg_baks').innerHTML=(d.backups||[]).map(b=>
      `<option value="${esc(b.name)}">${esc(b.name)} — ${b.bytes}B</option>`).join('')
      ||'<option value="">(no backups yet)</option>';
    cfgSay('loaded from '+(proxyName[curProxy()]||curProxy()));
  }catch(e){cfgSay('✗ '+e,'blerr')}
}
async function cfgPost(path,body,label){
  cfgSay(label+'…'); $('cfg_out').style.display='none';
  try{
    const r=await fetch(path,{method:'POST',headers:polHeaders(),
      body:JSON.stringify(Object.assign({proxy:isAll()?'':curProxy()},body))});
    const d=await r.json();
    $('cfg_out').style.display='block';
    if(path.endsWith('/check')){
      const bits=['parses with `squid -k parse`: '+(d.parses?'yes':'NO')];
      if((d.guards||[]).length) bits.push('\nsafety guards:\n  '+d.guards.join('\n  '));
      if((d.squid_errors||[]).length) bits.push('\nsquid said:\n  '+d.squid_errors.join('\n  '));
      $('cfg_out').textContent=bits.join('\n');
      cfgSay(d.ok?'✓ valid — safe to save':'✗ not safe to save yet',
             d.ok?'blok':'blerr');
      return;
    }
    if(!d.ok){
      $('cfg_out').textContent=(d.error||d.reason||'failed');
      cfgSay('✗ '+esc(d.reason||'refused'),'blerr'); return;
    }
    $('cfg_out').textContent='backup kept: '+(d.backup||'-')+
      '\nsquid reloaded: '+(d.reloaded?'yes':'no (squid was not running)')+
      ((d.overrides||[]).length?'\n\nOVERRIDDEN:\n  '+d.overrides.join('\n  '):'');
    cfgSay('✓ saved','blok');
    cfgLoad();
  }catch(e){cfgSay('✗ '+e,'blerr')}
}

/* ------------------------------------------------------------ drill-down */
let dCur=null;   // {kind,key}

function miniBars(obj,opt={}){
  const rows=Array.isArray(obj)?obj:Object.entries(obj||{}).map(([k,v])=>({key:k,n:v}));
  if(!rows.length)return '<div class="empty">none</div>';
  const max=Math.max(...rows.map(r=>r.n));
  return rows.map(r=>{
    const w=(r.n/max*100).toFixed(1);
    const warn=opt.warn&&opt.warn(r);
    const clk=opt.drill?` clik" data-dk="${opt.drill}" data-dv="${esc(r.key)}`:'';
    return `<div class="bar${warn?' warn':''}${clk}"><div class="top">
      <span class="nm">${esc(r.key)}</span><span class="ct">${fmtN(r.n)}</span></div>
      <div class="track"><div class="fill" style="width:${w}%"></div></div></div>`}).join('');
}

async function openDetail(kind,key){
  dCur={kind,key};
  $('d_title').textContent=(kind==='client'?'🖧 ':'🌐 ')+key;
  $('d_sub').textContent='loading…';
  $('d_body').innerHTML='<div class="empty">loading…</div>';
  $('dmask').classList.add('on');
  $('d_block').style.display=blUnlocked?'':'none';
  try{
    const u=`/api/detail?kind=${kind}&key=${encodeURIComponent(key)}`+
            `&proxy=${encodeURIComponent(isAll()?'all':curProxy())}`;
    const d=await (await fetch(u)).json();
    if(d.error){$('d_body').innerHTML=`<div class="empty">${esc(d.error)}</div>`;
      $('d_sub').textContent='';return}
    renderDetail(d);
  }catch(e){$('d_body').innerHTML=`<div class="empty blerr">${esc(''+e)}</div>`}
}

function renderDetail(d){
  const isClient=d.kind==='client';
  const span=(d.last-d.first)||0;
  $('d_sub').textContent=(d.proxy==='all'?'all proxies':(d.proxy_name||d.proxy||''))+
    (d.peer_total?` · ${d.peer_total} ${isClient?'destinations':'clients'}`:'');
  const seen=(d.seen_on||[]).map(x=>`${esc(x.name||x.proxy)} (${fmtN(x.requests)})`).join(', ');
  const den=(d.kinds||{}).denied||0, err=(d.kinds||{}).error||0;
  $('d_body').innerHTML=`
    <div class="dkpis">
      <div class="dk"><div class="l">requests</div><div class="v">${fmtN(d.requests)}</div></div>
      <div class="dk"><div class="l">transferred</div><div class="v">${fmtB(d.bytes)}</div></div>
      <div class="dk"><div class="l">avg latency</div><div class="v">${fmtN(d.avg_latency)}<span style="font-size:11px"> ms</span></div></div>
      <div class="dk"><div class="l">worst latency</div><div class="v">${fmtN(d.max_latency)}<span style="font-size:11px"> ms</span></div></div>
      <div class="dk"><div class="l">denied</div><div class="v" style="color:${den?'var(--deny)':'inherit'}">${fmtN(den)}</div></div>
      <div class="dk"><div class="l">errors</div><div class="v" style="color:${err?'var(--err)':'inherit'}">${fmtN(err)}</div></div>
    </div>
    <div class="dwhen">first seen ${hhmmss(d.first)} · last seen ${hhmmss(d.last)}
      ${span>1?`· active over ${fmtT(span)}`:''}${seen?` · seen on: ${seen}`:''}</div>
    ${(d.alerts&&d.alerts.length)?`<div class="dsec"><h4>⚠ alerts involving this ${d.kind}</h4>
      ${d.alerts.map(a=>`<div style="font-family:var(--mono);font-size:11px;padding:3px 0">
        <span class="sev-dot ${esc(a.severity)}"></span>${hhmmss(a.ts)} — ${esc(a.rule)}:
        <span class="dimc">${esc(a.msg)}</span></div>`).join('')}</div>`:''}
    <div class="dgrid">
      <div class="dsec"><h4>${isClient?'top destinations':'clients reaching it'}</h4>
        <div class="bars" id="d_peers"></div></div>
      <div>
        <div class="dsec"><h4>outcome</h4><div class="bars">${miniBars(d.kinds,{warn:r=>r.key==='denied'||r.key==='error'})}</div></div>
        <div class="dsec"><h4>status codes</h4><div class="bars">${miniBars(d.status,{warn:r=>+r.key>=400})}</div></div>
        <div class="dsec"><h4>methods</h4><div class="bars">${miniBars(d.methods)}</div></div>
        ${(d.users&&d.users.length)?`<div class="dsec"><h4>users</h4><div class="bars">${miniBars(d.users)}</div></div>`:''}
        <div class="dsec"><h4>squid actions</h4><div class="bars">${miniBars(d.actions)}</div></div>
      </div>
    </div>
    <div class="dsec"><h4>recent requests</h4>
      <div class="scroll" style="max-height:260px"><table><thead><tr>
        <th>time</th><th>m</th><th>st</th><th>outcome</th><th>bytes</th><th>ms</th>
        <th>${isClient?'host':'client'}</th><th>url</th></tr></thead><tbody>
        ${(d.recent||[]).map(r=>`<tr>
          <td class="dimc">${hhmmss(r.ts)}</td><td>${esc(r.method)}</td>
          <td class="${sclass(r.status)}">${r.status}</td>
          <td><span class="k ${esc(r.kind)}">${esc(r.kind)}</span></td>
          <td>${fmtB(r.size)}</td>
          <td class="${r.elapsed>=2000?'slowc':'dimc'}">${r.elapsed||'-'}</td>
          <td class="clik" data-dk="${isClient?'host':'client'}" data-dv="${esc(r.peer)}">${esc(r.peer)}</td>
          <td class="dimc" title="${esc(r.url)}">${esc(r.url)}</td></tr>`).join('')}
      </tbody></table></div></div>`;
  // peers list is clickable too — pivot from client to host and back
  $('d_peers').innerHTML=miniBars(d.peers,{drill:isClient?'host':'client',
    warn:r=>/malware|torrent|c2|phish/i.test(r.key)});
  $('d_body').querySelectorAll('.clik').forEach(el=>el.onclick=()=>
    openDetail(el.dataset.dk,el.dataset.dv));
  $('d_note').textContent=isClient
    ? 'client IP — blocking adds a src ACL entry'
    : 'destination host — blocking adds a dstdomain entry';
  $('d_block').textContent=isClient?'⛔ Block this IP':'⛔ Block this domain';
}

/* ------------------------------------------------------ client full history */
/* Clicking a row in the Client history panel — unlike openDetail() above
   (which only shows the last ~15 live in-memory requests), this pulls every
   retained request for that client from the history database. It also works
   as a standalone IP search: its own range picker (1h up to 3 months, or a
   custom span) is independent of whatever range the Client history panel
   behind it happens to be showing, and the IP itself can be changed without
   closing the modal. */
const CH_PAGE=2000;   // rows per fetch — "load older" pages beyond this
let chRows=[], chAllRows=[], chIp=null, chRange='1d', chSinceEpoch=null, chUntilEpoch=null;
let chWinSince=null, chWinUntil=null, chCursor=null, chMoreAvailable=false, chLoading=false;
async function openClientHistory(ip){
  chIp=ip; chRange=cliRange; chSinceEpoch=cliWindow.since; chUntilEpoch=cliWindow.until;
  $('ch_search_ip').value=ip;
  $('ch_ranges').querySelectorAll('.pchip').forEach(c=>
    c.classList.toggle('sel', c.dataset.r===chRange));
  $('ch_custom_wrap').style.display='none';
  $('chmask').classList.add('on');
  await loadClientHistory();
}
async function loadClientHistory(){
  if(!chIp) return;
  $('ch_ip').textContent=chIp;
  $('ch_sub').textContent=RANGE_LABEL[chRange]||'';
  $('ch_summary').textContent='loading…';
  $('ch_t').innerHTML=''; $('ch_empty').style.display='none';
  $('ch_more').style.display='none';
  const RANGE_HOURS={'1h':1,'1d':24,'2d':48,'7d':168,'15d':360,'30d':720,'90d':2160};
  const now=Date.now()/1000;
  let since=chSinceEpoch, until=chUntilEpoch;
  if(chRange!=='custom' || !since){ since=now-(RANGE_HOURS[chRange]||24)*3600; until=now; }
  chWinSince=since; chWinUntil=until; chCursor=until; chAllRows=[];
  await fetchChPage();
}
async function fetchChPage(){
  if(chLoading) return;
  chLoading=true;
  $('ch_more').textContent='loading…'; $('ch_more').disabled=true;
  const params=new URLSearchParams({client:chIp, limit:String(CH_PAGE),
    proxy:isAll()?'all':curProxy(), since:String(chWinSince), until:String(chCursor)});
  try{
    const d=await (await fetch('/api/history?'+params.toString())).json();
    if(d.enabled===false){
      $('ch_summary').textContent='';
      $('ch_empty').style.display='block';
      $('ch_empty').textContent=d.note||'request history needs --db PATH';
      chAllRows=[]; chMoreAvailable=false; applyChFilters();
      return;
    }
    const page=d.rows||[];
    chAllRows=chAllRows.concat(page);
    // rows come back newest-first; the oldest ts in this page becomes the
    // exclusive upper bound for the next (older) page
    if(page.length){
      const oldest=Math.min(...page.map(r=>r.ts));
      chCursor=oldest-0.001;
    }
    chMoreAvailable=page.length>=CH_PAGE && chCursor>chWinSince;
    const sinceS=new Date(chWinSince*1000).toLocaleString(), untilS=new Date(chWinUntil*1000).toLocaleString();
    $('ch_summary').dataset.window=`window ${esc(sinceS)} &rarr; ${esc(untilS)}`;
    applyChFilters();
    document.querySelectorAll('#chmask .pcol').forEach(el=>el.style.display=isAll()?'':'none');
  }catch(e){
    $('ch_summary').textContent='';
    $('ch_empty').style.display='block';
    $('ch_empty').textContent='could not load request history';
    chMoreAvailable=false;
  }finally{
    chLoading=false;
    $('ch_more').disabled=false; $('ch_more').textContent='⤓ load older';
    $('ch_more').style.display=chMoreAvailable?'':'none';
  }
}
function applyChFilters(){
  const fStatus=($('ch_f_status').value||'').trim();
  const fHost=($('ch_f_host').value||'').trim().toLowerCase();
  const fKind=$('ch_f_kind').value;
  const fAction=($('ch_f_action').value||'').trim().toLowerCase();
  chRows=chAllRows.filter(r=>
    (!fStatus || String(r.status||'').includes(fStatus)) &&
    (!fHost || (r.host||'').toLowerCase().includes(fHost)) &&
    (!fKind || r.kind===fKind) &&
    (!fAction || (r.action||'').toLowerCase().includes(fAction)));
  const win=$('ch_summary').dataset.window||'';
  const filtered=chRows.length!==chAllRows.length;
  $('ch_summary').innerHTML=`<b>${fmtN(chRows.length)}</b> request${chRows.length===1?'':'s'}`+
    (filtered?` <span class="dimc">(of ${fmtN(chAllRows.length)} loaded)</span>`:'')+
    ` &middot; ${win}`+
    (chMoreAvailable?' <span class="dimc">(more exist — click "load older" below)</span>':'');
  $('ch_empty').style.display=chRows.length?'none':'block';
  $('ch_empty').textContent=chAllRows.length?'no requests match these filters':'no requests from this client in this window';
  $('ch_t').innerHTML=chRows.map(r=>`<tr>
    <td class="dimc">${new Date(r.ts*1000).toLocaleString()}</td>
    <td class="pcol">${esc(proxyName[r.proxy]||r.proxy||'')}</td>
    <td>${esc(r.method)}</td><td class="${sclass(r.status)}">${r.status}</td>
    <td><span class="k ${esc(r.kind)}">${esc(r.kind)}</span></td>
    <td class="dimc">${esc(r.action)}</td>
    <td>${fmtB(r.bytes)}</td>
    <td class="${r.ms>=2000?'slowc':'dimc'}">${r.ms||'-'}</td>
    <td>${esc(r.host)}</td>
    <td class="dimc" title="${esc(r.url)}">${esc(r.url)}</td></tr>`).join('');
  document.querySelectorAll('#chmask .pcol').forEach(el=>el.style.display=isAll()?'':'none');
}
function clientHistoryToCSV(){
  const head=['time','proxy','method','status','outcome','action','bytes','ms','host','url'];
  const lines=[head.join(',')];
  for(const r of chRows){
    lines.push([new Date(r.ts*1000).toISOString(), r.proxy, r.method, r.status,
      r.kind, r.action, r.bytes, r.ms, r.host, r.url
    ].map(v=>`"${String(v==null?'':v).replace(/"/g,'""')}"`).join(','));
  }
  return lines.join('\n');
}
$('ch_close').onclick=()=>$('chmask').classList.remove('on');
$('chmask').onclick=e=>{if(e.target===$('chmask'))$('chmask').classList.remove('on')};
$('ch_csv').onclick=()=>{
  const blob=new Blob([clientHistoryToCSV()],{type:'text/csv'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=`client_${chIp||'unknown'}_requests.csv`;
  document.body.appendChild(a); a.click(); a.remove();
};
$('ch_go').onclick=()=>{
  const v=($('ch_search_ip').value||'').trim();
  if(!v) return;
  chIp=v; loadClientHistory();
};
$('ch_search_ip').addEventListener('keydown',e=>{if(e.key==='Enter')$('ch_go').click()});
$('ch_ranges').querySelectorAll('.pchip').forEach(chip=>{
  chip.onclick=()=>{
    chRange=chip.dataset.r;
    $('ch_ranges').querySelectorAll('.pchip').forEach(c=>c.classList.toggle('sel',c===chip));
    $('ch_custom_wrap').style.display=chRange==='custom'?'flex':'none';
    if(chRange==='custom'){
      if(!$('ch_since_in').value){
        const now=new Date();
        $('ch_since_in').value=toLocalInputValue(new Date(now-24*3600*1000));
        $('ch_until_in').value=toLocalInputValue(now);
      }
      chSinceEpoch=new Date($('ch_since_in').value).getTime()/1000;
      chUntilEpoch=new Date($('ch_until_in').value).getTime()/1000;
    }
    loadClientHistory();
  };
});
$('ch_apply').onclick=()=>{
  if(!$('ch_since_in').value) return;
  chSinceEpoch=new Date($('ch_since_in').value).getTime()/1000;
  chUntilEpoch=$('ch_until_in').value?new Date($('ch_until_in').value).getTime()/1000:null;
  loadClientHistory();
};
['ch_f_status','ch_f_host','ch_f_action'].forEach(id=>
  $(id).addEventListener('input',applyChFilters));
$('ch_f_kind').addEventListener('change',applyChFilters);
$('ch_f_clear').onclick=()=>{
  $('ch_f_status').value=''; $('ch_f_host').value='';
  $('ch_f_kind').value=''; $('ch_f_action').value='';
  applyChFilters();
};
$('ch_more').onclick=fetchChPage;

/* -------------------------------------------------------------- proxies */
async function loadProxies(){
  try{
    const d=await (await fetch('/api/proxies')).json();
    proxyList=d.proxies||[];
    proxyName={}; proxyList.forEach(p=>proxyName[p.id]=p.name);
    if(selProxy && selProxy!=='all' && !proxyName[selProxy]) selProxy='';
    const sel=$('proxy_sel');
    const multi=proxyList.length>1;
    sel.style.display=multi?'':'none';
    sel.innerHTML=(multi?`<option value="all">▦ All proxies (${proxyList.length})</option>`:'')
      +proxyList.map(p=>`<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');
    sel.value=selProxy||curProxy();
    document.querySelectorAll('.pcol').forEach(el=>el.style.display=isAll()?'':'none');
    drawStrip();
  }catch(e){}
}
function drawStrip(){
  const el=$('pstrip');
  if(proxyList.length<2){el.innerHTML='';return}
  el.innerHTML=`<span class="pchip ${isAll()?'sel':''}" data-p="all">▦ all
      <span class="n">${proxyList.length} proxies</span></span>`+
    proxyList.map(p=>`<span class="pchip ${p.id===selProxy?'sel':''}" data-p="${esc(p.id)}">
      <i class="dot ${p.source&&p.source.connected?'on':'off'}"></i>${esc(p.name)}
      <span class="n">${fmtN(p.requests||0)} req${p.alerts?' · '+p.alerts+' alerts':''}</span>
    </span>`).join('');
  el.querySelectorAll('.pchip').forEach(c=>c.onclick=()=>switchProxy(c.dataset.p));
}
function switchProxy(pid){
  selProxy=pid==='all'?'all':pid;
  sessionStorage.setItem('proxy',selProxy);
  $('proxy_sel').value=selProxy;
  rows=[]; $('feed').innerHTML=''; lastStats=null;
  // a frozen full denied/slow list belongs to the proxy it was loaded for
  if(deniedFull){deniedFull=null;$('deny_full').textContent='⤓ load up to 1000';$('deny_tag').textContent='policy violations'}
  if(slowFull){slowFull=null;$('slow_full').textContent='⤓ load up to 1000';$('slow_tag').textContent='> 2000 ms'}
  document.querySelectorAll('.pcol').forEach(el=>el.style.display=isAll()?'':'none');
  drawStrip(); refreshNow(); loadClients();
}
async function refreshNow(){
  try{
    const q=isAll()?'all':curProxy();
    const d=await (await fetch(`/api/stats?recent=150&proxy=${encodeURIComponent(q)}`)).json();
    if(!d.error){ rows=d.recent||[]; renderStats(d); drawFeed(); }
  }catch(e){}
}
/* the aggregate view is computed server-side on demand, so poll it */
setInterval(()=>{ if(isAll()) refreshNow(); }, 2500);
setInterval(loadProxies, 10000);

/* --------------------------------------------------------- client history */
const RANGE_LABEL={'1h':'last 1 hour','1d':'last 24 hours','2d':'last 2 days',
  '7d':'last 7 days','15d':'last 15 days','30d':'last 1 month','90d':'last 3 months',
  'custom':'custom range'};
async function loadClients(){
  const p=isAll()?'all':curProxy();
  const params=new URLSearchParams({proxy:p, limit:'2000'});
  if(cliRange==='custom' && cliSinceEpoch){
    params.set('since',cliSinceEpoch);
    if(cliUntilEpoch) params.set('until',cliUntilEpoch);
  } else {
    params.set('range', cliRange);
  }
  try{
    const d=await (await fetch('/api/clients?'+params.toString())).json();
    if(d.enabled===false){
      $('cli_t').innerHTML=''; cliRows=[];
      $('cli_summary').textContent='';
      $('cli_empty').style.display='block';
      $('cli_empty').textContent=d.note||'client history is unavailable';
      return;
    }
    cliRows=d.clients||[];
    cliWindow={since:d.since, until:d.until};
    $('cli_range_tag').textContent=RANGE_LABEL[cliRange]||cliRange;
    const since=new Date(d.since*1000), until=new Date(d.until*1000);
    $('cli_summary').innerHTML=
      `<b>${fmtN(d.unique||0)}</b> unique client${d.unique===1?'':'s'} &middot; `+
      `<b>${fmtN(d.total_requests||0)}</b> requests &middot; `+
      `window ${since.toLocaleString()} &rarr; ${until.toLocaleString()}`+
      (d.truncated?' <span class="dimc">(list capped — unique count above is exact)</span>':'');
    drawClients();
  }catch(e){
    $('cli_summary').textContent='could not load client history';
  }
}
function drawClients(){
  const filt=($('cli_q').value||'').trim().toLowerCase();
  const list=filt?cliRows.filter(c=>c.client.toLowerCase().includes(filt)):cliRows;
  $('cli_empty').style.display=list.length?'none':'block';
  $('cli_empty').textContent='no clients matched this window/filter';
  $('cli_t').innerHTML=list.map(c=>`<tr class="clik" data-ip="${esc(c.client)}" title="click to see every request from this client in the selected window">
    <td>${esc(c.client)}</td>
    <td>${fmtN(c.requests)}</td>
    <td>${fmtB(c.bytes)}</td>
    <td>${c.denied?('<span class="s4">'+fmtN(c.denied)+'</span>'):'0'}</td>
    <td>${c.errors?('<span class="s5">'+fmtN(c.errors)+'</span>'):'0'}</td>
    <td>${fmtN(c.hosts)}</td>
    <td>${new Date(c.first_seen*1000).toLocaleString()}</td>
    <td>${new Date(c.last_seen*1000).toLocaleString()}</td>
  </tr>`).join('');
  $('cli_t').querySelectorAll('tr.clik').forEach(tr=>
    tr.onclick=()=>openClientHistory(tr.dataset.ip));
}
function clientsToCSV(){
  const head=['client','requests','bytes','denied','errors','hosts_reached','first_seen','last_seen'];
  const lines=[head.join(',')];
  const filt=($('cli_q').value||'').trim().toLowerCase();
  const list=filt?cliRows.filter(c=>c.client.toLowerCase().includes(filt)):cliRows;
  for(const c of list){
    lines.push([c.client, c.requests, c.bytes, c.denied, c.errors, c.hosts,
      new Date(c.first_seen*1000).toISOString(), new Date(c.last_seen*1000).toISOString()
    ].map(v=>`"${String(v).replace(/"/g,'""')}"`).join(','));
  }
  return lines.join('\n');
}
function toLocalInputValue(d){
  const pad=n=>String(n).padStart(2,'0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
$('cli_ranges').querySelectorAll('.pchip').forEach(chip=>{
  chip.onclick=()=>{
    cliRange=chip.dataset.r;
    $('cli_ranges').querySelectorAll('.pchip').forEach(c=>c.classList.toggle('sel',c===chip));
    $('cli_custom_wrap').style.display=cliRange==='custom'?'flex':'none';
    if(cliRange==='custom'){
      if(!$('cli_since').value){
        const now=new Date();
        $('cli_since').value=toLocalInputValue(new Date(now-24*3600*1000));
        $('cli_until').value=toLocalInputValue(now);
      }
      cliSinceEpoch=new Date($('cli_since').value).getTime()/1000;
      cliUntilEpoch=new Date($('cli_until').value).getTime()/1000;
    }
    loadClients();
  };
});
$('cli_apply').onclick=()=>{
  if(!$('cli_since').value){return}
  cliSinceEpoch=new Date($('cli_since').value).getTime()/1000;
  cliUntilEpoch=$('cli_until').value?new Date($('cli_until').value).getTime()/1000:null;
  loadClients();
};
$('cli_q').addEventListener('input',drawClients);
$('cli_refresh').onclick=loadClients;
$('cli_csv').onclick=()=>{
  const blob=new Blob([clientsToCSV()],{type:'text/csv'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=`clients_${cliRange}_${Date.now()}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
};
/* historical, not live — a slow poll is enough, and avoids hammering the DB
   with the same query every couple of seconds */
setInterval(loadClients, 45000);

/* ------------------------------------------------------------------ sse */
let es=null, retry=1000;
function connect(){
  es=new EventSource('/events');
  es.onopen=()=>{retry=1000;$('dot').className='dot on';$('conn').textContent='live'};
  es.addEventListener('stats',e=>{try{const d=JSON.parse(e.data);
    // per-proxy snapshots arrive for every proxy; render only the selected one
    if(isAll())return;                       // aggregate is polled instead
    if(d.proxy && d.proxy!==curProxy())return;
    renderStats(d);
  }catch(x){}});
  es.addEventListener('req',e=>{if(paused)return;try{const r=JSON.parse(e.data);
    if(!isAll() && r.p && r.p!==curProxy())return;
    pushRow(r);
  }catch(x){}});
  es.addEventListener('alert',e=>{try{onAlert(JSON.parse(e.data),true)}catch(x){}});
  es.addEventListener('rules',e=>{try{const d=JSON.parse(e.data);
    if(!$('mask').classList.contains('on')){ruleDraft=(d.rules||[]).map(x=>({...x}))}}catch(x){}});
  es.addEventListener('cachemgr',e=>{});
  es.addEventListener('source',e=>{try{const d=JSON.parse(e.data);
    loadProxies();
    const who=d.p?(proxyName[d.p]||d.p):'source';
    if(!d.connected){
      if(isAll()||!d.p||d.p===curProxy()){$('banner').style.display='block';
        $('banner').innerHTML='⚠ <b>'+esc(who)+' down</b> — '+esc(d.error||'disconnected')+
          (d.reconnects?' <span class="dimc">(retry '+d.reconnects+')</span>':'');}
    } else if(d.p===curProxy()||isAll()){$('banner').style.display='none'}
  }catch(x){}});
  es.addEventListener('warn',e=>{try{const d=JSON.parse(e.data);
    $('banner').style.display='block';$('banner').textContent='⚠ '+d.msg}catch(x){}});
  es.onerror=()=>{$('dot').className='dot off';$('conn').textContent='reconnecting…';
    es.close();setTimeout(connect,retry);retry=Math.min(retry*1.7,12000)};
}
connect();

/* -------------------------------------------------------------- view tabs */
/* "Live feed" is kept on its own tab instead of on the main overview page —
   it's a dense, fast-scrolling table that crowds the KPIs/charts above it.
   Tabs (not a real page navigation) so the SSE connection and all polling
   keep running underneath regardless of which tab is visible — switching
   tabs never drops or re-fetches data, it only shows/hides existing DOM. */
function showView(name){
  const live=name==='live';
  $('view_overview').style.display=live?'none':'';
  $('view_overview2').style.display=live?'none':'';
  $('view_live').style.display=live?'':'none';
  document.querySelectorAll('.tabbtn').forEach(b=>
    b.classList.toggle('act', b.dataset.view===name));
  if(location.hash.replace('#','')!==name){
    history.replaceState(null,'',name==='live'?'#live':'#');
  }
}
document.querySelectorAll('.tabbtn').forEach(b=>
  b.onclick=()=>showView(b.dataset.view));
window.addEventListener('hashchange',()=>
  showView(location.hash==='#live'?'live':'overview'));
showView(location.hash==='#live'?'live':'overview');

/* -------------------------------------------------------------------- theme */
function applyTheme(t){
  document.documentElement.dataset.theme=t;
  try{localStorage.setItem('sqm_theme',t)}catch(e){}
  $('theme_btn').textContent=t==='light'?'🌙 Dark':'☀️ Light';
}
$('theme_btn').onclick=()=>applyTheme(
  document.documentElement.dataset.theme==='light'?'dark':'light');
applyTheme(document.documentElement.dataset.theme==='light'?'light':'dark');

/* ------------------------------------------------------------------ ui */
$('proxy_sel').onchange=()=>switchProxy($('proxy_sel').value);
loadProxies().then(refreshNow);
loadClients();
$('pause').onclick=()=>{paused=!paused;
  $('pause').textContent=paused?'▶ Resume feed':'⏸ Pause feed';
  $('pause').classList.toggle('act',paused);
  if(!paused)drawFeed()};
['f_q','f_kind','f_meth'].forEach(id=>$(id).addEventListener('input',drawFeed));
$('clear').onclick=()=>{$('f_q').value='';$('f_kind').value='';$('f_meth').value='';drawFeed()};

/* alert controls */
$('notif').onclick=async()=>{
  if(!('Notification' in window)){$('notif').textContent='🔔 unsupported';return}
  if(Notification.permission==='granted'){notifOn=!notifOn}
  else{const p=await Notification.requestPermission();notifOn=(p==='granted')}
  $('notif').textContent='🔔 Notify: '+(notifOn?'on':'off');
  $('notif').classList.toggle('act',notifOn);
  if(notifOn)new Notification('Squid Monitor',{body:'Desktop alerts enabled.',silent:true});
};
$('sound').onclick=()=>{soundOn=!soundOn;
  $('sound').textContent=(soundOn?'🔊':'🔈')+' Sound: '+(soundOn?'on':'off');
  $('sound').classList.toggle('act',soundOn); if(soundOn)beep('info')};
$('rules_btn').onclick=()=>{unseen=0;$('badge').classList.remove('on');openRules()};
$('m_close').onclick=()=>$('mask').classList.remove('on');
$('mask').onclick=e=>{if(e.target===$('mask'))$('mask').classList.remove('on')};
$('save_rules').onclick=saveRules;
$('add_rule').onclick=()=>{ruleDraft.push({id:'rule-'+Date.now().toString(36),
  name:'New rule',type:'denied_rate',enabled:true,severity:'warning',cooldown:120,
  window:60,threshold:25});drawRules();
  $('rule_list').lastElementChild.scrollIntoView({behavior:'smooth',block:'center'})};
$('test_alert').onclick=()=>fetch('/api/alerts/test',{method:'POST'});
$('reset_rules').onclick=async()=>{
  const r=await fetch('/api/alerts/reset',{method:'POST'}),d=await r.json();
  ruleDraft=(d.rules||[]).map(x=>({...x}));drawRules();
  $('save_note').textContent='restored default rules'};
$('clear_alerts').onclick=()=>{alertHist=[];seenSeq.clear();unseen=0;
  $('badge').classList.remove('on');drawAlerts()};

/* blocklist controls */
$('bl_unlock').onclick=()=>{blToken=$('bl_token').value.trim();
  if(!blToken){blSay('bl_msg','enter the token first',false);return}blLoad()};
$('bl_token').addEventListener('keydown',e=>{if(e.key==='Enter')$('bl_unlock').click()});
$('bl_refresh').onclick=blLoad;
$('bl_add').onclick=()=>{const v=$('bl_entry').value.trim();
  if(!v){blSay('bl_out','enter a domain or IP',false);return}
  blMutate('add',$('bl_kind').value,v)};
$('bl_entry').addEventListener('keydown',e=>{if(e.key==='Enter')$('bl_add').click()});
$('bl_rollback').onclick=()=>blMutate('rollback',$('bl_kind').value);
$('bl_kind').onchange=()=>{
  const k=$('bl_kind').value, e=$('bl_entry');
  e.placeholder={domains:'pastebin.com   ·   .anydesk.com  (covers subdomains)',
    ips:'10.20.30.7   ·   10.20.30.0/24',
    urls:'^http://site\\.com/path/   ·   \\.(exe|scr)(\\?|$)   — regex, http:// only',
    allow:'dropbox.example-bank.com.bd'}[k]||'';
  blSay('bl_out', k==='urls'
    ? 'URL patterns are POSIX regex and only match <b>http://</b> traffic — Squid cannot see the path inside HTTPS. To block an HTTPS site use <b>block domain</b>.'
    : '');
};
if(blToken){$('bl_token').value=blToken;blLoad()} else blLoad();
document.addEventListener('click',e=>{
  const b=e.target.closest('.blockbtn');
  if(b){ blQuickBlock(b.dataset.host); return; }   // block button wins over the row
  const row=e.target.closest('tr.arow');
  if(row&&row.dataset.seq) openAlert(row.dataset.seq);
});
$('ev_close').onclick=()=>$('evmask').classList.remove('on');
$('evmask').onclick=e=>{if(e.target.id==='evmask')$('evmask').classList.remove('on')};
document.addEventListener('keydown',e=>{if(e.key==='Escape'){
  $('mask').classList.remove('on'); $('dmask').classList.remove('on');
  $('evmask').classList.remove('on'); $('pmask').classList.remove('on');
  $('cmask').classList.remove('on'); $('chmask').classList.remove('on')}});
$('pol_btn').onclick=()=>{$('pmask').classList.add('on');
  if(polToken){$('pol_token').value=polToken;polLoad()}};
$('pol_close').onclick=()=>$('pmask').classList.remove('on');
$('pmask').onclick=e=>{if(e.target===$('pmask'))$('pmask').classList.remove('on')};
$('pol_unlock').onclick=()=>{polToken=$('pol_token').value.trim();
  if(!polToken){$('pol_msg').textContent='enter the token first';
    $('pol_msg').className='blerr';return}
  polLoad()};
$('pol_token').addEventListener('keydown',e=>{if(e.key==='Enter')$('pol_unlock').click()});
$('pol_reload').onclick=polLoad;
$('pol_check').onclick=()=>polPush('validate');
$('pol_apply').onclick=()=>polPush('apply');
$('pol_fleet').onclick=()=>polFleet();
$('cfg_btn').onclick=()=>{$('cmask').classList.add('on'); cfgLoad()};
$('cfg_close').onclick=()=>$('cmask').classList.remove('on');
$('cmask').onclick=e=>{if(e.target.id==='cmask')$('cmask').classList.remove('on')};
$('cfg_reload').onclick=()=>cfgLoad();
$('cfg_check').onclick=()=>cfgPost('/api/config/check',{text:$('cfg_text').value},'validating');
$('cfg_save').onclick=()=>{
  if(!confirm('Write this squid.conf to '+(proxyName[curProxy()]||curProxy())+
      ' and reload Squid?\n\nIt is validated with `squid -k parse` first, a '+
      'backup is kept, and it rolls back automatically if Squid objects.'))return;
  cfgPost('/api/config/save',{text:$('cfg_text').value,force:$('cfg_force').checked},'saving');
};
$('cfg_restore').onclick=()=>{
  const n=$('cfg_baks').value;
  if(!n){cfgSay('no backup selected','blerr');return}
  if(!confirm('Restore '+n+' and reload Squid?'))return;
  cfgPost('/api/config/restore',{name:n},'restoring');
};

/* role-aware UI: a view-only user should not be shown write controls at all.
   The server enforces this regardless — hiding a button is presentation, not
   access control — but showing buttons that always fail is a bad experience. */
async function applyRole(){
  let w;
  try{ w=await (await fetch('/api/whoami')).json(); }catch(e){ return; }
  if(!w.login) return;                       // token mode: leave the UI as-is
  const badge=$('who_badge');
  if(badge){ badge.style.display='inline-flex';
             badge.textContent='👤 '+w.user+' · '+w.role; }
  const out=$('logout_link'); if(out) out.style.display='inline-flex';
  if(!w.can_write){
    ['pol_btn','bl_btn','cfg_btn'].forEach(id=>{const e=$(id); if(e)e.style.display='none'});
  } else if(!w.can_edit_config){
    const e=$('cfg_btn'); if(e)e.style.display='none';
    const f=$('pol_fleet'); if(f)f.style.display='none';
  }
}
applyRole();

$('pol_undo').onclick=async()=>{
  if(!confirm('Roll the proxy back to the previous generated policy?'))return;
  const r=await fetch('/api/policy/rollback',{method:'POST',headers:polHeaders(),
    body:JSON.stringify({proxy:isAll()?'':curProxy()})});
  const d=await r.json();
  polSay(d.ok?'✓ '+esc(d.message||'rolled back'):'✗ '+esc(d.reason||d.message),
         d.ok?'blok':'blerr');
};
['o_drop','o_rawip','o_exe'].forEach(id=>$(id).addEventListener('change',()=>{
  if(!pol)return; pol.options=pol.options||{};
  pol.options.drop_connection=$('o_drop').checked;
  pol.options.deny_raw_ip_urls=$('o_rawip').checked;
  pol.options.deny_executables=$('o_exe').checked;
}));
$('pol_addgrp').onclick=()=>{
  if(!pol)return; pol.groups=pol.groups||[];
  const name=$('pol_newname').value.trim()||'New group';
  const id=name.toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'')
           .slice(0,20)||('g'+Date.now().toString(36).slice(-6));
  if(pol.groups.some(g=>g.id===id)){alert('a group with id "'+id+'" already exists');return}
  pol.groups.push({id,name,mode:$('pol_newmode').value,enabled:true,ips:[],
    deny_domains:[],deny_urls:[],allow_domains:[],allow_urls:[]});
  $('pol_newname').value=''; drawPolicy();
};
$('d_close').onclick=()=>$('dmask').classList.remove('on');
$('dmask').onclick=e=>{if(e.target===$('dmask'))$('dmask').classList.remove('on')};
$('d_filter').onclick=()=>{if(!dCur)return;
  $('f_q').value=dCur.key; drawFeed(); $('dmask').classList.remove('on');
  $('f_q').scrollIntoView({behavior:'smooth',block:'center'})};
$('d_block').onclick=()=>{if(!dCur)return;
  if(!blUnlocked){alert('Unlock the blocklist panel first (admin token).');return}
  blMutate('add',dCur.kind==='client'?'ips':'domains',dCur.key);
  $('dmask').classList.remove('on')};
/* clicking a client/host cell anywhere in the tables opens its details */
document.addEventListener('click',e=>{
  const c=e.target.closest('td.clik');
  if(c&&!c.closest('#d_body')) openDetail(c.dataset.dk,c.dataset.dv)});
setInterval(()=>{if(lastStats){lastStats.meta.uptime++;$('k_up').textContent=fmtT(lastStats.meta.uptime)}},1000);
</script></body></html>
"""


# --------------------------------------------------------------------------- #
#  Entrypoint
# --------------------------------------------------------------------------- #

def find_log():
    for p in DEFAULT_LOG_PATHS:
        if os.path.exists(p):
            return p
    return None


def _slug(text, taken):
    """Short stable id from a host/label, unique within `taken`."""
    base = re.sub(r"[^a-zA-Z0-9]+", "-", str(text)).strip("-").lower() or "proxy"
    base = base[:28]
    pid, i = base, 2
    while pid in taken:
        pid = f"{base}-{i}"; i += 1
    return pid


def parse_ssh_spec(spec, defaults=None):
    """'user@host:/path' (any part optional) -> dict of ssh connection fields."""
    d = dict(user=None, host=None, path=None, port=22, key=None, sudo=False,
             name=None)
    d.update(defaults or {})
    s = str(spec or "")
    if "@" in s:
        d["user"], s = s.split("@", 1)
    if ":" in s:
        host, rest = s.split(":", 1)
        d["host"] = host or d["host"]
        # a numeric segment before the path means an ssh port: host:2222:/path
        if rest and ":" in rest and rest.split(":", 1)[0].isdigit():
            portpart, rest = rest.split(":", 1)
            d["port"] = int(portpart)
        if rest:
            d["path"] = rest
    elif s:
        d["host"] = s
    d["path"] = d["path"] or "/var/log/squid/access.log"
    return d


def build_proxy_specs(args):
    """Assemble the list of proxies to monitor, from (in priority order):
    --proxies-config FILE, repeated --proxy flags, then the single-source flags.
    """
    specs, taken = [], set()

    def add(sp):
        sp["id"] = sp.get("id") or _slug(sp.get("name") or sp.get("host")
                                         or sp["kind"], taken)
        if sp["id"] in taken:
            sp["id"] = _slug(sp["id"], taken)
        taken.add(sp["id"])
        sp["name"] = sp.get("name") or sp.get("host") or sp["id"]
        specs.append(sp)

    # ---- a JSON file describing several proxies ---------------------------- #
    cfg_path = args.proxies_config
    if cfg_path and os.path.exists(cfg_path):
        try:
            with open(cfg_path) as fh:
                data = json.load(fh)
            rows = data.get("proxies") if isinstance(data, dict) else data
        except (OSError, ValueError) as e:
            print(f"!! cannot read {cfg_path}: {e}", file=sys.stderr)
            rows = []
        for row in rows or []:
            if not isinstance(row, dict) or row.get("enabled") is False:
                continue
            if row.get("ssh"):
                d = parse_ssh_spec(row["ssh"])
                d.update(kind="ssh", name=row.get("name"), id=row.get("id"),
                         squid_host=row.get("squid_host"),
                         sudo=bool(row.get("sudo", d["sudo"])),
                         key=row.get("key") or args.ssh_key,
                         # admin:false => monitor only; the UI cannot write to it
                         admin=row.get("admin", True) is not False)
                if row.get("port"):
                    d["port"] = int(row["port"])
                add(d)
            elif row.get("log"):
                add(dict(kind="file", path=row["log"], name=row.get("name"),
                         id=row.get("id"), squid_host=row.get("squid_host")))
            elif row.get("udp_port"):
                add(dict(kind="udp", port=int(row["udp_port"]),
                         name=row.get("name"), id=row.get("id"),
                         squid_host=row.get("squid_host")))
            elif row.get("tcp_port"):
                add(dict(kind="tcp", port=int(row["tcp_port"]),
                         name=row.get("name"), id=row.get("id"),
                         squid_host=row.get("squid_host")))

    # ---- repeated --proxy NAME=user@host:/path ----------------------------- #
    for raw in (args.proxy or []):
        name = None
        spec = raw
        if "=" in raw and "@" not in raw.split("=", 1)[0]:
            name, spec = raw.split("=", 1)
        d = parse_ssh_spec(spec, {"key": args.ssh_key, "port": args.ssh_port,
                                  "sudo": args.ssh_sudo})
        if not d["host"]:
            print(f"!! --proxy {raw!r} has no host", file=sys.stderr)
            sys.exit(2)
        d.update(kind="ssh", name=name)
        add(d)

    if specs:
        return specs

    # ---- fall back to the original single-source flags --------------------- #
    if args.demo:
        add(dict(kind="demo", rate=args.demo_rate, name="Demo"))
    elif args.ssh or args.ssh_host:
        d = parse_ssh_spec(args.ssh or "", {"user": args.ssh_user,
                                            "host": args.ssh_host,
                                            "path": args.ssh_path,
                                            "port": args.ssh_port,
                                            "key": args.ssh_key,
                                            "sudo": args.ssh_sudo})
        if not d["host"]:
            print("!! --ssh needs a host, e.g. "
                  "--ssh root@10.0.0.5:/var/log/squid/access.log", file=sys.stderr)
            sys.exit(2)
        d["kind"] = "ssh"
        add(d)
    elif args.udp_port:
        add(dict(kind="udp", port=args.udp_port, name=f"udp:{args.udp_port}"))
    elif args.tcp_port:
        add(dict(kind="tcp", port=args.tcp_port, name=f"tcp:{args.tcp_port}"))
    else:
        path = args.log or find_log()
        if not path:
            print("!! No data source given, and no local access.log found.\n\n"
                  "   One proxy:\n"
                  "     --ssh user@proxy:/var/log/squid/access.log\n"
                  "     --udp-port 5140         (Squid pushes to you)\n"
                  "     --log /path/access.log  (local or mounted)\n\n"
                  "   Several proxies (dropdown in the UI):\n"
                  "     --proxy Edge=opsuser@10.50.0.8:/var/log/squid/access.log \\\n"
                  "     --proxy Core=opsuser@10.50.0.7:/var/log/squid/access.log\n"
                  "     ...or list them in squid_proxies.json and pass "
                  "--proxies-config squid_proxies.json\n\n"
                  "   Just exploring?  --demo\n", file=sys.stderr)
            sys.exit(2)
        add(dict(kind="file", path=path, name=os.path.basename(path)))
    return specs


def main():
    ap = argparse.ArgumentParser(
        description=f"Real-time web dashboard for Squid proxy v{__version__} "
                    f"(stdlib only). Remote sources: --ssh / --udp-port / --tcp-port")
    ap.add_argument("--version", action="version",
                    version=f"squid_dashboard {__version__}")
    ap.add_argument("--log", help="path to a LOCAL (or mounted) Squid access.log")
    ap.add_argument("--host", default="127.0.0.1", help="dashboard bind address")
    ap.add_argument("--port", type=int, default=8899, help="dashboard port (default 8899)")

    g = ap.add_argument_group("remote proxy (run this script on your own PC)")
    g.add_argument("--ssh", metavar="USER@HOST:/PATH",
                   help="stream the log from a remote proxy over SSH, e.g. "
                        "root@10.0.0.5:/var/log/squid/access.log")
    g.add_argument("--ssh-host", help="proxy hostname/IP (alternative to --ssh)")
    g.add_argument("--ssh-user", help="SSH username")
    g.add_argument("--ssh-path", help="remote access.log path")
    g.add_argument("--ssh-port", type=int, default=22, help="SSH port (default 22)")
    g.add_argument("--ssh-key", help="private key file, e.g. ~/.ssh/id_ed25519")
    g.add_argument("--ssh-sudo", action="store_true",
                   help="run remote tail via sudo -n (needs NOPASSWD)")
    g.add_argument("--ssh-bin", default="ssh",
                   help="ssh binary to use (e.g. plink.exe on Windows)")
    g.add_argument("--check", action="store_true",
                   help="test the SSH setup and log permissions, then exit")

    m = ap.add_argument_group("multiple proxies (selectable from a dropdown)")
    m.add_argument("--proxy", action="append", metavar="NAME=USER@HOST:/PATH",
                   help="add a proxy; repeat for each one. The NAME= part is "
                        "optional and becomes the dropdown label.")
    m.add_argument("--proxies-config", metavar="FILE",
                   help="JSON file listing proxies (see squid_proxies.json)")
    g.add_argument("--udp-port", type=int,
                   help="listen for lines pushed by 'access_log udp://THIS_PC:PORT squid'")
    g.add_argument("--tcp-port", type=int,
                   help="listen for lines pushed by 'access_log tcp://THIS_PC:PORT squid'")
    g.add_argument("--listen-bind", default="0.0.0.0",
                   help="bind address for --udp-port/--tcp-port (default 0.0.0.0)")

    ap.add_argument("--squid-host", default="127.0.0.1",
                    help="Squid host for cache-manager stats (defaults to the SSH host)")
    ap.add_argument("--squid-port", type=int, default=3128, help="Squid proxy port")
    ap.add_argument("--squid-pass", help="cache manager password, if configured")
    ap.add_argument("--no-cachemgr", action="store_true", help="disable cache-manager polling")
    ap.add_argument("--backfill", type=int, default=2000,
                    help="how many existing log lines to preload (0 = none)")
    ap.add_argument("--demo", action="store_true",
                    help="generate synthetic traffic instead of reading a log")
    ap.add_argument("--demo-rate", type=int, default=6, help="demo requests per second")
    h = ap.add_argument_group("history database (optional)")
    h.add_argument("--db", metavar="PATH",
                   help="keep history in a SQLite file, e.g. --db squid.db. "
                        "Without this the dashboard is memory-only and forgets "
                        "everything on restart.")
    h.add_argument("--db-max-gb", type=float, default=5.0,
                   help="disk budget for the database (default 5). The oldest "
                        "raw requests are deleted to stay under it; the hourly "
                        "rollups are kept regardless, since they cost almost "
                        "nothing.")
    h.add_argument("--db-no-urls", action="store_true",
                   help="store hostnames but not full URLs — roughly halves "
                        "the disk per request, and avoids retaining full "
                        "browsing detail")
    ap.add_argument("--alerts-config", default="squid_alerts.json",
                    help="JSON file storing alert rules (default ./squid_alerts.json)")
    ap.add_argument("--no-alerts", action="store_true", help="disable the alert engine")
    ap.add_argument("--no-sysinfo", action="store_true",
                    help="disable the System health panel (CPU/memory/disk/"
                         "network for this host and each SSH proxy)")
    ap.add_argument("--sysinfo-interval", type=int, default=20, metavar="SECS",
                    help="how often to sample system resources, in seconds "
                         "(default 20). For SSH proxies this is one extra "
                         "short-lived SSH command per interval, reading only "
                         "/proc and df — nothing is installed on the proxy.")

    b = ap.add_argument_group("blocklist admin (writes ACL lists on the proxy)")
    b.add_argument("--enable-blocklist", action="store_true",
                   help="allow managing Squid block/allow lists from the dashboard "
                        "(needs squid-blocklist installed on the proxy)")
    b.add_argument("--admin-token",
                   help="token required for blocklist changes (auto-generated if omitted)")
    b.add_argument("--admin-token-file", metavar="PATH",
                   help="read the admin token from this file instead of the "
                        "command line. A token in ExecStart is readable by "
                        "every local user via `ps`, so a service should always "
                        "use this.")
    b.add_argument("--blocklist-helper", default="/usr/local/sbin/squid-blocklist",
                   help="path to the helper script on the proxy")
    b.add_argument("--blocklist-no-sudo", action="store_true",
                   help="call the helper without sudo (only if it runs as root already)")
    b.add_argument("--enable-policy", action="store_true",
                   help="allow editing the per-IP access policy from the dashboard "
                        "(needs squid-policy installed on the proxy)")
    b.add_argument("--policy-helper", default="/usr/local/sbin/squid-policy",
                   help="path to the policy helper on the proxy")
    b.add_argument("--policy-no-sudo", action="store_true",
                   help="call the policy helper without sudo (only if the "
                        "dashboard already runs as root)")
    n = ap.add_argument_group("network exposure (publishing beyond localhost)")
    n.add_argument("--auth-token",
                   help="require this token for the WHOLE dashboard, traffic "
                        "view included. Mandatory when binding anything other "
                        "than localhost — the traffic view discloses every URL "
                        "your users visit.")
    n.add_argument("--tls-cert", help="PEM certificate; enables HTTPS")
    n.add_argument("--tls-key", help="PEM private key for --tls-cert")
    n.add_argument("--allow-net", action="append", default=[], metavar="CIDR",
                   help="only accept connections from this network "
                        "(repeatable, e.g. --allow-net 10.60.0.0/16)")
    n.add_argument("--login-linux", action="store_true",
                   help="sign in with the proxy's own Linux accounts instead "
                        "of a shared token. Roles come from Linux groups "
                        "(squiddash-admin / -operator / -view), so access is "
                        "granted with usermod. Needs squid-dash-auth installed.")
    n.add_argument("--auth-helper", default="/usr/local/sbin/squid-dash-auth",
                   help="path to the login helper used by --login-linux")
    n.add_argument("--insecure-no-auth", action="store_true",
                   help="allow a non-localhost bind with no token. Do not use "
                        "on a proxy that carries real traffic.")
    b.add_argument("--local-admin", action="store_true",
                   help="the helper scripts are on THIS machine — invoke them "
                        "directly instead of over SSH. Use this when the "
                        "dashboard runs on the proxy itself; it removes the "
                        "SSH key, BatchMode and connect-timeout failure modes "
                        "entirely. Pair it with --log for the local access.log.")
    args = ap.parse_args()

    # a token file keeps the secret out of ExecStart and out of `ps`
    if args.admin_token_file:
        try:
            with open(args.admin_token_file) as fh:
                tok = fh.read().strip()
        except OSError as e:
            print(f"!! cannot read --admin-token-file {args.admin_token_file!r}: "
                  f"{e}\n", file=sys.stderr)
            sys.exit(2)
        if not tok:
            print(f"!! --admin-token-file {args.admin_token_file!r} is empty\n",
                  file=sys.stderr)
            sys.exit(2)
        if args.admin_token and args.admin_token != tok:
            print("!! both --admin-token and --admin-token-file were given and "
                  "they differ; using the file.\n", file=sys.stderr)
        args.admin_token = tok

    # validate flag combinations before doing any work, so a misconfiguration
    # reports its real cause instead of surfacing later as an unrelated error
    # --login-linux verifies accounts on the machine the dashboard runs on.
    # That is independent of WHERE policy is applied: on a management host the
    # operators' accounts live here while the proxies are driven over SSH.
    # Requiring --local-admin (an earlier assumption that both always happened
    # on the same box) made a central management host impossible.
    if args.login_linux and args.auth_token:
        print("!! --login-linux and --auth-token are two different front "
              "doors.\n   Pick one: Linux accounts (--login-linux) or a "
              "shared token (--auth-token).\n", file=sys.stderr)
        sys.exit(2)

    threads = []
    specs = build_proxy_specs(args)

    if args.check:
        ok = True
        for sp in specs:
            if sp["kind"] != "ssh":
                continue
            probe = SSHTailer(ProxyCtx(sp["id"], sp["name"]), host=sp["host"],
                              path=sp["path"], user=sp["user"], port=sp["port"],
                              key=sp["key"], backfill=0, use_sudo=sp["sudo"],
                              ssh_bin=args.ssh_bin)
            ok = ssh_preflight(probe) and ok
        if not any(sp["kind"] == "ssh" for sp in specs):
            print("!! --check only applies to SSH proxies", file=sys.stderr)
            sys.exit(2)
        sys.exit(0 if ok else 1)

    alerts_cfg = os.path.abspath(args.alerts_config)

    for sp in specs:
        ctx = ProxyCtx(sp["id"], sp["name"], sp)
        PROXIES[ctx.id] = ctx
        if not args.no_alerts:
            ctx.alerts = AlertEngine(alerts_cfg, pid=ctx.id, stats=ctx.stats)

        want_cachemgr = not args.no_cachemgr
        squid_host = sp.get("squid_host") or args.squid_host

        if sp["kind"] == "demo":
            ctx.stats.set_source("demo", f"synthetic ~{sp['rate']} req/s")
            ctx.stats.source_up()
            t = Demo(ctx, sp["rate"])
            want_cachemgr = False
        elif sp["kind"] == "ssh":
            t = SSHTailer(ctx, host=sp["host"], path=sp["path"], user=sp["user"],
                          port=sp["port"], key=sp["key"], backfill=args.backfill,
                          use_sudo=sp["sudo"], ssh_bin=args.ssh_bin)
            ctx.stats.set_source("ssh", t.target,
                                 hint="needs key-based SSH access to the proxy "
                                      "(BatchMode — no password prompt)")
            if squid_host in (None, "127.0.0.1"):
                squid_host = sp["host"]        # poll the proxy, not this PC
        elif sp["kind"] == "udp":
            t = UDPListener(ctx, args.listen_bind, sp["port"])
            ctx.stats.set_source("udp", t.target)
        elif sp["kind"] == "tcp":
            t = TCPListener(ctx, args.listen_bind, sp["port"])
            ctx.stats.set_source("tcp", t.target)
        else:                                   # local / mounted file
            path = sp["path"]
            if not os.access(path, os.R_OK):
                print(f"!! {path} is not readable by this user.\n"
                      f"   Fix:  sudo usermod -a -G squid $USER   (then re-login)\n",
                      file=sys.stderr)
            t = Tailer(ctx, path, backfill=args.backfill)
            ctx.stats.set_source("file", os.path.abspath(path))

        t.start(); ctx.threads.append(t); threads.append(t)

        if want_cachemgr:
            cm = CacheMgr(ctx, squid_host, args.squid_port, enabled=True,
                          password=args.squid_pass)
            cm.start(); ctx.threads.append(cm); threads.append(cm)

        # system health (CPU/mem/disk/net) — only meaningful for SSH proxies;
        # a demo/udp/tcp source has no host we could safely probe
        if not args.no_sysinfo and sp["kind"] == "ssh":
            si = SysCollector(ctx.id, ctx.name, mode="ssh", host=sp["host"],
                              user=sp["user"], port=sp["port"], key=sp["key"],
                              ssh_bin=args.ssh_bin,
                              interval=args.sysinfo_interval)
            si.start(); ctx.threads.append(si); threads.append(si)
            ctx.sysinfo = si

    if not args.no_sysinfo:
        globals()["LOCAL_SYS"] = SysCollector(
            "_local", "dashboard host", mode="local",
            interval=args.sysinfo_interval)
        LOCAL_SYS.start(); threads.append(LOCAL_SYS)

    if not args.no_alerts:
        ar = AlertRunner(); ar.start(); threads.append(ar)

    # ---- optional blocklist administration, one per SSH proxy -------------- #
    admin_token = None
    def admin_ctxs(flag):
        """Proxies this dashboard may write policy/blocklist changes to.

        Over SSH that means SSH-sourced proxies. With --local-admin the helper
        lives on this machine, so the log source is local (file/udp/tcp) and
        requiring kind=="ssh" would reject every proxy and exit — so accept any
        admin-enabled context in that mode.
        """
        cs = [c for c in PROXIES.values() if c.cfg.get("admin", True)
              and (args.local_admin or c.cfg.get("kind") == "ssh")]
        if not cs:
            # Not fatal. A service is installed with the write features enabled
            # and every proxy still admin:false, which is the correct starting
            # point for a fleet — you enable one node at a time. Exiting here
            # meant a fresh install could not start at all, and the UI already
            # explains per proxy why a write is refused.
            print(f"!! {flag} is on, but no proxy currently accepts changes "
                  f"(admin:false everywhere).\n"
                  f"   Monitoring works; the write panels will refuse until you "
                  f"set \"admin\": true\n   for a proxy and restart.\n",
                  file=sys.stderr)
            return []
        if args.local_admin and len(cs) > 1:
            print(f"!! {flag} with --local-admin, but {len(cs)} proxies are "
                  f"admin-enabled. The local helper only ever configures the "
                  f"proxy on THIS machine, so writes would be attributed to "
                  f"the wrong host. Set \"admin\": false on all but the local "
                  f"one.\n", file=sys.stderr)
            sys.exit(2)
        return cs

    if args.enable_blocklist:
        admin_token = args.admin_token or secrets.token_urlsafe(18)
        for c in admin_ctxs("--enable-blocklist"):
            c.blocklist = BlocklistAdmin(
                host=c.cfg.get("host", "127.0.0.1"), user=c.cfg.get("user"),
                port=c.cfg.get("port", 22), key=c.cfg.get("key"),
                ssh_bin=args.ssh_bin, helper=args.blocklist_helper,
                use_sudo=not args.blocklist_no_sudo, token=admin_token,
                local=args.local_admin)

    if args.enable_policy:
        if not admin_token:
            admin_token = args.admin_token or secrets.token_urlsafe(18)
        for c in admin_ctxs("--enable-policy"):
            c.policy = PolicyAdmin(
                host=c.cfg.get("host", "127.0.0.1"), user=c.cfg.get("user"),
                port=c.cfg.get("port", 22), key=c.cfg.get("key"),
                ssh_bin=args.ssh_bin, helper=args.policy_helper,
                # was: not args.blocklist_no_sudo — the policy helper was
                # taking the BLOCKLIST flag, so --blocklist-no-sudo silently
                # changed how the policy helper was invoked and there was no
                # way to control it independently.
                use_sudo=not args.policy_no_sudo, token=admin_token,
                local=args.local_admin)

    if args.db:
        try:
            globals()["STORE"] = Store(args.db,
                                       int(args.db_max_gb * 1024 ** 3),
                                       keep_urls=not args.db_no_urls)
        except sqlite3.Error as e:
            print(f"!! cannot open the history database {args.db!r}: {e}\n",
                  file=sys.stderr)
            sys.exit(2)

    b = Broadcaster(); b.start(); threads.append(b)

    # ---- front-door access control ---------------------------------------- #
    loopback = args.host in ("127.0.0.1", "::1", "localhost")
    nets = []
    for c in args.allow_net:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            print(f"!! --allow-net {c!r} is not a valid network.\n",
                  file=sys.stderr)
            sys.exit(2)
    if args.login_linux:
        globals()["LOGIN"] = LinuxAuth(helper=args.auth_helper, local=True)
    if not loopback and not args.auth_token and not args.login_linux \
            and not args.insecure_no_auth:
        print("!! Refusing to start.\n"
              f"   You bound {args.host}, which publishes this dashboard on the\n"
              "   network, but set no --auth-token. The traffic view lists every\n"
              "   URL each client visits and their IP addresses — anyone able to\n"
              "   reach this port would read it without authenticating.\n\n"
              "   Add:   --auth-token <a long random string>\n"
              "   Also strongly recommended:\n"
              "          --tls-cert cert.pem --tls-key key.pem   (else the token\n"
              "                                     crosses the network in clear)\n"
              "          --allow-net 10.60.0.0/16               (limit who may\n"
              "                                     even open the port)\n\n"
              "   To override anyway (not on a proxy carrying real traffic):\n"
              "          --insecure-no-auth\n", file=sys.stderr)
        sys.exit(2)
    if (args.tls_cert and not args.tls_key) or (args.tls_key and not args.tls_cert):
        print("!! --tls-cert and --tls-key must be given together.\n",
              file=sys.stderr)
        sys.exit(2)

    globals()["ACCESS"] = Access(token=args.auth_token, allow_nets=nets,
                                 secure_cookie=bool(args.tls_cert))

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    srv.login_hint = (f"proxy: {os.uname().nodename}" if args.login_linux
                      else "")
    scheme = "http"
    if args.tls_cert:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(args.tls_cert, args.tls_key)
        except (OSError, ssl.SSLError) as e:
            print(f"!! cannot load the TLS certificate/key: {e}\n",
                  file=sys.stderr)
            sys.exit(2)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        scheme = "https"
    shown_host = "127.0.0.1" if args.host in ("0.0.0.0", "") else args.host
    url = f"{scheme}://{shown_host}:{args.port}"

    print("\n" + "=" * 62)
    print(f"  SQUID PROXY LIVE DASHBOARD  v{__version__}")
    print("=" * 62)
    if len(PROXIES) == 1:
        c = next(iter(PROXIES.values()))
        print(f"  source     : {c.stats.source['kind']} · {c.stats.source['target']}")
        if c.stats.source.get("hint"):
            print(f"  setup      : {c.stats.source['hint']}")
    else:
        print(f"  proxies    : {len(PROXIES)} (switch with the dropdown in the UI)")
        for c in PROXIES.values():
            print(f"               · {c.name:<22} {c.stats.source['kind']}"
                  f" · {c.stats.source['target']}")
    if not args.no_cachemgr:
        print(f"  cache mgr  : port {args.squid_port} on each proxy")
    print(f"  dashboard  : {url}")
    if LOGIN:
        print(f"  sign-in    : Linux accounts on this host"
              f"{' · TLS on' if scheme == 'https' else ''}")
        print(f"  roles      : squiddash-admin (full) · squiddash-operator "
              f"(policy) · squiddash-view (read)")
        print(f"               check with: sudo {args.auth_helper} roles")
        if nets:
            print(f"               only from: {', '.join(str(x) for x in nets)}")
        if scheme != "https" and not loopback:
            print("  ⚠ WARNING  : no TLS — passwords would cross the network "
                  "in clear text.\n               Add --tls-cert/--tls-key "
                  "before using this.")
    elif ACCESS.enabled:
        print(f"  sign-in    : REQUIRED for the whole dashboard"
              f"{' · TLS on' if scheme == 'https' else ''}")
        if nets:
            print(f"               only from: {', '.join(str(x) for x in nets)}")
        if scheme != "https" and not loopback:
            print("  ⚠ WARNING  : no TLS — the access token and all traffic "
                  "data cross\n               the network in clear text. "
                  "Add --tls-cert/--tls-key.")
    elif not loopback:
        print("  ⚠ WARNING  : published with NO authentication "
              "(--insecure-no-auth)")
    eng = first_engine()
    if eng:
        n_on = sum(1 for r in eng.get_rules() if r["enabled"])
        print(f"  alerts     : {n_on} active / {len(eng.get_rules())} rules "
              f"({eng.config_path})")
    else:
        print(f"  alerts     : disabled")
    if any(getattr(c, "policy", None) for c in PROXIES.values()):
        wr = [c.name for c in PROXIES.values() if getattr(c, "policy", None)]
        ro = [c.name for c in PROXIES.values() if not getattr(c, "policy", None)]
        print(f"  policy     : WRITABLE on {', '.join(wr)}")
        if ro:
            print(f"               read-only (monitor only): {', '.join(ro)}")
    if any_blocklist():
        # a local (file/udp/tcp) proxy has no cfg["host"] at all, so indexing it
        # here crashed the whole startup once --local-admin made such a proxy
        # writable — describe_target() already handles both transports
        hosts = ", ".join(c.blocklist.describe_target()
                          for c in PROXIES.values()
                          if getattr(c, "blocklist", None))
        print(f"  blocklist  : WRITABLE on {hosts}")
    # print the token whenever ANY write feature is on — it used to be printed
    # only for the blocklist, so --enable-policy alone left the user with no way
    # to unlock the panel
    if admin_token:
        print("-" * 62)
        print(f"  ADMIN TOKEN: {admin_token}")
        print(f"               Paste this into the 🛡 Access policy / ⛔ Blocklist")
        print(f"               panel in the browser to unlock changes.")
        if not args.admin_token:
            print(f"               (auto-generated — it changes on every restart;")
            print(f"                use --admin-token \"your-secret\" to fix it)")
        print("-" * 62)
    print(f"  endpoints  : /api/stats  /api/alerts  /api/health  /api/export  /events")
    print(f"  stop       : Ctrl+C")
    print("=" * 62 + "\n", flush=True)

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down…")
    finally:
        for t in threads:
            if hasattr(t, "stop_flag"):
                t.stop_flag.set()
        srv.shutdown()


if __name__ == "__main__":
    main()
