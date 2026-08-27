#!/usr/bin/env python3
"""Simulate Example Bank's REAL downstream squid.conf with the squid-policy
include spliced in, and prove that:

  * per-IP blocking finally works for HTTPS (it cannot work below their
    `http_access allow CONNECT SSL_ports` line)
  * none of the payment / government integrations break
  * the SSH-over-CONNECT exception still works
  * port safety is unchanged

Squid semantics modelled: first match wins, ACLs on one line are ANDed,
`!acl` negates, dstdomain matches a bare name exactly and a dotted name as a
suffix, port ACLs match the request port.
"""
import importlib.machinery
import importlib.util
import ipaddress
import os
import re
import sys

os.environ.setdefault("SQUID_POLICY_DIR", "/tmp/poltest/etc")
os.environ.setdefault("SQUID_BIN", "/tmp/poltest/bin/squid")
os.environ.setdefault("SQUID_POLICY_AUDIT", "/tmp/poltest/audit.log")
_ld = importlib.machinery.SourceFileLoader("sp", "/agent/workspace/squid-policy")
sp = importlib.util.module_from_spec(importlib.util.spec_from_loader("sp", _ld))
_ld.exec_module(sp)

# --------------------------------------------------------------------------- #
#  Their ACLs, transcribed from the config they sent
# --------------------------------------------------------------------------- #
SAFE_PORTS = [80, 443, 21, 22, 70, 210, 280, 488, 591, 777, 18288, 19288, 18286,
              7010, 5222, 8080, 10900, 20010, 2006, 885, 5555, 42759, 90, 8087,
              8086, 8443, 2447, 8880, 2265, 8084] + list(range(1025, 65536))
SSL_PORTS = [80, 443, 18288, 19288, 18286, 7010, 5222, 8080, 10900, 20010, 2006,
             885, 5555, 42759, 90, 8087, 8086, 8443, 2447, 8880, 2265, 8084]
SSH_PORTS = [22]

SSH_CLIENT = ["10.60.11.222", "10.60.11.220", "192.168.150.8", "192.168.150.14",
              "10.60.6.118", "10.60.6.175", "10.60.6.117", "10.60.6.116",
              "10.60.6.114", "10.60.6.158", "10.60.6.124", "10.60.6.177",
              "10.60.6.161", "172.17.16.28", "10.60.6.128",
              "10.50.6.140", "10.50.6.141", "10.50.6.142"]
LOCALNET = ["10.60.0.0/16", "10.104.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
            "100.64.0.0/10", "169.254.0.0/16"]
ALLOWED_NETS = ["10.60.0.0/16", "10.104.0.0/16", "172.16.0.0/12", "192.168.0.0/16"]
PAY_CLIENTS = ["10.31.2.7", "10.31.2.10", "10.31.2.11", "10.50.2.7", "10.50.2.10",
               "10.50.2.11", "10.31.8.75", "10.31.8.76", "10.31.8.77",
               "10.50.8.37", "10.60.11.222"]
GENERAL_INTERNET = ["10.31.2.7", "10.31.2.10", "10.31.2.11", "10.50.2.7",
                    "10.50.2.10", "10.50.2.11", "10.31.8.75", "10.31.8.76",
                    "10.31.8.77"]

THEIR_ACLS = {
    "Safe_ports": ("port", SAFE_PORTS),
    "SSL_ports": ("port", SSL_PORTS),
    "SSH_ports": ("port", SSH_PORTS),
    "ssh_client": ("src", SSH_CLIENT),
    "localnet": ("src", LOCALNET),
    "allowed_nets": ("src", ALLOWED_NETS),
    "localhost": ("src", ["127.0.0.1/32"]),
    "manager": ("manager", []),
    "CONNECT": ("method", ["CONNECT"]),
    "NPA_CLIENT": ("src", ["10.50.2.46", "10.60.11.222"]),
    "NPA_SERVER": ("dstdomain", ["gateway.pension.example.gov"]),
    "PAYGATE2_CLIENT": ("src", PAY_CLIENTS),
    "PAYGATE2_SERVER": ("dstdomain", ["igw.paygate2.example.com"]),
    "PAYGATE1_CLIENT": ("src", PAY_CLIENTS),
    "PAYGATE1_SERVER": ("dstdomain", ["gw.paygate1.example.com", "uat-gw.paygate1.example.com"]),
    "NID_CLIENT": ("src", PAY_CLIENTS + ["10.50.8.37"]),
    "NID_SERVER": ("dstdomain", ["prportal.nid.example.gov"]),
    "CPA_CLIENT": ("src", ["10.60.11.173", "10.60.11.58", "10.60.11.147",
                           "10.60.11.180", "10.60.11.175", "10.60.11.109",
                           "10.60.11.222"]),
    "CPA_SERVER": ("dst", ["10.50.1.243"]),
    "general_internet_clients": ("src", GENERAL_INTERNET),
}

THEIR_RULES_HEAD = [
    "http_access deny !Safe_ports",
    "http_access allow ssh_client CONNECT SSH_ports",
    "http_access deny CONNECT !SSL_ports",
]
THEIR_RULES_TAIL = [
    "http_access allow CONNECT SSL_ports",
    "http_access allow localhost manager",
    "http_access deny manager",
    "http_access allow NPA_CLIENT NPA_SERVER",
    "http_access allow PAYGATE2_CLIENT PAYGATE2_SERVER",
    "http_access allow PAYGATE1_CLIENT PAYGATE1_SERVER",
    "http_access allow NID_CLIENT NID_SERVER",
    "http_access allow CPA_CLIENT CPA_SERVER",
    "http_access allow localnet",
    "http_access allow allowed_nets",
    "http_access allow general_internet_clients",
    "http_access allow localhost",
    "http_access deny all",
]


class Sim:
    def __init__(self, acls, rules):
        self.acls = dict(acls)
        self.rules = []
        for line in rules:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("acl "):
                m = re.match(r'acl\s+(\S+)\s+(\S+)\s+(.*)$', line)
                if not m:
                    continue
                name, atype, rest = m.groups()
                if rest.startswith('"'):
                    with open(rest.strip('"')) as fh:
                        vals = [l.strip() for l in fh
                                if l.strip() and not l.startswith("#")]
                else:
                    vals = [v for v in rest.split() if v != "-i"]
                if name in self.acls:            # squid appends on redeclare
                    self.acls[name] = (self.acls[name][0],
                                       self.acls[name][1] + vals)
                else:
                    self.acls[name] = (atype, vals)
            elif line.startswith("http_access "):
                p = line.split()
                self.rules.append((p[1], p[2:]))

    def _one(self, name, req):
        neg = name.startswith("!")
        name = name.lstrip("!")
        if name == "all":
            return not neg
        atype, vals = self.acls.get(name, (None, []))
        r = False
        if atype == "src":
            ip = ipaddress.ip_address(req["client"])
            r = any(ip in ipaddress.ip_network(v, strict=False)
                    for v in vals if ":" not in v)
        elif atype == "port":
            r = req["port"] in vals
        elif atype == "method":
            r = req["method"] in vals
        elif atype == "manager":
            r = req["host"].startswith("cache_object") or "squid-internal-mgr" in req["url"]
        elif atype == "dstdomain":
            # real Squid semantics, confirmed live against Squid 5.5:
            #   "d.com"  matches ONLY the exact host d.com
            #   ".d.com" matches d.com AND every subdomain of it
            # Modelling the bare form as a suffix match (an earlier version of
            # this file) hid a real bug: www.dropbox.com stayed reachable
            # while dropbox.com was blocked.
            h = req["host"].lower()
            for v in vals:
                v = v.lower()
                if v.startswith("."):
                    if h == v[1:] or h.endswith(v):
                        r = True
                elif h == v:
                    r = True
        elif atype == "dst":
            # dst values can be bare IPs or CIDRs; only an IP-literal host can
            # match without a DNS lookup, which is what we model here
            try:
                dip = ipaddress.ip_address(req["host"])
            except ValueError:
                dip = None
            if dip is not None:
                for v in vals:
                    try:
                        if dip in ipaddress.ip_network(v, strict=False):
                            r = True
                            break
                    except ValueError:
                        continue
        elif atype == "url_regex":
            r = any(re.search(v, req["url"]) for v in vals
                    if _safe_re(v))
        return (not r) if neg else r

    def decide(self, req):
        for i, (act, names) in enumerate(self.rules):
            if all(self._one(n, req) for n in names):
                return act, i, " ".join([act] + names)
        return "default", -1, "(no match)"


def _safe_re(v):
    try:
        re.compile(v)
        return True
    except re.error:
        return False


def req(client, url, method=None, port=None):
    host = re.sub(r"^[a-z]+://", "", url).split("/")[0]
    if ":" in host:
        host, _, p = host.partition(":")
        port = port or int(p)
    if port is None:
        port = 443 if url.startswith("https") else 80
    if method is None:
        method = "CONNECT" if url.startswith("https") else "GET"
    return {"client": client, "url": url, "host": host, "port": port,
            "method": method}


# --------------------------------------------------------------------------- #
#  the policy we propose for them
# --------------------------------------------------------------------------- #

def their_policy():
    p = sp.baseline_policy()
    g = {x["id"]: x for x in p["groups"]}
    g["quarantine"]["ips"] = ["10.60.99.99"]          # example compromised host
    g["it_admins"]["ips"] = ["10.60.11.222"]          # Opsuser's IT security host
    g["staff"]["ips"] = ["10.60.11.0/24"]
    g["staff"]["deny_domains"] = ["facebook.com", "youtube.com", "tiktok.com"]
    # kiosk left empty on purpose — see the payment-rails test below
    g["kiosk"]["ips"] = []
    p["options"]["drop_connection"] = True
    return p


CASES = [
    # label, client, url, expected
    ("HTTPS block now works: staff -> facebook", "10.60.11.58",
     "https://www.facebook.com/", "deny"),
    ("staff -> youtube (HTTPS)", "10.60.11.58", "https://m.youtube.com/", "deny"),
    ("staff -> ordinary HTTPS still fine", "10.60.11.58",
     "https://www.google.com/", "allow"),
    ("staff -> ordinary HTTP still fine", "10.60.11.58",
     "http://neverssl.com/", "allow"),

    ("quarantined host -> HTTPS", "10.60.99.99", "https://www.google.com/", "deny"),
    ("quarantined host -> HTTP", "10.60.99.99", "http://example.com/", "deny"),

    ("IT admin -> dropbox (policy tier bypassed)", "10.60.11.222",
     "https://www.dropbox.com/", "allow"),
    ("IT admin -> anydesk (security tier still denies)", "10.60.11.222",
     "https://anydesk.com/", "deny"),

    # --- the integrations that must NOT break -----------------------------
    ("PAYMENT: paygate2 client -> igw.paygate2.example.com", "10.31.2.7",
     "https://igw.paygate2.example.com/api", "allow"),
    ("PAYMENT: paygate1 client -> gw.paygate1.example.com", "10.31.2.10",
     "https://gw.paygate1.example.com/token", "allow"),
    ("PAYMENT: NID client -> prportal.nid.example.gov", "10.50.2.11",
     "https://prportal.nid.example.gov/x", "allow"),
    ("PAYMENT: NPA client -> gateway.pension.example.gov", "10.50.2.46",
     "https://gateway.pension.example.gov/x", "allow"),
    ("PAYMENT: nagad port 10900 CONNECT", "10.31.2.7",
     "https://gw.paygate1.example.com:10900/x", "allow"),
    ("CPA client -> 10.50.1.243 (dst IP rule)", "10.60.11.58",
     "http://10.50.1.243/app", "allow"),
    ("internal .examplebank.internal still reachable", "10.60.11.58",
     "https://intranet.examplebank.internal/", "allow"),
    ("BB portal on 8443", "10.60.11.58", "https://www.cb.example.gov:8443/", "allow"),

    # --- SSH over CONNECT exception ---------------------------------------
    ("ssh_client -> CONNECT :22", "10.60.6.118", "https://git.example.com:22/",
     "allow"),
    ("non-ssh client -> CONNECT :22", "10.60.11.58",
     "https://git.example.com:22/", "deny"),

    # --- port safety unchanged --------------------------------------------
    ("unsafe port 23 denied", "10.60.11.58", "http://x.example.com:23/", "deny"),

    # --- global tiers for everyone ----------------------------------------
    ("normal -> mining pool", "10.104.5.5", "https://pool.minexmr.com/", "deny"),
    ("normal -> teamviewer", "10.104.5.5", "https://teamviewer.com/", "deny"),
    ("normal -> pastebin (policy tier)", "10.104.5.5", "https://pastebin.com/", "deny"),
    ("normal -> raw IP url", "10.104.5.5", "http://93.184.216.34/x", "deny"),
]


def main():
    os.makedirs(sp.LISTS, exist_ok=True)
    os.makedirs(sp.BACKUPS, exist_ok=True)
    norm = sp.validate(their_policy())
    policy_cfg = sp.generate(norm)
    open("/tmp/policy_for_examplebank.conf", "w").write(policy_cfg)

    # splice the include exactly where it has to go: after their CONNECT port
    # guard, before `http_access allow CONNECT SSL_ports`
    merged = THEIR_RULES_HEAD + policy_cfg.splitlines() + THEIR_RULES_TAIL
    sim = Sim(THEIR_ACLS, merged)

    print(f"simulating {len(sim.rules)} http_access rules "
          f"({len(policy_cfg.splitlines())} lines spliced in)\n")
    print(f"{'case':<46}{'want':<8}{'got':<8}")
    print("-" * 86)
    fails = 0
    for label, client, url, want in CASES:
        got, idx, rule = sim.decide(req(client, url))
        if got == "default":
            got = "deny"          # their config ends with `http_access deny all`
        ok = got == want
        if not ok:
            fails += 1
        print(f"{label:<46}{want:<8}{got:<8}{'' if ok else '  <-- MISMATCH'}")
        if not ok:
            print(f"{'':<46}matched: {rule}")
    print("-" * 86)
    print(f"{len(CASES) - fails}/{len(CASES)} passed")

    # what happens if someone puts a payment host into allowlist_only?
    print("\n--- guard: payment host in an allowlist_only group ---")
    p = their_policy()
    k = [g for g in p["groups"] if g["id"] == "kiosk"][0]
    k["ips"] = ["10.31.2.7"]
    k["allow_domains"] = ["cb.example.gov"]          # forgot the payment gateways
    try:
        n2 = sp.validate(p)
        cfg2 = sp.generate(n2)
        s2 = Sim(THEIR_ACLS, THEIR_RULES_HEAD + cfg2.splitlines() + THEIR_RULES_TAIL)
        got, _, rule = s2.decide(req("10.31.2.7", "https://igw.paygate2.example.com/api"))
        print(f"  paygate2 call from 10.31.2.7 -> {got}   (rule: {rule})")
        print("  ** allowlist_only on a payment host DOES break the rail —"
              " the tool cannot guess the gateways, so this must be caught by"
              " review. Documented in the runbook. **"
              if got == "deny" else "  (allowed — gateways were covered)")
    except sp.Refuse as e:
        print(f"  refused at validation: {e}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
