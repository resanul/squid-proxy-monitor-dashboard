#!/usr/bin/env python3
"""Simulate Squid's http_access evaluation against the config squid-policy
generates, and assert the intended per-IP outcomes.

Reading generated ACL rules by eye is exactly how proxy outages happen, so the
rules are executed here the way Squid executes them: first match wins, ACLs on
one line are ANDed, dstdomain matches a bare name exactly and a dotted name as
a suffix.
"""
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
import re
import sys

os.environ.setdefault("SQUID_POLICY_DIR", "/tmp/poltest/etc")
os.environ.setdefault("SQUID_BIN", "/tmp/poltest/bin/squid")
os.environ.setdefault("SQUID_POLICY_AUDIT", "/tmp/poltest/audit.log")

_loader = importlib.machinery.SourceFileLoader("sp", "/agent/workspace/squid-policy")
_spec = importlib.util.spec_from_loader("sp", _loader)
sp = importlib.util.module_from_spec(_spec)
_loader.exec_module(sp)


# --------------------------------------------------------------------------- #
#  a small Squid http_access evaluator
# --------------------------------------------------------------------------- #

class SquidSim:
    def __init__(self, config_text):
        self.acls = {}          # name -> (type, [values])
        self.rules = []         # (allow|deny, [acl names])
        for line in config_text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("acl "):
                m = re.match(r'acl\s+(\S+)\s+(\S+)\s+(.*)$', line)
                if not m:
                    continue
                name, atype, rest = m.groups()
                if rest.startswith('"'):
                    path = rest.strip('"')
                    with open(path) as fh:
                        vals = [l.strip() for l in fh
                                if l.strip() and not l.startswith("#")]
                else:
                    vals = [v for v in rest.split() if v not in ("-i",)]
                self.acls[name] = (atype, vals)
            elif line.startswith("http_access "):
                parts = line.split()
                self.rules.append((parts[1], parts[2:]))

    # -- individual ACL types ---------------------------------------------- #
    def _match_acl(self, name, client, url, host):
        neg = name.startswith("!")
        name = name.lstrip("!")
        r = self._match_one(name, client, url, host)
        return (not r) if neg else r

    def _match_one(self, name, client, url, host):
        atype, vals = self.acls.get(name, (None, []))
        if atype == "src":
            ip = ipaddress.ip_address(client)
            for v in vals:
                try:
                    if ip in ipaddress.ip_network(v, strict=False):
                        return True
                except ValueError:
                    continue
            return False
        if atype == "dstdomain":
            # real Squid semantics, confirmed live against Squid 5.5:
            #   "d.com"  matches ONLY the exact host d.com
            #   ".d.com" matches d.com AND every subdomain of it
            # Modelling the bare form as a suffix match (an earlier version of
            # this file) hid a real bug: www.dropbox.com stayed reachable
            # while dropbox.com was blocked.
            h = host.lower()
            for v in vals:
                v = v.lower()
                if v.startswith("."):
                    if h == v[1:] or h.endswith(v):
                        return True
                elif h == v:
                    return True
            return False
        if atype == "url_regex":
            for v in vals:
                try:
                    if re.search(v, url):
                        return True
                except re.error:
                    continue
            return False
        if atype == "dst":
            try:
                dip = ipaddress.ip_address(host)
            except ValueError:
                return False
            for v in vals:
                try:
                    if dip in ipaddress.ip_network(v, strict=False):
                        return True
                except ValueError:
                    continue
            return False
        return False

    def decide(self, client, url):
        """Return ('allow'|'deny'|'default', matched rule index)."""
        host = re.sub(r"^[a-z]+://", "", url).split("/")[0].split(":")[0]
        for i, (action, names) in enumerate(self.rules):
            if all(self._match_acl(n, client, url, host) for n in names):
                return action, i
        return "default", -1


# --------------------------------------------------------------------------- #
#  build the policy that covers the four requirements
# --------------------------------------------------------------------------- #

def build_policy():
    p = sp.baseline_policy()
    g = {x["id"]: x for x in p["groups"]}
    g["quarantine"]["ips"] = ["10.60.10.41"]                    # 1 no internet
    g["it_admins"]["ips"] = ["10.50.0.22", "10.50.0.23"]   # 3 full access
    g["kiosk"]["ips"] = ["10.31.2.7"]                            # 4 allow-only
    g["kiosk"]["allow_domains"] = ["cb.example.gov", "example-bank.com.bd"]
    g["staff"]["ips"] = ["10.60.11.0/24"]                       # 2 per-IP deny
    g["staff"]["deny_domains"] = ["facebook.com", "youtube.com"]
    g["staff"]["deny_urls"] = [r"^http://intranet-test\.local/admin/"]
    return p


CASES = [
    # (label, client, url, expected)
    # --- 1) blacklisted IP: no internet at all -------------------------------
    ("quarantined -> ordinary site",   "10.60.10.41", "https://www.google.com/", "deny"),
    ("quarantined -> bank site",       "10.60.10.41", "https://cb.example.gov/",      "deny"),
    ("quarantined -> windowsupdate",   "10.60.10.41", "http://windowsupdate.microsoft.com/x.cab", "deny"),

    # --- 2) per-IP URL/domain deny ------------------------------------------
    ("staff -> facebook (denied)",     "10.60.11.58", "https://facebook.com/",    "deny"),
    ("staff -> www.facebook (denied)", "10.60.11.58", "https://www.facebook.com/","deny"),
    ("staff -> youtube (denied)",      "10.60.11.58", "https://m.youtube.com/",   "deny"),
    ("staff -> denied url path",       "10.60.11.58", "http://intranet-test.local/admin/x", "deny"),
    ("staff -> same host other path",  "10.60.11.58", "http://intranet-test.local/public/x", "default"),
    ("staff -> ordinary site",         "10.60.11.58", "https://www.google.com/",  "default"),
    ("non-staff -> facebook",          "10.20.0.9",    "https://facebook.com/",    "default"),

    # --- 3) whitelisted IP: full internet -----------------------------------
    ("admin -> policy-blocked site",   "10.50.0.22", "https://dropbox.com/",    "allow"),
    ("admin -> ordinary site",         "10.50.0.22", "https://www.google.com/", "allow"),
    ("admin -> facebook",              "10.50.0.22", "https://facebook.com/",   "allow"),
    # the security tier must still bite, even for an unrestricted host
    ("admin -> anydesk (SECURITY)",    "10.50.0.22", "https://anydesk.com/",    "deny"),
    ("admin -> mining pool (SECURITY)","10.50.0.22", "https://pool.minexmr.com/","deny"),

    # --- 4) allowlist-only IP ----------------------------------------------
    ("kiosk -> permitted bank site",   "10.31.2.7", "https://cb.example.gov/",          "allow"),
    ("kiosk -> permitted subdomain",   "10.31.2.7", "https://www.example-bank.com.bd/","allow"),
    ("kiosk -> anything else",         "10.31.2.7", "https://www.google.com/",     "deny"),
    ("kiosk -> facebook",              "10.31.2.7", "https://facebook.com/",       "deny"),

    # --- global tiers for everyone else -------------------------------------
    ("normal -> mining pool",          "10.20.0.9", "https://pool.minexmr.com/",   "deny"),
    ("normal -> anydesk",              "10.20.0.9", "https://anydesk.com/",        "deny"),
    ("normal -> dropbox (policy)",     "10.20.0.9", "https://dropbox.com/",        "deny"),
    # regression: a bare dstdomain entry blocked the apex but let www.* pass.
    # Found live — www.dropbox.com tunnelled fine minutes after the policy
    # had "successfully" applied. Every blocked service needs its subdomains
    # covered, and the dot form must not over-match a lookalike domain.
    ("normal -> www.dropbox (policy)", "10.20.0.9", "https://www.dropbox.com/",    "deny"),
    ("normal -> www.anydesk (SEC)",    "10.20.0.9", "https://www.anydesk.com/",    "deny"),
    ("normal -> deep sub of anydesk",  "10.20.0.9", "https://a.b.anydesk.com/",    "deny"),
    ("normal -> lookalike NOT blocked","10.20.0.9", "https://notdropbox.com/",     "default"),
    ("normal -> suffix-trap NOT blkd", "10.20.0.9", "https://myanydesk.com/",      "default"),
    ("normal -> raw-IP url",           "10.20.0.9", "http://93.184.216.34/x",      "deny"),
    ("normal -> windowsupdate OK",     "10.20.0.9", "http://windowsupdate.microsoft.com/x.cab", "default"),
    ("normal -> bank site OK",         "10.20.0.9", "https://cb.example.gov/",          "default"),
    ("normal -> google OK",            "10.20.0.9", "https://www.google.com/",     "default"),
]


def main():
    os.makedirs(sp.LISTS, exist_ok=True)
    os.makedirs(sp.BACKUPS, exist_ok=True)
    norm = sp.validate(build_policy())
    cfg = sp.generate(norm)
    open("/tmp/generated.conf", "w").write(cfg)
    sim = SquidSim(cfg)

    print(f"parsed {len(sim.acls)} ACLs, {len(sim.rules)} http_access rules\n")
    print(f"{'case':<34}{'client':<16}{'want':<9}{'got':<9}")
    print("-" * 74)
    fails = 0
    for label, client, url, want in CASES:
        got, idx = sim.decide(client, url)
        ok = got == want
        if not ok:
            fails += 1
        rule = (" ".join([sim.rules[idx][0]] + sim.rules[idx][1])
                if idx >= 0 else "(no rule matched -> site default)")
        print(f"{label:<34}{client:<16}{want:<9}{got:<9}{'' if ok else '  <-- MISMATCH'}")
        if not ok:
            print(f"{'':<34}matched: {rule}")
    print("-" * 74)
    print(f"{len(CASES) - fails}/{len(CASES)} passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
