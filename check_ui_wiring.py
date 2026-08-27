#!/usr/bin/env python3
"""Static consistency check for the dashboard's inline HTML/JS.

The UI is one big template string, so a mistyped element id fails silently in
the browser at click time rather than at import time. This walks every $('id')
reference in the JS and asserts the element actually exists in the markup, then
checks that each ev* CSS class the evidence panel uses is really styled.
"""
import importlib.machinery
import importlib.util
import re
import sys

_l = importlib.machinery.SourceFileLoader("dash", "/agent/workspace/squid_dashboard.py")
dash = importlib.util.module_from_spec(importlib.util.spec_from_loader("dash", _l))
sys.modules["dash"] = dash
_l.exec_module(dash)

html = dash.INDEX_HTML
fails = 0

ids = set(re.findall(r'id="([^"]+)"', html))
refs = set(re.findall(r"\$\('([^']+)'\)", html))
missing = sorted(refs - ids)
print(f"element ids in markup   : {len(ids)}")
print(f"ids referenced from JS  : {len(refs)}")
print(f"referenced but MISSING  : {missing if missing else 'none'}")
fails += len(missing)

print("\n--- alert -> evidence wiring ---")
for token, what in [
    ('id="evmask"', "evidence modal container"),
    ('id="ev_title"', "modal title element"),
    ('id="ev_body"', "modal body element"),
    ('id="ev_close"', "close button"),
    ("function openAlert", "openAlert() is defined"),
    ("openAlert(row.dataset.seq)", "clicking a row calls openAlert"),
    ("tr.arow", "clickable-row style"),
    (".evcue", "'requests' cue style"),
    (".evtab", "evidence table style"),
    ("data-seq=", "rows carry the alert seq"),
    ("/api/alert?seq=", "evidence endpoint is fetched"),
    ("openDetail(el.dataset.kind", "can drill from evidence into client/host"),
    ("closest('.blockbtn')", "block button still handled before the row click"),
]:
    ok = token in html
    fails += 0 if ok else 1
    print(f"  {'OK     ' if ok else 'MISSING'}  {what}")

used = set(re.findall(r'class="(ev[a-z]+)"', html))
styled = set(re.findall(r"\.(ev[a-z]+)\s*[{,:]", html))
unstyled = sorted(used - styled)
print(f"\nev* classes used but not styled: {unstyled or 'none'}")
fails += len(unstyled)

# the modals the Escape key should close
esc = re.search(r"key==='Escape'\)\{(.+?)\}\}\)", html, re.S)
if esc:
    closed = set(re.findall(r"\$\('(\w+)'\)\.classList\.remove", esc.group(1)))
    want = {"mask", "dmask", "evmask", "pmask"}
    gap = sorted(want - closed)
    print(f"Escape closes: {sorted(closed)}"
          + (f"   MISSING: {gap}" if gap else ""))
    fails += len(gap)
else:
    print("could not find the Escape handler")
    fails += 1

print(f"\n{'PASS' if not fails else f'{fails} PROBLEM(S)'}")
sys.exit(1 if fails else 0)
