#!/usr/bin/env python3
"""Verify the bank blacklist regexes: must catch the risky hosts and must NOT
fire on domains a bank legitimately uses every day."""
import re

PATTERNS = {
"exfil-storage": r"\b(?:dropbox|mega\.(?:nz|io)|mediafire|4shared|zippyshare|sendspace|wetransfer|filemail|terabox|pcloud|anonfiles|gofile\.io|file\.io|krakenfiles|bayfiles|uploadfiles\.io|dosyaupload)\b|\b(?:pastebin\.com|paste\.ee|ghostbin|hastebin|privnote|justpaste\.it|controlc\.com|0bin\.net|rentry\.co|dpaste\.(?:com|org))\b",
"tunnel-anonymizer": r"\.onion\b|\btorproject\.org\b|\b(?:teamviewer|anydesk|logmein|gotomypc|rustdesk|ultraviewer|radmin|ammyy|showmypc|splashtop)\b|\b(?:ngrok\.(?:io|com|app)|localtunnel|trycloudflare\.com|serveo\.net|pagekite|portmap\.io|localhost\.run)\b|\b(?:nordvpn|expressvpn|protonvpn|surfshark|windscribe|tunnelbear|zenmate|hotspotshield|psiphon\d*|ultrasurf|browsec|hola\.org|vpngate|softether)\b",
"crypto-mining": r"\b(?:xmrig|minexmr|nanopool|ethermine|f2pool|poolin|antpool|2miners|hiveon|cryptonight|coinhive|coin-hive|jsecoin|webminepool|minergate|supportxmr)\b|\bstratum\+tcp\b",
"dyndns-c2": r"\b(?:duckdns\.org|no-ip\.(?:com|org|biz)|ddns\.net|dynu\.com|hopto\.org|zapto\.org|serveftp\.com|myftp\.(?:biz|org)|redirectme\.net|sytes\.net|afraid\.org|freedns\.|changeip\.com|dnsdynamic)\b",
"personal-webmail": r"\b(?:mail\.ru|yandex\.(?:com|ru)/?mail|protonmail\.com|proton\.me|tutanota\.com|gmx\.(?:com|net)|mail\.com|temp-mail\.org|10minutemail|guerrillamail|mailinator|yopmail)\b",
}

MUST_MATCH = {
"exfil-storage": ["dropbox.com", "www.dropbox.com/s/abc/report.xlsx", "mega.nz",
                  "wetransfer.com", "gofile.io", "file.io", "pastebin.com",
                  "privnote.com", "anonfiles.com", "terabox.com", "rentry.co"],
"tunnel-anonymizer": ["expyuzz4wqqyqhjn.onion", "www.torproject.org", "anydesk.com",
                      "teamviewer.com", "abc123.ngrok.io", "test.trycloudflare.com",
                      "nordvpn.com", "psiphon3.com", "hola.org", "rustdesk.com",
                      "xyz.localhost.run"],
"crypto-mining": ["pool.minexmr.com", "eu.nanopool.org", "xmrig.com",
                  "supportxmr.com", "stratum+tcp://pool.example.com:3333",
                  "f2pool.com", "2miners.com"],
"dyndns-c2": ["evil.duckdns.org", "c2.no-ip.com", "beacon.ddns.net",
              "host.hopto.org", "x.sytes.net", "panel.dynu.com"],
"personal-webmail": ["mail.ru", "protonmail.com", "proton.me", "temp-mail.org",
                     "mailinator.com", "guerrillamail.com"],
}

# Domains a bank actually uses — none of these may fire on ANY pattern
BENIGN = [
 "example-bank.com.bd", "www.cb.example.gov", "centralbank.example.gov", "swift.com",
 "www.visa.com", "mastercard.com", "secure.napas.com", "temenos.com",
 "finastra.com", "oracle.com", "login.microsoftonline.com", "outlook.office365.com",
 "windowsupdate.microsoft.com", "download.windowsupdate.com", "github.com",
 "pypi.org", "cdn.jsdelivr.net", "google.com", "www.linkedin.com",
 "tenable.com", "crowdstrike.com", "trellix.com", "checkpoint.com",
 # substring traps: must NOT match "tor", "poolin", "mega", "file", "mail"
 "store.bank.com", "mentor.example.com", "doctor.com", "contractor.com",
 "history.com", "megatrends.com", "carpooling.example.com", "antpoolside.com",
 "filemaker.com", "myfile.io.example.com", "gmail.com", "webmail.example-bank.com.bd",
 "mailchimp.com", "email.example-bank.com.bd", "detailed.com", "retailer.com",
 "restaurantpool.com", "torque.example.com", "victoria.com", "auditor.com",
]

fail = 0
print("=" * 72)
for name, pat in PATTERNS.items():
    rx = re.compile(pat, re.I)
    print(f"\n[{name}]")
    missed = [h for h in MUST_MATCH[name] if not rx.search(h)]
    if missed:
        fail += len(missed); print("  MISSED (should have matched):")
        for m in missed: print("    -", m)
    else:
        print(f"  caught all {len(MUST_MATCH[name])} risky samples")
    fps = [h for h in BENIGN if rx.search(h)]
    if fps:
        fail += len(fps); print("  FALSE POSITIVES on benign bank domains:")
        for f in fps: print("    !", f, "->", rx.search(f).group(0))
    else:
        print(f"  no false positives across {len(BENIGN)} benign domains")

print("\n" + "=" * 72)
print("ALL CLEAN" if not fail else f"{fail} PROBLEM(S) FOUND")
