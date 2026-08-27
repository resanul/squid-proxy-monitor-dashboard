# Squid Proxy Live Dashboard  ·  v1.6.0

Real-time, interactive web dashboard for Squid proxy. **Pure Python stdlib — কোনো pip install লাগবে না।**

> **সঠিক version চালাচ্ছেন কি না দেখে নিন:**
> ```bash
> python3 squid_dashboard.py --version      # 1.6.0 দেখাতে হবে
> ```
> `error: unrecognized arguments: --ssh` এলে পুরোনো file চালাচ্ছেন — নতুনটা download করুন।
>
> **Windows এ `python3` কাজ না করলে `python` লিখুন** (`python3 : The term 'python3' is not
> recognized` এলে)। Windows এ সাধারণত শুধু `python` থাকে; Linux/macOS এ `python3`।
> v1.0 = local tail · v1.1 = + alerts · v1.2 = + remote (ssh/udp/tcp) · v1.3 = + blocklist · v1.4 = + multi-proxy · v1.5 = + drill-down · v1.6 = + URL block / TCP_RESET

## Quick start

```bash
# 1) আগে demo mode এ দেখে নিন (Squid ছাড়াই চলবে)
python3 squid_dashboard.py --demo

# 2) Squid অন্য মেশিনে আছে? (সবচেয়ে সহজ — শুধু SSH লাগবে)
python3 squid_dashboard.py --ssh root@10.0.0.5:/var/log/squid/access.log

# 3) log local বা mounted share এ থাকলে
python3 squid_dashboard.py --log /var/log/squid/access.log
```

তারপর ব্রাউজারে খুলুন → **http://127.0.0.1:8899**

---

## একাধিক proxy একসাথে (dropdown দিয়ে বেছে নেওয়া)

দুইভাবে যোগ করা যায়:

```bash
# A) command line এ (NAME= অংশটা dropdown এর label)
python3 squid_dashboard.py \
  --proxy "Proxy 105.8=opsuser@10.50.0.8:/var/log/squid/access.log" \
  --proxy "Proxy 105.7=opsuser@10.50.0.7:/var/log/squid/access.log"

# B) config file এ (সুবিধাজনক — একবার লিখে রাখুন)
python3 squid_dashboard.py --proxies-config squid_proxies.json
```

Header এ একটা **dropdown** আসবে, সাথে নিচে প্রতিটা proxy র জন্য একটা chip
(সবুজ/লাল dot + request count + alert count) — chip এ ক্লিক করেও switch করা যায়।

**▦ All proxies** option টা সব proxy কে **একসাথে** দেখায় — KPI যোগ হয়, leaderboard গুলো
merge হয়, আর live feed + alert log এ কোন proxy থেকে এসেছে সেটার label থাকে।

### গুরুত্বপূর্ণ: প্রতিটা proxy সম্পূর্ণ আলাদা

| জিনিস | কীভাবে কাজ করে |
|---|---|
| Counters / KPI | প্রতি proxy আলাদা |
| Alert window | **প্রতি proxy আলাদা** — একটা ব্যস্ত proxy অন্যটার threshold ছোঁয় না |
| Alert rules | সবার জন্য এক (একবার edit করলে সব proxy তে লাগে) |
| Alert notification | যে proxy তে ঘটেছে সেটার নাম label করা থাকে, অন্য proxy দেখলেও toast আসে |
| Blocklist | **যে proxy দেখছেন সেটাতেই** apply হয় (confirm dialog এ নাম দেখায়) |
| CSV export | বর্তমান selection অনুযায়ী |

Blocklist এর ক্ষেত্রে এটা জরুরি — ভুল proxy তে domain block হয়ে গেলে বিপদ। তাই প্রতিটা
proxy র নিজের helper connection আলাদা, আর confirm dialog এ proxy র নাম দেখানো হয়।

### প্রতিটা নতুন proxy তে যা লাগবে

নতুন proxy যোগ করার আগে ওই server এও দুইটা জিনিস দরকার:

```powershell
# 1) SSH key বসান (একবার password লাগবে)
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh USER@NEWPROXY "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

# 2) log পড়ার অনুমতি (RHEL এ ACL সবচেয়ে নিরাপদ)
ssh -t USER@NEWPROXY "sudo setfacl -m u:USER:rx /var/log/squid; sudo setfacl -m u:USER:r /var/log/squid/access.log; sudo setfacl -d -m u:USER:r /var/log/squid"

# 3) যাচাই — সব proxy একসাথে check হয়
python3 squid_dashboard.py --proxies-config squid_proxies.json --check
```

`--check` এখন config এর **প্রতিটা** SSH proxy আলাদা করে যাচাই করে।

---

## Remote proxy থেকে data আনা (script আপনার PC তে চলবে)

Squid server এ কিছু install করার দরকার নেই। চারটা transport আছে — পরিস্থিতি অনুযায়ী বেছে নিন:

### Option 1 — SSH (recommended, proxy এ কোনো change লাগে না)

```bash
python3 squid_dashboard.py --ssh squiduser@10.0.0.5:/var/log/squid/access.log

# key file, custom port, sudo দরকার হলে
python3 squid_dashboard.py \
  --ssh squiduser@10.0.0.5:/var/log/squid/access.log \
  --ssh-key ~/.ssh/id_ed25519 --ssh-port 2222 --ssh-sudo
```

ভেতরে যা হয়: `ssh proxy "tail -F access.log"` চলে আর output stream হয়ে আসে।

**প্রথমে `--check` চালান** — SSH login আর log permission দুইটাই যাচাই করে, সমস্যা থাকলে
ঠিক কী command চালাতে হবে সেটা বলে দেয়:
```bash
python3 squid_dashboard.py --ssh opsuser@10.50.9.165:/var/log/squid/access.log --check
```

- **Key-based login বাধ্যতামূলক** (`BatchMode` — password prompt এ আটকে থাকবে না)।

  Linux/macOS এ: `ssh-copy-id squiduser@10.0.0.5`

  **Windows (PowerShell)** — `ssh-copy-id` নেই, তাই:
  ```powershell
  ssh-keygen -t ed25519                      # key না থাকলে (Enter চাপতে থাকুন)
  type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh squiduser@10.0.0.5 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
  ssh squiduser@10.0.0.5 "echo OK"           # password ছাড়াই OK আসতে হবে
  ```
  শেষ command টা password ছাড়া কাজ না করলে dashboard ও connect করতে পারবে না।

- **Key তে passphrase থাকলে** BatchMode এ কাজ করবে না (script prompt এর উত্তর দিতে পারে না)।
  `Enter passphrase for key` দেখলে দুইটা উপায়:
  ```powershell
  # A) passphrase রেখেই — ssh-agent এ key load করুন (recommended)
  Get-Service ssh-agent | Set-Service -StartupType Automatic
  Start-Service ssh-agent
  ssh-add $env:USERPROFILE\.ssh\id_ed25519

  # B) passphrase তুলে দিন (সহজ)
  ssh-keygen -p -f $env:USERPROFILE\.ssh\id_ed25519    # নতুন passphrase খালি রাখুন
  ```
  `--check` নিজেই ধরতে পারে key encrypted কি না আর agent এ load আছে কি না।
- **`access.log` সাধারণত world-readable না** (`640 root:root` বা `proxy:proxy`)। তাই
  normal user দিয়ে `Permission denied` আসতে পারে। দুইটা সমাধান:
  ```bash
  # proxy server এ (recommended)
  sudo usermod -a -G proxy opsuser     # Debian/Ubuntu; RHEL এ group টা 'squid'
  # অথবা dashboard চালান --ssh-sudo দিয়ে (remote এ NOPASSWD sudo লাগবে)
  ```
  আগে যাচাই করুন: `ssh USER@PROXY "tail -n 2 /var/log/squid/access.log"`

  **`sudo` চালাতে `ssh -t` লাগবে** — না হলে `sudo: a terminal is required to read the
  password` আসবে (SSH command mode এ terminal থাকে না):
  ```powershell
  ssh -t USER@PROXY "sudo usermod -a -G proxy USER"
  ```
  নোট: `--ssh-sudo` flag টা `sudo -n` (password ছাড়া) ব্যবহার করে, তাই sudo password
  লাগলে ওটা কাজ করবে না — group membership ই সঠিক সমাধান।

  > Password কখনো command line এ দেবেন না — shell history আর process list এ থেকে যায়।
  > তাই এই tool এ `--ssh-password` option নেই; key auth ব্যবহার করুন।
- Link ছিঁড়ে গেলে **নিজে থেকে reconnect** করে (exponential backoff, max 30s)।
  Reconnect এর সময় পুরোনো line আবার count হয় না
- Windows এ OpenSSH না থাকলে: `--ssh-bin "C:\path\to\plink.exe"`

### Option 2 — Squid নিজেই push করবে (UDP), SSH ছাড়া

আপনার PC তে:
```bash
python3 squid_dashboard.py --udp-port 5140
```
Squid server এর `squid.conf` এ একটা line যোগ করুন (`<YOUR_PC_IP>` বসান):
```
access_log udp://<YOUR_PC_IP>:5140 squid
```
তারপর `squid -k reconfigure`

আগের local log file রাখতে চাইলে দুইটা line একসাথেই রাখতে পারেন:
```
access_log /var/log/squid/access.log squid
access_log udp://<YOUR_PC_IP>:5140 squid
```

> UDP তে packet হারাতে পারে (fire-and-forget), আর PC র IP বদলালে config বদলাতে হবে।
> rsyslog দিয়ে forward করলেও কাজ করবে — syslog prefix নিজে থেকেই strip হয়।

### Option 3 — Squid push করবে (TCP), reliable stream

```bash
python3 squid_dashboard.py --tcp-port 5141
```
```
access_log tcp://<YOUR_PC_IP>:5141 squid
```
UDP এর মতোই, কিন্তু TCP তাই line হারায় না। Squid restart করলে reconnect হয়।

> ⚠️ Squid এর TCP log module এ receiver down থাকলে Squid block হতে পারে। Production
> proxy তে UDP বা SSH বেশি নিরাপদ।

### Option 4 — Mounted share

sshfs / SMB / NFS দিয়ে log mount করে সাধারণ `--log` ব্যবহার করুন:
```bash
sshfs squiduser@10.0.0.5:/var/log/squid /mnt/squid -o ro
python3 squid_dashboard.py --log /mnt/squid/access.log
```

### Cache manager stats (optional)

SSH mode এ `--squid-host` নিজে থেকেই proxy IP ধরে নেয়। এই panel ভরতে Squid এর
manager interface আপনার PC থেকে allow করতে হবে:
```
acl dashboard src <YOUR_PC_IP>/32
http_access allow manager dashboard
```
না দিলে dashboard শুধু ওই panel টা "denied" দেখাবে — বাকি সব monitoring আগের মতোই চলবে।
`squidclient` binary লাগে **না**; protocol টা সরাসরি socket এ কথা বলে (দরকার হলে
`squidclient` থাকলে fallback হিসেবে ব্যবহার করে)।

### Header এ connection status

উপরের pill এ live source দেখা যায় — `🔗 ssh://…`, `📡 udp://…`, `🔌 tcp://…`, `📄 file`।
সবুজ dot = connected, লাল = down (কারণ সহ banner দেখাবে), সাথে reconnect count।

## Requirements

- আপনার PC তে **Python 3.8+** (আর কিছুই না — কোনো pip package লাগে না)
- Proxy server এ **কিছুই install করতে হবে না**
- Data আনার জন্য যেকোনো একটা: SSH access, বা Squid এ একটা `access_log` line যোগ করার সুযোগ,
  বা log file টা mounted থাকা

Local log পড়তে গিয়ে permission error এলে:
```bash
sudo usermod -a -G squid $USER    # তারপর re-login
```

## Options

| Flag | কাজ | Default |
|---|---|---|
| `--ssh USER@HOST:/PATH` | remote proxy থেকে SSH দিয়ে log stream | — |
| `--ssh-key` / `--ssh-port` / `--ssh-sudo` | SSH key, port, sudo দিয়ে tail | — / 22 / off |
| `--check` | SSH login + log permission যাচাই করে exit (ssh mode এ) | off |
| `--ssh-bin` | ssh binary (Windows এ plink.exe) | `ssh` |
| `--udp-port N` | Squid এর `access_log udp://` receive করা | — |
| `--tcp-port N` | Squid এর `access_log tcp://` receive করা | — |
| `--listen-bind` | UDP/TCP listener bind address | `0.0.0.0` |
| `--log PATH` | local বা mounted access.log | auto-detect |
| `--host` | dashboard bind address | `127.0.0.1` |
| `--port` | dashboard port | `8899` |
| `--squid-host` / `--squid-port` | cache manager address | SSH host / `3128` |
| `--squid-pass` | cache manager password | — |
| `--no-cachemgr` | cache manager polling বন্ধ | off |
| `--backfill N` | শুরুতে কত পুরোনো line preload হবে | `2000` |
| `--demo` | synthetic traffic (Squid দরকার নেই) | off |
| `--demo-rate N` | demo mode এ req/sec | `6` |
| `--proxy NAME=USER@HOST:/PATH` | একটা proxy যোগ করে (একাধিকবার দেওয়া যায়) | — |
| `--proxies-config FILE` | proxy তালিকার JSON file | — |
| `--alerts-config PATH` | alert rules এর JSON file | `./squid_alerts.json` |
| `--no-alerts` | alert engine বন্ধ | off |
| `--enable-blocklist` | proxy তে block/allow list manage করার feature চালু | **off** |
| `--admin-token` | blocklist change এর জন্য token | auto-generate |
| `--blocklist-helper` | proxy তে helper script এর path | `/usr/local/sbin/squid-blocklist` |

অন্য ডিভাইস থেকে দেখতে চাইলে: `--host 0.0.0.0` (শুধু trusted network এ, কারণ কোনো auth নেই)

## ক্লিক করে বিস্তারিত দেখা (drill-down)

**Top Clients** বা **Top Destinations** এর যেকোনো সারিতে ক্লিক করলে একটা বিস্তারিত panel খোলে।
Live request stream এর client/host column গুলোতেও ক্লিক করা যায়।

একটা client IP এর জন্য যা দেখবেন:

- **KPI** — মোট request, transferred bytes, avg ও worst latency, denied count, error count
- **কখন থেকে কখন** — first seen, last seen, কত সময় ধরে active
- **⚠ এই IP সংক্রান্ত alert** গুলো (থাকলে)
- **Top destinations** — এই client কোন কোন site এ গেছে, কতবার
- **Outcome / status code / method / user / Squid action** breakdown
- **সাম্প্রতিক request** এর তালিকা (url সহ)

Destination host এ ক্লিক করলে উল্টোটা — **কোন কোন client** ওই host এ গেছে।

তিনটা সুবিধা:
- **Pivot** — detail panel এর ভেতরের যেকোনো IP/host এ ক্লিক করলে সেটার detail খোলে (client → host → client…)
- **Filter live feed to this** — ওই entity তে live stream filter হয়ে যায়
- **⛔ Block** — সরাসরি blocklist এ পাঠায় (client হলে src IP, host হলে dstdomain; blocklist unlock করা থাকলে)

> Memory bounded: সর্বোচ্চ ৪০০০ client আর ৪০০০ host track হয়, প্রতিটার শেষ ১৫টা request।
> বেশি হলে সবচেয়ে কম active গুলো বাদ পড়ে — দিনের পর দিন চললেও memory বাড়বে না।

## যা যা মনিটর হয়

**KPI cards** — total requests, req/sec, cache hit ratio, throughput (with live B/s), avg latency, denied count, unique clients, uptime

**Charts** — 120-second scrolling traffic chart (requests/s + cache hits/s + bytes/s), outcome donut (hit/miss/denied/error), status code breakdown

**Leaderboards** — top clients (requests + bytes), top destination hosts, HTTP methods, live Squid cache-manager stats

**Tables** — live request stream (filter by host/client/url/user, outcome, method + pause/resume), denied/blocked requests, slowest requests (>2000ms)

খারাপ domain (malware/torrent/c2/phish pattern) গুলো লাল হয়ে highlight হয়।

## Alert rules

Header এর **⚙ Alert rules** বাটনে ক্লিক করে UI থেকেই rule add/edit/enable করা যায়। Save করলে
`squid_alerts.json` এ লেখা হয় — restart করলেও rule গুলো থাকবে।

Alert fire করলে তিনভাবে জানানো হয়:
- **Toast** — উপরে ডান দিকে slide করে আসে (critical toast নিজে থেকে যায় না, manually বন্ধ করতে হয়)
- **Desktop notification** — `🔔 Notify` বাটনে একবার permission দিলে browser minimize থাকলেও notification আসবে
- **Sound** — `🔈 Sound` toggle (severity অনুযায়ী আলাদা tone; WebAudio, কোনো audio file লাগে না)

Critical alert এ browser tab এর title ও বদলে যায়, আর সব alert নিচের **Alert log** table এ জমা থাকে।

### Rule types

| Type | কী চেক করে | Fields |
|---|---|---|
| `blacklist` | প্রতিটা request এর host/URL regex এর সাথে মেলে কিনা (instant) | `pattern` |
| `denied_rate` | window এ denied request সংখ্যা | `window`, `threshold` |
| `error_rate` | window এ error response সংখ্যা | `window`, `threshold` |
| `bandwidth_spike` | একক client এর window এ transfer | `window`, `threshold_mb` |
| `client_request_rate` | একক client এর window এ request সংখ্যা | `window`, `threshold` |
| `slow_rate` | window এ slow request সংখ্যা | `window`, `threshold`, `latency_ms` |
| `hit_ratio_low` | cache hit ratio নির্দিষ্ট % এর নিচে | `window`, `threshold_pct`, `min_requests` |
| `status_code` | নির্দিষ্ট status code কতবার এলো | `window`, `threshold`, `code` |

প্রতিটা rule এ `severity` (`info`/`warning`/`critical`) আর `cooldown` (সেকেন্ড) থাকে।
**Cooldown** একই alert বারবার আসা আটকায় — `bandwidth_spike` আর `client_request_rate` এর ক্ষেত্রে
cooldown **per-client**, আর `blacklist` এর ক্ষেত্বে **per-host**, তাই একটা noisy client
অন্য client এর alert চাপা দেয় না।

Default এ ৫টা rule active থাকে (blacklist, denied burst, bandwidth spike, request flood, error rate)
আর ২টা off থাকে (slow pileup, hit ratio collapse) — UI থেকে on করে নিতে পারেন।

### Bank / enterprise ruleset

`squid_alerts_bank.json` — ১৭টা rule (১৫টা enabled) financial institution এর জন্য সাজানো:
data exfiltration (file-sharing, paste site), policy bypass (VPN/TOR/remote access),
crypto mining, dynamic-DNS C2, malware keyword, bandwidth spike (দুই স্তরে),
beaconing rate, denial burst, 407 auth failure, 502/503 upstream error, slow pileup,
cache hit collapse।

```bash
python3 squid_dashboard.py --ssh user@proxy:/var/log/squid/access.log \
        --alerts-config squid_alerts_bank.json
```

Blacklist regex গুলো ৪৩টা আসল banking domain (Bangladesh Bank, SWIFT, Visa, Office 365,
Temenos, Finastra…) আর substring trap (`store`, `mentor`, `filemaker`, `carpooling`,
`antpoolside`) এর বিরুদ্ধে টেস্ট করা — false positive শূন্য।

### Threshold calibration (গুরুত্বপূর্ণ)

Volume-ভিত্তিক threshold গুলো ~৫০০-২০০০ user, ৩০-৮০ req/s peak ধরে বসানো। আপনার
environment আলাদা হলে dashboard থেকে baseline দেখে হিসাব করুন — ব্যস্ত সময়ে ৩০ মিনিট
চালিয়ে KPI card থেকে নিন, তারপর:

| Rule | Formula | কেন |
|---|---|---|
| `denied-burst` | ৬০ সেকেন্ডের স্বাভাবিক denied সংখ্যা × ৩ | normal policy block গুলো alert করবে না |
| `beacon-rate` | peak req/s ÷ unique clients × window × ১০ | একক client স্বাভাবিকের ১০ গুণ করলে ধরবে |
| `exfil-bandwidth` | সবচেয়ে ব্যস্ত client এর ৫ মিনিটের MB × ৩ | software update/backup কে বাদ দেয় |
| `auth-failures` | user সংখ্যা ÷ ১০ (প্রতি মিনিটে) | কিছু 407 স্বাভাবিক, spike না |
| `upstream-5xx` | ২৫ থেকে শুরু, প্রতিদিন ২টার বেশি alert এলে বাড়ান | |
| `hit-collapse` | স্বাভাবিক hit ratio এর অর্ধেক | |

**Rollout পদ্ধতি:** প্রথম সপ্তাহে volume-ভিত্তিক rule গুলো `info` severity তে রাখুন,
Alert log দেখে যেগুলো noise সেগুলোর threshold বাড়ান, তারপর `warning`/`critical` করুন।
Blacklist rule গুলো দিন ১ থেকেই `critical` রাখা যায় — ওগুলো volume এর উপর নির্ভর করে না।

### দুইটা limitation জেনে রাখুন

- `status_code` rule **global** ভাবে গোনে, per-client না। তাই একক client এর 407
  brute-force আর সবার মিলিত 407 আলাদা করা যায় না।
- কোনো rule **off-hours aware** না। রাত ২টার ৫০ MB upload আর দুপুরের ৫০ MB একই ভাবে দেখে।
  চাইলে অফিস সময়ের বাইরে আলাদা কঠিন threshold নিয়ে দুইটা instance চালাতে পারেন।

---

## Blocklist admin — dashboard থেকে domain/IP block করা

Dashboard **`squid.conf` কখনো edit করে না**। Proxy তে একটা root-owned helper script
(`squid-blocklist`) বসে, সেটাই আলাদা ACL list file গুলো maintain করে। Default এ পুরো
feature **বন্ধ** — `--enable-blocklist` ছাড়া কোনো write endpoint কাজ করবে না।

### Proxy server এ একবার setup (root হিসেবে)

```bash
# 1) helper টা বসান
sudo install -o root -g root -m 0755 squid-blocklist /usr/local/sbin/

# 2) list file গুলো তৈরি করুন + squid.conf এর লাইন গুলো দেখুন
sudo /usr/local/sbin/squid-blocklist init

# 3) squid.conf এ ওই লাইন গুলো যোগ করুন (http_access allow এর আগে):
#      acl blocked_domains dstdomain "/etc/squid/blocklist_domains.txt"
#      acl blocked_srcips  src       "/etc/squid/blocklist_ips.txt"
#      acl allowed_domains dstdomain "/etc/squid/allowlist_domains.txt"
#      http_access allow allowed_domains
#      http_access deny  blocked_domains
#      http_access deny  blocked_srcips
sudo squid -k parse && sudo squid -k reconfigure

# 4) শুধু এই script এর জন্য passwordless sudo
echo 'opsuser ALL=(root) NOPASSWD: /usr/local/sbin/squid-blocklist' \
  | sudo tee /etc/sudoers.d/squid-blocklist
sudo chmod 0440 /etc/sudoers.d/squid-blocklist
```

### আপনার PC তে চালানো

```bash
python3 squid_dashboard.py \
  --ssh opsuser@10.50.9.165:/var/log/squid/access.log \
  --enable-blocklist
```

Console এ একটা **admin token** print হবে (নিজে দিতে চাইলে `--admin-token`)। Dashboard এর
নিচে **⛔ Squid blocklist** panel এ ওই token দিয়ে unlock করলে domain/IP add-remove করা যাবে।
Alert log এর প্রতিটা row এ **⛔ block** বাটন আছে — malware domain দেখে এক ক্লিকে block।

### Safety rails (সবগুলো টেস্ট করা)

| Guard | কী করে |
|---|---|
| Protected list | `windowsupdate.com`, `cb.example.gov`, `swift.com`, `visa.com`, Office 365 ইত্যাদি **কখনো** block হবে না। subdomain সহ। `/etc/squid/blocklist_protected.txt` এ নিজের domain যোগ করুন |
| CIDR width limit | `/24` এর চেয়ে চওড়া range block করতে দেবে না (`0.0.0.0/0`, `10.0.0.0/8` refuse) |
| `squid -k parse` | reload এর আগে config যাচাই; Squid আপত্তি করলে **নিজে থেকে rollback** |
| Reload failure | reconfigure fail করলেও আগের অবস্থায় ফিরে যায় |
| Auto backup | প্রতিটা change এর আগে copy → `blocklist_backups/`, "Undo last change" বাটন |
| Placeholder guard | list খালি হতে দেয় না (খালি ACL তে Squid fatal error দেয়) |
| Audit log | proxy তে `/var/log/squid/blocklist_audit.log` — কে, কখন, কোথা থেকে, কী |
| Token | সব read/write endpoint এ `X-Admin-Token` লাগে |
| Rate limit | মিনিটে সর্বোচ্চ ২০টা change |
| Input validation | domain/IP regex, shell metacharacter reject (injection টেস্ট করা) |
| Self-check | helper root-owned আর non-writable না হলে চলতে অস্বীকার করে |
| Fail-closed | protected list পড়তে না পারলে change refuse করে |

### Block করলে connection DROP হবে না error page দেখাবে?

Default এ Squid একটা **403 "Access Denied" page** দেখায় — user বুঝে ফেলে proxy block করেছে।

**Connection চুপচাপ drop** করাতে চাইলে `squid.conf` এ `http_access deny` লাইনগুলোর ঠিক পরে
এই তিন লাইন যোগ করুন:

```
deny_info TCP_RESET blocked_domains
deny_info TCP_RESET blocked_srcips
deny_info TCP_RESET blocked_urls
```

তারপর `sudo squid -k parse && sudo squid -k reconfigure`

এতে Squid একটা **TCP reset** পাঠায় — browser এ "connection failed" আসে, proxy block page
আসে না। HTTPS (CONNECT) এর ক্ষেত্রে এটাই পরিষ্কার আচরণ, কারণ CONNECT এ 403 দিলে
বিভ্রান্তিকর TLS error দেখায়।

> বিকল্প: `deny_info TCP_RESET` এর বদলে নিজের error page দেখাতে চাইলে
> `deny_info ERR_CUSTOM_PAGE blocked_domains` ব্যবহার করা যায়।

### URL block করা — একটা জরুরি সীমাবদ্ধতা

| যা block করতে চান | HTTP | HTTPS (CONNECT) |
|---|---|---|
| পুরো domain (`facebook.com`) | ✅ | ✅ |
| শুধু path (`facebook.com/games`) | ✅ | ❌ **সম্ভব না** |

HTTPS এ Squid শুধু `host:443` দেখে — path টা encrypted, তাই `url_regex` কাজ করে না।
SSL bump (`ssl_bump`) চালু থাকলে ভিন্ন কথা। HTTPS site block করতে **domain** ব্যবহার করুন।

`block URL pattern` option টা POSIX regex নেয় (Squid এর `url_regex`), যেমন:

```
^http://insecure\.example\.com/download/     # নির্দিষ্ট path
\.(exe|scr|bat|msi)(\?|$)                     # extension ধরে
utm_campaign=badactor                         # query parameter ধরে
```

**Regex guard:** একটা ভুল pattern পুরো bank এর internet বন্ধ করে দিতে পারে, তাই helper
নিচের সবগুলো reject করে — `.*`, `http`, ৪ অক্ষরের কম, invalid regex, protected domain
এর সাথে মেলে এমন pattern (`windowsupdate\.com`, `bb\.org\.bd/.*`), আর সাধারণ traffic
ধরে ফেলে এমন pattern (`http://.*\.com/`)।

### Blocklist endpoints

| Endpoint | কাজ |
|---|---|
| `GET /api/blocklist` | সব list + proxy status |
| `POST /api/blocklist/add` | `{"kind":"domains\|ips\|urls\|allow","entry":"..."}` |
| `POST /api/blocklist/remove` | একই shape |
| `POST /api/blocklist/rollback` | `{"kind":"..."}` — শেষ change undo |

### Production এ নেওয়ার আগে

- `blocklist_protected.txt` এ **আপনার bank এর সব domain** আর core banking/SWIFT endpoint যোগ করুন
- Dashboard `127.0.0.1` এ রাখুন (default)। LAN এ খুললে auth reverse proxy দিন
- `--admin-token` একটা লম্বা random string দিন, script এ hardcode করবেন না
- Audit log টা SIEM এ forward করুন — NetWitness এ file collector দিয়ে সহজ
- Change management: প্রতিটা block এর কারণ audit log এ থাকে, কিন্তু ticket reference চাইলে
  helper script এর `audit()` function এ একটা extra argument যোগ করা যায়

### Alert endpoints

| Endpoint | কাজ |
|---|---|
| `GET /api/alerts` | rules + available types |
| `POST /api/alerts` | rules replace করে disk এ save (`{"rules":[...]}`) |
| `POST /api/alerts/test` | test alert fire করে (notification wiring যাচাই) |
| `POST /api/alerts/reset` | default rules ফিরিয়ে আনে |
| `GET /api/alerts/history` | alert history + per-rule fire counts |

Invalid rule গুলো চুপচাপ sanitize হয় — ভাঙা regex neutralize হয়, unknown type বাদ যায়,
junk value default এ ফেরে, duplicate id rename হয়, আর window/cooldown safe range এ clamp হয়।
তাই ভুল config দিলেও dashboard crash করবে না।

## Architecture

```
       PROXY SERVER                          YOUR PC (this script)
  ┌──────────────────┐
  │ squid access.log │──ssh tail -F ──┐
  │                  │                │
  │ access_log udp://│───push────────►├─> parser ─> in-memory Stats ──┬──┐
  │ access_log tcp://│───push────────►│                 │             │  │
  │                  │                │                 └> rolling    │  ├─SSE─> browser
  │ cache manager    │◄──poll(15s)────┤                    window     │  │      (req/stats/
  │   :3128          │   (raw socket) │                      │        │  │       alert/source)
  └──────────────────┘                │      alert engine ───┘        │  │
                                      │      (per-request +           │  │
   mounted share ────────────────────►┘       every 5s eval) ─────────┘──┘
```

চারটা transport এর যেকোনোটা দিয়েই data আসতে পারে, বাকি pipeline একই থাকে।

- **Transport:** Server-Sent Events (`/events`) — WebSocket এর চেয়ে হালকা, auto-reconnect সহ (exponential backoff)
- প্রতিটা নতুন log line সাথে সাথে `req` event হিসেবে push হয়; প্রতি 2 সেকেন্ডে aggregated `stats` snapshot যায়
- **Log rotation & truncation** handle করা হয় inode + size + content-fingerprint দিয়ে — `logrotate` এর `copytruncate` mode ও ধরা পড়ে (`tail -F` এখানে line miss করে)
- Squid mid-write এ থাকলে **partial line** buffer করা হয়, ভাঙা entry parse হয় না
- দুইটা log format support করে: Squid **native** এবং **common/combined** (`httpd_emulate on`)

## API endpoints

| Endpoint | কি দেয় |
|---|---|
| `GET /` | dashboard UI |
| `GET /events` | SSE live stream |
| `GET /api/stats?recent=N` | পুরো aggregated snapshot (JSON) |
| `GET /api/recent?limit=N` | সাম্প্রতিক request rows |
| `GET /api/health` | health + কত request দেখা হয়েছে |
| `GET /api/export` | recent requests CSV download |

## Notes

- সব data **memory তে** থাকে (bounded deques) — কোনো database নেই, restart করলে counters reset হয়
  (তবে alert **rules** disk এ persist করে)
- Dashboard এ কোনো authentication নেই; loopback এ রাখুন বা reverse proxy এর পিছনে auth দিন
- `squidclient` install থাকলে cache manager panel নিজে থেকেই ভরে যাবে, না থাকলে gracefully skip করে
