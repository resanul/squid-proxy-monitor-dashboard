# Squid Dashboard — Setup Checklist

চারটা ভাগ। প্রতিটা command এর পাশে লেখা আছে **কোথায়** চালাতে হবে আর **কী দেখলে বুঝবেন কাজ হয়েছে**।

> ## পরিকল্পনা: আগে test node, পরে production
>
> | Node | ভূমিকা | Dashboard কী করতে পারবে |
> |---|---|---|
> | **10.50.0.12** | **TEST** | সব কিছু — policy লেখা, block করা |
> | 10.50.0.8 | PROD | শুধু **দেখা** (`admin: false`) |
> | 10.50.0.7 | PROD | শুধু **দেখা** (`admin: false`) |
>
> `squid_proxies.json` এ production দুইটার `"admin": false` দেওয়া আছে। মানে dashboard
> ওদের traffic **দেখাবে**, কিন্তু Policy/Blocklist panel থেকে ওদের উপর কিছু **লিখতে
> পারবে না** — ভুল করে production এ apply হয়ে যাওয়ার সম্ভাবনা শূন্য।
>
> সব ভাগ (A→D) শুধু **.12** এর জন্য করুন। সন্তুষ্ট হলে শেষে "ভাগ E" দেখুন।

---

## ভাগ A — আপনার PC তে file নামানো  (৩ ধাপ)

### A1. পাঁচটা file download করুন

কোথায়: **PowerShell, আপনার PC**

```powershell
cd C:\Users\opsuser

Invoke-WebRequest -Uri "https://pub.hyperagent.com/api/published/pbf01M09VST50_EQQNRSGK6GZNE8N8/squid_dashboard.py"      -OutFile squid_dashboard.py
Invoke-WebRequest -Uri "https://pub.hyperagent.com/api/published/pbf01M0CHVVC2_20XFV720DGRY3Y9Z/squid-policy"  -OutFile squid-policy
Invoke-WebRequest -Uri "https://pub.hyperagent.com/api/published/pbf01M0CGJDT1_ZQR3RQKTGGWRRD28/squid-blocklist"   -OutFile squid-blocklist
Invoke-WebRequest -Uri "https://pub.hyperagent.com/api/published/pbf01M09VSTNV_J38F5J3GFCPABFMD/squid_alerts_bank.json"  -OutFile squid_alerts_bank.json
Invoke-WebRequest -Uri "https://pub.hyperagent.com/api/published/pbf01M09WT33J_CFPY2E0MZRVNY1G2/squid_proxies.json" -OutFile squid_proxies.json
```

### A2. ঠিকভাবে এসেছে কি না দেখুন

```powershell
python squid_dashboard.py --version
```

✅ **`squid_dashboard 1.8.0`** দেখাতে হবে। অন্য কিছু দেখালে file অসম্পূর্ণ — আবার download করুন।

### A3. Demo mode এ একবার চালিয়ে দেখুন (proxy লাগবে না)

```powershell
python squid_dashboard.py --demo
```

✅ ব্রাউজারে **http://127.0.0.1:8899** খুললে চলমান dashboard দেখবেন।
বন্ধ করতে `Ctrl + C`।

---

## ভাগ B — Proxy server এ helper বসানো  (৬ ধাপ)

### B0. নতুন node এ SSH key আর log permission (একবার)

`.12` তে এখনো key বসানো নেই, তাই আগে এই দুইটা। **password এই একবারই লাগবে।**

কোথায়: **PowerShell, আপনার PC**

```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh opsuser@10.50.0.12 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
ssh opsuser@10.50.0.12 "echo OK"
```

✅ শেষ command টা **password ছাড়াই** `OK` দিতে হবে।

তারপর log পড়ার অনুমতি:

```powershell
ssh -t opsuser@10.50.0.12 "sudo setfacl -m u:opsuser:rx /var/log/squid; sudo setfacl -m u:opsuser:r /var/log/squid/access.log; sudo setfacl -d -m u:opsuser:r /var/log/squid; echo ACL-OK"
```

✅ **`ACL-OK`** (sudo password চাইবে)

যাচাই:

```powershell
python squid_dashboard.py --ssh opsuser@10.50.0.12:/var/log/squid/access.log --check
```

✅ **`All good — starting the dashboard.`**

### B1. দুইটা helper file proxy তে পাঠান

কোথায়: **PowerShell, আপনার PC**

```powershell
scp squid-policy squid-blocklist opsuser@10.50.0.12:/tmp/
```

✅ `100%` progress দেখাবে।

### B2. squid.conf এর backup নিন — এটা বাদ দেবেন না

কোথায়: **TEST proxy** — `ssh -t opsuser@10.50.0.12`

```bash
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.bak-$(date +%F-%H%M) && echo BACKUP-OK
```

✅ **`BACKUP-OK`**

### B3. helper দুইটা install করুন

```bash
sudo install -o root -g root -m 0755 /tmp/squid-policy    /usr/local/sbin/
sudo install -o root -g root -m 0755 /tmp/squid-blocklist /usr/local/sbin/
sudo /usr/local/sbin/squid-policy init
```

✅ শেষে `include /etc/squid/policy/rules.conf` লাইনটা print হবে — পরের ধাপে ওটাই লাগবে।

### B4. squid.conf এ include লাইন বসান

**এটাই সবচেয়ে গুরুত্বপূর্ণ ধাপ।** লাইনটা ঠিক `http_access deny CONNECT !SSL_ports` এর
**পরে** বসতে হবে — না হলে HTTPS block কাজ করবে না।

```bash
grep -q 'include /etc/squid/policy/rules.conf' /etc/squid/squid.conf \
  || sudo sed -i '/^http_access deny CONNECT !SSL_ports/a include /etc/squid/policy/rules.conf' /etc/squid/squid.conf
```

> `grep -q ... ||` অংশটা থাকার কারণে command টা **দুইবার চালালেও** লাইন দুইবার বসবে না।

যাচাই করুন:

```bash
grep -n -B1 -A1 'include /etc/squid/policy' /etc/squid/squid.conf
```

✅ এমন দেখতে হবে:

```
http_access deny CONNECT !SSL_ports
include /etc/squid/policy/rules.conf
http_access allow CONNECT SSL_ports
```

❌ **কিছুই না দেখালে** লাইনটা বসেনি (আপনার config এ ওই লেখাটা হুবহু নেই)। তখন
`nano /etc/squid/squid.conf` দিয়ে হাতে বসান — `http_access deny CONNECT !SSL_ports`
এর ঠিক পরের লাইনে।

### B5. Config ঠিক আছে কি না যাচাই করুন

```bash
sudo squid -k parse && echo PARSE-OK
```

✅ **`PARSE-OK`**
❌ error এলে backup ফিরিয়ে আনুন: `sudo cp /etc/squid/squid.conf.bak-* /etc/squid/squid.conf`

### B6. Dashboard কে helper চালানোর অনুমতি দিন

```bash
printf 'opsuser ALL=(root) NOPASSWD: /usr/local/sbin/squid-policy\nopsuser ALL=(root) NOPASSWD: /usr/local/sbin/squid-blocklist\n' | sudo tee /etc/sudoers.d/squid-dashboard
sudo chmod 0440 /etc/sudoers.d/squid-dashboard
sudo visudo -c && echo SUDOERS-OK
```

✅ **`SUDOERS-OK`**

তারপর policy চালু করুন আর reload দিন:

```bash
sudo /usr/local/sbin/squid-policy apply && sudo /usr/local/sbin/squid-policy show
```

✅ `applied` লেখা JSON, তারপর group গুলোর তালিকা। এই মুহূর্তে সব group খালি, তাই
**কারো উপর কোনো প্রভাব পড়েনি** — এটাই কাঙ্ক্ষিত।

---

## ভাগ C — Dashboard চালু করা  (১ ধাপ)

কোথায়: **PowerShell, আপনার PC**

```powershell
cd C:\Users\opsuser
python squid_dashboard.py --proxies-config squid_proxies.json --alerts-config squid_alerts_bank.json --enable-policy --enable-blocklist
```

✅ Console এ দেখবেন:

```
proxies    : 3 (switch with the dropdown in the UI)
             · TEST 10.50.0.12    ssh · ...
             · PROD 10.50.0.8     ssh · ...
             · PROD 10.50.0.7     ssh · ...
policy     : WRITABLE on TEST 10.50.0.12
             read-only (monitor only): PROD 10.50.0.8, PROD 10.50.0.7
admin token: <একটা লম্বা random string>     <-- এটা copy করুন
dashboard  : http://127.0.0.1:8899
```

✅ **`WRITABLE on TEST ...`** আর **`read-only ... PROD ...`** — এই দুই লাইন দেখলেই
বুঝবেন safety ঠিকভাবে বসেছে।

### admin token কী?

Dashboard এ কোনো login নেই। কিন্তু Policy/Blocklist panel দিয়ে **proxy র config বদলানো
যায়** — তাই ওই লেখার কাজগুলো একটা token দিয়ে আটকানো।

| কাজ | token লাগে? |
|---|---|
| Traffic দেখা, alert, drill-down, CSV | ❌ লাগে না |
| Policy / Blocklist **পড়া বা লেখা** | ✅ লাগে |

Console এ এভাবে দেখাবে — এটাই copy করে UI তে paste করবেন:

```
--------------------------------------------------------------
  ADMIN TOKEN: VcIEhzdoLMb0HJqYVYE7AM2S
               Paste this into the 🛡 Access policy / ⛔ Blocklist
               panel in the browser to unlock changes.
--------------------------------------------------------------
```

**নিজের token ঠিক করে দিলে প্রতিবার বদলাবে না** (recommended):

```powershell
python squid_dashboard.py --proxies-config squid_proxies.json --alerts-config squid_alerts_bank.json --enable-policy --enable-blocklist --admin-token "একটা-লম্বা-গোপন-শব্দ"
```

> Token টা browser এর sessionStorage এ থাকে (tab বন্ধ করলে মুছে যায়), server এ শুধু
> memory তে — কোনো file এ লেখা হয় না। PowerShell history তে থেকে যায়, তাই একদম
> গোপনীয় কিছু না দিয়ে একটা আলাদা string ব্যবহার করুন।

> PowerShell window টা খোলা রাখবেন। বন্ধ করতে `Ctrl + C`।

---

## ভাগ D — UI থেকে কাজ করা  (৪ ধাপ)

ব্রাউজার: **http://127.0.0.1:8899**

### D1. উপরের dropdown এ **TEST 10.50.0.12** বেছে নিন

Default এই ওটাই থাকবে (list এ প্রথম)। তারপর **🛡 Access policy** বাটনে ক্লিক করুন।

> Production proxy বেছে policy খুলতে গেলে 🔒 লেখা আসবে —
> *"monitor-only (admin:false)"*। এটাই কাঙ্ক্ষিত আচরণ।

### D2. admin token paste করে **Unlock**

✅ চারটা group card দেখবেন: Quarantine, IT admins, Kiosk, Staff — সব খালি।

### D3. IP বসান

| আপনি যা চান | কোন group | কী করবেন |
|---|---|---|
| এই IP এর internet পুরো বন্ধ | **Quarantine** | IP box এ IP লিখে Enter |
| এই IP এর সব কিছুতে access | **IT admins** | IP লিখে Enter |
| এই IP শুধু কিছু site এ যাবে | **Kiosk** | IP + permitted domains |
| এই IP এর কিছু site বন্ধ | **Staff** | IP + blocked domains |

চিপ মুছতে × এ ক্লিক। নতুন group লাগলে নিচে **+ Add group**।

### D4. আগে **Validate**, তারপর **Apply**

1. **Validate (dry run)** — proxy তে কিছুই বদলায় না, শুধু দেখায় কোন rule বসবে
   ✅ সবুজ `✓ valid — N active group(s)` + rule গুলোর তালিকা
   ❌ লাল হলে কারণ লেখা থাকবে (যেমন "IP is in both groups") — ঠিক করে আবার Validate

2. **Apply to proxy** — confirm করলে proxy তে বসে যায়, Squid reload হয়
   ✅ সবুজ `✓ applied — N group(s), M IP(s) live on the proxy`

### যাচাই করুন সত্যিই কাজ করছে

যে PC কে block করেছেন সেখান থেকে browse করে দেখুন, অথবা proxy তে:

```bash
sudo tail -f /var/log/squid/access.log | grep DENIED
```

---

## ভাগ E — Production এ নেওয়া (test সফল হওয়ার পর)

`.12` তে সব ঠিক কাজ করলে, প্রতিটা production node এ:

**E1.** ভাগ B0 → B6 আবার করুন, শুধু IP বদলে (`10.50.0.8`, তারপর `10.50.0.7`)

**E2.** `squid_proxies.json` এ ওই node এর `"admin": false` কে `true` করুন:

```json
{ "id": "p8", "name": "PROD 10.50.0.8", "admin": true, ... }
```

**E3.** Dashboard restart করুন (`Ctrl + C`, তারপর আবার ভাগ C এর command)

✅ Banner এ এখন `WRITABLE on TEST 10.50.0.12, PROD 10.50.0.8` দেখাবে।

**E4.** Production এ প্রথম policy দেওয়ার আগে **অবশ্যই Validate** চালান, আর অফিস
সময়ের বাইরে করুন। প্রথমে একটা group এ **একটা IP** দিয়ে শুরু করুন — সব একসাথে না।

> একটা node এ সমস্যা হলে ওটার `admin` আবার `false` করে restart দিলেই dashboard
> থেকে আর কোনো পরিবর্তন যাবে না, কিন্তু monitoring চালু থাকবে।

---

## কিছু ভেঙে গেলে — ৩টা উপায়

| পরিস্থিতি | কী করবেন |
|---|---|
| ভুল policy apply হয়ে গেছে | UI তে **Undo last apply** |
| UI খুলছে না, policy ফেরাতে হবে | proxy তে: `sudo /usr/local/sbin/squid-policy rollback` |
| পুরো policy বন্ধ করতে চাই | proxy তে include লাইনটা `#` দিয়ে comment করুন, তারপর `sudo squid -k reconfigure` |
| squid.conf ই ভেঙে গেছে | `sudo cp /etc/squid/squid.conf.bak-* /etc/squid/squid.conf && sudo squid -k parse && sudo squid -k reconfigure` |
| এই node এ আর কোনো পরিবর্তন যাক না চাই | `squid_proxies.json` এ ওটার `"admin": false` করে dashboard restart |

Squid নিজেই একটা নিরাপত্তা স্তর: helper যেকোনো পরিবর্তনের আগে `squid -k parse`
চালায়, Squid আপত্তি করলে **নিজে থেকেই আগের config ফিরিয়ে আনে**।

---

## যা কখনো block হবে না (নিরাপত্তা জাল)

Helper এই destination গুলো কোনো deny list এ ঢুকতে দেয় না, আর allowlist-only
group এ স্বয়ংক্রিয়ভাবে যোগ করে দেয়:

`igw.paygate2.example.com` · `gw.paygate1.example.com` · `uat-gw.paygate1.example.com` ·
`prportal.nid.example.gov` · `gateway.pension.example.gov` · `.examplebank.internal` ·
Windows Update · Office 365 · `cb.example.gov` · `swift.com` · `visa.com` · `mastercard.com`

নতুন কোনো critical domain যোগ করতে proxy তে:
`/etc/squid/policy/` এর `blocklist_protected.txt` এ লিখুন (এক লাইনে একটা)।
