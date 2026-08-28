این درخواست یک جهشِ بزرگ و حرفه‌ای در معماریِ پروژه شماست! با این کار شما عملاً یک «سیستم توزیع پروکسیِ دوگانه» (Dual-Channel Proxy Distribution) می‌سازید.

در این آپدیت:

1. **لیست `all_proxies.txt`:** تمام کانفیگ‌های موجود در سورس (بدون تست اتصال) را دریافت، **تکراری‌گیری (Deduplicate)**، و بر اساس لوکیشن تغییر نام می‌دهد.
2. **لیست `working_proxies.txt`:** همان کانفیگ‌ها را از تونلِ تست و فیلترینگ عبور داده و فقط سالم‌ها را نگه می‌دارد.
3. **ذخیره‌سازیِ زنده (Live Sync):** هر ۵۰ عدد کانفیگی که بررسی می‌شود، سیستم متوقف نمی‌شود؛ بلکه کانفیگ‌های موفقی که تا این لحظه پیدا کرده را به همراه لیست کُل، روی گیت‌هاب می‌فرستد تا شما در لحظه بتوانید از کانفیگ‌های جدید استفاده کنید.
4. **حذف محدودیت:** کد تا آخرین کانفیگ موجود در سورس را اسکن خواهد کرد (بدون سقف عددی).

### ۱. فایل `yml` گیت‌هاب اکشنز (`scanner.yml`)

این کد را در فایل yml خود جایگزین کنید (مدت زمان تایم‌اوت را روی ۳۵۰ دقیقه نگه داشتم تا کد فرصت کند هزاران کانفیگ را تا انتها اسکن کند):

```yaml
name: GeoIP V2Ray Scanner

on:
  schedule:
    - cron: '0 */4 * * *'
  workflow_dispatch:

permissions:
  contents: write

jobs:
  run-scanner:
    runs-on: ubuntu-latest
    timeout-minutes: 350
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Install Python Dependencies
        run: pip install requests

      - name: Run Proxy Scanner
        run: python proxy_scanner.py

      - name: Commit and Push Results
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add working_proxies.txt all_proxies.txt geoip_database.db || true
          if git diff --cached --quiet; then
            echo "No changes to commit"
          else
            git commit -m "🌐 Live Update: Working & All Proxies Synced"
            git pull --rebase origin main
            git push origin main
          fi

```

### ۲. فایل اصلی پایتون (`proxy_scanner.py`)

این اسکریپت را به جای اسکریپت قبلیِ خود قرار دهید:

```python
import os, re, subprocess, tempfile, json, time, requests, shutil, base64, sqlite3
import urllib.parse

# ==================== تنظیمات ====================
SOURCE_URL = "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/mixed_iran.txt"
OUTPUT_WORKING = "working_proxies.txt"
OUTPUT_ALL = "all_proxies.txt"
DB_FILE = "geoip_database.db"

TEST_URL = "http://www.gstatic.com/generate_204"
TEST_TIMEOUT = 5.0
BATCH_SIZE = 50       # آپدیت گیت‌هاب پس از هر ۵۰ تست
MAX_RETESTS = 100     # تعداد کانفیگ‌های قدیمی برای ری‌تست
MAX_FAILURES = 1      # حذف پس از چند بار شکست
EXPIRY_HOURS = 12     # ری‌تست پس از چند ساعت
PURGE_INTERVAL = 3    # هر چند بار اجرا، کل دیتابیس شخم زده شود

# ==================== توابع هوشمندِ تشخیص و تغییر نام ====================
def get_clean_config_id(link):
    """
    استخراج هسته (مغز) کانفیگ برای جلوگیری از تکراری شدن.
    کانال‌های مختلف نام‌های متفاوتی روی یک کانفیگ می‌گذارند که با این روش شناسایی می‌شوند.
    """
    try:
        if link.startswith("vmess://"):
            b64 = link[8:]
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            data = json.loads(base64.b64decode(b64).decode('utf-8'))
            if "ps" in data: del data["ps"]
            return "vmess://" + json.dumps(data, sort_keys=True)
        else:
            return link.split("#")[0]
    except: return link

def get_config_address(link):
    """ استخراج IP یا دامنه برای لوکیشن‌یابی انبوه بدون نیاز به اتصال """
    try:
        if link.startswith("vmess://"):
            b64 = link[8:] + "=" * ((4 - len(link[8:]) % 4) % 4)
            return json.loads(base64.b64decode(b64).decode('utf-8')).get("add", "")
        else:
            return urllib.parse.urlparse(link).hostname or ""
    except: return ""

def get_flag_emoji(country_code):
    if not country_code or len(country_code) != 2: return "🌍"
    return "".join(chr(ord(c) + 127397) for c in country_code.upper())

def rename_config(link, country_name, country_code):
    prefix = f"[{get_flag_emoji(country_code)} {country_name}] "
    try:
        if link.startswith("vmess://"):
            b64 = link[8:]
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            data = json.loads(base64.b64decode(b64).decode('utf-8'))
            old_name = data.get("ps", "Config")
            if not old_name.startswith("["): data["ps"] = prefix + old_name
            return "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
        else:
            if "#" in link:
                base, old_name = link.split("#", 1)
                old_name = urllib.parse.unquote(old_name)
                new_name = urllib.parse.quote(old_name) if old_name.startswith("[") else urllib.parse.quote(prefix + old_name)
                return f"{base}#{new_name}"
            else:
                return f"{link}#{urllib.parse.quote(prefix.strip())}"
    except: return link

# ==================== دیتابیس ====================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS proxies (link TEXT PRIMARY KEY, delay REAL, country TEXT, cc TEXT, last_test REAL, fails INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS failed_proxies (link TEXT PRIMARY KEY, last_seen REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sys_state (id INTEGER PRIMARY KEY, run_count INTEGER)''')
    c.execute("INSERT OR IGNORE INTO sys_state (id, run_count) VALUES (1, 0)")
    conn.commit()
    conn.close()

def execute_db(query, args=()):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(query, args)
    res = c.fetchall()
    conn.commit()
    conn.close()
    return res

def remove_duplicates_from_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT link FROM proxies")
    rows = c.fetchall()
    seen_ids, duplicates = set(), []
    
    for (link,) in rows:
        cid = get_clean_config_id(link)
        if cid in seen_ids: duplicates.append(link)
        else: seen_ids.add(cid)
            
    for dup in duplicates: c.execute("DELETE FROM proxies WHERE link=?", (dup,))
    conn.commit()
    conn.close()
    if duplicates: print(f"🧹 {len(duplicates)} کانفیگ تکراری از دیتابیس حذف شدند.")

def get_all_cached_ids():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    valid_ids = [get_clean_config_id(r[0]) for r in c.execute("SELECT link FROM proxies").fetchall()]
    failed_ids = [get_clean_config_id(r[0]) for r in c.execute("SELECT link FROM failed_proxies").fetchall()]
    conn.close()
    return set(valid_ids).union(set(failed_ids))

# ==================== دریافت و GeoIP انبوه ====================
def get_raw_configs():
    print("📡 در حال دریافت لیست از سورس...")
    try:
        r = requests.get(SOURCE_URL, timeout=15)
        text = base64.b64decode(r.text).decode('utf-8') if "://" not in r.text[:50] else r.text
        links = re.findall(r'(?:vless|vmess|trojan|ss)://\S+', text)
        return links
    except Exception as e:
        print(f"⚠️ خطا در دریافت سورس: {e}")
        return []

def get_bulk_geoip(addresses):
    unique_addrs = list(set(a for a in addresses if a))
    geo_cache = {}
    for i in range(0, len(unique_addrs), 100):
        batch = unique_addrs[i:i+100]
        try:
            data = [{"query": ip, "fields": "status,country,countryCode"} for ip in batch]
            r = requests.post("http://ip-api.com/batch", json=data, timeout=10)
            if r.status_code == 200:
                for res in r.json():
                    if res.get("status") == "success":
                        geo_cache[res["query"]] = (res.get("country", "Unknown"), res.get("countryCode", "XX"))
        except: pass
        time.sleep(1.5) # رعایت Rate Limit
    return geo_cache

# ==================== موتور Xray ====================
def download_xray():
    resp = requests.get("https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip", stream=True)
    tmp_zip = tempfile.mktemp(suffix=".zip")
    with open(tmp_zip, "wb") as f:
        for chunk in resp.iter_content(8192): f.write(chunk)
    xray_dir = tempfile.mkdtemp()
    shutil.unpack_archive(tmp_zip, xray_dir)
    xray_bin = os.path.join(xray_dir, "xray")
    os.chmod(xray_bin, 0o755)
    return xray_bin

def parse_to_xray(link):
    try:
        if link.startswith("vmess://"):
            b64 = link[8:] + "=" * ((4 - len(link[8:]) % 4) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8'))
            out = {"protocol": "vmess", "settings": {"vnext": [{"address": d["add"], "port": int(d["port"]), "users": [{"id": d["id"], "security": d.get("scy", "auto")}]}]}, "streamSettings": {"network": d.get("net", "tcp")}}
            if d.get("net") == "ws": out["streamSettings"]["wsSettings"] = {"path": d.get("path", "/"), "headers": {"Host": d.get("host", d["add"])} if d.get("host") else {}}
            if d.get("tls") == "tls": out["streamSettings"]["security"] = "tls"; out["streamSettings"]["tlsSettings"] = {"serverName": d.get("sni", d["add"])}
            return out

        elif link.startswith("ss://"):
            p = urllib.parse.urlparse(link)
            if not p.username: return None
            try:
                dec = base64.b64decode(p.username + '=' * ((4 - len(p.username) % 4) % 4)).decode('utf-8')
                method, pw = dec.split(':', 1) if ':' in dec else ("aes-256-gcm", dec)
            except:
                method, pw = p.username.split(':', 1) if ':' in p.username else ("aes-256-gcm", p.username)
            return {"protocol": "shadowsocks", "settings": {"servers": [{"address": p.hostname, "port": int(p.port), "method": method, "password": pw}]}, "streamSettings": {"network": "tcp", "security": "none"}}

        elif link.startswith("vless://") or link.startswith("trojan://"):
            p = urllib.parse.urlparse(link)
            proto = "vless" if link.startswith("vless") else "trojan"
            sett = {"vnext": [{"address": p.hostname, "port": p.port, "users": [{"id": p.username, "encryption": "none", "flow": ""}]}]} if proto == "vless" else {"servers": [{"address": p.hostname, "port": p.port, "password": p.username}]}
            params = urllib.parse.parse_qs(p.query)
            def gp(k, d=""): return params.get(k, [d])[0]
            
            out = {"protocol": proto, "settings": sett, "streamSettings": {"network": gp("type", "tcp"), "security": gp("security", "none")}}
            if proto == "vless" and gp("flow"): out["settings"]["vnext"][0]["users"][0]["flow"] = gp("flow")
            if gp("type") == "ws": out["streamSettings"]["wsSettings"] = {"path": gp("path", "/"), "headers": {"Host": gp("host")} if gp("host") else {}}
            elif gp("type") == "tcp" and gp("headerType") == "http": out["streamSettings"]["tcpSettings"] = {"header": {"type": "http", "request": {"headers": {"Host": gp("host")} if gp("host") else {}, "path": gp("path", "/")}}}
            elif gp("type") == "grpc": out["streamSettings"]["grpcSettings"] = {"serviceName": gp("path", "/").lstrip("/"), "multiMode": False}
            elif gp("type") == "httpupgrade": out["streamSettings"]["httpupgradeSettings"] = {"path": gp("path", "/"), "host": gp("host")}
            
            if gp("security") == "tls": out["streamSettings"]["tlsSettings"] = {"serverName": gp("sni", p.hostname), "fingerprint": gp("fp", ""), "allowInsecure": gp("allowInsecure")=="1"}
            elif gp("security") == "reality": out["streamSettings"]["realitySettings"] = {"serverName": gp("sni", p.hostname), "fingerprint": gp("fp", "chrome"), "publicKey": gp("pbk", ""), "shortId": gp("sid", ""), "spiderX": gp("spx", "")}
            return out
    except: return None

def test_connectivity_and_geo(xray_bin, link):
    outbound = parse_to_xray(link)
    if not outbound: return False, 0, "", ""

    conf = {"inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth"}}], "outbounds": [outbound]}
    conf_path = tempfile.mktemp(suffix=".json")
    with open(conf_path, "w") as f: json.dump(conf, f)
        
    proc = subprocess.Popen([xray_bin, "run", "-c", conf_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2) 
    res = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{time_total}", "--socks5-hostname", "127.0.0.1:10808", TEST_URL, "--connect-timeout", str(TEST_TIMEOUT)], capture_output=True, text=True)
    
    is_ok, delay, c_name, c_code = False, 9999, "Unknown", "XX"

    if res.returncode == 0 and res.stdout.strip():
        delay = float(res.stdout.strip()) * 1000
        is_ok = True
        try:
            geo_res = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:10808", "http://ip-api.com/json?fields=status,country,countryCode", "--connect-timeout", "4"], capture_output=True, text=True)
            if geo_res.returncode == 0:
                geo_data = json.loads(geo_res.stdout)
                if geo_data.get("status") == "success":
                    c_name, c_code = geo_data.get("country", "Unknown"), geo_data.get("countryCode", "XX")
            time.sleep(0.5) 
        except: pass

    proc.terminate()
    try: proc.wait(2)
    except: proc.kill()
    os.unlink(conf_path)
    return is_ok, delay, c_name, c_code

# ==================== آپدیت زنده گیت‌هاب ====================
def setup_git():
    subprocess.run(["git", "config", "user.name", "github-actions[bot]"], check=False)
    subprocess.run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], check=False)

def generate_and_push(commit_message):
    valid_configs = execute_db("SELECT link, country, cc FROM proxies ORDER BY delay ASC")
    final_list = [rename_config(l, c, cc) for l, c, cc in valid_configs]
        
    with open(OUTPUT_WORKING, "w") as f: 
        f.write(base64.b64encode("\n".join(final_list).encode()).decode())
        
    subprocess.run(["git", "add", OUTPUT_WORKING, OUTPUT_ALL, DB_FILE], check=False)
    res = subprocess.run(["git", "diff", "--cached", "--quiet"], capture_output=True)
    if res.returncode != 0:
        subprocess.run(["git", "commit", "-m", commit_message], check=False)
        subprocess.run(["git", "pull", "--rebase", "origin", "main"], check=False)
        subprocess.run(["git", "push", "origin", "main"], check=False)
        print(f"📦 آپدیت زنده انجام شد! (تعداد متصل: {len(final_list)})")

# ==================== بدنه اصلی ====================
if __name__ == "__main__":
    setup_git()
    init_db()
    
    # 1. حذف تکراری‌ها و تمیزکاری اولیه
    remove_duplicates_from_db()
    execute_db("DELETE FROM failed_proxies WHERE last_seen < ?", (time.time() - 7 * 24 * 3600,))
    
    raw_links = get_raw_configs()
    
    # تکراری‌گیری از سورس خام
    unique_dict = {}
    for lk in raw_links:
        cid = get_clean_config_id(lk)
        if cid not in unique_dict: unique_dict[cid] = lk
    unique_links = list(unique_dict.values())
    print(f"📋 {len(unique_links)} کانفیگ یونیک استخراج شد.")

    # 2. ساخت فایل All Proxies (بدون فیلتر اتصال)
    print("\n🌍 در حال ایجاد لیست کل (All Proxies) با لوکیشن‌یابی انبوه...")
    addresses = [get_config_address(lk) for lk in unique_links]
    bulk_geo = get_bulk_geoip(addresses)
    
    all_renamed = []
    for lk in unique_links:
        addr = get_config_address(lk)
        c_name, c_code = bulk_geo.get(addr, ("Unknown", "XX"))
        all_renamed.append(rename_config(lk, c_name, c_code))
        
    with open(OUTPUT_ALL, "w") as f:
        f.write(base64.b64encode("\n".join(all_renamed).encode()).decode())
    print(f"✅ فایل {OUTPUT_ALL} با {len(all_renamed)} کانفیگ آماده شد.")

    # 3. شروع تست کانکشن برای Working Proxies
    xray_bin = download_xray()
    cached_ids = get_all_cached_ids()
    new_links = [lk for lk in unique_links if get_clean_config_id(lk) not in cached_ids]
    
    total_new = len(new_links)
    if total_new > 0:
        print(f"\n🧪 شروع تست {total_new} کانفیگ کاملا جدید...")
        new_in_batch = 0
        for i, link in enumerate(new_links, 1):
            ok, dly, c_name, c_code = test_connectivity_and_geo(xray_bin, link)
            if ok:
                execute_db("INSERT INTO proxies VALUES (?, ?, ?, ?, ?, ?)", (link, dly, c_name, c_code, time.time(), 0))
                print(f"[{i}/{total_new}] ✅ {c_name} ({dly:.0f}ms)")
                new_in_batch += 1
            else:
                execute_db("INSERT OR REPLACE INTO failed_proxies VALUES (?, ?)", (link, time.time()))
                print(f"[{i}/{total_new}] ❌")
                
            # آپدیت زنده (Live Sync) پس از هر BATCH_SIZE
            if i % BATCH_SIZE == 0 or i == total_new:
                generate_and_push(f"🔄 Live Sync: +{new_in_batch} valid configs added")
                new_in_batch = 0
    else:
        print("\n✅ کانفیگ کاملاً جدیدی برای تست وجود نداشت.")

    # 4. پالایش و ری‌تست کانفیگ‌های قدیمی
    run_count = execute_db("SELECT run_count FROM sys_state WHERE id=1")[0][0]
    
    if run_count >= PURGE_INTERVAL:
        print("\n🧹 شروع پالایشِ کاملِ دیتابیس (بررسی همه کانفیگ‌های متصل قبلی)...")
        links = execute_db("SELECT link FROM proxies")
        for (link,) in links:
            ok, _, _, _ = test_connectivity_and_geo(xray_bin, link)
            if not ok: 
                execute_db("DELETE FROM proxies WHERE link=?", (link,))
                execute_db("INSERT OR REPLACE INTO failed_proxies VALUES (?, ?)", (link, time.time()))
        execute_db("UPDATE sys_state SET run_count=0 WHERE id=1")
        generate_and_push("🧹 Full Purge: Removed dead configs from database")
    else:
        execute_db("UPDATE sys_state SET run_count=? WHERE id=1", (run_count + 1,))
        expired = execute_db(f"SELECT link, fails FROM proxies WHERE last_test < {time.time() - EXPIRY_HOURS * 3600} LIMIT {MAX_RETESTS}")
        if expired:
            print(f"\n🔄 شروع ری‌تست {len(expired)} کانفیگ منقضی شده...")
            changed = False
            for i, (link, fails) in enumerate(expired, 1):
                ok, dly, _, _ = test_connectivity_and_geo(xray_bin, link) 
                if ok:
                    execute_db("UPDATE proxies SET delay=?, last_test=?, fails=0 WHERE link=?", (dly, time.time(), link))
                    print(f"[{i}/{len(expired)}] 🔁 ✅ زنده ماند")
                else:
                    if fails + 1 >= MAX_FAILURES:
                        execute_db("DELETE FROM proxies WHERE link=?", (link,))
                        execute_db("INSERT OR REPLACE INTO failed_proxies VALUES (?, ?)", (link, time.time()))
                        print(f"[{i}/{len(expired)}] 🔁 🗑️ حذف شد")
                        changed = True
                    else:
                        execute_db("UPDATE proxies SET fails=?, last_test=? WHERE link=?", (fails+1, time.time(), link))
                        print(f"[{i}/{len(expired)}] 🔁 ❌ یک خطا ثبت شد")
            if changed:
                generate_and_push("🧹 Auto-Purge: Removed expired dead configs")

    shutil.rmtree(os.path.dirname(xray_bin), ignore_errors=True)
    print(f"\n🎉 پایان موفقیت‌آمیز عملیات!")

```
