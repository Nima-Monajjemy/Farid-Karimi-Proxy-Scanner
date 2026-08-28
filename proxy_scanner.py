import os, re, subprocess, tempfile, json, time, requests, shutil, base64, sqlite3
import urllib.parse

# ==================== تنظیمات ====================
SOURCE_URL = "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/mixed_iran.txt"
OUTPUT_FILE = "working_proxies.txt"
DB_FILE = "geoip_database.db"

TEST_URL = "http://www.gstatic.com/generate_204"
TEST_TIMEOUT = 4.0
BATCH_SIZE = 30       # تعداد کانفیگ‌ها در هر بسته برای ذخیره و پوش کردن
MAX_RETESTS = 100     # تعداد کانفیگ‌های قدیمی که برای حذف شدن یا ماندن ری‌تست می‌شوند
MAX_FAILURES = 1      # چند بار اتصال ناموفق باعث حذف کانفیگ شود
EXPIRY_HOURS = 12     # زمان انقضای تست قبلی (به ساعت)

# ==================== توابع کمکی ====================
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
            if not old_name.startswith("["): 
                data["ps"] = prefix + old_name
            new_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
            return "vmess://" + new_b64
        else:
            if "#" in link:
                base, old_name = link.split("#", 1)
                old_name = urllib.parse.unquote(old_name)
                if not old_name.startswith("["):
                    new_name = urllib.parse.quote(prefix + old_name)
                else:
                    new_name = urllib.parse.quote(old_name)
                return f"{base}#{new_name}"
            else:
                return f"{link}#{urllib.parse.quote(prefix.strip())}"
    except:
        return link

# ==================== دیتابیس (ارتقا یافته با لیست سیاه) ====================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # جدول کانفیگ‌های موفق و متصل
    c.execute('''CREATE TABLE IF NOT EXISTS proxies
                 (link TEXT PRIMARY KEY, delay REAL, country TEXT, cc TEXT, last_test REAL, fails INTEGER)''')
    # جدول قبرستان (کانفیگ‌های تست شده اما ناموفق)
    c.execute('''CREATE TABLE IF NOT EXISTS failed_proxies
                 (link TEXT PRIMARY KEY, last_seen REAL)''')
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

# ==================== مدیریت گیت‌هاب (Push مرحله‌ای) ====================
def setup_git():
    subprocess.run(["git", "config", "user.name", "github-actions[bot]"], check=False)
    subprocess.run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], check=False)

def generate_and_push(commit_message):
    valid_configs = execute_db("SELECT link, country, cc FROM proxies ORDER BY delay ASC")
    final_list = []
    for link, country, cc in valid_configs:
        final_list.append(rename_config(link, country, cc))
        
    content = base64.b64encode("\n".join(final_list).encode()).decode()
    with open(OUTPUT_FILE, "w") as f: 
        f.write(content)
        
    subprocess.run(["git", "add", OUTPUT_FILE, DB_FILE], check=False)
    res = subprocess.run(["git", "diff", "--cached", "--quiet"], capture_output=True)
    
    if res.returncode != 0:
        subprocess.run(["git", "commit", "-m", commit_message], check=False)
        subprocess.run(["git", "pull", "--rebase", "origin", "main"], check=False)
        subprocess.run(["git", "push", "origin", "main"], check=False)
        print(f"📦 تغییرات ذخیره و در گیت‌هاب منتشر شد (مجموع معتبرها: {len(final_list)})")
    else:
        print("   ↳ تغییری برای Push وجود نداشت.")

# ==================== دریافت سورس ====================
def get_raw_configs():
    print("📡 در حال دریافت لیست از سورس...")
    try:
        r = requests.get(SOURCE_URL, timeout=15)
        text = r.text
        try: text = base64.b64decode(text).decode('utf-8')
        except: pass
        links = re.findall(r'(?:vless|vmess|trojan|ss)://\S+', text)
        unique_links = list(set(links))
        print(f"📋 {len(unique_links)} کانفیگ یکتا از منبع استخراج شد.")
        return unique_links
    except Exception as e:
        print(f"⚠️ خطا در دریافت سورس: {e}")
        return []

# ==================== موتور Xray ====================
def download_xray():
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    resp = requests.get(url, stream=True)
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
            b64 = link[8:]
            b64 += "=" * ((4 - len(b64) % 4) % 4)
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
    
    is_ok = False
    delay = 9999
    c_name, c_code = "Unknown", "XX"

    if res.returncode == 0 and res.stdout.strip():
        delay = float(res.stdout.strip()) * 1000
        is_ok = True
        
        # تست لوکیشن (GeoIP)
        try:
            geo_res = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:10808", "http://ip-api.com/json?fields=status,country,countryCode", "--connect-timeout", "4"], capture_output=True, text=True)
            if geo_res.returncode == 0:
                geo_data = json.loads(geo_res.stdout)
                if geo_data.get("status") == "success":
                    c_name = geo_data.get("country", "Unknown")
                    c_code = geo_data.get("countryCode", "XX")
            time.sleep(0.5) 
        except: pass

    proc.terminate()
    try: proc.wait(2)
    except: proc.kill()
    os.unlink(conf_path)
    
    return is_ok, delay, c_name, c_code

# ==================== بدنه اصلی ====================
if __name__ == "__main__":
    setup_git()
    init_db()
    
    # حذف کانفیگ‌های لیست سیاه که قدیمی‌تر از ۷ روز هستند (جلوگیری از حجیم شدن دیتابیس)
    execute_db("DELETE FROM failed_proxies WHERE last_seen < ?", (time.time() - 7 * 24 * 3600,))
    
    raw_links = get_raw_configs()
    xray_bin = download_xray()
    
    # واکشی تمام کانفیگ‌های تست شده (چه موفق، چه ناموفق)
    cached_valid = {r[0] for r in execute_db("SELECT link FROM proxies")}
    cached_failed = {r[0] for r in execute_db("SELECT link FROM failed_proxies")}
    all_cached = cached_valid.union(cached_failed)
    
    # -------- 1. تست کانفیگ‌های کاملا جدید (موجود در سورس اما غایب در حافظه) --------
    new_links = [lk for lk in raw_links if lk not in all_cached]
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
                # ثبت در لیست سیاه تا دیگر تست نشود
                execute_db("INSERT OR REPLACE INTO failed_proxies VALUES (?, ?)", (link, time.time()))
                print(f"[{i}/{total_new}] ❌ (انتقال به لیست سیاه)")
                
            # ذخیره و Push کردن مرحله‌ای هر BATCH_SIZE کانفیگ (یا در آخرین کانفیگ)
            if i % BATCH_SIZE == 0 or i == total_new:
                if new_in_batch > 0:
                    print(f"\n⏳ رسیدن به بسته {i}. در حال ذخیره و Push کردن {new_in_batch} کانفیگ موفق اخیر...")
                    generate_and_push(f"🔄 Batch update: +{new_in_batch} valid configs")
                    new_in_batch = 0
    else:
        print("\n✅ کانفیگ کاملاً جدیدی در سورس یافت نشد.")

    # -------- 2. پالایش و ری‌تست کانفیگ‌های قدیمی (حذف مرده‌ها) --------
    expired = execute_db(f"SELECT link, fails FROM proxies WHERE last_test < {time.time() - EXPIRY_HOURS * 3600} LIMIT {MAX_RETESTS}")
    if expired:
        print(f"\n🔄 شروع ری‌تست {len(expired)} کانفیگ قدیمی در لیست نهایی...")
        recheck_changes = False
        
        for i, (link, fails) in enumerate(expired, 1):
            ok, dly, _, _ = test_connectivity_and_geo(xray_bin, link) 
            if ok:
                execute_db("UPDATE proxies SET delay=?, last_test=?, fails=0 WHERE link=?", (dly, time.time(), link))
                print(f"[{i}/{len(expired)}] 🔁 ✅ زنده ماند")
            else:
                if fails + 1 >= MAX_FAILURES:
                    # حذف از لیست موفق‌ها و انتقال به لیست سیاه
                    execute_db("DELETE FROM proxies WHERE link=?", (link,))
                    execute_db("INSERT OR REPLACE INTO failed_proxies VALUES (?, ?)", (link, time.time()))
                    print(f"[{i}/{len(expired)}] 🔁 🗑️ حذف و به لیست سیاه منتقل شد")
                    recheck_changes = True
                else:
                    execute_db("UPDATE proxies SET fails=?, last_test=? WHERE link=?", (fails+1, time.time(), link))
                    print(f"[{i}/{len(expired)}] 🔁 ❌ یک خطا ثبت شد")
        
        if recheck_changes:
            print("\n⏳ ذخیره نهایی تغییراتِ مربوط به حذف کانفیگ‌های مرده...")
            generate_and_push("🧹 Purge dead configs from database")

    shutil.rmtree(os.path.dirname(xray_bin), ignore_errors=True)
    print(f"\n🎉 پایان عملیات! اسکن، تغییر نام و ذخیره‌سازی با موفقیت انجام شد.")
