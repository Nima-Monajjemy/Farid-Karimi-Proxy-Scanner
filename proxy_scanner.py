import os, re, subprocess, tempfile, json, time, requests, shutil, base64, sqlite3
import urllib.parse

# ==================== تنظیمات ====================
SOURCE_URL = "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/mixed_iran.txt"
OUTPUT_FILE = "working_proxies.txt"
DB_FILE = "geoip_database.db"

TEST_URL = "http://www.gstatic.com/generate_204"
TEST_TIMEOUT = 4.0
MAX_NEW_TESTS = 300   # تعداد کانفیگ‌های جدیدی که در هر بار اجرا تست می‌شوند
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
            # جلوگیری از اضافه شدن چندباره پرچم
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

# ==================== دیتابیس ====================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS proxies
                 (link TEXT PRIMARY KEY, delay REAL, country TEXT, cc TEXT, last_test REAL, fails INTEGER)''')
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

# ==================== دریافت سورس ====================
def get_raw_configs():
    print("📡 در حال دریافت لیست از سورس...")
    try:
        r = requests.get(SOURCE_URL, timeout=15)
        text = r.text
        try: text = base64.b64decode(text).decode('utf-8')
        except: pass
        found = re.findall(r'(vless|vmess|trojan|ss)://\S+', text)
        # بازگردانی کل لینک (چون findall با گروه فقط بخش اول را می‌دهد، باید الگو را اصلاح کنیم)
        links = re.findall(r'(?:vless|vmess|trojan|ss)://\S+', text)
        print(f"📋 {len(set(links))} کانفیگ پیدا شد.")
        return list(set(links))
    except Exception as e:
        print(f"⚠️ خطا: {e}")
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
    # تبدیل ساده لینک به خروجی جیسون Xray بدون فیلتر
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
    time.sleep(2) # انتظار برای اجرای Xray
    
    # 1. تست پینگ
    res = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{time_total}", "--socks5-hostname", "127.0.0.1:10808", TEST_URL, "--connect-timeout", str(TEST_TIMEOUT)], capture_output=True, text=True)
    
    is_ok = False
    delay = 9999
    c_name, c_code = "Unknown", "XX"

    if res.returncode == 0 and res.stdout.strip():
        delay = float(res.stdout.strip()) * 1000
        is_ok = True
        
        # 2. تست لوکیشن (فقط اگر متصل شد)
        try:
            geo_res = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:10808", "http://ip-api.com/json?fields=status,country,countryCode", "--connect-timeout", "4"], capture_output=True, text=True)
            if geo_res.returncode == 0:
                geo_data = json.loads(geo_res.stdout)
                if geo_data.get("status") == "success":
                    c_name = geo_data.get("country", "Unknown")
                    c_code = geo_data.get("countryCode", "XX")
            time.sleep(0.5) # جلوگیری از بلاک شدن API لوکیشن
        except: pass

    proc.terminate()
    try: proc.wait(2)
    except: proc.kill()
    os.unlink(conf_path)
    
    return is_ok, delay, c_name, c_code

# ==================== بدنه اصلی ====================
if __name__ == "__main__":
    init_db()
    raw_links = get_raw_configs()
    xray_bin = download_xray()
    
    # واکشی دیتای قبلی
    cached = {r[0] for r in execute_db("SELECT link FROM proxies")}
    
    # 1. تست کانفیگ‌های کاملا جدید
    new_links = [lk for lk in raw_links if lk not in cached][:MAX_NEW_TESTS]
    print(f"\n🧪 شروع تست {len(new_links)} کانفیگ جدید...")
    for i, link in enumerate(new_links, 1):
        ok, dly, c_name, c_code = test_connectivity_and_geo(xray_bin, link)
        if ok:
            execute_db("INSERT INTO proxies VALUES (?, ?, ?, ?, ?, ?)", (link, dly, c_name, c_code, time.time(), 0))
            print(f"[{i}/{len(new_links)}] ✅ {c_name} ({dly:.0f}ms)")
        else:
            print(f"[{i}/{len(new_links)}] ❌")

    # 2. پالایش و ری‌تست کانفیگ‌های قدیمی (حذف مرده‌ها)
    expired = execute_db(f"SELECT link, fails FROM proxies WHERE last_test < {time.time() - EXPIRY_HOURS * 3600} LIMIT {MAX_RETESTS}")
    if expired:
        print(f"\n🔄 شروع ری‌تست {len(expired)} کانفیگ قدیمی...")
        for i, (link, fails) in enumerate(expired, 1):
            ok, dly, _, _ = test_connectivity_and_geo(xray_bin, link) # فقط تست پینگ برای آپدیت
            if ok:
                execute_db("UPDATE proxies SET delay=?, last_test=?, fails=0 WHERE link=?", (dly, time.time(), link))
                print(f"[{i}/{len(expired)}] 🔁 ✅ زنده ماند")
            else:
                if fails + 1 >= MAX_FAILURES:
                    execute_db("DELETE FROM proxies WHERE link=?", (link,))
                    print(f"[{i}/{len(expired)}] 🔁 🗑️ حذف شد")
                else:
                    execute_db("UPDATE proxies SET fails=?, last_test=? WHERE link=?", (fails+1, time.time(), link))
                    print(f"[{i}/{len(expired)}] 🔁 ❌ یک خطا ثبت شد")

    # 3. تولید خروجی
    print("\n📦 در حال ایجاد فایل خروجی...")
    valid_configs = execute_db("SELECT link, country, cc FROM proxies ORDER BY delay ASC")
    final_list = []
    for link, country, cc in valid_configs:
        final_list.append(rename_config(link, country, cc))
        
    content = base64.b64encode("\n".join(final_list).encode()).decode()
    with open(OUTPUT_FILE, "w") as f: f.write(content)
    
    shutil.rmtree(os.path.dirname(xray_bin), ignore_errors=True)
    print(f"🎉 پایان! {len(final_list)} کانفیگ فعال و لیبل‌دار در {OUTPUT_FILE} ذخیره شد.")
