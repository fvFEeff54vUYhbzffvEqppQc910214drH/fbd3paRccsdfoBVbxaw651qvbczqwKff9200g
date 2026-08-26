import requests
from bs4 import BeautifulSoup
import re
import os
import html
import json
import base64
import urllib.parse
from datetime import datetime, timezone

# =============================================================
#  بخش تنظیمات عمومی (General Settings)
# =============================================================
MY_CHANNEL_ID = ""
CUSTOM_SEPARATOR = "|"
NOT_FOUND_FLAG = "🌐"

PINNED_CONFIGS = [
    "ss://bm9uZTpmOGY3YUN6Y1BLYnNGOHAz@lil:360?#%F0%9F%91%91",
]

SUPPORTED_PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://', 'ss://', 'shadowsocks://']

DB_EXPIRY_HOURS = 48       
SCRAPER_SEARCH_LIMIT_HOURS = 1   

# =============================================================
#  تنظیمات اختصاصی فایل خروجی 1.txt
# =============================================================
FILE_1_LIMIT = 50            
FILE_1_TARGET_MINUTES = 60   

ROTATION_LIMIT_2 = 1000   
ROTATION_LIMIT_3 = 100000   
# =============================================================

def get_only_flag(text):
    if not text: return 
    try:
        text = urllib.parse.unquote(urllib.parse.unquote(str(text)))
    except: pass
    flag_pattern = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
    flags = flag_pattern.findall(text)
    return flags[0] if flags else NOT_FOUND_FLAG

def parse_vmess_uri(config):
    try:
        b64_str = config[8:]
        # رفع باگ اول: استخراج خالص‌ترین بخش Base64 و دور ریختن پسماندهای تگ‌های HTML یا متون اضافه
        match = re.match(r'^[A-Za-z0-9+/=_-]+', b64_str)
        if not match: return None, False
        b64_str = match.group(0)
        
        # استانداردسازی کاراکترها
        b64_str = b64_str.replace('-', '+').replace('_', '/')
        b64_str += "=" * (-len(b64_str) % 4)
        data = json.loads(base64.b64decode(b64_str).decode('utf-8'))
        return data, True
    except:
        return None, False

def get_config_fingerprint(config):
    try:
        config = config.strip()
        if config.startswith("vmess://"):
            data, ok = parse_vmess_uri(config)
            if ok:
                keys = ['add', 'port', 'id', 'net', 'tls', 'path', 'host', 'sni']
                return "vmess:" + "|".join(str(data.get(k, '')).lower() for k in keys)
        
        base_part = config.split('#')[0]
        parsed = urllib.parse.urlparse(base_part)
        query_params = urllib.parse.parse_qsl(parsed.query)
        filtered_params = sorted([(k.lower(), v.lower()) for k, v in query_params if k.lower() not in ['remark', 'ps', 'name']])
        normalized_query = urllib.parse.urlencode(filtered_params)
        return f"{parsed.scheme}:{parsed.netloc.lower()}{parsed.path.lower()}?{normalized_query}"
    except:
        return config

def analyze_and_rename(config, channel_name):
    try:
        config = config.strip()
        clean_source = channel_name.replace("https://t.me/", "@").replace("t.me/", "@")
        if not clean_source.startswith("@"): clean_source = f"@{clean_source}"

        transport, security, flag = "TCP", "None", NOT_FOUND_FLAG
        
        if config.startswith("vmess://"):
            data, ok = parse_vmess_uri(config)
            if ok:
                flag = get_only_flag(data.get('ps', ''))
                t_map = {'tcp': 'TCP', 'ws': 'WS', 'grpc': 'GRPC', 'kcp': 'KCP', 'h2': 'H2', 'quic': 'QUIC', 'httpupgrade': 'HTTPUpgrade', 'xhttp': 'XHTTP'}
                # رفع باگ دوم: استفاده از ()str برای جلوگیری از کرش در مواجهه با مقادیر Null
                transport = t_map.get(str(data.get('net', 'tcp')).lower(), 'TCP')
                security = 'TLS' if str(data.get('tls', '')).lower() == 'tls' else 'None'
                data['ps'] = f"{flag} {transport}-{security} {CUSTOM_SEPARATOR} {clean_source}"
                # رفع باگ سوم: استفاده از separators برای حذف فاصله‌های اضافی در JSON
                return "vmess://" + base64.b64encode(json.dumps(data, separators=(',', ':')).encode('utf-8')).decode('utf-8')

        base_url, raw_fragment = config.split('#', 1) if '#' in config else (config, "")
        flag = get_only_flag(raw_fragment)
        
        parsed = urllib.parse.urlparse(base_url)
        params = {k.lower(): v.lower() for k, v in urllib.parse.parse_qsl(parsed.query)}

        if 'security' in params:
            if params['security'] in ['tls', 'xtls', 'ssl']: security = 'TLS'
            elif params['security'] == 'reality': security = 'Reality'
        elif 'sni' in params or 'pbk' in params: security = 'Reality' if 'pbk' in params else 'TLS'

        t_val = params.get('type', params.get('net', 'tcp'))
        t_map = {'tcp': 'TCP', 'ws': 'WS', 'grpc': 'GRPC', 'kcp': 'KCP', 'httpupgrade': 'HTTPUpgrade', 'xhttp': 'XHTTP'}
        transport = t_map.get(t_val, 'TCP')

        if config.startswith(('hysteria2://', 'hy2://')): transport, security = "Hysteria", "TLS"
        elif config.startswith(('ss://', 'shadowsocks://')):
            transport, security = "TCP", "None"
            plugin = urllib.parse.unquote(params.get('plugin', '')).lower()
            if 'tls' in plugin or 'ssl' in plugin: security = "TLS"
            if 'ws' in plugin or 'websocket' in plugin: transport = "WS"
            elif 'grpc' in plugin: transport = "GRPC"

        final_name = f"{flag} {transport}-{security} {CUSTOM_SEPARATOR} {clean_source}"
        return f"{base_url}#{urllib.parse.quote(final_name)}"
    except:
        return config

def extract_configs_logic(msg_div):
    for img in msg_div.find_all("img"):
        if 'emoji' in img.get('class', []) and img.get('alt'): img.replace_with(img['alt'])
    for br in msg_div.find_all("br"): br.replace_with("\n")
    full_text = html.unescape(msg_div.get_text())
    extracted = []
    for line in full_text.split('\n'):
        line = line.strip()
        for proto in SUPPORTED_PROTOCOLS:
            if proto in line:
                start_idx = line.find(proto)
                extracted.append(line[start_idx:].strip())
                break
    return extracted

def run():
    if not os.path.exists('channels.txt'): return
    with open('channels.txt', 'r') as f:
        channels = [line.strip() for line in f if line.strip()]

    db_data = []
    if os.path.exists('data.temp'):
        with open('data.temp', 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('|', 2)
                if len(parts) == 3: db_data.append(parts)

    now = datetime.now().timestamp()
    all_raw_seen = {d[2] for d in db_data}

    for ch in channels:
        try:
            resp = requests.get(f"https://t.me/s/{ch}", timeout=15)
            if resp.status_code != 200: continue
            soup = BeautifulSoup(resp.text, 'html.parser')
            for wrap in soup.find_all('div', class_='tgme_widget_message_wrap'):
                time_tag = wrap.find('time')
                if not time_tag: continue
                msg_time = datetime.fromisoformat(time_tag['datetime'])
                if (datetime.now(timezone.utc) - msg_time).total_seconds() > (SCRAPER_SEARCH_LIMIT_HOURS * 3600): continue
                msg_text = wrap.find('div', class_='tgme_widget_message_text')
                if not msg_text: continue
                for c in extract_configs_logic(msg_text):
                    if c not in all_raw_seen:
                        db_data.append([str(now), ch, c])
                        all_raw_seen.add(c)
        except: continue

    valid_items = [item for item in db_data if now - float(item[0]) < (DB_EXPIRY_HOURS * 3600)]

    unique_pool = []
    fingerprints_seen = set()
    for pin in PINNED_CONFIGS: fingerprints_seen.add(get_config_fingerprint(pin))
    
    for item in valid_items:
        fp = get_config_fingerprint(item[2])
        if fp not in fingerprints_seen:
            unique_pool.append(item)
            fingerprints_seen.add(fp)

    current_index = 0
    if os.path.exists('pointer.txt'):
        try:
            with open('pointer.txt', 'r') as f: current_index = int(f.read().strip())
        except: current_index = 0

    pool_size = len(unique_pool)
    if current_index >= pool_size: current_index = 0

    def save_output(filename, batch):
        with open(filename, 'w', encoding='utf-8') as f:
            for pin in PINNED_CONFIGS: f.write(pin + "\n\n")
            for ts, source_ch, raw_cfg in batch:
                f.write(analyze_and_rename(raw_cfg, source_ch) + "\n\n")

    # =============================================================
    #  منطق اختصاصی پردازش فایل 1.txt
    # =============================================================
    pool_target_time = [item for item in unique_pool if now - float(item[0]) <= (FILE_1_TARGET_MINUTES * 60)]
    
    if len(pool_target_time) <= FILE_1_LIMIT:
        global_sorted_desc = sorted(unique_pool, key=lambda x: float(x[0]), reverse=True)
        file_1_batch = global_sorted_desc[:FILE_1_LIMIT]
    else:
        t_size = len(pool_target_time)
        idx = current_index % t_size
        if idx + FILE_1_LIMIT <= t_size:
            file_1_batch = pool_target_time[idx : idx + FILE_1_LIMIT]
        else:
            file_1_batch = pool_target_time[idx:] + pool_target_time[:FILE_1_LIMIT - (t_size - idx)]

    save_output('1.txt', file_1_batch)

    # =============================================================
    #  منطق اصلی سایر فایل‌ها
    # =============================================================
    def get_rotated_batch_original(size, specific_pool):
        t_size = len(specific_pool)
        if t_size == 0: return []
        idx = current_index % t_size
        actual_size = min(size, t_size)
        if idx + actual_size <= t_size:
            return specific_pool[idx : idx + actual_size]
        else:
            return specific_pool[idx:] + specific_pool[:actual_size - (t_size - idx)]

    pool_3h = [item for item in unique_pool if now - float(item[0]) <= 10800]

    save_output('2.txt', get_rotated_batch_original(ROTATION_LIMIT_2, pool_3h))
    save_output('3.txt', unique_pool[-ROTATION_LIMIT_3:])
    save_output('4.txt', [item for item in unique_pool if now - float(item[0]) < 300])

    # =============================================================
    #  سیستم شناسایی کانال‌های غیرفعال
    # =============================================================
    active_channels = {item[1].strip().lower() for item in valid_items}
    inactive_channels = []
    
    for ch in channels:
        ch_clean = ch.strip()
        if ch_clean.lower() not in active_channels:
            formatted_ch = ch_clean if ch_clean.startswith('@') else f"@{ch_clean}"
            inactive_channels.append(formatted_ch)

    with open('inactive_channels.txt', 'w', encoding='utf-8') as f:
        for ch_name in inactive_channels:
            f.write(ch_name + "\n")

    # =============================================================
    #  بروزرسانی نهایی فایل‌های سیستمی (دیتا و پوینتر)
    # =============================================================
    with open('data.temp', 'w', encoding='utf-8') as f:
        for item in valid_items: f.write("|".join(item) + "\n")

    # پوینتر همیشه آپدیت می‌شود تا فایل‌های دیگر (مثل ۲) به چرخش خود ادامه دهند
    with open('pointer.txt', 'w', encoding='utf-8') as f:
        f.write(str((current_index + FILE_1_LIMIT) % pool_size if pool_size > 0 else 0))

if __name__ == "__main__":
    run()
