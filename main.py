# main.py/hamed
import requests
import re
import json
import hashlib
import time
import os
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse, parse_qs
import logging
from bs4 import BeautifulSoup

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHANNEL_ID = int(os.environ.get("CHANNEL_ID", "-1003748742163"))

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN environment variable is required")

CHANNELS = [
    "https://t.me/s/hddify",
    "https://t.me/s/ProxyAnonymous",
    "https://t.me/s/JavidanNet",
    "https://t.me/s/ShadowProxy66",
    "https://t.me/s/BestProxyTel1",
    "https://t.me/s/proxyir01",
    "https://t.me/s/proxymtprotoir",
    "https://t.me/s/iRoProxy",
    "https://t.me/s/IPCF_Proxy",
    "https://t.me/s/proxy_bolt",
    "https://t.me/s/proxyskyy",
    "https://t.me/s/ProxySkull"
]

IPV4 = r'(?:25[0-5]|2[0-4]\d|1?\d?\d)'

PROXY_PATTERNS = [
    rf'(mtproto://[^\s<>"\'()]+)',
    rf'(https?://t\.me/proxy\?[^\s<>"\'()]+)',
    rf'(https?://t\.me/socks\?[^\s<>"\'()]+)',
    rf'(tg://proxy\?[^\s<>"\'()]+)',
    rf'(tg://socks\?[^\s<>"\'()]+)',
    rf'(socks5://[^\s<>"\'()]+)',
    rf'((?:{IPV4}\.){{3}}{IPV4}:\d{{1,5}}:[a-fA-F0-9]+)',
    rf'((?:{IPV4}\.){{3}}{IPV4}:\d{{1,5}}(?:[:][^:\s]+[:][^:\s]+)?)'
]

AD_KEYWORDS = [
    'join', 'channel', 'عضویت', 'کانال', 'ادمین', 'خرید', 'فروش', 'تبلیغ',
    'instagram.com', 'اینستاگرام', 'آموزش', 'tutorial', 'support',
    'telegram.me/join', 't.me/join', 'click', 'لینک عضویت'
]

SENT_HISTORY_FILE = "sent_proxies.json"
MAX_PROXIES_PER_POST = 6
CLEANUP_FILE = "last_cleanup.json"


class MTProtoSocksExtractor:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        self.sent_proxies = self.load_sent_history()
        self.cache_file = "dead_cache.json"
        self.dead_cache = self.load_dead_cache()
        self.failed_counter = {}
        self.last_cleanup = self.load_last_cleanup()
        
        # انجام پاکسازی خودکار در شروع
        self.auto_cleanup()

    def load_last_cleanup(self) -> datetime:
        """بارگذاری زمان آخرین پاکسازی"""
        try:
            if os.path.exists(CLEANUP_FILE):
                with open(CLEANUP_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return datetime.fromisoformat(data.get("last_cleanup", "2000-01-01T00:00:00"))
        except:
            pass
        return datetime(2000, 1, 1)
    
    def save_last_cleanup(self):
        """ذخیره زمان پاکسازی"""
        try:
            with open(CLEANUP_FILE, 'w', encoding='utf-8') as f:
                json.dump({"last_cleanup": datetime.now().isoformat()}, f)
        except:
            pass
    
    def auto_cleanup(self):
        """پاکسازی خودکار کش هر ۲۴ ساعت"""
        now = datetime.now()
        if now - self.last_cleanup >= timedelta(hours=24):
            logger.info("🔄 Performing automatic cache cleanup...")
            
            # پاکسازی کش کانال‌های مرده
            old_dead_count = len(self.dead_cache)
            self.dead_cache.clear()
            self.save_dead_cache()
            
            # پاکسازی کش پروکسی‌های ارسال شده
            old_sent_count = len(self.sent_proxies)
            self.sent_proxies.clear()
            self.save_sent_history()
            
            # ریست شمارنده خطاها
            self.failed_counter.clear()
            
            # ذخیره زمان پاکسازی
            self.last_cleanup = now
            self.save_last_cleanup()
            
            logger.info(f"✅ Cleaned {old_dead_count} dead channels and {old_sent_count} sent proxies")
        else:
            # اگر ۲۴ ساعت نگذشته، فقط کش‌های منقضی شده رو پاک کن
            self.clean_expired_entries()
    
    def clean_expired_entries(self):
        """پاک کردن آیتم‌های منقضی شده (بیشتر از ۲۴ ساعت)"""
        now = datetime.now()
        cleaned = False
        
        # پاک کردن کانال‌های منقضی
        expired_channels = [url for url, dt in self.dead_cache.items() 
                           if now - dt >= timedelta(hours=24)]
        for url in expired_channels:
            del self.dead_cache[url]
        if expired_channels:
            self.save_dead_cache()
            logger.info(f"Removed {len(expired_channels)} expired channels")
            cleaned = True
        
        # پاک کردن پروکسی‌های منقضی
        expired_proxies = [h for h, dt in self.sent_proxies.items() 
                          if now - dt >= timedelta(hours=24)]
        for h in expired_proxies:
            del self.sent_proxies[h]
        if expired_proxies:
            self.save_sent_history()
            logger.info(f"Removed {len(expired_proxies)} expired proxies")
            cleaned = True
        
        return cleaned

    def load_sent_history(self) -> Dict:
        if os.path.exists(SENT_HISTORY_FILE):
            try:
                with open(SENT_HISTORY_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for k, v in data.items():
                        data[k] = datetime.fromisoformat(v)
                    return data
            except:
                return {}
        return {}

    def save_sent_history(self):
        try:
            with open(SENT_HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump({k: v.isoformat() for k, v in self.sent_proxies.items()}, f, ensure_ascii=False, indent=2)
        except:
            pass

    def load_dead_cache(self) -> Dict:
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for k, v in data.items():
                        data[k] = datetime.fromisoformat(v)
                    return data
            except:
                return {}
        return {}

    def save_dead_cache(self):
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump({k: v.isoformat() for k, v in self.dead_cache.items()}, f, ensure_ascii=False, indent=2)
        except:
            pass

    def should_skip_channel(self, url: str) -> bool:
        if url in self.dead_cache:
            if datetime.now() - self.dead_cache[url] < timedelta(hours=24):
                return True
            else:
                del self.dead_cache[url]
                self.save_dead_cache()
        return False

    def update_dead_cache(self, url: str):
        """Update dead cache for failed channels"""
        self.failed_counter[url] = self.failed_counter.get(url, 0) + 1
        if self.failed_counter[url] >= 3:
            self.dead_cache[url] = datetime.now()
            self.save_dead_cache()
            logger.info(f"Channel {url} added to dead cache after 3 failures")

    def is_proxy_already_sent(self, proxy: str) -> bool:
        h = hashlib.md5(proxy.encode()).hexdigest()
        if h in self.sent_proxies:
            if datetime.now() - self.sent_proxies[h] < timedelta(hours=24):
                return True
            else:
                del self.sent_proxies[h]
                self.save_sent_history()
        return False

    def mark_as_sent(self, proxy: str):
        h = hashlib.md5(proxy.encode()).hexdigest()
        self.sent_proxies[h] = datetime.now()
        self.save_sent_history()

    def has_ad_keywords(self, text: str) -> bool:
        t = text.lower()
        for k in AD_KEYWORDS:
            if k in t:
                return True
        return False

    def extract_from_text(self, text: str) -> List[str]:
        out = []
        for p in PROXY_PATTERNS:
            out += re.findall(p, text, re.IGNORECASE)
        return list(set(out))

    def extract_proxy_buttons(self, soup) -> List[str]:
        proxies = []
        buttons = soup.find_all("a", href=True)
        for btn in buttons:
            href = btn.get("href", "").strip()
            if not href:
                continue
            href_lower = href.lower()
            if "joinchat" in href_lower:
                continue
            if "/+" in href:
                continue
            if (
                href.startswith("tg://proxy?")
                or href.startswith("tg://socks?")
                or href.startswith("https://t.me/proxy?")
                or href.startswith("https://t.me/socks?")
                or href.startswith("mtproto://")
                or href.startswith("socks5://")
            ):
                proxies.append(self.normalize_proxy(href))
        return list(set(proxies))

    def normalize_proxy(self, proxy: str) -> str:
        proxy = proxy.strip()
        if proxy.startswith('https://t.me/proxy?'):
            proxy = proxy.replace('https://t.me/proxy?', 'tg://proxy?')
        elif proxy.startswith('https://t.me/socks?'):
            proxy = proxy.replace('https://t.me/socks?', 'tg://socks?')
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}:\d+:[a-fA-F0-9]+$', proxy):
            a, b, c = proxy.split(':')
            proxy = f"tg://proxy?server={a}&port={b}&secret={c}"
        elif re.match(r'^\d{1,3}(\.\d{1,3}){3}:\d+$', proxy):
            a, b = proxy.split(':')
            proxy = f"socks5://{a}:{b}"
        elif re.match(r'^\d{1,3}(\.\d{1,3}){3}:\d+:[^:]+:[^:]+$', proxy):
            a, b, c, d = proxy.split(':')
            proxy = f"socks5://{c}:{d}@{a}:{b}"
        return proxy

    def fetch_page(self, url: str) -> Optional[str]:
        try:
            r = self.session.get(url, timeout=20)
            return r.text
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            return None

    def extract_proxies_from_channel(self, url: str) -> List[str]:
        if self.should_skip_channel(url):
            logger.info(f"Skipping {url} (in dead cache)")
            return []
        
        html = self.fetch_page(url)
        if not html:
            self.update_dead_cache(url)
            return []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            blocks = soup.find_all('div', class_='tgme_widget_message_text')
            result = []
            
            # Extract from buttons
            button_proxies = self.extract_proxy_buttons(soup)
            for p in button_proxies:
                if not self.is_proxy_already_sent(p):
                    result.append(p)
            
            # Extract from text blocks
            for b in blocks:
                text = b.get_text()
                if self.has_ad_keywords(text):
                    continue
                found = self.extract_from_text(text)
                for f in found:
                    n = self.normalize_proxy(f)
                    if not self.is_proxy_already_sent(n):
                        result.append(n)
            
            # Reset failure counter on success
            self.failed_counter[url] = 0
            logger.info(f"Extracted {len(result)} proxies from {url}")
            return list(set(result))
            
        except Exception as e:
            logger.error(f"Error parsing {url}: {e}")
            self.update_dead_cache(url)
            return []

    def collect_all_proxies(self) -> List[Tuple[str, str]]:
        allp = []
        for c in CHANNELS:
            ps = self.extract_proxies_from_channel(c)
            for p in ps:
                t = "MTProto" if "proxy" in p else "SOCKS5"
                allp.append((p, t))
        
        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for p, t in allp:
            if p not in seen:
                seen.add(p)
                unique.append((p, t))
        
        logger.info(f"Collected {len(unique)} unique proxies from all channels")
        return unique


class TelegramSender:
    def __init__(self, token: str, chat_id: int):
        self.api = f"https://api.telegram.org/bot{token}"
        self.chat_id = chat_id

    def send_message(self, text: str, reply_markup=None) -> bool:
        try:
            data = {
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True
            }
            if reply_markup:
                data["reply_markup"] = json.dumps(reply_markup)
            r = requests.post(self.api + "/sendMessage", data=data, timeout=30)
            success = r.status_code == 200
            if not success:
                logger.error(f"Failed to send message: {r.status_code}")
            return success
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return False

    def create_proxy_keyboard(self, proxies: List[Tuple[str, str]]) -> dict:
        kb = []
        row = []
        for i, (p, t) in enumerate(proxies):
            row.append({
                "text": f"📡 {t}" if t == "MTProto" else f"🔒 {t}",
                "url": p
            })
            if len(row) == 2 or i == len(proxies) - 1:
                kb.append(row)
                row = []
        return {"inline_keyboard": kb}

    def create_caption(self, proxies: List[Tuple[str, str]]) -> str:
        return """✅ پروکسی‌های جدید 💯
👈 برای اتصال به پروکسی‌ها از دکمه‌های زیر استفاده کنید.
➖➖➖➖➖➖➖➖
🚀 @hamedproxy1 🚀
➖➖➖➖➖➖➖➖
<blockquote>کانال اصلی ما : @hamedvpns 👉👉
</blockquote>
<blockquote>لینک گروه ما : @hamedgrp 👉👉
</blockquote>
<blockquote>اسپانسر : @aristapanel 👉👉
</blockquote>
➖➖➖➖➖➖➖➖
#پروکسی #proxy #MTProto #SOCKS5"""

    def send_proxies_batch(self, proxies: List[Tuple[str, str]]) -> bool:
        if not proxies:
            return False
        return self.send_message(self.create_caption(proxies), self.create_proxy_keyboard(proxies))


class ProxyScheduler:
    def __init__(self):
        self.ext = MTProtoSocksExtractor()
        self.sender = TelegramSender(BOT_TOKEN, CHANNEL_ID)

    async def run_once(self):
        logger.info("Starting proxy collection...")
        proxies = self.ext.collect_all_proxies()
        
        if proxies:
            logger.info(f"Sending {len(proxies)} proxies in batches of {MAX_PROXIES_PER_POST}")
            for i in range(0, len(proxies), MAX_PROXIES_PER_POST):
                batch = proxies[i:i + MAX_PROXIES_PER_POST]
                if self.sender.send_proxies_batch(batch):
                    for p, _ in batch:
                        self.ext.mark_as_sent(p)
                    logger.info(f"Sent batch {i//MAX_PROXIES_PER_POST + 1}/{(len(proxies)-1)//MAX_PROXIES_PER_POST + 1}")
                else:
                    logger.error(f"Failed to send batch {i//MAX_PROXIES_PER_POST + 1}")
                await asyncio.sleep(1)
        else:
            logger.info("No new proxies found")


def main():
    asyncio.run(ProxyScheduler().run_once())


if __name__ == "__main__":
    main()
