import argparse
import csv
import ipaddress
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = CYAN = GREEN = YELLOW = BLUE = MAGENTA = WHITE = BLACK = RESET = ''
        LIGHTRED_EX = LIGHTCYAN_EX = LIGHTGREEN_EX = LIGHTYELLOW_EX = LIGHTBLUE_EX = LIGHTMAGENTA_EX = LIGHTWHITE_EX = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

@dataclass
class VlessConfig:
    raw: str
    uuid: str
    host: str
    port: int
    remark: str
    query: Dict[str, str]

@dataclass
class ScanResult:
    ip: str
    ok: bool
    latency_ms: Optional[float] = None
    status_code: Optional[int] = None
    error: str = ""
    speed_mbps: Optional[float] = None
    speed_bytes: int = 0
    speed_error: str = ""
    recheck_passed: int = 0
    recheck_total: int = 0
    source_type: str = ""

class NavigationBack(Exception):
    pass

class NavigationExit(Exception):
    pass

class ScanInterrupted(Exception):
    def __init__(self, results: List[ScanResult], stage: str = "scan"):
        self.results = results
        self.stage = stage

def app_dir() -> Path:
    home = Path.home()
    app_dir_path = home / ".vless_scanner"
    app_dir_path.mkdir(exist_ok=True)
    return app_dir_path

def used_ips_file() -> Path:
    return app_dir() / "used_ips.json"

def load_used_ips() -> set:
    used_file = used_ips_file()
    if used_file.exists():
        try:
            with open(used_file, 'r') as f:
                data = json.load(f)
                return set(data.get('ips', []))
        except:
            return set()
    return set()

def save_used_ips(ips: set):
    used_file = used_ips_file()
    with open(used_file, 'w') as f:
        json.dump({'ips': list(ips), 'updated_at': datetime.now().isoformat()}, f)

def get_unique_targets(all_targets: List[str], used_ips: set, max_ips: int = 5000) -> List[str]:
    unused = [ip for ip in all_targets if ip not in used_ips]
    if not unused:
        used_ips.clear()
        save_used_ips(used_ips)
        return all_targets[:max_ips]
    return unused[:max_ips]

def fetch_ip_ranges_from_github(url: str) -> List[str]:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode('utf-8')
            ips = []
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    if '/' in line:
                        try:
                            network = ipaddress.ip_network(line, strict=False)
                            ips.extend([str(ip) for ip in network.hosts()])
                        except ValueError:
                            ips.append(line)
                    else:
                        ips.append(line)
            return ips
    except Exception as e:
        print(f"{Fore.RED}Error fetching {url}: {e}{Style.RESET_ALL}")
        return []

def expand_cidr(cidr: str, max_ips_per_cidr: int = 500) -> List[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())
        total = len(hosts)
        if total <= max_ips_per_cidr:
            return [str(ip) for ip in hosts]
        step = total // max_ips_per_cidr
        return [str(hosts[i]) for i in range(0, total, step)][:max_ips_per_cidr]
    except ValueError:
        return [cidr] if cidr else []

def get_global_ip_sources() -> List[Tuple[str, str]]:
    return [
        ("telegram", "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/telegram/telegram_plain_ipv4.txt"),
        ("vercel", "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/vercel/vercel_plain_ipv4.txt"),
        ("meta", "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/meta/meta_plain_ipv4.txt"),
        ("hetzner", "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/hetzner/hetzner_plain_ipv4.txt"),
        ("fastly", "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/fastly/fastly_plain_ipv4.txt"),
        ("cloudflare", "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/cloudflare/cloudflare_plain_ipv4.txt"),
        ("akamai", "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/akamai/akamai_plain_ipv4.txt"),
        ("cdn77", "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/cdn77/cdn77_plain_ipv4.txt"),
        ("cogent", "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/cogent/cogent_plain_ipv4.txt"),
        ("digitalocean", "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/digitalocean/digitalocean_plain_ipv4.txt"),
    ]

def get_iran_ip_sources() -> List[Tuple[str, str]]:
    return [
        ("Afranet", "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Afranet.txt"),
        ("AsiaTech", "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/AsiaTech-ip-CF.txt"),
        ("Telecom", "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Iran%20Telecommunication%20Company%20PJS.txt"),
        ("Mizban", "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Mizban%20Dade.txt"),
        ("ManageIt", "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/MnageIt.txt"),
        ("Arvan1", "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Noyan%20Abr%20Arvan%20Co_1.txt"),
        ("Arvan2", "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Noyan%20Abr%20Arvan%20Co_2.txt"),
        ("Arvan3", "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Noyan%20Abr%20Arvan%20Co_3.txt"),
        ("ParsAbr", "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Pars%20Abr.txt"),
        ("ParsOnline", "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Pars%20Online.txt"),
        ("Respina", "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Respina.txt"),
        ("Tookan", "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Tookan.txt"),
    ]

def load_ip_ranges(sources: List[Tuple[str, str]], max_per_source: int = 500, max_per_cidr: int = 50) -> Tuple[List[str], Dict[str, List[str]]]:
    all_ips = []
    source_ips = {}
    
    for name, url in sources:
        print(f"{Fore.CYAN}Loading {name} from {url}{Style.RESET_ALL}")
        ranges = fetch_ip_ranges_from_github(url)
        ips = []
        for r in ranges[:100]:
            ips.extend(expand_cidr(r, max_per_cidr))
        
        if ips:
            ips = list(set(ips))[:max_per_source]
            source_ips[name] = ips
            all_ips.extend(ips)
            print(f"  {Fore.GREEN}Got {len(ips)} IPs from {name}{Style.RESET_ALL}")
    
    return list(set(all_ips)), source_ips

def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def wait_port(port: int, timeout: float) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                return True
        except (socket.error, ConnectionRefusedError):
            time.sleep(0.1)
    return False

def vless_to_xray_outbound(v: VlessConfig, server_ip: str) -> Dict:
    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": server_ip,
                "port": v.port,
                "users": [{"id": v.uuid, "encryption": "none"}]
            }]
        },
        "streamSettings": {
            "network": v.query.get("type", "tcp"),
            "security": v.query.get("security", "none")
        }
    }
    
    if v.query.get("security") == "reality":
        outbound["streamSettings"]["realitySettings"] = {
            "serverName": v.query.get("sni", ""),
            "fingerprint": v.query.get("fp", "chrome"),
            "publicKey": v.query.get("pbk", ""),
            "shortId": v.query.get("sid", "")
        }
    elif v.query.get("security") == "tls":
        outbound["streamSettings"]["tlsSettings"] = {
            "serverName": v.query.get("sni", v.host),
            "allowInsecure": True
        }
    
    if v.query.get("type") == "ws":
        outbound["streamSettings"]["wsSettings"] = {
            "path": v.query.get("path", "/"),
            "headers": {"Host": v.query.get("host", v.host)}
        }
    
    return outbound

def make_xray_config(v: VlessConfig, server_ip: str, socks_port: int, loglevel: str) -> Dict:
    return {
        "log": {"loglevel": loglevel},
        "inbounds": [{
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True}
        }],
        "outbounds": [vless_to_xray_outbound(v, server_ip), {"protocol": "freedom", "tag": "direct"}],
        "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["socks"], "outboundTag": "proxy"}]}
    }

def test_ip(v: VlessConfig, ip: str, xray: Path, timeout: int, tries: int, url: str, loglevel: str, keep_configs: bool = False) -> ScanResult:
    import requests
    
    for attempt in range(tries):
        socks_port = free_port()
        config = make_xray_config(v, ip, socks_port, loglevel)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            config_path = Path(f.name)
        
        proc = None
        try:
            proc = subprocess.Popen([str(xray), "-config", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            if not wait_port(socks_port, 5.0):
                raise Exception("SOCKS port not ready")
            
            proxies = {"http": f"socks5://127.0.0.1:{socks_port}", "https": f"socks5://127.0.0.1:{socks_port}"}
            start = time.time()
            resp = requests.get(url, proxies=proxies, timeout=timeout, verify=False)
            latency_ms = (time.time() - start) * 1000
            
            if resp.status_code == 204 or resp.status_code == 200:
                return ScanResult(ip=ip, ok=True, latency_ms=latency_ms, status_code=resp.status_code)
            return ScanResult(ip=ip, ok=False, error=f"HTTP {resp.status_code}")
        
        except Exception as e:
            if attempt == tries - 1:
                return ScanResult(ip=ip, ok=False, error=str(e))
        finally:
            if proc:
                proc.terminate()
                time.sleep(0.1)
                proc.kill()
            if not keep_configs:
                try:
                    config_path.unlink()
                except:
                    pass
    
    return ScanResult(ip=ip, ok=False, error="All attempts failed")

def run_scan(v: VlessConfig, targets: List[str], xray: Path, concurrency: int, timeout: int, tries: int, url: str, loglevel: str, keep_configs: bool, source_type: str = "") -> List[ScanResult]:
    results = []
    total = len(targets)
    completed = 0
    lock = threading.Lock()
    
    print(f"\n{Fore.CYAN}Scanning {total} IPs with concurrency {concurrency}...{Style.RESET_ALL}")
    
    def scan_one(ip: str) -> ScanResult:
        nonlocal completed
        result = test_ip(v, ip, xray, timeout, tries, url, loglevel, keep_configs)
        result.source_type = source_type
        with lock:
            completed += 1
            if result.ok:
                print(f"{Fore.GREEN}[{completed}/{total}] {ip} - OK - {result.latency_ms:.0f}ms{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[{completed}/{total}] {ip} - FAIL - {result.error[:50]}{Style.RESET_ALL}")
        return result
    
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(scan_one, ip): ip for ip in targets}
        try:
            for future in as_completed(futures):
                results.append(future.result())
        except KeyboardInterrupt:
            executor.shutdown(wait=False, cancel_futures=True)
            raise ScanInterrupted(results, "scan")
    
    return results

def speed_test_ip(v: VlessConfig, base_result: ScanResult, xray: Path, timeout: int, speed_bytes: int, speed_duration: int, speed_url_template: str, loglevel: str) -> ScanResult:
    import requests
    
    result = ScanResult(
        ip=base_result.ip,
        ok=base_result.ok,
        latency_ms=base_result.latency_ms,
        status_code=base_result.status_code,
        source_type=base_result.source_type
    )
    
    if not base_result.ok:
        return result
    
    socks_port = free_port()
    config = make_xray_config(v, base_result.ip, socks_port, loglevel)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f)
        config_path = Path(f.name)
    
    proc = None
    try:
        proc = subprocess.Popen([str(xray), "-config", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if not wait_port(socks_port, 5.0):
            raise Exception("SOCKS port not ready")
        
        proxies = {"http": f"socks5://127.0.0.1:{socks_port}", "https": f"socks5://127.0.0.1:{socks_port}"}
        url = speed_url_template.format(bytes=speed_bytes)
        
        start = time.time()
        resp = requests.get(url, proxies=proxies, timeout=timeout, verify=False, stream=True)
        
        downloaded = 0
        for chunk in resp.iter_content(chunk_size=65536):
            downloaded += len(chunk)
            elapsed = time.time() - start
            if elapsed >= speed_duration:
                break
        
        elapsed = time.time() - start
        speed_mbps = (downloaded * 8) / (elapsed * 1024 * 1024) if elapsed > 0 else 0
        
        result.speed_bytes = downloaded
        result.speed_mbps = speed_mbps
        
    except Exception as e:
        result.speed_error = str(e)
    finally:
        if proc:
            proc.terminate()
            time.sleep(0.1)
            proc.kill()
        try:
            config_path.unlink()
        except:
            pass
    
    return result

def run_speed_tests(v: VlessConfig, ok_results: List[ScanResult], xray: Path, workers: int, timeout: int, speed_bytes: int, speed_duration: int, speed_url_template: str, loglevel: str) -> List[ScanResult]:
    results = []
    total = len(ok_results)
    completed = 0
    lock = threading.Lock()
    
    if not ok_results:
        return []
    
    print(f"\n{Fore.CYAN}Speed testing {total} IPs with {workers} workers...{Style.RESET_ALL}")
    
    def test_one(result: ScanResult) -> ScanResult:
        nonlocal completed
        r = speed_test_ip(v, result, xray, timeout, speed_bytes, speed_duration, speed_url_template, loglevel)
        with lock:
            completed += 1
            if r.speed_mbps:
                print(f"{Fore.GREEN}[{completed}/{total}] {r.ip} - {r.speed_mbps:.1f}Mbps{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[{completed}/{total}] {r.ip} - speed test failed{Style.RESET_ALL}")
        return r
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(test_one, r) for r in ok_results]
        try:
            for future in as_completed(futures):
                results.append(future.result())
        except KeyboardInterrupt:
            executor.shutdown(wait=False, cancel_futures=True)
            raise ScanInterrupted(results, "speed")
    
    return sorted(results, key=lambda x: x.speed_mbps or 0, reverse=True)

def save_results(results: List[ScanResult], output_dir: Path, filename_prefix: str = "clean_ips", max_latency_ms: float = 0, min_speed_mbps: float = 0, include_speed_errors: bool = False) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    
    filtered = []
    for r in results:
        if not r.ok:
            continue
        if max_latency_ms > 0 and r.latency_ms and r.latency_ms > max_latency_ms:
            continue
        if min_speed_mbps > 0 and (not r.speed_mbps or r.speed_mbps < min_speed_mbps):
            continue
        if not include_speed_errors and r.speed_error:
            continue
        filtered.append(r)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = output_dir / f"{filename_prefix}_{timestamp}.txt"
    csv_path = output_dir / f"{filename_prefix}_{timestamp}.csv"
    
    with open(txt_path, 'w') as f:
        for r in filtered:
            f.write(f"{r.ip}\n")
    
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ip', 'latency_ms', 'speed_mbps', 'status_code', 'source_type'])
        for r in filtered:
            writer.writerow([r.ip, r.latency_ms or '', r.speed_mbps or '', r.status_code or '', r.source_type])
    
    return txt_path, csv_path

def save_detailed_outputs(global_results: List[ScanResult], iran_results: List[ScanResult], output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    global_good = [r for r in global_results if r.ok]
    iran_good = [r for r in iran_results if r.ok]
    
    global_by_speed = sorted(global_good, key=lambda x: x.speed_mbps or 0, reverse=True)
    iran_by_speed = sorted(iran_good, key=lambda x: x.speed_mbps or 0, reverse=True)
    global_by_latency = sorted(global_good, key=lambda x: x.latency_ms or 9999)
    iran_by_latency = sorted(iran_good, key=lambda x: x.latency_ms or 9999)
    
    with open(output_dir / f"global_best_speed_{timestamp}.txt", 'w') as f:
        for r in global_by_speed[:50]:
            if r.speed_mbps:
                f.write(f"{r.ip} - {r.speed_mbps:.1f}Mbps - {r.latency_ms:.0f}ms\n")
            else:
                f.write(f"{r.ip} - {r.latency_ms:.0f}ms\n")
    
    with open(output_dir / f"iran_best_speed_{timestamp}.txt", 'w') as f:
        for r in iran_by_speed[:50]:
            if r.speed_mbps:
                f.write(f"{r.ip} - {r.speed_mbps:.1f}Mbps - {r.latency_ms:.0f}ms\n")
            else:
                f.write(f"{r.ip} - {r.latency_ms:.0f}ms\n")
    
    with open(output_dir / f"global_best_latency_{timestamp}.txt", 'w') as f:
        for r in global_by_latency[:50]:
            if r.speed_mbps:
                f.write(f"{r.ip} - {r.latency_ms:.0f}ms - {r.speed_mbps:.1f}Mbps\n")
            else:
                f.write(f"{r.ip} - {r.latency_ms:.0f}ms\n")
    
    with open(output_dir / f"iran_best_latency_{timestamp}.txt", 'w') as f:
        for r in iran_by_latency[:50]:
            if r.speed_mbps:
                f.write(f"{r.ip} - {r.latency_ms:.0f}ms - {r.speed_mbps:.1f}Mbps\n")
            else:
                f.write(f"{r.ip} - {r.latency_ms:.0f}ms\n")
    
    with open(output_dir / f"global_ips_only_{timestamp}.txt", 'w') as f:
        for r in global_by_speed:
            f.write(f"{r.ip}\n")
    
    with open(output_dir / f"iran_ips_only_{timestamp}.txt", 'w') as f:
        for r in iran_by_speed:
            f.write(f"{r.ip}\n")
    
    all_ips_path = output_dir / f"all_good_ips_{timestamp}.txt"
    with open(all_ips_path, 'w') as f:
        for r in global_by_speed:
            f.write(f"{r.ip} #global latency={r.latency_ms:.1f}ms")
            if r.speed_mbps:
                f.write(f" speed={r.speed_mbps:.1f}Mbps")
            f.write("\n")
        for r in iran_by_speed:
            f.write(f"{r.ip} #iran latency={r.latency_ms:.1f}ms")
            if r.speed_mbps:
                f.write(f" speed={r.speed_mbps:.1f}Mbps")
            f.write("\n")
    
    save_results(global_results, output_dir, "global_clean", 200, 0)
    save_results(iran_results, output_dir, "iran_clean", 200, 0)
    
    return output_dir

def parse_vless(uri_or_file: str) -> VlessConfig:
    if Path(uri_or_file).exists():
        with open(uri_or_file, 'r') as f:
            uri_or_file = f.read().strip()
    
    if not uri_or_file.startswith('vless://'):
        raise ValueError("Invalid VLESS URI")
    
    raw = uri_or_file
    parts = uri_or_file[8:].split('@')
    uuid = parts[0]
    rest = parts[1] if len(parts) > 1 else ''
    
    host_part = rest.split('?')[0] if '?' in rest else rest
    if ':' in host_part:
        host, port = host_part.split(':')
    else:
        host, port = host_part, '443'
    
    query = {}
    if '?' in rest:
        query_str = rest.split('?')[1].split('#')[0]
        query = parse_qs(query_str)
        query = {k: v[0] for k, v in query.items()}
    
    remark = rest.split('#')[-1] if '#' in rest else uri_or_file.split('#')[-1] if '#' in uri_or_file else "VLESS"
    
    return VlessConfig(raw=raw, uuid=uuid, host=host, port=int(port), remark=remark, query=query)

def find_xray(explicit: Optional[str] = None) -> Optional[Path]:
    if explicit:
        path = Path(explicit)
        if path.exists() and path.is_file():
            return path
    
    common_paths = [
        Path("./xray"),
        Path("./Xray"),
        Path("/usr/local/bin/xray"),
        Path("/usr/bin/xray"),
        app_dir() / "xray",
        Path.home() / ".xray/xray",
        Path.home() / "xray",
    ]
    
    for path in common_paths:
        if path.exists() and path.is_file():
            return path
    
    return None

def download_xray(target_path: Path) -> bool:
    import urllib.request
    import zipfile
    
    try:
        print(f"{Fore.CYAN}Downloading Xray...{Style.RESET_ALL}")
        req = urllib.request.Request(
            'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip',
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=60) as response:
            with open(target_path.with_suffix('.zip'), 'wb') as f:
                f.write(response.read())
        
        with zipfile.ZipFile(target_path.with_suffix('.zip'), 'r') as zip_ref:
            zip_ref.extractall(target_path.parent)
        
        target_path.chmod(0o755)
        (target_path.with_suffix('.zip')).unlink()
        print(f"{Fore.GREEN}Xray downloaded to {target_path}{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"{Fore.RED}Failed to download Xray: {e}{Style.RESET_ALL}")
        return False

def interactive():
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.GREEN}VLESS IP Scanner - Professional Edition")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    vless_uri = input(f"{Fore.YELLOW}Enter VLESS URI or path to config file: {Style.RESET_ALL}").strip()
    if not vless_uri:
        print(f"{Fore.RED}No VLESS URI provided{Style.RESET_ALL}")
        return
    
    try:
        vless_config = parse_vless(vless_uri)
        print(f"{Fore.GREEN}✓ Config loaded: {vless_config.remark} ({vless_config.host}:{vless_config.port}){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error parsing VLESS config: {e}{Style.RESET_ALL}")
        return
    
    xray_path = find_xray()
    if not xray_path:
        print(f"{Fore.YELLOW}Xray not found. Attempting to download...{Style.RESET_ALL}")
        xray_path = app_dir() / "xray"
        if not download_xray(xray_path):
            print(f"{Fore.RED}Please download Xray manually from: https://github.com/XTLS/Xray-core/releases{Style.RESET_ALL}")
            return
    
    print(f"{Fore.GREEN}✓ Xray found: {xray_path}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Select target type:")
    print("1. Global IPs only")
    print("2. Iran IPs only")
    print("3. Both")
    
    choice = input(f"{Fore.YELLOW}Choice (1-3): {Style.RESET_ALL}").strip()
    
    max_per_source = int(input(f"{Fore.YELLOW}Max IPs per source (default 500): {Style.RESET_ALL}").strip() or "500")
    concurrency = int(input(f"{Fore.YELLOW}Scan concurrency (default 30): {Style.RESET_ALL}").strip() or "30")
    timeout = int(input(f"{Fore.YELLOW}Timeout seconds (default 8): {Style.RESET_ALL}").strip() or "8")
    
    global_ips = []
    iran_ips = []
    
    if choice in ["1", "3"]:
        print(f"\n{Fore.CYAN}Loading global IP ranges...{Style.RESET_ALL}")
        global_ips, _ = load_ip_ranges(get_global_ip_sources(), max_per_source, 50)
        print(f"{Fore.GREEN}Total unique global IPs: {len(global_ips)}{Style.RESET_ALL}")
    
    if choice in ["2", "3"]:
        print(f"\n{Fore.CYAN}Loading Iran IP ranges...{Style.RESET_ALL}")
        iran_ips, _ = load_ip_ranges(get_iran_ip_sources(), max_per_source, 50)
        print(f"{Fore.GREEN}Total unique Iran IPs: {len(iran_ips)}{Style.RESET_ALL}")
    
    used_ips = load_used_ips()
    
    if choice in ["1", "3"]:
        global_ips = get_unique_targets(global_ips, used_ips, 3000)
    if choice in ["2", "3"]:
        iran_ips = get_unique_targets(iran_ips, used_ips, 3000)
    
    print(f"\n{Fore.CYAN}IPs to scan (new only):")
    if choice in ["1", "3"]:
        print(f"  Global: {len(global_ips)}")
    if choice in ["2", "3"]:
        print(f"  Iran: {len(iran_ips)}")
    
    output_dir = app_dir() / "scan_results"
    output_dir.mkdir(exist_ok=True)
    
    global_results = []
    iran_results = []
    
    try:
        if choice in ["1", "3"] and global_ips:
            print(f"\n{Fore.CYAN}{'='*40}")
            print(f"Scanning Global IPs")
            print(f"{'='*40}{Style.RESET_ALL}")
            global_results = run_scan(vless_config, global_ips, xray_path, concurrency, timeout, 2, "https://www.gstatic.com/generate_204", "warning", False, "global")
        
        if choice in ["2", "3"] and iran_ips:
            print(f"\n{Fore.CYAN}{'='*40}")
            print(f"Scanning Iran IPs")
            print(f"{'='*40}{Style.RESET_ALL}")
            iran_results = run_scan(vless_config, iran_ips, xray_path, concurrency, timeout, 2, "https://www.gstatic.com/generate_204", "warning", False, "iran")
    
    except ScanInterrupted as e:
        print(f"\n{Fore.YELLOW}Scan interrupted! Saving partial results...{Style.RESET_ALL}")
        if e.stage == "scan":
            if choice in ["1", "3"]:
                global_results = [r for r in e.results if r.source_type == "global"]
            if choice in ["2", "3"]:
                iran_results = [r for r in e.results if r.source_type == "iran"]
    
    global_ok = [r for r in global_results if r.ok]
    iran_ok = [r for r in iran_results if r.ok]
    
    print(f"\n{Fore.GREEN}{'='*40}")
    print(f"Scan Results Summary")
    print(f"{'='*40}{Style.RESET_ALL}")
    if choice in ["1", "3"]:
        print(f"Global: {len(global_ok)}/{len(global_results)} OK")
        if global_ok:
            avg_latency = sum(r.latency_ms for r in global_ok) / len(global_ok)
            print(f"  Avg latency: {avg_latency:.1f}ms")
    if choice in ["2", "3"]:
        print(f"Iran: {len(iran_ok)}/{len(iran_results)} OK")
        if iran_ok:
            avg_latency = sum(r.latency_ms for r in iran_ok) / len(iran_ok)
            print(f"  Avg latency: {avg_latency:.1f}ms")
    
    if global_ok or iran_ok:
        speed_test = input(f"\n{Fore.YELLOW}Run speed tests? (y/n): {Style.RESET_ALL}").lower() == 'y'
        if speed_test:
            speed_workers = int(input(f"{Fore.YELLOW}Speed test workers (default 5): {Style.RESET_ALL}").strip() or "5")
            speed_mb = int(input(f"{Fore.YELLOW}Download size MB (default 10): {Style.RESET_ALL}").strip() or "10")
            speed_bytes = speed_mb * 1024 * 1024
            
            if global_ok:
                print(f"\n{Fore.CYAN}Speed testing global IPs...{Style.RESET_ALL}")
                global_results = run_speed_tests(vless_config, global_ok, xray_path, speed_workers, 30, speed_bytes, 10, "https://speed.cloudflare.com/__down?bytes={bytes}", "warning")
            
            if iran_ok:
                print(f"\n{Fore.CYAN}Speed testing Iran IPs...{Style.RESET_ALL}")
                iran_results = run_speed_tests(vless_config, iran_ok, xray_path, speed_workers, 30, speed_bytes, 10, "https://speed.cloudflare.com/__down?bytes={bytes}", "warning")
    
    save_detailed_outputs(global_results, iran_results, output_dir)
    
    all_scanned_ips = set([r.ip for r in global_results + iran_results])
    used_ips.update(all_scanned_ips)
    save_used_ips(used_ips)
    
    print(f"\n{Fore.GREEN}{'='*40}")
    print(f"Scan Completed Successfully!")
    print(f"Results saved to: {output_dir}")
    print(f"{'='*40}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="VLESS IP Scanner - Professional Edition")
    parser.add_argument("--vless", "-v", help="VLESS URI or config file path")
    parser.add_argument("--xray", help="Path to Xray binary")
    parser.add_argument("--global-ips", "-g", action="store_true", help="Scan global IPs")
    parser.add_argument("--iran-ips", "-i", action="store_true", help="Scan Iran IPs")
    parser.add_argument("--max-per-source", "-m", type=int, default=500, help="Max IPs per source")
    parser.add_argument("--concurrency", "-c", type=int, default=30, help="Scan concurrency")
    parser.add_argument("--timeout", "-t", type=int, default=8, help="Timeout per test")
    parser.add_argument("--speed-test", "-s", action="store_true", help="Run speed tests after scan")
    parser.add_argument("--no-cache", action="store_true", help="Ignore used IPs cache")
    parser.add_argument("--output", "-o", default="scan_results", help="Output directory")
    
    args = parser.parse_args()
    
    if not args.vless:
        interactive()
        return
    
    xray_path = find_xray(args.xray)
    if not xray_path:
        print(f"{Fore.RED}Xray not found. Please provide path with --xray or download Xray{Style.RESET_ALL}")
        return
    
    try:
        vless_config = parse_vless(args.vless)
        print(f"{Fore.GREEN}Config loaded: {vless_config.remark}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error parsing VLESS: {e}{Style.RESET_ALL}")
        return
    
    all_targets = []
    
    if args.global_ips:
        print(f"{Fore.CYAN}Loading global IPs...{Style.RESET_ALL}")
        global_ips, _ = load_ip_ranges(get_global_ip_sources(), args.max_per_source, 50)
        if not args.no_cache:
            used_ips = load_used_ips()
            global_ips = get_unique_targets(global_ips, used_ips, 3000)
        all_targets.extend([(ip, "global") for ip in global_ips])
        print(f"{Fore.GREEN}Got {len(global_ips)} global IPs{Style.RESET_ALL}")
    
    if args.iran_ips:
        print(f"{Fore.CYAN}Loading Iran IPs...{Style.RESET_ALL}")
        iran_ips, _ = load_ip_ranges(get_iran_ip_sources(), args.max_per_source, 50)
        if not args.no_cache:
            used_ips = load_used_ips()
            iran_ips = get_unique_targets(iran_ips, used_ips, 3000)
        all_targets.extend([(ip, "iran") for ip in iran_ips])
        print(f"{Fore.GREEN}Got {len(iran_ips)} Iran IPs{Style.RESET_ALL}")
    
    if not all_targets:
        print(f"{Fore.RED}No targets selected. Use --global-ips and/or --iran-ips{Style.RESET_ALL}")
        return
    
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results = []
    targets_list = [ip for ip, _ in all_targets]
    source_map = {ip: src for ip, src in all_targets}
    
    print(f"\n{Fore.CYAN}Scanning {len(targets_list)} targets...{Style.RESET_ALL}")
    
    try:
        scan_results = run_scan(vless_config, targets_list, xray_path, args.concurrency, args.timeout, 2, "https://www.gstatic.com/generate_204", "warning", False, "")
        for r in scan_results:
            r.source_type = source_map.get(r.ip, "")
        results = scan_results
    except ScanInterrupted as e:
        results = e.results
    
    if args.speed_test:
        ok_results = [r for r in results if r.ok]
        if ok_results:
            print(f"\n{Fore.CYAN}Running speed tests...{Style.RESET_ALL}")
            results = run_speed_tests(vless_config, ok_results, xray_path, 5, 30, 10*1024*1024, 10, "https://speed.cloudflare.com/__down?bytes={bytes}", "warning")
    
    global_res = [r for r in results if r.source_type == "global"]
    iran_res = [r for r in results if r.source_type == "iran"]
    
    save_detailed_outputs(global_res, iran_res, output_dir)
    
    if not args.no_cache:
        all_scanned_ips = set([r.ip for r in results])
        used_ips = load_used_ips()
        used_ips.update(all_scanned_ips)
        save_used_ips(used_ips)
    
    good_count = len([r for r in results if r.ok])
    print(f"\n{Fore.GREEN}Done! Found {good_count} good IPs. Results saved to {output_dir}{Style.RESET_ALL}")

if __name__ == "__main__":
    sys.exit(main())
