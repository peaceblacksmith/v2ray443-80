#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2ray Config Filter and Merge Automation
- Port 80 and 443 filtering
- Duplicate removal
- Connection test
"""

import requests
import base64
import json
import asyncio
import aiohttp
import socket
from urllib.parse import unquote
from collections import Counter
from typing import List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor

# Source URLs
SOURCE_URLS = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt"
]

# Allowed ports
ALLOWED_PORTS = {80, 443}

# Connection test timeout (seconds)
CONNECTION_TIMEOUT = 8
MAX_CONCURRENT_TESTS = 50  # Number of configs to test concurrently


def download_source(url: str) -> str:
    """Download config list from source URL"""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"⚠️  Download error ({url}): {e}")
        return ""


def decode_subscription(content: str) -> List[str]:
    """Decode base64 encoded subscription"""
    content = content.strip()
    
    if not content:
        return []
    
    # Try base64 decode
    try:
        # Fix base64 padding
        padding = len(content) % 4
        if padding:
            content += '=' * (4 - padding)
        
        decoded = base64.b64decode(content).decode('utf-8')
        configs = [line.strip() for line in decoded.split('\n') if line.strip()]
        
        # Check if decode was successful and contains valid configs
        if configs and any(cfg.startswith(('vmess://', 'vless://', 'trojan://', 'ss://', 'hy2://', 'hysteria2://', 'tuic://')) for cfg in configs):
            return configs
    except:
        pass
    
    # Accept as plain text
    return [line.strip() for line in content.split('\n') if line.strip()]


def extract_port_from_config(config_line: str) -> Optional[int]:
    """Extract port number correctly from config line"""
    config_line = config_line.strip()
    if not config_line:
        return None
    
    # URL decode
    try:
        decoded = unquote(config_line)
    except:
        decoded = config_line
    
    # Detect protocol and extract port
    try:
        if decoded.startswith("vmess://"):
            # Base64 decode
            b64_data = decoded[8:]
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
            json_data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            port = json_data.get('port')
            return int(port) if port else None
        
        elif decoded.startswith("vless://"):
            # vless://uuid@domain:port/path?query#fragment
            rest = decoded[8:]
            if '@' in rest:
                domain_port = rest.split('@')[1].split('/')[0].split('?')[0].split('#')[0]
                if ':' in domain_port:
                    return int(domain_port.split(':')[-1])
        
        elif decoded.startswith("trojan://"):
            # trojan://password@domain:port/path?query#fragment
            rest = decoded[9:]
            if '@' in rest:
                domain_port = rest.split('@')[1].split('/')[0].split('?')[0].split('#')[0]
                if ':' in domain_port:
                    return int(domain_port.split(':')[-1])
        
        elif decoded.startswith("ss://"):
            # ss://method:password@domain:port#name or ss://base64@domain:port#name
            rest = decoded[5:]
            if '@' in rest:
                domain_port = rest.split('@')[1].split('/')[0].split('?')[0].split('#')[0]
                if ':' in domain_port:
                    return int(domain_port.split(':')[-1])
        
        elif decoded.startswith("hy2://"):
            # hy2://...@domain:port/...
            rest = decoded[6:]
            if '@' in rest:
                domain_port = rest.split('@')[1].split('/')[0].split('?')[0].split('#')[0]
                if ':' in domain_port:
                    return int(domain_port.split(':')[-1])
        
        elif decoded.startswith("hysteria2://"):
            # hysteria2://...@domain:port/...
            rest = decoded[11:]
            if '@' in rest:
                domain_port = rest.split('@')[1].split('/')[0].split('?')[0].split('#')[0]
                if ':' in domain_port:
                    return int(domain_port.split(':')[-1])
        
        elif decoded.startswith("tuic://"):
            # tuic://...@domain:port/...
            rest = decoded[7:]
            if '@' in rest:
                domain_port = rest.split('@')[1].split('/')[0].split('?')[0].split('#')[0]
                if ':' in domain_port:
                    return int(domain_port.split(':')[-1])
    
    except Exception:
        pass
    
    return None


def extract_name_from_config(config_line: str) -> str:
    """Extract name/label from config"""
    try:
        decoded = unquote(config_line)
        
        if decoded.startswith("vmess://"):
            b64_data = decoded[8:]
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
            json_data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            return json_data.get('ps', '').strip()
        
        # For other protocols, extract name from fragment (#)
        if '#' in decoded:
            return decoded.split('#')[-1].strip()
    
    except:
        pass
    
    return ""


def filter_configs(configs: List[str]) -> List[str]:
    """Filter configs with port 80 or 443 and remove duplicates"""
    filtered = []
    seen_hashes = set()
    
    print(f"\n🔍 Port filtering started... ({len(configs)} configs)")
    
    for config in configs:
        port = extract_port_from_config(config)
        
        # Skip if port is not 80 or 443
        if port not in ALLOWED_PORTS:
            continue
        
        # Get hash of full config (duplicate detection)
        config_hash = hash(config.strip())
        
        if config_hash not in seen_hashes:
            seen_hashes.add(config_hash)
            filtered.append(config)
    
    print(f"✅ Port filtering completed: {len(filtered)} configs remaining")
    return filtered


def handle_duplicate_names(configs: List[str]) -> List[str]:
    """Add -1, -2 numbering to configs with same names"""
    # Name counter
    name_counter = Counter()
    name_occurrences = {}
    
    # First count how many times each name appears
    for config in configs:
        name = extract_name_from_config(config)
        if name:
            name_counter[name] += 1
    
    # Initialize name occurrence tracker
    for name in name_counter:
        name_occurrences[name] = 0
    
    # Rename configs
    result = []
    for config in configs:
        name = extract_name_from_config(config)
        
        if name and name_counter[name] > 1:
            # Duplicate name exists, add numbering
            name_occurrences[name] += 1
            new_name = f"{name}-{name_occurrences[name]}"
            
            # Update config with new name
            config = update_config_name(config, new_name)
        
        result.append(config)
    
    return result


def update_config_name(config_line: str, new_name: str) -> str:
    """Update config name"""
    try:
        decoded = unquote(config_line)
        
        if decoded.startswith("vmess://"):
            b64_data = decoded[8:]
            b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
            json_data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            json_data['ps'] = new_name
            new_b64 = base64.b64encode(json.dumps(json_data).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}"
        
        # For other protocols, update fragment (#)
        if '#' in decoded:
            parts = decoded.rsplit('#', 1)
            return f"{parts[0]}#{new_name}"
    
    except:
        pass
    
    return config_line


def dns_resolve_sync(domain: str) -> bool:
    """Synchronous DNS resolution (for executor)"""
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False


def tcp_connect_sync(domain: str, port: int, timeout: float) -> bool:
    """Synchronous TCP connection test (for executor)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((domain, port))
        sock.close()
        return result == 0
    except:
        return False


async def test_single_config(session: aiohttp.ClientSession, config: str, semaphore: asyncio.Semaphore, executor: ThreadPoolExecutor) -> Tuple[bool, str]:
    """Test a single config"""
    async with semaphore:
        try:
            decoded = unquote(config)
            
            # Extract domain/IP
            domain = None
            port = None
            
            if decoded.startswith("vmess://"):
                b64_data = decoded[8:]
                b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
                json_data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
                domain = json_data.get('add', '')
                port = json_data.get('port', 443)
            else:
                # For other protocols: @domain:port
                if '@' in decoded:
                    rest = decoded.split('@')[1].split('/')[0].split('?')[0].split('#')[0]
                    if ':' in rest:
                        parts = rest.rsplit(':', 1)
                        domain = parts[0]
                        try:
                            port = int(parts[1])
                        except ValueError:
                            return False, config
            
            if not domain or not port:
                return False, config
            
            # Test DNS resolution (non-blocking via executor)
            loop = asyncio.get_event_loop()
            dns_ok = await loop.run_in_executor(executor, dns_resolve_sync, domain)
            if not dns_ok:
                return False, config
            
            # Test TCP connection to port (non-blocking via executor)
            tcp_ok = await loop.run_in_executor(
                executor,
                tcp_connect_sync,
                domain,
                port,
                CONNECTION_TIMEOUT
            )
            
            return tcp_ok, config
                
        except Exception:
            return False, config


async def test_all_configs(configs: List[str]) -> List[str]:
    """Test all configs and return working ones"""
    print(f"\n🔌 Connection test started... ({len(configs)} configs)")
    print(f"⏱️  Timeout: {CONNECTION_TIMEOUT}s, Concurrent: {MAX_CONCURRENT_TESTS}")
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
    working_configs = []
    
    # Use thread pool executor for blocking socket calls
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_TESTS) as executor:
        async with aiohttp.ClientSession() as session:
            tasks = [
                test_single_config(session, config, semaphore, executor)
                for config in configs
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, tuple):
                    success, config = result
                    if success:
                        working_configs.append(config)
    
    print(f"✅ Connection test completed: {len(working_configs)} working configs")
    return working_configs


def encode_to_base64(configs: List[str]) -> str:
    """Encode config list to base64"""
    content = '\n'.join(configs)
    return base64.b64encode(content.encode('utf-8')).decode('utf-8')


def main():
    print("=" * 60)
    print("V2ray Config Filter Automation")
    print("=" * 60)
    
    # 1. Download sources
    print("\n📥 Downloading sources...")
    all_configs = []
    
    for url in SOURCE_URLS:
        print(f"  → {url[:60]}...")
        content = download_source(url)
        configs = decode_subscription(content)
        print(f"    ✓ {len(configs)} configs found")
        all_configs.extend(configs)
    
    print(f"\n📊 Total {len(all_configs)} configs merged")
    
    # 2. Port filtering (80 and 443)
    filtered_configs = filter_configs(all_configs)
    
    # 3. Number duplicate names
    final_configs = handle_duplicate_names(filtered_configs)
    
    # 4. Create sub.txt (all filtered configs)
    sub_content = encode_to_base64(final_configs)
    with open('sub.txt', 'w', encoding='utf-8') as f:
        f.write(sub_content)
    print(f"\n💾 sub.txt created ({len(final_configs)} configs)")
    
    # 5. Connection test
    print("\n" + "=" * 60)
    print("Connection test starting (this may take a while)...")
    
    working_configs = asyncio.run(test_all_configs(final_configs))
    
    if working_configs:
        super_sub_content = encode_to_base64(working_configs)
        with open('supersub.txt', 'w', encoding='utf-8') as f:
            f.write(super_sub_content)
        print(f"💾 supersub.txt created ({len(working_configs)} configs)")
    else:
        print("⚠️  No configs passed connection test")
        # Create empty file
        with open('supersub.txt', 'w', encoding='utf-8') as f:
            f.write("")
    
    print("\n" + "=" * 60)
    print("✅ All operations completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()

