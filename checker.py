import re
import json
import base64
import urllib.parse
import subprocess
import os
import time
import requests
import asyncio
import aiohttp
import argparse
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from itertools import islice
import ipaddress

@dataclass
class ConfigData:
    type: str
    name: str = ""
    server: str = ""
    port: int = 443
    uuid: str = ""
    path: str = "/"
    tls: str = "tls"
    network: str = "tcp"
    security: str = "none"
    encryption: str = "none"
    host: str = ""
    sni: str = ""
    fp: str = ""
    alpn: str = ""
    flow: str = ""
    aid: int = 0
    method: str = "auto"
    password: str = ""
    headerType: str = ""
    xtls: bool = False
    grpc_service_name: str = ""
    pbk: str = ""
    sid: str = ""

def decode_vmess_base64(vmess_str: str) -> Dict:
    if vmess_str.startswith("vmess://"):
        vmess_str = vmess_str[8:]
    
    try:
        decoded = base64.b64decode(vmess_str + "=" * (-len(vmess_str) % 4))
        return json.loads(decoded)
    except:
        return {}

def parse_vless(url: str) -> ConfigData:
    url = url.replace("vless://", "")
    
    if "@" in url:
        user_info, server_info = url.split("@", 1)
    else:
        return ConfigData(type="vless")
    
    parsed = urlparse(f"https://{server_info}")
    params = parse_qs(parsed.query)
    
    config = ConfigData(type="vless")
    config.uuid = user_info
    config.server = parsed.hostname or ""
    config.port = int(parsed.port or 443)
    
    if "type" in params:
        config.network = params["type"][0]
    if "path" in params:
        config.path = params["path"][0]
    if "security" in params:
        config.security = params["security"][0]
    if "encryption" in params:
        config.encryption = params["encryption"][0]
    if "host" in params:
        config.host = params["host"][0]
    if "sni" in params:
        config.sni = params["sni"][0]
    if "fp" in params:
        config.fp = params["fp"][0]
    if "alpn" in params:
        config.alpn = params["alpn"][0]
    if "flow" in params:
        config.flow = params["flow"][0]
    if "headerType" in params:
        config.headerType = params["headerType"][0]
    if "xtls" in params:
        config.xtls = params["xtls"][0].lower() == "true"
    if "serviceName" in params:
        config.grpc_service_name = params["serviceName"][0]
    if "pbk" in params:
        config.pbk = params["pbk"][0]
    if "sid" in params:
        config.sid = params["sid"][0]
    
    return config

def parse_vmess(url: str) -> ConfigData:
    if not url.startswith("vmess://"):
        return ConfigData(type="vmess")
    
    vmess_data = decode_vmess_base64(url)
    
    config = ConfigData(type="vmess")
    config.server = vmess_data.get("add", "")
    config.port = int(vmess_data.get("port", 443))
    config.uuid = vmess_data.get("id", "")
    config.aid = int(vmess_data.get("aid", 0))
    config.network = vmess_data.get("net", "tcp")
    config.path = vmess_data.get("path", "/")
    config.host = vmess_data.get("host", "")
    config.tls = "tls" if vmess_data.get("tls") == "tls" else "none"
    config.headerType = vmess_data.get("type", "")
    
    return config

def parse_trojan(url: str) -> ConfigData:
    if not url.startswith("trojan://"):
        return ConfigData(type="trojan")
    
    url = url.replace("trojan://", "")
    
    if "@" in url:
        password, server_info = url.split("@", 1)
    else:
        return ConfigData(type="trojan")
    
    parsed = urlparse(f"https://{server_info}")
    params = parse_qs(parsed.query)
    
    config = ConfigData(type="trojan")
    config.password = password
    config.server = parsed.hostname or ""
    config.port = int(parsed.port or 443)
    
    if "type" in params:
        config.network = params["type"][0]
    if "path" in params:
        config.path = params["path"][0]
    if "security" in params:
        config.security = params["security"][0]
    if "sni" in params:
        config.sni = params["sni"][0]
    if "headerType" in params:
        config.headerType = params["headerType"][0]
    
    return config

def parse_shadowsocks(url: str) -> ConfigData:
    if not url.startswith("ss://"):
        return ConfigData(type="shadowsocks")
    
    url = url.replace("ss://", "")
    
    try:
        if "@" in url:
            user_info, server_info = url.split("@", 1)
            decoded = base64.b64decode(user_info + "=" * (-len(user_info) % 4)).decode()
            method, password = decoded.split(":", 1)
        else:
            decoded = base64.b64decode(url + "=" * (-len(url) % 4)).decode()
            method, rest = decoded.split(":", 1)
            password, server_info = rest.split("@", 1)
            
        parsed = urlparse(f"https://{server_info}")
        
        config = ConfigData(type="shadowsocks")
        config.method = method
        config.password = password
        config.server = parsed.hostname or ""
        config.port = int(parsed.port or 443)
        
        return config
    except:
        return ConfigData(type="shadowsocks")

def config_to_json(config_url: str, inbound_port: int = 1080, output_filename: str = "config_output.json") -> Dict:
    """Convert various config formats to Xray JSON format
    
    Args:
        config_url: The config URL string
        inbound_port: The port number for inbound SOCKS connection
    """
    if config_url.startswith("vless://"):
        config = parse_vless(config_url)
    elif config_url.startswith("vmess://"):
        config = parse_vmess(config_url)
    elif config_url.startswith("trojan://"):
        config = parse_trojan(config_url)
    elif config_url.startswith("ss://"):
        config = parse_shadowsocks(config_url)
    else:
        return {"error": "Unsupported config format"}
    
    xray_config = {
        "inbounds": [{
            "port": inbound_port,
            "protocol": "socks",
            "settings": {
                "udp": True
            }
        }],
        "outbounds": [{
            "protocol": config.type,
            "settings": {},
            "streamSettings": {
                "network": config.network,
                "security": config.security,
            }
        }]
    }
    
    # Add TLS or XTLS settings if security is not none
    if config.security != "none":
        xray_config["outbounds"][0]["streamSettings"]["tlsSettings"] = {
            "serverName": config.sni or config.host or config.server,
            "fingerprint": config.fp or "firefox",
            "alpn": [config.alpn] if config.alpn else []
        }
    if config.xtls:
        xray_config["outbounds"][0]["streamSettings"]["xtlsSettings"] = {
            "serverName": config.sni or config.host or config.server
        }
    
    # Handle Reality settings
    if config.security == "reality":
        xray_config["outbounds"][0]["streamSettings"]["realitySettings"] = {
            "publicKey": config.pbk,
            "shortId": config.sid,
            "serverName": config.sni,
            "fingerprint": config.fp or "firefox"
        }
    
    # Handle different network types and settings
    if config.network == "tcp" and config.headerType == "http":
        xray_config["outbounds"][0]["streamSettings"]["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "version": "1.1",
                    "method": "GET",
                    "path": [config.path] if config.path else ["/"],
                    "headers": {
                        "Host": [config.host] if config.host else [],
                        "User-Agent": [
                            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
                            "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46"
                        ],
                        "Accept-Encoding": ["gzip, deflate"],
                        "Connection": ["keep-alive"],
                        "Pragma": "no-cache"
                    }
                }
            }
        }
    elif config.network == "ws":
        xray_config["outbounds"][0]["streamSettings"]["wsSettings"] = {
            "path": config.path,
            "headers": {
                "Host": config.host
            }
        }
    elif config.network == "grpc":
        xray_config["outbounds"][0]["streamSettings"]["grpcSettings"] = {
            "serviceName": config.grpc_service_name,
            "multiMode": False
        }
    elif config.network == "quic":
        xray_config["outbounds"][0]["streamSettings"]["quicSettings"] = {
            "security": config.security,
            "key": config.password,
            "header": {
                "type": config.headerType
            }
        }
    
    outbound_settings = xray_config["outbounds"][0]["settings"]
    
    if config.type == "vless":
        outbound_settings["vnext"] = [{
            "address": config.server,
            "port": config.port,
            "users": [{
                "id": config.uuid,
                "encryption": config.encryption,
                "flow": config.flow if config.flow else ""
            }]
        }]
    elif config.type == "vmess":
        outbound_settings["vnext"] = [{
            "address": config.server,
            "port": config.port,
            "users": [{
                "id": config.uuid,
                "alterId": config.aid,
                "security": "auto"
            }]
        }]
    elif config.type == "trojan":
        outbound_settings["servers"] = [{
            "address": config.server,
            "port": config.port,
            "password": config.password
        }]
    elif config.type == "shadowsocks":
        outbound_settings["servers"] = [{
            "address": config.server,
            "port": config.port,
            "method": config.method,
            "password": config.password
        }]
    
       # Save to output JSON file
    with open(output_filename, 'w') as f:
        json.dump(xray_config, f, indent=2)
    
    return xray_config

def fetch_subscription(url: str) -> List[str]:
    """Fetch and decode subscription link content"""
    try:
        response = requests.get(url)
        response.raise_for_status()
        content = response.text.strip()
        
        # Try base64 decoding if content looks encoded
        try:
            decoded = base64.b64decode(content + "=" * (-len(content) % 4)).decode()
            configs = decoded.splitlines()
        except:
            configs = content.splitlines()
            
        return [line.strip() for line in configs if line.strip()]
    except Exception as e:
        print(f"Error fetching subscription: {str(e)}")
        return []

def save_working_config(config: str, filename: str = "working_configs.txt"):
    """Save a single working config to file if it doesn't already exist"""
    try:
        # Check if file exists
        existing_configs = set()
        if os.path.exists(filename):
            with open(filename, "r") as f:
                existing_configs = set(line.strip() for line in f)
        
        # Check if config already exists
        if config in existing_configs:
            print(f"\033[93m[SKIP]\033[0m Config already exists in {filename}")
            return
        
        # If config is new, append it to file
        with open(filename, "a") as f:
            f.write(f"{config}\n")
        print(f"\033[92m[SAVED]\033[0m Config saved to {filename}")
    except Exception as e:
        print(f"\033[91mError saving config: {str(e)}\033[0m")

async def test_config(config_url: str, port: int) -> Dict:
    """Test a single config using specified port"""
    process = None
    process_curl = None
    temp_filename = None
    
    try:
        # Convert config to Xray JSON format
        config = config_to_json(config_url, port)
        if "error" in config:
            return {"config": config_url, "status": "error", "message": config["error"]}

        # Save temporary config file
        temp_filename = f"config_{port}.json"
        with open(temp_filename, 'w') as f:
            json.dump(config, f, indent=2)

        # Start Xray process
        process = subprocess.Popen(
            ["./xray", "run", "-c", temp_filename],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Wait for Xray to start
        await asyncio.sleep(2)

        # Test connection using curl
        try:
            process_curl = await asyncio.create_subprocess_exec(
                "curl", "-s", "-x", f"socks5h://localhost:{port}", 
                "--connect-timeout", "10",
                "ipconfig.io",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(process_curl.communicate(), timeout=15)
                if stdout:
                    output = stdout.decode().strip()
                    # Check if output contains HTML tags
                    if "<html" in output.lower() or "<!doctype" in output.lower():
                        return {
                            "config": config_url,
                            "status": "failed",
                            "message": "Received HTML response instead of IP",
                            "port": port
                        }
                    try:
                        ipaddress.ip_address(output)
                    except ValueError:
                        return {
                            "config": config_url,
                            "status": "failed",
                            "message": f"Invalid IP: {output}",
                            "port": port
                        }
                        
                    # Before saving, check if it already exists
                    if os.path.exists("working_configs.txt"):
                        with open("working_configs.txt", "r") as f:
                            if config_url in set(line.strip() for line in f):
                                print(f"\033[93m[SKIP]\033[0m Config already exists")
                                return {
                                    "config": config_url,
                                    "status": "success",
                                    "ip": output,
                                    "port": port,
                                    "already_exists": True
                                }
                    
                    # If we got here, save the new working config
                    save_working_config(config_url)
                    return {
                        "config": config_url,
                        "status": "success",
                        "ip": output,
                        "port": port,
                        "already_exists": False
                    }
                else:
                    return {
                        "config": config_url,
                        "status": "failed",
                        "message": "No response from IP check service",
                        "port": port
                    }
            except asyncio.TimeoutError:
                return {
                    "config": config_url,
                    "status": "failed",
                    "message": "Connection timeout",
                    "port": port
                }

        except Exception as e:
            return {
                "config": config_url,
                "status": "error",
                "message": str(e),
                "port": port
            }

    finally:
        # Cleanup
        if process:
            process.kill()
        if process_curl:
            try:
                process_curl.kill()
            except:
                pass
        if temp_filename and os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
            except:
                pass

async def test_config_batch(configs: List[str], start_port: int = 1080, batch_size: int = 40):
    """Test a batch of configs simultaneously"""
    tasks = []
    for i, config in enumerate(configs):
        # Use modulo to cycle through the port range
        port = start_port + (i % batch_size)
        task = asyncio.create_task(test_config(config, port))
        tasks.append(task)
    
    results = await asyncio.gather(*tasks)
    return results

def print_results(results: List[Dict], batch_num: int, total_batches: int):
    """Print test results with formatting"""
    print(f"\nResults for batch {batch_num}/{total_batches}:")
    print("-" * 50)
    
    working_count = sum(1 for r in results if r["status"] == "success")
    new_count = sum(1 for r in results if r["status"] == "success" and not r.get("already_exists", False))
    existing_count = working_count - new_count
    
    print(f"Working configs in this batch: {working_count}/{len(results)}")
    if existing_count > 0:
        print(f"New working configs: {new_count}")
        print(f"Already existing configs: {existing_count}")
    
    for result in results:
        if result["status"] == "success":
            status_str = "\033[92m[SUCCESS]\033[0m"
            if result.get("already_exists", False):
                status_str += " (Already Exists)"
            print(f"\n{status_str} - Port: {result['port']}")
            print(f"IP: {result['ip']}")
            print(f"Config: {result['config']}")
        else:
            print(f"\n\033[91m[FAILED]\033[0m - Port: {result.get('port', 'N/A')}")
            print(f"Error: {result.get('message', 'Unknown error')}")
            print(f"Config: {result['config']}")
    print("-" * 50)
    
def read_configs_from_file(file_path: str) -> List[str]:
    """Read configs from a file where each line is a config"""
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading file: {str(e)}")
        return []

async def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Test V2Ray configurations')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-config', help='Subscription link or single config')
    group.add_argument('-file', help='Path to file containing configs (one per line)')
    
    # Add optional arguments for port and batch size
    parser.add_argument('-port', type=int, default=1080, 
                      help='Starting port number (default: 1080)')
    parser.add_argument('-batch', type=int, default=40, 
                      help='Batch size for testing configs (default: 40)')
    
    args = parser.parse_args()
    
    try:
        configs = []
        
        if args.config:
            # Handle subscription link or single config
            if args.config.startswith("http"):
                print("Fetching subscription configs...")
                configs = fetch_subscription(args.config)
                print(f"Found {len(configs)} configs")
            else:
                configs = [args.config]
        elif args.file:
            # Handle file input
            print(f"Reading configs from file: {args.file}")
            configs = read_configs_from_file(args.file)
            print(f"Found {len(configs)} configs in file")

        if not configs:
            print("No valid configs found!")
            return

        # Use command line arguments for batch_size and start_port
        batch_size = args.batch
        start_port = args.port
        
        print(f"\nUsing settings:")
        print(f"Starting port: {start_port}")
        print(f"Batch size: {batch_size}")
        
        total_batches = (len(configs) + batch_size - 1) // batch_size
        all_results = []

        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(configs))
            current_batch = configs[start_idx:end_idx]
            
            print(f"\nTesting batch {batch_num + 1}/{total_batches} ({len(current_batch)} configs)")
            
            results = await test_config_batch(
                current_batch,
                start_port,
                batch_size
            )
            
            print_results(results, batch_num + 1, total_batches)
            all_results.extend(results)

        # Print final summary
        total_working = sum(1 for r in all_results if r["status"] == "success")
        print(f"\nFinal Summary:")
        print(f"Total configs tested: {len(all_results)}")
        print(f"Working configs: {total_working}")
        print(f"Success rate: {(total_working/len(all_results)*100):.1f}%")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
