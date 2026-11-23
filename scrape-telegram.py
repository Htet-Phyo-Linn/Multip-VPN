#!/usr/bin/env python3
"""
Multip VPN - Telegram Scraper & VPN Config Extractor
Scrapes decrypted tunnel configurations from Telegram groups (e.g., https://t.me/decrypt_file_vpn)
within a specified time range (-d days), downloads files, extracts proxy outbounds, and exports 
compliant sing-box JSON (vpn_file_01.json).
"""

import os
import sys
import re
import json
import base64
import asyncio
import argparse
import subprocess
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

# ── Load Environment Variables from .env ─────────────────────────────────────
def load_env(env_path=None):
    if env_path is None:
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())

load_env()

API_ID_RAW = os.environ.get("API_ID", "").strip()
API_HASH = os.environ.get("API_HASH", "").strip()

try:
    API_ID = int(API_ID_RAW) if API_ID_RAW else None
except ValueError:
    API_ID = None


# ── Color Output Helpers ─────────────────────────────────────────────────────
class Colors:
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    MAGENTA = "\033[95m"
    GRAY    = "\033[90m"
    RESET   = "\033[0m"

def log_info(msg):    print(f"{Colors.CYAN}[*]{Colors.RESET} {msg}")
def log_ok(msg):      print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")
def log_warn(msg):    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")
def log_err(msg):     print(f"{Colors.RED}[-]{Colors.RESET} {msg}")
def log_header(msg):  print(f"\n{Colors.MAGENTA}=== {msg} ==={Colors.RESET}")


# ── Extraction & Parser Logic ────────────────────────────────────────────────
class VpnExtractor:
    def __init__(self):
        self.outbounds = []
        self.seen_keys = set()

    def add_outbound(self, ob, source=""):
        if not ob or not isinstance(ob, dict) or "type" not in ob:
            return False

        ob_type = str(ob.get("type", "")).strip().lower()
        server = str(ob.get("server", "")).strip().lower()
        port = int(ob.get("server_port", 0))
        user = str(ob.get("user", "") or ob.get("uuid", "")).strip()

        unique_key = f"{ob_type}://{server}:{port}@{user}"
        if unique_key in self.seen_keys:
            return False

        self.seen_keys.add(unique_key)
        self.outbounds.append(ob)
        tag = ob.get("tag", "node")
        log_ok(f"Extracted [{ob_type}] '{tag}' -> {server}:{port} ({source})")
        return True

    def parse_dark_tunnel(self, raw_text, source=""):
        m = re.search(r"darktunnel://([A-Za-z0-9+/=_-]+)", raw_text)
        if not m:
            return False

        b64 = m.group(1).replace("-", "+").replace("_", "/")
        b64 += "=" * ((4 - len(b64) % 4) % 4)
        try:
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            tag = f"DarkTunnel-{data.get('name', 'node')}"
            ssh_cfg = data.get("sshTunnelConfig", {}).get("sshConfig", {})
            host = ssh_cfg.get("host")
            port = ssh_cfg.get("port", 443)
            user = ssh_cfg.get("username", "root")
            pwd = ssh_cfg.get("password", "")

            if host and user:
                ob = {
                    "type": "ssh",
                    "tag": tag,
                    "server": str(host).strip(),
                    "server_port": int(port),
                    "user": str(user).strip(),
                    "password": str(pwd).strip()
                }
                return self.add_outbound(ob, source=source)
        except Exception as e:
            log_warn(f"Failed to decode DarkTunnel payload from {source}: {e}")
        return False

    def parse_json_content(self, raw_text, source=""):
        found_any = False
        m = re.search(r'(\{"app_version"[\s\S]*\}|\{[\s\S]*"config"[\s\S]*\})', raw_text)
        if not m:
            return False

        try:
            data = json.loads(m.group(1))
            configs = data.get("config", [])
            if isinstance(configs, dict):
                configs = [configs]

            for idx, cfg in enumerate(configs, start=1):
                raw_tag = cfg.get("name") or cfg.get("label") or f"node-{idx}"
                clean_tag = re.sub(r'[^a-zA-Z0-9_\-\. ]', '', str(raw_tag))

                # 1. Standard SSH Protocol
                host = cfg.get("host")
                user = cfg.get("username")
                port = cfg.get("port", 443)
                pwd = cfg.get("password", "")

                if host and user:
                    ob = {
                        "type": "ssh",
                        "tag": f"SSH-{clean_tag}",
                        "server": str(host).strip(),
                        "server_port": int(port),
                        "user": str(user).strip(),
                        "password": str(pwd).strip()
                    }
                    if self.add_outbound(ob, source=source):
                        found_any = True

                # 2. sshField format: "host:port@user:password" or "user:password@host:port"
                ssh_field = cfg.get("sshField", "")
                if ssh_field:
                    m1 = re.match(r"^([^:]+):(\d+)@([^:]+):(.*)$", ssh_field.strip())
                    m2 = re.match(r"^([^:]+):(.*)@([^:]+):(\d+)$", ssh_field.strip())
                    if m1:
                        ob = {
                            "type": "ssh",
                            "tag": f"SSH-{clean_tag}",
                            "server": m1.group(1).strip(),
                            "server_port": int(m1.group(2)),
                            "user": m1.group(3).strip(),
                            "password": m1.group(4).strip()
                        }
                        if self.add_outbound(ob, source=source):
                            found_any = True
                    elif m2:
                        ob = {
                            "type": "ssh",
                            "tag": f"SSH-{clean_tag}",
                            "server": m2.group(3).strip(),
                            "server_port": int(m2.group(4)),
                            "user": m2.group(1).strip(),
                            "password": m2.group(2).strip()
                        }
                        if self.add_outbound(ob, source=source):
                            found_any = True
        except Exception:
            pass
        return found_any

    def parse_share_links(self, raw_text, source=""):
        found_any = False

        # ssh://user:password@host:port
        for m in re.finditer(r"ssh://([^:]+):([^@]+)@([^:]+):(\d+)", raw_text):
            ob = {
                "type": "ssh",
                "tag": f"SSH-{m.group(3)}",
                "server": m.group(3).strip(),
                "server_port": int(m.group(4)),
                "user": m.group(1).strip(),
                "password": m.group(2).strip()
            }
            if self.add_outbound(ob, source=source):
                found_any = True

        # vless://uuid@host:port?query#tag
        for m in re.finditer(r"vless://([a-fA-F0-9\-]+)@([^:]+):(\d+)(\?[^\s#]+)?(#([^\s]+))?", raw_text):
            uuid = m.group(1)
            server = m.group(2)
            port = int(m.group(3))
            query = m.group(4) or ""
            raw_tag = unquote(m.group(6)) if m.group(6) else f"VLESS-{server}"

            ob = {
                "type": "vless",
                "tag": raw_tag,
                "server": server,
                "server_port": port,
                "uuid": uuid
            }

            if query:
                params = dict(part.split("=", 1) for part in query.lstrip("?").split("&") if "=" in part)
                sec = params.get("security", "").lower()
                if sec in ("tls", "reality"):
                    tls = {"enabled": True}
                    if "sni" in params:
                        tls["server_name"] = unquote(params["sni"])
                    if sec == "reality":
                        reality = {"enabled": True}
                        if "pbk" in params: reality["public_key"] = unquote(params["pbk"])
                        if "sid" in params: reality["short_id"] = unquote(params["sid"])
                        tls["reality"] = reality
                    ob["tls"] = tls

                if params.get("type", "").lower() == "ws":
                    ws = {"type": "ws"}
                    if "path" in params: ws["path"] = unquote(params["path"])
                    if "host" in params: ws["headers"] = {"Host": unquote(params["host"])}
                    ob["transport"] = ws

            if self.add_outbound(ob, source=source):
                found_any = True

        # ss://base64@host:port#tag
        for m in re.finditer(r"ss://([A-Za-z0-9+/=_-]+)@([^:]+):(\d+)(#([^\s]+))?", raw_text):
            server = m.group(2)
            port = int(m.group(3))
            raw_tag = unquote(m.group(5)) if m.group(5) else f"SS-{server}"
            b64 = m.group(1).replace("-", "+").replace("_", "/")
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            try:
                dec = base64.b64decode(b64).decode("utf-8", errors="ignore")
                if ":" in dec:
                    method, pwd = dec.split(":", 1)
                    ob = {
                        "type": "shadowsocks",
                        "tag": raw_tag,
                        "server": server,
                        "server_port": port,
                        "method": method,
                        "password": pwd
                    }
                    if self.add_outbound(ob, source=source):
                        found_any = True
            except Exception:
                pass

        return found_any

    def parse_file(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            fname = os.path.basename(file_path)
            self.parse_dark_tunnel(content, source=fname)
            self.parse_json_content(content, source=fname)
            self.parse_share_links(content, source=fname)
        except Exception as e:
            log_warn(f"Error reading file {file_path}: {e}")

    def export_singbox_json(self, output_file="vpn_file_01.json", base_dir=None):
        if base_dir is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))

        out_path = output_file if os.path.isabs(output_file) else os.path.join(base_dir, output_file)

        config_data = {
            "outbounds": self.outbounds
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=4, ensure_ascii=False)

        log_ok(f"Saved {len(self.outbounds)} standard outbound(s) to: {out_path}")

        # Validate with sing-box.exe check if present
        singbox_bin = os.path.join(base_dir, "sing-box.exe")
        if os.path.exists(singbox_bin):
            log_info("Validating configuration with sing-box check...")
            res = subprocess.run([singbox_bin, "check", "-c", out_path], capture_output=True, text=True)
            if res.returncode == 0:
                log_ok("sing-box check PASSED! 100% compliant standard configuration.")
            else:
                log_warn(f"sing-box check returned warning/code {res.returncode}:\n{res.stderr or res.stdout}")
        return out_path


# ── Telegram Client & Scraper ────────────────────────────────────────────────
async def check_session_status(client):
    log_info("Connecting to Telegram...")
    try:
        await client.connect()
    except Exception as e:
        log_err(f"Failed to connect to Telegram network: {e}")
        return False

    is_auth = await client.is_user_authorized()
    if is_auth:
        try:
            me = await client.get_me()
            user_handle = f"@{me.username}" if me.username else f"ID: {me.id}"
            phone_display = f" (+{me.phone})" if me.phone else ""
            log_ok(f"Login session is VALID! Logged in as: {me.first_name} {user_handle}{phone_display}")
            return True
        except Exception as e:
            log_warn(f"Authorized check error: {e}")
            return False
    else:
        log_warn("Login session is INVALID or NOT FOUND.")
        return False

async def perform_telegram_login(client):
    log_header("Telegram Interactive Login")
    print("Please enter your Telegram credentials when prompted:")
    await client.start()
    me = await client.get_me()
    log_ok(f"Successfully authenticated as: {me.first_name} (@{me.username or me.id})")
    log_ok("Session saved to 'telegram_session.session' - future runs will use this session automatically!")

async def scrape_telegram_group(client, target_channel, days, download_dir):
    os.makedirs(download_dir, exist_ok=True)
    cutoff_time = datetime.now(timezone.utc) - timedelta(days=days)

    log_header(f"Scraping '{target_channel}'")
    log_info(f"Time Range : Past {days} day(s)")
    log_info(f"Cutoff Date: {cutoff_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    log_info(f"Target Dir : {download_dir}")

    try:
        entity = await client.get_entity(target_channel)
    except Exception as e:
        log_err(f"Could not resolve Telegram entity '{target_channel}': {e}")
        return []

    downloaded_files = []
    scanned_count = 0
    match_count = 0

    log_info("Fetching messages from newest to oldest...")

    async for msg in client.iter_messages(entity):
        scanned_count += 1
        msg_date = msg.date
        if msg_date < cutoff_time:
            log_info(f"Reached cutoff timestamp ({msg_date.strftime('%Y-%m-%d %H:%M:%S')}). Stopping scrape.")
            break

        # Check for attached documents
        if msg.document:
            file_name = None
            for attr in msg.document.attributes:
                if hasattr(attr, "file_name") and attr.file_name:
                    file_name = attr.file_name
                    break

            if not file_name:
                ext = msg.file.ext if msg.file else ".txt"
                file_name = f"file_{msg.id}{ext}"

            # Filter relevant VPN / text formats
            lower_name = file_name.lower()
            if any(lower_name.endswith(ext) for ext in [".txt", ".dark", ".json", ".npvs", ".hc", ".ehi", ".ssc", ".nm", ".ar"]):
                dest_path = os.path.join(download_dir, file_name)
                # Avoid re-downloading identical files if already present
                if not os.path.exists(dest_path):
                    log_info(f"Downloading [{msg.date.strftime('%Y-%m-%d')}] '{file_name}'...")
                    await msg.download_media(file=dest_path)
                    downloaded_files.append(dest_path)
                    match_count += 1
                else:
                    downloaded_files.append(dest_path)

        # Check for inline text payloads in message body
        if msg.text:
            if any(proto in msg.text for proto in ["darktunnel://", "vless://", "vmess://", "ss://", "sshField", '"config":']):
                inline_file = os.path.join(download_dir, f"msg_{msg.id}_inline.txt")
                if not os.path.exists(inline_file):
                    with open(inline_file, "w", encoding="utf-8") as f:
                        f.write(msg.text)
                    downloaded_files.append(inline_file)
                    match_count += 1

    log_ok(f"Scanned {scanned_count} message(s). Downloaded/Found {match_count} VPN file(s) within the last {days} day(s).")
    return downloaded_files


# ── Main Entry Point ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Multip VPN - Telegram Scraper & Extractor to sing-box JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python scrape-telegram.py -d 3
  python scrape-telegram.py -d 1 --output vpn_file_01.json
  python scrape-telegram.py --check-login
  python scrape-telegram.py --extract-only
"""
    )
    parser.add_argument("-d", "--days", type=float, default=3, help="Time range in days to scrape (default: 3)")
    parser.add_argument("-o", "--output", default="vpn_file_01.json", help="Output sing-box JSON file (default: vpn_file_01.json)")
    parser.add_argument("--target", default="decrypt_file_vpn", help="Telegram channel/group handle (default: decrypt_file_vpn)")
    parser.add_argument("--folder", default="vpn file", help="Local directory to store VPN files (default: 'vpn file')")
    parser.add_argument("--login", action="store_true", help="Start interactive login to create or refresh telegram session")
    parser.add_argument("--check-login", action="store_true", help="Check whether the Telegram login session is valid and exit")
    parser.add_argument("--extract-only", action="store_true", help="Extract existing files from folder without scraping Telegram")

    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    download_dir = args.folder if os.path.isabs(args.folder) else os.path.join(script_dir, args.folder)

    # Mode 1: Extract existing folder without Telegram network call
    if args.extract_only:
        log_header("Local Extraction Mode")
        extractor = VpnExtractor()
        if os.path.exists(download_dir):
            for fname in os.listdir(download_dir):
                fpath = os.path.join(download_dir, fname)
                if os.path.isfile(fpath):
                    extractor.parse_file(fpath)
        out_file = extractor.export_singbox_json(output_file=args.output, base_dir=script_dir)
        log_ok(f"Extraction complete! {len(extractor.outbounds)} node(s) saved to {out_file}")
        return

    # Verify Telegram API credentials
    if not API_ID or not API_HASH:
        log_err("Missing API_ID or API_HASH. Please ensure .env contains:")
        print("  API_ID=your_api_id")
        print("  API_HASH=your_api_hash")
        sys.exit(1)

    from telethon import TelegramClient

    session_name = os.path.join(script_dir, "telegram_session")
    client = TelegramClient(session_name, API_ID, API_HASH)

    async def runner():
        # Handle explicit --login
        if args.login:
            await perform_telegram_login(client)
            await client.disconnect()
            return

        # Check login validity
        is_valid = await check_session_status(client)

        if args.check_login:
            if is_valid:
                log_ok("Session is ready for scraping.")
            else:
                log_warn("Run 'python scrape-telegram.py --login' in your terminal to authenticate.")
            await client.disconnect()
            sys.exit(0 if is_valid else 1)

        if not is_valid:
            if sys.stdin.isatty():
                log_warn("Session is not authorized. Initiating interactive login...")
                await perform_telegram_login(client)
            else:
                log_err("Telegram login session is not authorized.")
                log_info("Please run 'python scrape-telegram.py --login' in your PowerShell/Terminal to log in once.")
                await client.disconnect()
                sys.exit(1)

        # Scrape Telegram group within time range
        await scrape_telegram_group(client, args.target, args.days, download_dir)
        await client.disconnect()

        # Parse and Extract all files into sing-box JSON
        log_header("Extracting VPN Configurations")
        extractor = VpnExtractor()
        if os.path.exists(download_dir):
            for fname in os.listdir(download_dir):
                fpath = os.path.join(download_dir, fname)
                if os.path.isfile(fpath):
                    extractor.parse_file(fpath)

        out_path = extractor.export_singbox_json(output_file=args.output, base_dir=script_dir)

        print("\n" + "=" * 64)
        print(f"  {Colors.GREEN}PIPELINE COMPLETE!{Colors.RESET}")
        print(f"  Output File : {os.path.basename(out_path)}")
        print(f"  Total Nodes : {len(extractor.outbounds)}")
        print(f"  Connect with: .\\connect-cluster.ps1 or .\\clean-configs.ps1")
        print("=" * 64 + "\n")

    asyncio.run(runner())

if __name__ == "__main__":
    main()
