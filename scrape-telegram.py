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
import unicodedata
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
        m = re.search(r'(\{"metadata"[\s\S]*\}|\{"document"[\s\S]*\}|\{"app_version"[\s\S]*\}|\{[\s\S]*"config"[\s\S]*\})', raw_text)
        if not m:
            return False

        try:
            data = json.loads(m.group(1))

            # 1. Format: { "config": [ ... ] } (HTTP Custom / SP-DECODE)
            configs = data.get("config", [])
            if isinstance(configs, dict):
                configs = [configs]

            for idx, cfg in enumerate(configs, start=1):
                raw_tag = cfg.get("name") or cfg.get("label") or f"node-{idx}"
                clean_tag = re.sub(r'[^a-zA-Z0-9_\-\. ]', '', str(raw_tag)).strip() or f"Node-{idx}"

                # Standard SSH Protocol
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

                # sshField format: "host:port@user:password" or "user:password@host:port"
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

            # 2. Format: { "document": { "configs": [ ... ] } } (Alain Bot Decrypt)
            doc_configs = data.get("document", {}).get("configs", [])
            for idx, cfg in enumerate(doc_configs, start=1):
                raw_tag = cfg.get("name") or f"doc-node-{idx}"
                clean_tag = re.sub(r'[^a-zA-Z0-9_\-\. ]', '', str(raw_tag)).strip() or f"Node-{idx}"
                ssh_cfg = cfg.get("sshConfig", {})
                h = ssh_cfg.get("sshHost") or cfg.get("address", "").split(":")[0]
                p = ssh_cfg.get("sshPort") or 80
                u = ssh_cfg.get("sshUsername")
                pwd = ssh_cfg.get("sshPassword", "")
                if h and u:
                    ob = {
                        "type": "ssh",
                        "tag": f"SSH-{clean_tag}",
                        "server": str(h).strip(),
                        "server_port": int(p),
                        "user": str(u).strip(),
                        "password": str(pwd).strip()
                    }
                    if self.add_outbound(ob, source=source):
                        found_any = True
        except Exception:
            pass
        return found_any

    def parse_bot_message_fields(self, raw_text, source=""):
        found_any = False
        norm = unicodedata.normalize('NFKD', raw_text)

        # 1. Universal Decodez Bot [sshField] : host:port@user:pass
        for m in re.finditer(r'\[sshField\]\s*:\s*[`"]?([^:`"\s]+):(\d+)@([^:`"\s]+):([^`"\s\n\r]+)[`"]?', norm, re.I):
            host, port, user, pwd = m.group(1).strip(), int(m.group(2)), m.group(3).strip(), m.group(4).strip()
            ob = {
                "type": "ssh",
                "tag": f"SSH-{host}",
                "server": host,
                "server_port": port,
                "user": user,
                "password": pwd
            }
            if self.add_outbound(ob, source=source):
                found_any = True

        for m in re.finditer(r'\[sshField\]\s*:\s*[`"]?([^:`"\s]+):([^@`"\s]+)@([^:`"\s]+):(\d+)[`"]?', norm, re.I):
            user, pwd, host, port = m.group(1).strip(), m.group(2).strip(), m.group(3).strip(), int(m.group(4))
            ob = {
                "type": "ssh",
                "tag": f"SSH-{host}",
                "server": host,
                "server_port": port,
                "user": user,
                "password": pwd
            }
            if self.add_outbound(ob, source=source):
                found_any = True

        # 2. Universal Decodez Bot field blocks: [host], [port], [user], [password]
        host_m = re.search(r'\[host\]\s*:\s*[`"]?([^`"\s]+)[`"]?', norm, re.I)
        port_m = re.search(r'\[port\]\s*:\s*[`"]?(\d+)[`"]?', norm, re.I)
        user_m = re.search(r'\[user\]\s*:\s*[`"]?([^`"\s]+)[`"]?', norm, re.I)
        pwd_m  = re.search(r'\[password\]\s*:\s*[`"]?([^`"\s]+)[`"]?', norm, re.I)
        if host_m and user_m:
            host = host_m.group(1).strip()
            port = int(port_m.group(1)) if port_m else 443
            user = user_m.group(1).strip()
            pwd  = pwd_m.group(1).strip() if pwd_m else ""
            ob = {
                "type": "ssh",
                "tag": f"SSH-{host}",
                "server": host,
                "server_port": port,
                "user": user,
                "password": pwd
            }
            if self.add_outbound(ob, source=source):
                found_any = True

        return found_any

    def parse_vmess_links(self, raw_text, source=""):
        found_any = False
        for m in re.finditer(r"vmess://([A-Za-z0-9+/=_-]+)", raw_text):
            b64 = m.group(1).replace("-", "+").replace("_", "/")
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            try:
                data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
                raw_tag = data.get("ps") or f"VMESS-{data.get('add', 'node')}"
                clean_tag = re.sub(r'[^a-zA-Z0-9_\-\. ]', '', str(raw_tag)).strip() or "VMESS-Node"
                server = str(data.get("add", "")).strip()
                port = int(data.get("port", 443))
                uuid = str(data.get("id", "")).strip()
                if not server or not uuid:
                    continue

                ob = {
                    "type": "vmess",
                    "tag": clean_tag,
                    "server": server,
                    "server_port": port,
                    "uuid": uuid,
                    "security": data.get("scy", "auto") or "auto",
                    "alter_id": int(data.get("aid", 0))
                }

                tls_val = str(data.get("tls", "")).lower()
                if tls_val == "tls":
                    sni = data.get("sni") or data.get("host", "").split("\n")[0]
                    ob["tls"] = {
                        "enabled": True,
                        "server_name": sni.strip() if sni else server
                    }

                net_val = str(data.get("net", "")).lower()
                if net_val == "ws":
                    ws = {"type": "ws"}
                    if data.get("path"):
                        ws["path"] = data.get("path")
                    host_hdr = data.get("host")
                    if host_hdr:
                        ws["headers"] = {"Host": host_hdr.split("\n")[0].strip()}
                    ob["transport"] = ws

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
            norm_content = unicodedata.normalize('NFKD', content)
            self.parse_dark_tunnel(norm_content, source=fname)
            self.parse_json_content(norm_content, source=fname)
            self.parse_bot_message_fields(norm_content, source=fname)
            self.parse_vmess_links(norm_content, source=fname)
            self.parse_share_links(norm_content, source=fname)
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
    log_header("Telegram Authentication")
    print("Choose login method:")
    print("  [1] QR Code (Recommended - instant, no SMS/code required)")
    print("  [2] Phone Number & Verification Code")
    choice = input("\nEnter choice [1 or 2] (default: 1): ").strip()
    if choice == "2":
        await client.start()
        me = await client.get_me()
        log_ok(f"Successfully authenticated as: {me.first_name} (@{me.username or me.id})")
        log_ok("Session saved to 'telegram_session.session'!")
    else:
        await perform_qr_login(client)

async def perform_qr_login(client):
    log_header("Telegram QR Code Login")
    log_info("Connecting to Telegram and generating login QR code...")
    try:
        if not client.is_connected():
            await client.connect()
    except Exception as e:
        log_err(f"Connection failed: {e}")
        return False

    qr_login = await client.qr_login()

    import qrcode
    qr = qrcode.QRCode()
    qr.add_data(qr_login.url)
    qr.print_ascii(invert=True)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    qr_img_path = os.path.join(script_dir, "telegram_qr_login.png")
    try:
        img = qrcode.make(qr_login.url)
        img.save(qr_img_path)
        log_info(f"Also saved QR image to: {qr_img_path}")
    except Exception:
        pass

    print("\n" + "=" * 60)
    print("  HOW TO LOG IN VIA QR CODE:")
    print("  1. Open Telegram on your phone")
    print("  2. Go to: Settings (⚙️) ➔ Devices ➔ Link Desktop Device")
    print("  3. Point your camera at the QR code above")
    print("     (Or open 'telegram_qr_login.png' from this folder)")
    print("=" * 60 + "\n")
    print("Waiting for scan (timeout: 120 seconds)...")

    try:
        user = await qr_login.wait(timeout=120)
        log_ok(f"Successfully authenticated as: {user.first_name} (@{user.username or user.id})")
        log_ok("Session saved to 'telegram_session.session' - future runs will use this session automatically!")
        if os.path.exists(qr_img_path):
            try: os.remove(qr_img_path)
            except Exception: pass
        return True
    except asyncio.TimeoutError:
        log_err("QR code timed out. Please run 'python scrape-telegram.py --qr' again.")
        if os.path.exists(qr_img_path):
            try: os.remove(qr_img_path)
            except Exception: pass
        return False
    except Exception as e:
        from telethon.errors import SessionPasswordNeededError
        if isinstance(e, SessionPasswordNeededError):
            pwd = input("Your account has Two-Step Verification (2FA). Enter password: ")
            user = await client.sign_in(password=pwd)
            log_ok(f"Successfully authenticated as: {user.first_name} (@{user.username or user.id})")
            if os.path.exists(qr_img_path):
                try: os.remove(qr_img_path)
                except Exception: pass
            return True
        log_err(f"Login error: {e}")
        return False

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

        # Check for inline text payloads in message body (decrypted bot messages or share links)
        if msg.text:
            norm_text = unicodedata.normalize('NFKD', msg.text)
            is_decrypted = any(k in norm_text for k in [
                "Universal Decodez Bot", "ALAIN BOT DECRYPT", "SP-DECODE",
                "sshField", "[host]", "[port]", "[user]", "vmess://", "vless://",
                "darktunnel://", "ss://", '"document":', '"config":'
            ])
            if is_decrypted:
                inline_file = os.path.join(download_dir, f"msg_{msg.id}_decrypted.txt")
                if not os.path.exists(inline_file):
                    log_info(f"Saving decrypted message text [{msg.date.strftime('%Y-%m-%d %H:%M')}] -> 'msg_{msg.id}_decrypted.txt'")
                    with open(inline_file, "w", encoding="utf-8") as f:
                        f.write(norm_text)
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
    parser.add_argument("--qr", action="store_true", help="Log in instantly by scanning a QR code with your Telegram mobile app")
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
        # Handle explicit QR code login
        if args.qr:
            await perform_qr_login(client)
            await client.disconnect()
            return

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
