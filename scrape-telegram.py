#!/usr/bin/env python3
"""
Multip VPN - Telegram Scraper & VPN Config Extractor
Scrapes decrypted tunnel configurations from Telegram groups (e.g., https://t.me/decrypt_file_vpn)
within a specified time range (-d days), directly extracts proxy outbounds from bot messages,
and exports 100% compliant sing-box JSON (vpn_file_01.json).
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


def clean_tag(raw_tag, fallback="Node"):
    """Clean markdown backticks, asterisks, and special characters from outbound tags."""
    t = re.sub(r'[`*~_#\[\]]', '', str(raw_tag or "")).strip()
    t = re.sub(r'\s+', ' ', t)
    return t if t else fallback


# ── Extraction & Parser Engine ───────────────────────────────────────────────
class VpnExtractor:
    def __init__(self):
        self.outbounds = []
        self.seen_keys = set()
        self.seen_tags = set()
        self.counter = 0

    def add_outbound(self, ob, source=""):
        if not ob or not isinstance(ob, dict) or "type" not in ob:
            return False

        ob_type = str(ob.get("type", "")).strip().lower()
        server = str(ob.get("server", "")).strip().lower()
        port = int(ob.get("server_port", 0))
        user = str(ob.get("user", "") or ob.get("uuid", "")).strip()

        # Reject invalid servers, injector placeholders, or single-word usernames
        if not server or port <= 0 or port > 65535:
            return False
        if "[" in server or "]" in server or server in ("localhost", "127.0.0.1", "0.0.0.0"):
            return False
        if "." not in server:
            return False

        unique_key = f"{ob_type}://{server}:{port}@{user}"
        if unique_key in self.seen_keys:
            return False

        self.seen_keys.add(unique_key)
        self.counter += 1

        # Strict tag deduplication & sanitization (prevents sing-box duplicate tag errors)
        base_tag = clean_tag(ob.get("tag", f"{ob_type.upper()}-{server}"))
        final_tag = base_tag
        suffix = 1
        while final_tag in self.seen_tags:
            suffix += 1
            final_tag = f"{base_tag}-{suffix}"

        self.seen_tags.add(final_tag)
        ob["tag"] = final_tag

        self.outbounds.append(ob)
        log_ok(f"Extracted [{ob_type.upper():5}] '{final_tag}' -> {server}:{port} ({source})")
        return True

    def parse_text(self, text, source=""):
        if not text:
            return 0
        norm = unicodedata.normalize('NFKD', text)
        before_count = len(self.outbounds)

        # Check for optional config name / remarks in bot message (e.g. 【✧】 [name] : KnowledgeGate0)
        cfg_name_m = re.search(r'(?:【✧】|[~-])\s*\*?\*?\[(?:name|remarks)\]\*?\*?\s*:\s*[`*"\s]*([^`*"\n\r]+)', norm, re.I)
        common_tag = clean_tag(cfg_name_m.group(1)) if cfg_name_m else None

        # 1. sshField: [sshField] : host:port@user:pass (HTTP Custom standard)
        for m in re.finditer(r'sshfield[^\n\r:]*:\s*[`*"\s]*([^:`*"\s]+):(\d+)@([^:`*"\s]+):([^`*"\s\n\r]+)', norm, re.I):
            tag = common_tag if common_tag else f"SSH-{m.group(1)}"
            self.add_outbound({
                "type": "ssh",
                "tag": tag,
                "server": m.group(1).strip(),
                "server_port": int(m.group(2)),
                "user": m.group(3).strip(),
                "password": m.group(4).strip()
            }, source=source)

        # 2. Universal Decodez field blocks: [host], [port], [user], [password]
        # Bullet-line anchored (【✧】 or - or ~) to avoid matching inside [payload] macros like Host: [host]
        host_m = re.search(r'(?:【✧】|[~-])\s*\*?\*?\[host\]\*?\*?\s*:\s*[`*"\s]*([a-zA-Z0-9\.\-_]+)', norm, re.I)
        port_m = re.search(r'(?:【✧】|[~-])\s*\*?\*?\[port\]\*?\*?\s*:\s*[`*"\s]*(\d+)', norm, re.I)
        user_m = re.search(r'(?:【✧】|[~-])\s*\*?\*?\[user\]\*?\*?\s*:\s*[`*"\s]*([^`*"\s]+)', norm, re.I)
        pwd_m  = re.search(r'(?:【✧】|[~-])\s*\*?\*?\[password\]\*?\*?\s*:\s*[`*"\s]*([^`*"\s]+)', norm, re.I)
        if host_m and user_m:
            tag = common_tag if common_tag else f"SSH-{host_m.group(1)}"
            self.add_outbound({
                "type": "ssh",
                "tag": tag,
                "server": host_m.group(1).strip(),
                "server_port": int(port_m.group(1)) if port_m else 443,
                "user": user_m.group(1).strip(),
                "password": pwd_m.group(1).strip() if pwd_m else ""
            }, source=source)

        # 3. SSC Custom format: [ADDRESS], [PORT], [USERNAME], [PASSWORD]
        ssc_addr = re.search(r'\[address\][^\n\r:]*:\s*[`*"\s]*([a-zA-Z0-9\.\-_]+)', norm, re.I)
        ssc_port = re.search(r'\[port\][^\n\r:]*:\s*[`*"\s]*(\d+)', norm, re.I)
        ssc_user = re.search(r'\[username\][^\n\r:]*:\s*[`*"\s]*([^`*"\s]+)', norm, re.I)
        ssc_pwd  = re.search(r'\[password\][^\n\r:]*:\s*[`*"\s]*([^`*"\s]+)', norm, re.I)
        if ssc_addr and ssc_user:
            self.add_outbound({
                "type": "ssh",
                "tag": f"SSH-{ssc_addr.group(1)}",
                "server": ssc_addr.group(1).strip(),
                "server_port": int(ssc_port.group(1)) if ssc_port else 80,
                "user": ssc_user.group(1).strip(),
                "password": ssc_pwd.group(1).strip() if ssc_pwd else ""
            }, source=source)

        # 4. Howdy VPN format: Server : ..., Username : ..., Password : ..., Port : ...
        howdy_srv = re.search(r'Server\s*:\s*[`*"\s]*([a-zA-Z0-9\.\-_]+)', norm, re.I)
        howdy_usr = re.search(r'Username\s*:\s*[`*"\s]*([^`*"\s]+)', norm, re.I)
        howdy_pwd = re.search(r'Password\s*:\s*[`*"\s]*([^`*"\s]+)', norm, re.I)
        howdy_prt = re.search(r'Port\s*:\s*[`*"\s]*(\d+)', norm, re.I)
        if howdy_srv and howdy_usr:
            self.add_outbound({
                "type": "ssh",
                "tag": f"SSH-{howdy_srv.group(1)}",
                "server": howdy_srv.group(1).strip(),
                "server_port": int(howdy_prt.group(1)) if howdy_prt else 443,
                "user": howdy_usr.group(1).strip(),
                "password": howdy_pwd.group(1).strip() if howdy_pwd else ""
            }, source=source)

        # 5. NapsternetV / Npvs v2rayProfile format
        npv_srv  = re.search(r'\[server\][^\n\r:]*:\s*[`*"\s]*([a-zA-Z0-9\.\-_]+)', norm, re.I)
        npv_port = re.search(r'\[serverport\][^\n\r:]*:\s*[`*"\s]*(\d+)', norm, re.I)
        npv_pwd  = re.search(r'\[password\][^\n\r:]*:\s*[`*"\s]*([^`*"\s]+)', norm, re.I)
        npv_host = re.search(r'\[host\][^\n\r:]*:\s*[`*"\s]*([a-zA-Z0-9\.\-_]+)', norm, re.I)
        npv_path = re.search(r'\[path\][^\n\r:]*:\s*[`*"\s]*([^`*"\s]+)', norm, re.I)
        npv_name = re.search(r'\[remarks\][^\n\r:]*:\s*[`*"\s]*([^`*"\n\r]+)', norm, re.I)
        if npv_srv and npv_pwd and re.match(r'^[a-f0-9\-]{36}$', npv_pwd.group(1).strip(), re.I):
            ob = {
                "type": "vmess",
                "tag": clean_tag(npv_name.group(1) if npv_name else npv_srv.group(1)),
                "server": npv_srv.group(1).strip(),
                "server_port": int(npv_port.group(1)) if npv_port else 80,
                "uuid": npv_pwd.group(1).strip(),
                "security": "auto",
                "alter_id": 0
            }
            if npv_path:
                ws = {"type": "ws", "path": npv_path.group(1).strip()}
                if npv_host:
                    ws["headers"] = {"Host": npv_host.group(1).strip()}
                ob["transport"] = ws
            self.add_outbound(ob, source=source)

        # 6. vmess:// links
        for m in re.finditer(r"vmess://([A-Za-z0-9+/=_-]+)", norm):
            b64 = m.group(1).replace("-", "+").replace("_", "/")
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            try:
                data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
                srv = str(data.get("add", "")).strip()
                uuid = str(data.get("id", "")).strip()
                if srv and uuid:
                    ob = {
                        "type": "vmess",
                        "tag": clean_tag(data.get("ps") or srv),
                        "server": srv,
                        "server_port": int(data.get("port", 443)),
                        "uuid": uuid,
                        "security": data.get("scy", "auto") or "auto",
                        "alter_id": int(data.get("aid", 0))
                    }
                    if str(data.get("tls", "")).lower() == "tls":
                        sni = data.get("sni") or data.get("host", "").split("\n")[0]
                        ob["tls"] = {"enabled": True, "server_name": sni.strip() if sni else srv}
                    if str(data.get("net", "")).lower() == "ws":
                        ws = {"type": "ws"}
                        if data.get("path"): ws["path"] = data.get("path")
                        if data.get("host"): ws["headers"] = {"Host": data.get("host").split("\n")[0].strip()}
                        ob["transport"] = ws
                    self.add_outbound(ob, source=source)
            except Exception:
                pass

        # 7. vless:// links
        for m in re.finditer(r"vless://([a-fA-F0-9\-]+)@([^:]+):(\d+)(\?[^\s#]+)?(#([^\s\n\r`]+))?", norm):
            srv = m.group(2).strip()
            raw_tag = unquote(m.group(6)) if m.group(6) else f"VLESS-{srv}"
            ob = {
                "type": "vless",
                "tag": clean_tag(raw_tag),
                "server": srv,
                "server_port": int(m.group(3)),
                "uuid": m.group(1).strip()
            }
            q = m.group(4) or ""
            if q:
                params = dict(part.split("=", 1) for part in q.lstrip("?").split("&") if "=" in part)
                sec = params.get("security", "").lower()
                if sec in ("tls", "reality"):
                    tls = {"enabled": True}
                    if "sni" in params: tls["server_name"] = unquote(params["sni"])
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
            self.add_outbound(ob, source=source)

        # 8. ssh://user:pass@host:port (Netmod format)
        for m in re.finditer(r"ssh://([^:]+):([^@]+)@([^:/?\s]+):(\d+)", norm):
            self.add_outbound({
                "type": "ssh",
                "tag": f"SSH-{m.group(3)}",
                "server": m.group(3).strip(),
                "server_port": int(m.group(4)),
                "user": m.group(1).strip(),
                "password": m.group(2).strip()
            }, source=source)

        # 9. darktunnel://<base64>
        for m in re.finditer(r"darktunnel://([A-Za-z0-9+/=_-]+)", norm):
            b64 = m.group(1).replace("-", "+").replace("_", "/")
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            try:
                dec_bytes = base64.b64decode(b64)
                data = json.loads(dec_bytes.decode("utf-8", errors="ignore"))
                tag = f"DarkTunnel-{clean_tag(data.get('name', 'node'))}"
                ssh_cfg = data.get("sshTunnelConfig", {}).get("sshConfig", {})
                h = ssh_cfg.get("host")
                p = ssh_cfg.get("port", 443)
                u = ssh_cfg.get("username", "root")
                pwd = ssh_cfg.get("password", "")
                if h and u:
                    self.add_outbound({
                        "type": "ssh",
                        "tag": tag,
                        "server": str(h).strip(),
                        "server_port": int(p),
                        "user": str(u).strip(),
                        "password": str(pwd).strip()
                    }, source=source)
            except Exception:
                pass

        # 10. JSON blocks (Alain Bot document.configs or HTTP Custom config array)
        for json_match in re.finditer(r'(\{"document"[\s\S]*?\}|\{"metadata"[\s\S]*?\}|\{[\s\S]*?"config"\s*:\s*\[[\s\S]*?\][\s\S]*?\})', norm):
            try:
                data = json.loads(json_match.group(1))
                configs = data.get("document", {}).get("configs", []) or data.get("config", [])
                if isinstance(configs, dict): configs = [configs]
                for idx, c in enumerate(configs, start=1):
                    ssh = c.get("sshConfig", {})
                    h = ssh.get("sshHost") or c.get("host") or (c.get("address", "").split(":")[0] if c.get("address") else None)
                    p = ssh.get("sshPort") or c.get("port") or 80
                    u = ssh.get("sshUsername") or c.get("username")
                    pwd = ssh.get("sshPassword") or c.get("password", "")
                    if h and u:
                        self.add_outbound({
                            "type": "ssh",
                            "tag": clean_tag(c.get("name") or f"SSH-{h}"),
                            "server": str(h).strip(),
                            "server_port": int(p),
                            "user": str(u).strip(),
                            "password": str(pwd).strip()
                        }, source=source)
            except Exception:
                pass

        return len(self.outbounds) - before_count

    def parse_file(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            fname = os.path.basename(file_path)
            return self.parse_text(content, source=fname)
        except Exception as e:
            log_warn(f"Error reading file {file_path}: {e}")
            return 0

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
                log_warn(f"sing-box check warning/code {res.returncode}:\n{res.stderr or res.stdout}")
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

async def scrape_telegram_group(client, target_channel, days, extractor, download_dir=None):
    cutoff_time = datetime.now(timezone.utc) - timedelta(days=days)

    log_header(f"Scraping '{target_channel}'")
    log_info(f"Time Range : Past {days} day(s)")
    log_info(f"Cutoff Date: {cutoff_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    try:
        entity = await client.get_entity(target_channel)
    except Exception as e:
        log_err(f"Could not resolve Telegram entity '{target_channel}': {e}")
        return

    scanned_count = 0
    bot_msg_count = 0

    log_info("Scanning messages from newest to oldest (in-memory extraction)...")

    async for msg in client.iter_messages(entity):
        scanned_count += 1
        msg_date = msg.date
        if msg_date < cutoff_time:
            log_info(f"Reached cutoff timestamp ({msg_date.strftime('%Y-%m-%d %H:%M:%S')}). Stopping scrape.")
            break

        # 1. Parse message text directly in memory
        if msg.text:
            added = extractor.parse_text(msg.text, source=f"msg_{msg.id}")
            if added > 0:
                bot_msg_count += 1

        # 2. If message has attached .txt or .dark or .json document, read in-memory
        if msg.document:
            file_name = None
            for attr in msg.document.attributes:
                if hasattr(attr, "file_name") and attr.file_name:
                    file_name = attr.file_name
                    break

            if file_name:
                lower_name = file_name.lower()
                # Only read text/decrypted documents, do NOT download raw locked containers (.hc, .npvs, .ehi, etc.)
                if lower_name.endswith(".txt") or lower_name.endswith(".dark") or lower_name.endswith(".json"):
                    try:
                        content_bytes = await msg.download_media(bytes)
                        text_content = content_bytes.decode("utf-8", errors="ignore")
                        added = extractor.parse_text(text_content, source=f"doc_{file_name}")
                        if added > 0:
                            bot_msg_count += 1
                    except Exception as e:
                        log_warn(f"Error reading attached document '{file_name}': {e}")

    log_ok(f"Scanned {scanned_count} message(s). Extracted decrypted nodes from {bot_msg_count} message(s)/document(s).")


# ── Main Entry Point ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Multip VPN - Telegram Scraper & Extractor to sing-box JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python scrape-telegram.py -d 3
  python scrape-telegram.py -d 1 --output vpn_file_01.json
  python scrape-telegram.py --qr
  python scrape-telegram.py --check-login
  python scrape-telegram.py --extract-only
"""
    )
    parser.add_argument("-d", "--days", type=float, default=3, help="Time range in days to scrape (default: 3)")
    parser.add_argument("-o", "--output", default="vpn_file_01.json", help="Output sing-box JSON file (default: vpn_file_01.json)")
    parser.add_argument("--target", default="decrypt_file_vpn", help="Telegram channel/group handle (default: decrypt_file_vpn)")
    parser.add_argument("--folder", default="vpn file", help="Local directory to parse in --extract-only mode (default: 'vpn file')")
    parser.add_argument("--qr", action="store_true", help="Log in instantly by scanning a QR code with your Telegram mobile app")
    parser.add_argument("--login", action="store_true", help="Start interactive login to create or refresh telegram session")
    parser.add_argument("--check-login", action="store_true", help="Check whether the Telegram login session is valid and exit")
    parser.add_argument("--extract-only", action="store_true", help="Extract existing local files without connecting to Telegram")

    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Mode 1: Extract existing local folder without Telegram network call
    if args.extract_only:
        log_header("Local Extraction Mode")
        download_dir = args.folder if os.path.isabs(args.folder) else os.path.join(script_dir, args.folder)
        extractor = VpnExtractor()
        if os.path.exists(download_dir):
            for fname in os.listdir(download_dir):
                fpath = os.path.join(download_dir, fname)
                if os.path.isfile(fpath) and any(fname.lower().endswith(x) for x in (".txt", ".dark", ".json")):
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
                log_warn("Run 'python scrape-telegram.py --qr' in your terminal to authenticate.")
            await client.disconnect()
            sys.exit(0 if is_valid else 1)

        if not is_valid:
            if sys.stdin.isatty():
                log_warn("Session is not authorized. Initiating QR login...")
                await perform_qr_login(client)
            else:
                log_err("Telegram login session is not authorized.")
                log_info("Please run 'python scrape-telegram.py --qr' in your PowerShell/Terminal to authenticate.")
                await client.disconnect()
                sys.exit(1)

        # Scrape Telegram group within time range (in-memory extraction)
        extractor = VpnExtractor()
        await scrape_telegram_group(client, args.target, args.days, extractor)
        await client.disconnect()

        # Export all extracted nodes into sing-box JSON and validate
        log_header("Exporting sing-box Configuration")
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
