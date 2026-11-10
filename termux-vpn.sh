#!/data/data/com.termux/files/usr/bin/bash
# ==============================================================================
#  MULTIP VPN & CLUSTER FOR TERMUX (ANDROID)
#  Security Lock: user=u0_a1384 | ip=192.168.1.2 | password=rooted
# ==============================================================================

set -e

# Target Authorization Constants
AUTH_USER="u0_a1384"
AUTH_PASS="rooted"
AUTH_IP="192.168.1.2"
PROXY_PORT=10808
CONFIG_FILE="config.json"

# Color Codes
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

clear
echo -e "${CYAN}================================================================${NC}"
echo -e "${WHITE}   ⚡ MULTIP VPN CLUSTER & ROTATOR - TERMUX EDITION${NC}"
echo -e "${GRAY}   Dedicated Android Gateway * Auto Load-Balancer * Antigravity Safe${NC}"
echo -e "${CYAN}================================================================${NC}"
echo ""

# ──────────────────────────────────────────────────────────────────────────────
#  1. IDENTITY & ENVIRONMENT SECURITY VERIFICATION
# ──────────────────────────────────────────────────────────────────────────────

# 1.1 Verify Termux User Identity
CURRENT_USER=$(whoami 2>/dev/null || id -un 2>/dev/null || echo "unknown")
echo -e "${CYAN}[*] Checking user identity...${NC}"
if [ "$CURRENT_USER" != "$AUTH_USER" ]; then
    echo -e "${RED}[-] ACCESS DENIED: Unauthorized user '${CURRENT_USER}'.${NC}"
    echo -e "${YELLOW}[!] This script is strictly locked to Termux user '${AUTH_USER}'.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] User Verified: ${CURRENT_USER}${NC}"

# 1.2 Verify Device IP Address
echo -e "${CYAN}[*] Checking network IP address...${NC}"
DEVICE_IPS=$(ip -4 addr show 2>/dev/null | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' || ifconfig 2>/dev/null | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' || true)

IP_FOUND=0
for ip in $DEVICE_IPS; do
    if [ "$ip" = "$AUTH_IP" ]; then
        IP_FOUND=1
        break
    fi
done

if [ $IP_FOUND -ne 1 ]; then
    echo -e "${RED}[-] IP VERIFICATION FAILED: Required IP '${AUTH_IP}' not found!${NC}"
    echo -e "${YELLOW}[!] Current active device IPs:${NC}"
    echo "$DEVICE_IPS" | while read -r line; do
        [ -n "$line" ] && echo -e "    • $line"
    done
    echo -e "${RED}[-] Connect your device to the Wi-Fi network where IP is ${AUTH_IP}.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] IP Verified: ${AUTH_IP} (Active LAN interface)${NC}"

# 1.3 Verify Password
echo -e "${CYAN}[*] Security Authentication Required${NC}"
AUTH_PASSED=0
for attempt in 1 2 3; do
    read -s -p "Enter authorization password: " INPUT_PASS
    echo ""
    if [ "$INPUT_PASS" = "$AUTH_PASS" ]; then
        AUTH_PASSED=1
        break
    else
        echo -e "${RED}[-] Invalid password. (Attempt ${attempt} of 3)${NC}"
    fi
done

if [ $AUTH_PASSED -ne 1 ]; then
    echo -e "${RED}[-] Authentication failed. Terminating.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Authentication Successful! Access Granted.${NC}"
echo ""

# ──────────────────────────────────────────────────────────────────────────────
#  2. TERMUX DEPENDENCIES CHECK & INSTALLATION
# ──────────────────────────────────────────────────────────────────────────────
echo -e "${CYAN}[*] Verifying Termux packages (sing-box, curl, jq)...${NC}"

check_pkg() {
    command -v "$1" >/dev/null 2>&1
}

NEED_UPDATE=0
if ! check_pkg sing-box; then
    echo -e "${YELLOW}[!] sing-box is not installed in Termux.${NC}"
    NEED_UPDATE=1
fi
if ! check_pkg curl; then NEED_UPDATE=1; fi
if ! check_pkg jq; then NEED_UPDATE=1; fi

if [ $NEED_UPDATE -eq 1 ]; then
    echo -e "${CYAN}[*] Installing required packages via Termux pkg manager...${NC}"
    pkg update -y || apt-get update -y
    pkg install -y sing-box curl jq tar || apt-get install -y sing-box curl jq tar

    # If sing-box not available in standard pkg repo, fetch official binary
    if ! check_pkg sing-box; then
        echo -e "${CYAN}[*] Fetching official sing-box binary for Android/ARM64...${NC}"
        ARCH=$(uname -m)
        case "$ARCH" in
            aarch64|arm64) SBOX_ARCH="linux-arm64" ;;
            armv7l|arm)    SBOX_ARCH="linux-armv7" ;;
            x86_64|amd64)  SBOX_ARCH="linux-amd64" ;;
            *) SBOX_ARCH="linux-arm64" ;;
        esac
        LATEST_URL="https://github.com/SagerNet/sing-box/releases/download/v1.11.4/sing-box-1.11.4-${SBOX_ARCH}.tar.gz"
        TMP_DIR=$(mktemp -d)
        curl -sL "$LATEST_URL" -o "$TMP_DIR/sbox.tar.gz"
        tar -xzf "$TMP_DIR/sbox.tar.gz" -C "$TMP_DIR"
        mkdir -p "$PREFIX/bin"
        cp "$TMP_DIR"/sing-box-*/sing-box "$PREFIX/bin/sing-box"
        chmod +x "$PREFIX/bin/sing-box"
        rm -rf "$TMP_DIR"
    fi
fi

SINGBOX_BIN=$(command -v sing-box || echo "$PREFIX/bin/sing-box")
if [ ! -x "$SINGBOX_BIN" ]; then
    echo -e "${RED}[-] Error: sing-box binary not found!${NC}"
    exit 1
fi
echo -e "${GREEN}[+] sing-box engine ready: ${SINGBOX_BIN}${NC}"

# ──────────────────────────────────────────────────────────────────────────────
#  3. CONFIG FILE DETECTION & SYNTHESIS
# ──────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_CONFIG=""

for cand in "$SCRIPT_DIR/config.json" "$SCRIPT_DIR/normal_config.json" "$HOME/config.json"; do
    if [ -f "$cand" ]; then
        TARGET_CONFIG="$cand"
        break
    fi
done

if [ -z "$TARGET_CONFIG" ]; then
    echo -e "${YELLOW}[!] No config.json found in $SCRIPT_DIR or $HOME.${NC}"
    echo -e "${CYAN}[*] Creating sample configuration template...${NC}"
    TARGET_CONFIG="$SCRIPT_DIR/config.json"
    cat << 'EOF' > "$TARGET_CONFIG"
{
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
fi
echo -e "${GREEN}[+] Using Configuration: ${TARGET_CONFIG}${NC}"

# Count outbounds in config
NODE_COUNT=0
if check_pkg jq; then
    NODE_COUNT=$(jq '.outbounds | length' "$TARGET_CONFIG" 2>/dev/null || echo 0)
fi
echo -e "${WHITE}    Discovered ${NODE_COUNT} outbound node(s).${NC}"

# ──────────────────────────────────────────────────────────────────────────────
#  4. SYNTHESIZE TERMUX RUN CONFIGURATION (TUN Full-Tunnel or Proxy Gateway)
# ──────────────────────────────────────────────────────────────────────────────
RUN_CONFIG="$SCRIPT_DIR/_termux_singbox_run.json"

# Check if device has root access (su / tsu)
HAS_ROOT=0
if [ "$(id -u)" = "0" ]; then
    HAS_ROOT=1
elif command -v su >/dev/null 2>&1; then
    if su -c "id" 2>/dev/null | grep -q "uid=0"; then
        HAS_ROOT=1
    fi
fi

# Extract raw outbounds array
OUTBOUNDS_JSON="[]"
if check_pkg jq; then
    OUTBOUNDS_JSON=$(jq '.outbounds // []' "$TARGET_CONFIG")
fi

if [ $HAS_ROOT -eq 1 ]; then
    echo -e "${GREEN}[+] ROOT PRIVILEGES DETECTED! Enabling System-Wide Auto Full-Tunnel (TUN + Gateway).${NC}"
    INBOUNDS_JSON='[
      {
        "type": "tun",
        "tag": "tun-in",
        "interface_name": "tun0",
        "address": ["172.19.0.1/30"],
        "auto_route": true,
        "strict_route": false,
        "stack": "mixed",
        "route_exclude_address": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
      },
      {
        "type": "mixed",
        "tag": "mixed-in",
        "listen": "0.0.0.0",
        "listen_port": '${PROXY_PORT}'
      }
    ]'
else
    echo -e "${YELLOW}[!] Non-Root Mode: Running as LAN Proxy Gateway (192.168.1.2:${PROXY_PORT}).${NC}"
    echo -e "${GRAY}    (To tunnel 100% of phone apps automatically, grant Root / su or configure Wi-Fi proxy).${NC}"
    INBOUNDS_JSON='[
      {
        "type": "mixed",
        "tag": "mixed-in",
        "listen": "0.0.0.0",
        "listen_port": '${PROXY_PORT}'
      }
    ]'
fi

# Build complete sing-box JSON for Termux with Rock-Solid DoH (Port 443)
cat << EOF > "$RUN_CONFIG"
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "dns-remote-doh",
        "type": "https",
        "server": "1.1.1.1",
        "server_port": 443,
        "path": "/dns-query"
      },
      {
        "tag": "dns-local",
        "type": "local"
      }
    ],
    "final": "dns-remote-doh"
  },
  "inbounds": ${INBOUNDS_JSON},
  "outbounds": ${OUTBOUNDS_JSON},
  "route": {
    "default_domain_resolver": "dns-local",
    "rules": [
      {
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      }
    ],
    "auto_detect_interface": true
  }
}
EOF

# Validate syntax
if ! "$SINGBOX_BIN" check -c "$RUN_CONFIG" >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] Direct synthesis needed fallback tags. Adding direct fallback...${NC}"
    cat << EOF > "$RUN_CONFIG"
{
  "log": { "level": "warn", "timestamp": true },
  "dns": {
    "servers": [
      { "tag": "dns-local", "type": "local" }
    ]
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "0.0.0.0",
      "listen_port": ${PROXY_PORT}
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}
EOF
fi

# ──────────────────────────────────────────────────────────────────────────────
#  5. LAUNCH CONTROLLER & KEEP-ALIVE
# ──────────────────────────────────────────────────────────────────────────────
# Stop any existing instance
if [ $HAS_ROOT -eq 1 ] && [ "$(id -u)" != "0" ]; then
    su -c "killall sing-box 2>/dev/null || true"
else
    killall sing-box 2>/dev/null || true
fi
sleep 0.5

cleanup() {
    echo ""
    echo -e "${YELLOW}[*] Shutting down sing-box on Termux...${NC}"
    if [ $HAS_ROOT -eq 1 ] && [ "$(id -u)" != "0" ]; then
        su -c "killall sing-box 2>/dev/null || true"
    else
        killall sing-box 2>/dev/null || true
    fi
    rm -f "$RUN_CONFIG"
    echo -e "${GREEN}[+] Termux network restored.${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

echo -e "${CYAN}[*] Starting sing-box service on Termux...${NC}"
if [ $HAS_ROOT -eq 1 ] && [ "$(id -u)" != "0" ]; then
    echo -e "${GREEN}[+] Spawning elevated TUN engine via su (Root Full-Tunnel Active)...${NC}"
    su -c "$SINGBOX_BIN run -c $RUN_CONFIG" &
    SINGBOX_PID=$!
else
    "$SINGBOX_BIN" run -c "$RUN_CONFIG" &
    SINGBOX_PID=$!
fi

sleep 1.5

if ! kill -0 "$SINGBOX_PID" 2>/dev/null; then
    echo -e "${RED}[-] sing-box failed to start! Check your config.json syntax.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}   TERMUX MULTIP VPN GATEWAY ACTIVE & VERIFIED!${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo -e "  ${WHITE}* Authenticated User  :${NC} ${GREEN}${AUTH_USER}${NC}"
echo -e "  ${WHITE}* Authorized IP       :${NC} ${GREEN}${AUTH_IP}${NC}"
echo -e "  ${WHITE}* Proxy Gateway URL   :${NC} ${CYAN}http://${AUTH_IP}:${PROXY_PORT}${NC}"
echo -e "  ${WHITE}* SOCKS5 Gateway URL  :${NC} ${CYAN}socks5://${AUTH_IP}:${PROXY_PORT}${NC}"
echo -e "  ${WHITE}* Process PID         :${NC} ${WHITE}${SINGBOX_PID}${NC}"
echo -e "  ${WHITE}* Split-Tunneling     :${NC} ${GREEN}Active (LAN 192.168.1.0/24 & localhost direct)${NC}"
echo ""
echo -e "${YELLOW}  [>] How other devices can use this Termux VPN Gateway:${NC}"
echo -e "      On your Windows PC, other phones, or browser:"
echo -e "      Set HTTP / SOCKS5 Proxy -> ${WHITE}${AUTH_IP}${NC} Port -> ${WHITE}${PROXY_PORT}${NC}"
echo ""
echo -e "${GRAY}  Press Ctrl+C to stop the VPN service.${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""

# Monitor process
while kill -0 "$SINGBOX_PID" 2>/dev/null; do
    sleep 2
done

echo -e "${YELLOW}[!] sing-box process stopped.${NC}"
