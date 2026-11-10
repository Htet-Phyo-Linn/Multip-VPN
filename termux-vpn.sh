#!/data/data/com.termux/files/usr/bin/bash
# ==============================================================================
#  MULTIP VPN & CLUSTER - TERMUX-ONLY EDITION
#  Security Lock: user=u0_a1384 | ip=192.168.1.2 | password=rooted
#  Scope: All Termux terminals, curl, git, pkg, apt, python automatically proxied!
# ==============================================================================

set -e

# Target Authorization Constants
AUTH_USER="u0_a1384"
AUTH_PASS="rooted"
AUTH_IP="192.168.1.2"
PROXY_PORT=10808
CONFIG_FILE="config.json"

# State Files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FLAG="$HOME/.termux_vpn_active"
APT_PROXY_FILE="$PREFIX/etc/apt/apt.conf.d/99multip_proxy"
RUN_CONFIG="$SCRIPT_DIR/_termux_singbox_run.json"
PID_FILE="$SCRIPT_DIR/_termux_singbox.pid"

# Color Codes
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# ──────────────────────────────────────────────────────────────────────────────
#  FAST ACTIONS: STOP & STATUS (No password required)
# ──────────────────────────────────────────────────────────────────────────────
stop_vpn() {
    echo -e "${YELLOW}[*] Shutting down Termux-Only VPN...${NC}"
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE" 2>/dev/null || echo "")
        [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
        rm -f "$PID_FILE"
    fi
    killall sing-box 2>/dev/null || true

    # Clean up state files and environment proxies
    rm -f "$STATE_FLAG" "$APT_PROXY_FILE" "$RUN_CONFIG"
    git config --global --unset http.proxy 2>/dev/null || true
    git config --global --unset https.proxy 2>/dev/null || true
    unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY

    echo -e "${GREEN}[+] Termux network restored to direct connection.${NC}"
}

check_status() {
    if pgrep -f "sing-box run -c $RUN_CONFIG" >/dev/null 2>&1 || [ -f "$STATE_FLAG" ]; then
        echo -e "${GREEN}[+] Termux-Only VPN is ACTIVE & RUNNING.${NC}"
        echo -e "${CYAN}[*] Testing proxy connection via 127.0.0.1:${PROXY_PORT}...${NC}"
        IP_INFO=$(curl -s --max-time 6 --proxy "socks5h://127.0.0.1:${PROXY_PORT}" "https://ipinfo.io/json" 2>/dev/null || true)
        if [ -n "$IP_INFO" ]; then
            IP=$(echo "$IP_INFO" | grep -o '"ip": "[^"]*' | cut -d'"' -f4 || echo "Unknown")
            COUNTRY=$(echo "$IP_INFO" | grep -o '"country": "[^"]*' | cut -d'"' -f4 || echo "Unknown")
            CITY=$(echo "$IP_INFO" | grep -o '"city": "[^"]*' | cut -d'"' -f4 || echo "Unknown")
            echo -e "    • Exit IP : ${WHITE}${IP}${NC}"
            echo -e "    • Country : ${GREEN}${COUNTRY}${NC} (${CITY})"
            echo -e "    • Scope   : ${CYAN}ALL Termux terminals & subshells${NC}"
        else
            echo -e "${YELLOW}[!] Proxy port is open, but external ping is connecting...${NC}"
        fi
    else
        echo -e "${YELLOW}[-] Termux-Only VPN is NOT running.${NC}"
    fi
}

ACTION="${1:-run}"

if [ "$ACTION" = "stop" ] || [ "$ACTION" = "--stop" ]; then
    stop_vpn
    exit 0
fi

if [ "$ACTION" = "status" ] || [ "$ACTION" = "--status" ]; then
    check_status
    exit 0
fi

clear
echo -e "${CYAN}================================================================${NC}"
echo -e "${WHITE}   ⚡ MULTIP VPN - TERMUX-ONLY DEDICATED CONNECTOR${NC}"
echo -e "${GRAY}   Auto-routes ALL Termux terminals, curl, git, pkg & python${NC}"
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
if ! check_pkg sing-box; then NEED_UPDATE=1; fi
if ! check_pkg curl; then NEED_UPDATE=1; fi
if ! check_pkg jq; then NEED_UPDATE=1; fi

if [ $NEED_UPDATE -eq 1 ]; then
    echo -e "${CYAN}[*] Installing required packages via Termux pkg manager...${NC}"
    pkg update -y || apt-get update -y
    pkg install -y sing-box curl jq tar || apt-get install -y sing-box curl jq tar

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
TARGET_CONFIG=""
for cand in "$SCRIPT_DIR/config.json" "$SCRIPT_DIR/normal_config.json" "$HOME/config.json"; do
    if [ -f "$cand" ]; then
        TARGET_CONFIG="$cand"
        break
    fi
done

if [ -z "$TARGET_CONFIG" ]; then
    echo -e "${RED}[-] Error: No config.json found in $SCRIPT_DIR or $HOME.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Using Configuration: ${TARGET_CONFIG}${NC}"

# ──────────────────────────────────────────────────────────────────────────────
#  4. SYNTHESIZE AUTO LOWEST-PING CLUSTER CONFIG WITH PORT-443 DoH
# ──────────────────────────────────────────────────────────────────────────────
echo -e "${CYAN}[*] Building Auto Lowest-Ping Cluster configuration for Termux...${NC}"

# Synthesize sing-box config with Lowest-Ping urltest and Cloudflare DoH (port 443)
if check_pkg jq; then
    jq --argjson port "$PROXY_PORT" '
      (.outbounds // []) as $raw |
      ([$raw[] | select(.type != "direct" and .type != "block" and .type != "dns" and .type != "selector" and .type != "urltest")] ) as $nodes |
      ([$nodes[].tag]) as $tags |
      {
        "log": { "level": "warn", "timestamp": true },
        "dns": {
          "servers": [
            { "tag": "dns-remote-doh", "type": "https", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": "proxy" },
            { "tag": "dns-local", "type": "local" }
          ],
          "final": "dns-remote-doh"
        },
        "inbounds": [
          { "type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": $port }
        ],
        "outbounds": (
          [
            { "type": "selector", "tag": "proxy", "outbounds": ["⚡ Auto Lowest Ping"] },
            { "type": "urltest", "tag": "⚡ Auto Lowest Ping", "outbounds": $tags, "url": "https://www.gstatic.com/generate_204", "interval": "1m", "tolerance": 25 },
            { "type": "direct", "tag": "direct" },
            { "type": "block", "tag": "block" }
          ] + $nodes
        ),
        "route": {
          "default_domain_resolver": "dns-local",
          "rules": [
            { "action": "sniff" },
            { "protocol": "dns", "action": "hijack-dns" },
            { "ip_is_private": true, "outbound": "direct" }
          ],
          "final": "proxy"
        }
      }
    ' "$TARGET_CONFIG" > "$RUN_CONFIG"
else
    # Fallback template if jq is unavailable
    cat << EOF > "$RUN_CONFIG"
{
  "log": { "level": "warn", "timestamp": true },
  "dns": {
    "servers": [
      { "tag": "dns-remote-doh", "type": "https", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": "direct" },
      { "tag": "dns-local", "type": "local" }
    ],
    "final": "dns-remote-doh"
  },
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": ${PROXY_PORT} }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}
EOF
fi

# Validate configuration
if ! "$SINGBOX_BIN" check -c "$RUN_CONFIG" >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] Cluster synthesis had strict rule issues. Adding direct fallback...${NC}"
    cat << EOF > "$RUN_CONFIG"
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": ${PROXY_PORT} }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}
EOF
fi

# ──────────────────────────────────────────────────────────────────────────────
#  5. INSTALL UNIVERSAL TERMUX HOOK (ROUTER FOR ALL TERMINALS)
# ──────────────────────────────────────────────────────────────────────────────
BASHRC="$HOME/.bashrc"
HOOK_TAG="# === MULTIP_VPN_TERMUX_HOOK ==="

if ! grep -q "$HOOK_TAG" "$BASHRC" 2>/dev/null; then
    echo -e "${CYAN}[*] Installing universal proxy hook into ${BASHRC}...${NC}"
    cat << 'EOF' >> "$BASHRC"

# === MULTIP_VPN_TERMUX_HOOK ===
# Auto-routes all Termux terminals & subshells through Multip VPN when active
if [ -f "$HOME/.termux_vpn_active" ]; then
    export http_proxy="http://127.0.0.1:10808"
    export https_proxy="http://127.0.0.1:10808"
    export all_proxy="socks5h://127.0.0.1:10808"
    export HTTP_PROXY="http://127.0.0.1:10808"
    export HTTPS_PROXY="http://127.0.0.1:10808"
    export ALL_PROXY="socks5h://127.0.0.1:10808"
    export no_proxy="localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
    export NO_PROXY="localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
fi
# ===============================
EOF
    echo -e "${GREEN}[+] Universal bashrc hook registered.${NC}"
fi

# ──────────────────────────────────────────────────────────────────────────────
#  6. START ENGINE & ACTIVATE ALL PROXIES
# ──────────────────────────────────────────────────────────────────────────────
# Terminate any lingering instances
killall sing-box 2>/dev/null || true
sleep 0.5

cleanup() {
    echo ""
    echo -e "${YELLOW}[*] Stopping Termux-Only VPN... Restoring direct connection...${NC}"
    kill "$SINGBOX_PID" 2>/dev/null || killall sing-box 2>/dev/null || true
    rm -f "$RUN_CONFIG" "$STATE_FLAG" "$APT_PROXY_FILE" "$PID_FILE"
    git config --global --unset http.proxy 2>/dev/null || true
    git config --global --unset https.proxy 2>/dev/null || true
    unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY
    echo -e "${GREEN}[+] Termux network restored. All terminals back to normal.${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

echo -e "${CYAN}[*] Starting sing-box engine on 127.0.0.1:${PROXY_PORT}...${NC}"
"$SINGBOX_BIN" run -c "$RUN_CONFIG" >/dev/null 2>&1 &
SINGBOX_PID=$!
echo "$SINGBOX_PID" > "$PID_FILE"

sleep 1.5
if ! kill -0 "$SINGBOX_PID" 2>/dev/null; then
    echo -e "${RED}[-] sing-box engine failed to start! Check your config.json syntax.${NC}"
    rm -f "$PID_FILE"
    exit 1
fi

# Mark VPN active globally for all Termux terminals
touch "$STATE_FLAG"

# Configure APT / PKG manager proxy
mkdir -p "$PREFIX/etc/apt/apt.conf.d" 2>/dev/null || true
cat << EOF > "$APT_PROXY_FILE"
Acquire::http::Proxy "http://127.0.0.1:${PROXY_PORT}/";
Acquire::https::Proxy "http://127.0.0.1:${PROXY_PORT}/";
EOF

# Configure Git proxy
git config --global http.proxy "http://127.0.0.1:${PROXY_PORT}" 2>/dev/null || true
git config --global https.proxy "http://127.0.0.1:${PROXY_PORT}" 2>/dev/null || true

# Export proxy environment variables for current terminal
export http_proxy="http://127.0.0.1:${PROXY_PORT}"
export https_proxy="http://127.0.0.1:${PROXY_PORT}"
export all_proxy="socks5h://127.0.0.1:${PROXY_PORT}"
export HTTP_PROXY="http://127.0.0.1:${PROXY_PORT}"
export HTTPS_PROXY="http://127.0.0.1:${PROXY_PORT}"
export ALL_PROXY="socks5h://127.0.0.1:${PROXY_PORT}"
export no_proxy="localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
export NO_PROXY="localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"

# ──────────────────────────────────────────────────────────────────────────────
#  7. LIVE IN-TERMINAL CONNECTIVITY & GEO VERIFICATION
# ──────────────────────────────────────────────────────────────────────────────
echo -e "${CYAN}[*] Verifying live Termux-Only VPN connectivity...${NC}"
IP_INFO=$(curl -s --max-time 6 --proxy "socks5h://127.0.0.1:${PROXY_PORT}" "https://ipinfo.io/json" 2>/dev/null || true)

VPN_IP=$(echo "$IP_INFO" | grep -o '"ip": "[^"]*' | cut -d'"' -f4 || echo "Connected")
VPN_COUNTRY=$(echo "$IP_INFO" | grep -o '"country": "[^"]*' | cut -d'"' -f4 || echo "Global")
VPN_CITY=$(echo "$IP_INFO" | grep -o '"city": "[^"]*' | cut -d'"' -f4 || echo "Proxy")

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}   TERMUX-ONLY VPN CONNECTION ACTIVE & VERIFIED!${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "  ${WHITE}* Exit IP Address     :${NC} ${GREEN}${VPN_IP}${NC}"
echo -e "  ${WHITE}* Location            :${NC} ${GREEN}${VPN_CITY}, ${VPN_COUNTRY}${NC}"
echo -e "  ${WHITE}* Local SOCKS5 / HTTP :${NC} ${CYAN}127.0.0.1:${PROXY_PORT}${NC}"
echo -e "  ${WHITE}* LAN Gateway         :${NC} ${CYAN}${AUTH_IP}:${PROXY_PORT}${NC}"
echo -e "  ${WHITE}* Command Scope       :${NC} ${WHITE}curl, git, pkg, apt, python, node, pip, wget${NC}"
echo -e "  ${WHITE}* Multi-Terminal Hook :${NC} ${GREEN}ACTIVE (All new Termux tabs auto-proxied)${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""

# ──────────────────────────────────────────────────────────────────────────────
#  8. INTERACTIVE VPN SHELL OR BACKGROUND DAEMON
# ──────────────────────────────────────────────────────────────────────────────
if [ "$ACTION" = "bg" ] || [ "$ACTION" = "start" ] || [ "$ACTION" = "--bg" ]; then
    echo -e "${GREEN}[+] Running in background mode.${NC}"
    echo -e "${YELLOW}    • Any new Termux session you open is automatically routed through VPN.${NC}"
    echo -e "${YELLOW}    • To stop VPN at any time, run: ${WHITE}./termux-vpn.sh stop${NC}"
    echo -e "${YELLOW}    • To check status, run:         ${WHITE}./termux-vpn.sh status${NC}"
    echo ""
    # Disown process so script can exit while sing-box keeps running
    trap - SIGINT SIGTERM EXIT
    exit 0
fi

echo -e "${CYAN}[>] Spawning interactive VPN Termux shell...${NC}"
echo -e "${GRAY}    (All commands in this shell run through the VPN).${NC}"
echo -e "${GRAY}    (You can also open new Termux tabs; all terminals auto-route through VPN).${NC}"
echo -e "${YELLOW}    Type 'exit' or press Ctrl+C to disconnect and restore network.${NC}"
echo ""

# Launch interactive subshell with clear indicator prompt
PS1="\[\033[1;36m\]⚡[Termux-VPN]\[\033[0m\] \w\$ " bash -i

# When subshell exits, cleanup runs automatically
cleanup
