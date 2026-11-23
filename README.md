# Multip VPN & Load Balancer

A high-performance transparent TUN VPN and load-balancing toolkit powered by **`sing-box`** and **`xray`** dual-engine architecture.

It features automatic key conversion, live proxy health verification, Antigravity & Google AI policy compliance (auto-filtering unsupported regions like Hong Kong and China), multi-node lowest-ping clustering, dedicated YouTube streaming pools, and live remote subscription auto-updating with Post-Quantum REALITY support.

---

## Key Features

- **Dual-Engine Architecture (sing-box + xray)**: Both official `sing-box.exe` and `xray.exe` binaries are directly bundled in the repository—no external downloads or installations required.
- **Post-Quantum REALITY & Xray Bridge**: Modern Xray-core Reality servers requiring post-quantum hybrid key shares (`X25519MLKEM768`) are transparently bridged through a high-speed internal loopback bridge, eliminating `reality verification failed` errors.
- **Load-Balanced Cluster**: Parallel ping checks, automated country filtering, and lowest-latency routing using `urltest`.
- **Dedicated YouTube & Streaming Pool**: Enforces sticky 5-minute sessions and 150ms tolerance for `youtube.com`, `googlevideo.com`, and `ytimg.com` to prevent "Experiencing interruptions?" streaming errors caused by rapid exit IP hopping.
- **AI & Antigravity Priority Pool**: Routes Google AI Studio, Gemini, and development tools through high-trust Tier-1 nodes (SG, JP, US, CA, UK, DE, ES, CH, SE) with strict encrypted DoH and IPv6 leak blocking.
- **Customer VPN Coexistence**: Seamlessly operates alongside corporate VPNs (FortiClient, Cisco AnyConnect, GlobalProtect) without IP/route collisions.
- **Automated Lifecycle Cleanup**: Scripts automatically detect and terminate leftover or hanging `sing-box` / `xray` processes on startup and restore routes gracefully on Ctrl+C.

---

## Repository Structure & Core Scripts

| Script / File | Purpose |
| :--- | :--- |
| **`connect-cluster.ps1`** | **Load-Balanced Cluster**: Aggregates all nodes across your configs, runs parallel health checks, builds transparent TUN, and balances traffic via lowest ping. |
| **`connect-subscription.ps1`** | **Live Subscription Engine**: Auto-fetches Gist / Base64 / Sub-Store links from `subscriptions.txt`, bridges Xray Reality nodes, hot-reloads key changes (or single fetch with `-Pause`), and supports instant-connect. |
| **`clean-configs.ps1`** | **Health Checker & Consolidator**: 16-thread parallel probe test, removes dead/expired nodes, filters blocked regions, purges Google Cloud IPs (`-gcp` / `-gpc`), and consolidates surviving nodes into `config.json`. |
| **`convert-keys.ps1`** | **Key to JSON Converter**: Converts raw links (SS, VLESS Reality/WS, VMess, Trojan, Hy2, TUIC) or Base64 bundles from `key.txt` into validated sing-box JSON. |
| **`extract-vpn-files.ps1`** | **VPN File Extractor**: Scans injector & tunnel files (`vpn file/`), parses decrypted HTTP Custom, Dark Tunnel (`.dark`), SSH, and embedded links, and exports compliant sing-box JSON (`vpn_file_01.json`). |
| **`reset-network.ps1`** | **Emergency Network Restoration**: Reboot-free cleanup that flushes DNS/ARP, clears virtual TUN adapters, removes lingering static routes, and resets proxy/firewall rules. |
| **`subscriptions.txt`** | Plain text list of remote subscription URLs (Gist, Hiddify, Sub-Store, Clash, or raw share links) to auto-fetch and monitor. |
| **`sing-box.exe`** | Core transparent proxy & TUN routing engine (bundled). |
| **`xray.exe`** | Core Xray engine for MLKEM768 / Post-Quantum Reality loopback bridging (bundled). |
| **`geoip.dat` / `geosite.dat`** | Routing rule databases for geographic IP and domain classifications. |
| **`config.example.json`** | Reference template for sing-box configuration files. |

---

## Getting Started

### Prerequisites
- Windows 10 / 11 (64-bit)
- PowerShell 5.1+ or PowerShell 7+
- **Administrator Privileges** (required to configure virtual TUN adapters and network routing)

To run PowerShell scripts without execution policy restrictions:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

---

## Usage Guide

### 1. Load-Balanced Cluster
Starts the multi-node load-balanced cluster with dedicated pools for general traffic, streaming, and AI tools.

```powershell
# Run with transparent TUN mode (Administrator required)
.\connect-cluster.ps1

# Run in Proxy-Only mode (SOCKS5/HTTP on 127.0.0.1:10808, no TUN)
.\connect-cluster.ps1 -ProxyOnly

# Run in Proxy-Only mode and configure Windows System Proxy automatically
.\connect-cluster.ps1 -ProxyOnly -SystemProxy
```

### 2. Live Subscription Connector
Fetches subscription links defined in `subscriptions.txt`, performs rapid pre-checks, bridges Xray keys if needed, and starts the tunnel.

```powershell
# Connect using URLs from subscriptions.txt (auto-update lifecycle active)
.\connect-subscription.ps1

# Connect with -Pause (fetches keys once at startup, disables recurring background interval polling)
.\connect-subscription.ps1 -Pause

# Connect directly to a specific subscription URL
.\connect-subscription.ps1 -Url "https://gist.github.com/.../raw/your-sub"

# Connect in Proxy-Only mode
.\connect-subscription.ps1 -ProxyOnly
```

#### Key Subscription Parameters
- **`-Pause`**: By default, the subscription engine periodically checks and re-fetches the remote subscription (e.g. every 60 minutes) to hot-reload updated keys. Specifying `-Pause` fetches the subscription **only once** at startup, keeping the connection locked to those nodes without background polling.
- **`-Url <string>`**: Connects to an ad-hoc subscription or Gist URL without editing `subscriptions.txt`.
- **`-ProxyOnly`**: Runs mixed SOCKS5/HTTP proxy on `127.0.0.1:10808` without creating a virtual TUN adapter.

#### Configuring Subscriptions
Add your remote subscription links to `subscriptions.txt` (one per line):
```text
# Remote Subscription URLs
https://gist.github.com/username/hash/raw/sub-name
https://my-substore.com/download/clash
```

### 3. Converting Raw VPN Keys
Paste your share links (`ss://`, `vless://`, `vmess://`, `trojan://`, `hysteria2://`, `tuic://`) into `key.txt` and convert them:

```powershell
# Bundle all live keys into a single config (e.g. config02.json)
.\convert-keys.ps1

# Split each key into its own config file
.\convert-keys.ps1 -Split

# Convert from a specific input file to a specific output file
.\convert-keys.ps1 -InputFile "custom_keys.txt" -OutputFile "config.json"
```

### 4. Extracting from VPN Injector Files (`extract-vpn-files.ps1`)
Extracts proxy outbounds from injector and tunnel files stored in `vpn file/` (including decrypted HTTP Custom / SP-DECODE JSON, Dark Tunnel `.dark` base64 configs, direct SSH credentials, and embedded share links):

```powershell
# Extract all valid nodes from 'vpn file/' into 'vpn_file_01.json'
.\extract-vpn-files.ps1

# Extract to a specific output file or config slot
.\extract-vpn-files.ps1 -OutputFile "vpn_file_01.json"
.\extract-vpn-files.ps1 -OutputFile "config03.json"

# Scan a custom folder
.\extract-vpn-files.ps1 -Folder "D:\custom\vpn\files" -OutputFile "vpn_file_01.json"
```

> [!NOTE]
> Proprietary encrypted formats (`.hc`, `.ehi`, `.npvs`, `.ssc`, `.nm`, `.ar`) are encrypted Android APK containers. Once unlocked via a decryption bot (such as Telegram `@decrypt_file_vpn` or `@syuw3n`), save the decrypted `.txt` result file into `vpn file/` and run `.\extract-vpn-files.ps1` to extract them automatically.

### 5. Cleaning & Auditing Configs
Tests all candidate nodes across existing config files, filters out dead or blocked nodes, and merges working ones:

```powershell
# Clean and consolidate all working nodes into config.json
.\clean-configs.ps1

# Clean and purge Google Cloud Platform (GCP) datacenter nodes
.\clean-configs.ps1 -gcp

# Dry run (test and display status without modifying files)
.\clean-configs.ps1 -DryRun

# Clean files in-place without merging
.\clean-configs.ps1 -KeepSplit
```

#### Key Cleaner Parameters
- **`-gcp` / `-gpc` (or `-PurgeGcp`)**: Checks candidate nodes against known Google Cloud Platform CIDR ranges (`34.64.0.0/10`, `35.184.0.0/13`, `104.154.*`, `130.211.*`, etc.), reverse DNS `*.bc.googleusercontent.com`, and `gcp` tags. Purges all GCP datacenter nodes to safeguard Antigravity IDE and Google AI Studio from datacenter ASN blocks (`AS396982` / `AS15169`).
- **`-DryRun`**: Previews alive, dead, and purged nodes without touching configuration files on disk.
- **`-KeepSplit`**: Cleans and validates nodes inside individual config files without merging them into master `config.json`.
- **`-TargetFile <name>`**: Targets a specific JSON file (e.g. `config02.json`).

### 6. Emergency Network Reset
If a terminal is closed abruptly or a network glitch leaves lingering routing rules:

```powershell
# Restores adapter settings, DNS, routes, and terminates orphaned processes
.\reset-network.ps1
```

---

## Technical Architecture

| Component | Technical Implementation |
| :--- | :--- |
| **Dual-Engine Core** | `sing-box` handles TUN encapsulation and policy routing; `xray` runs an automated local bridge on `127.0.0.1` for post-quantum REALITY ciphers (`X25519MLKEM768`). |
| **TUN Addressing** | `198.18.0.1/30` with MTU 1400. Avoids conflicts with corporate subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). |
| **Streaming Protection** | Dedicated `🎥 YouTube & Streaming Pool` with 150ms tolerance and 5-minute interval prevents video chunk 403 errors and session invalidation. |
| **Corporate Coexistence** | Dynamically discovers FortiClient/AnyConnect gateways and routes corporate domains (`.corp`, `.internal`, intranet hostnames) directly through customer VPN adapters. |
| **DNS Leak Prevention** | Public internet DNS queries resolve through encrypted DoH (`https://1.1.1.1/dns-query`) over port 443 inside the tunnel. |
| **Protocol Suppression** | Rejects QUIC (UDP 443) and DoT (UDP 853) to force browsers and WebView2 apps onto reliable TCP TLS. |
| **IPv4-Only Strategy** | Enforces `ipv4_only` DNS strategy to eliminate DNS64 (`64:ff9b::`) latency penalties and connection timeouts. |
