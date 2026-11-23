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
| **`check-scraped.ps1`** | **Scraped Node Live Checker**: Standalone 16-thread connectivity & ping tester for scraped JSON files (`vpn_file_01.json`). Diagnostic check without touching `config.json` or deleting files. Supports `-OutFile`, `-Prune`, and `-SortByLatency`. |
| **`convert-keys.ps1`** | **Key to JSON Converter**: Converts raw links (SS, VLESS Reality/WS, VMess, Trojan, Hy2, TUIC) or Base64 bundles from `key.txt` into validated sing-box JSON. |
| **`scrape-telegram.py`** | **Telegram Scraper & Extractor**: Connects to `@decrypt_file_vpn` with session check & time-range filter (`-d 3`), downloads decrypted files, extracts SSH/VLESS/DarkTunnel, and exports `vpn_file_01.json`. |
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

### 4. Telegram Scraper & Extractor (`scrape-telegram.py`)
Connects to Telegram (`@decrypt_file_vpn` or custom groups), downloads files within a specified time range, and directly extracts all proxy outbounds into standard sing-box `vpn_file_01.json`:

```powershell
# 1. Check if Telegram session is authorized
python scrape-telegram.py --check-login

# 2. Login interactively (run once to create telegram_session)
python scrape-telegram.py --login

# 3. Scrape Telegram group for the last 3 days and export vpn_file_01.json
python scrape-telegram.py -d 3

# 4. Scrape the last 24 hours to a custom file
python scrape-telegram.py -d 1 -o vpn_file_01.json

# 5. Extract local files in 'vpn file/' without scraping Telegram
python scrape-telegram.py --extract-only
```

#### Supported Scraper Flags
- **`-d <float>` / `--days <float>`**: Time range in days to scrape (default: `3`). The script scans newest messages first and stops once it reaches the cutoff date.
- **`-o <path>` / `--output <path>`**: Destination sing-box JSON file (default: `vpn_file_01.json`).
- **`--check-login`**: Verifies whether the stored Telegram session is valid without starting a scrape.
- **`--login`**: Starts interactive login prompting for phone number and Telegram verification code.
- **`--extract-only`**: Parses existing files in `vpn file/` without connecting to Telegram.
- **`--target <handle>`**: Telegram group or channel handle (default: `decrypt_file_vpn`).

### 5. Live Checking Scraped VPN Files (`check-scraped.ps1`)
Dedicated multi-threaded connectivity and latency tester specifically built for scraped files (like `vpn_file_01.json`). Unlike `clean-configs.ps1`, it **does not** touch `config.json`, does not delete secondary configs, and operates purely as a safe diagnostic tool unless instructed to export or prune:

```powershell
# 1. Quick diagnostic check of vpn_file_01.json (read-only, no file changes)
.\check-scraped.ps1

# 2. Check and save only verified ALIVE nodes into a separate JSON file
.\check-scraped.ps1 -OutFile vpn_file_01_live.json

# 3. Sort surviving nodes from lowest ping to highest ping
.\check-scraped.ps1 -OutFile vpn_file_01_live.json -SortByLatency

# 4. Prune dead nodes in-place (creates safety backup .bak first)
.\check-scraped.ps1 -Prune

# 5. Check a custom scraped file with custom timeout and thread count
.\check-scraped.ps1 custom_vpn.json -Threads 20 -TimeoutMs 5000

# 6. Check and immediately launch cluster connection with surviving nodes
.\check-scraped.ps1 -OutFile config_scraped.json -Connect
```

#### Supported Live-Check Parameters
- **`[string]$File`** (Position 0): Path to the scraped JSON file (default: `vpn_file_01.json`).
- **`-OutFile <path>`**: Exports only surviving, verified ALIVE nodes to a new sing-box JSON file.
- **`-Prune`**: Overwrites the input file in place with only the verified alive nodes (automatically makes a `.bak` backup first).
- **`-SortByLatency`**: Orders surviving nodes from fastest to slowest ping before saving.
- **`-Threads <int>`**: Parallel probe concurrency (default: `16`).
- **`-TimeoutMs <int>`**: Probe timeout per node in milliseconds (default: `6000`).
- **`-TestUrl <string>`**: Endpoint to fetch through each node (default: `https://www.gstatic.com/generate_204`).
- **`-NoGeo`**: Skips GeoIP lookups to maximize test speed.
- **`-Connect`**: Automatically launches `connect-cluster.ps1` with the alive nodes upon test completion.

### 6. Cleaning & Auditing Configs
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

### 7. Emergency Network Reset
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
