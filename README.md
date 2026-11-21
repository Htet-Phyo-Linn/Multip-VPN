# Multip VPN & Load Balancer

A high-performance transparent TUN VPN and load-balancing toolkit powered by `sing-box`. It features automatic key conversion, live proxy health checks, Antigravity/Google AI policy filtering (auto-dropping Hong Kong, China, etc.), multi-node lowest-ping clustering, and live remote subscription auto-updating.

---

## Available Commands & Purpose

| Command / Script | Type | Purpose |
| :--- | :---: | :--- |
| **`Connect-Cluster.bat`** | Batch / Desktop | Starts the **Load-Balanced Cluster** (lowest-ping auto-failover across all available working nodes). |
| **`connect-cluster.ps1`** | PowerShell | Core engine for the load-balanced cluster. Discovers all nodes, filters blocked countries, and builds the TUN tunnel. |
| **`Connect-Subscription.bat`** | Batch / Desktop | Starts the **Live Subscription Connector** with auto-update lifecycle and FortiClient corporate shield. |
| **`connect-subscription.ps1`** | PowerShell | Core live subscription engine. Auto-fetches Gist/Base64/Sub-Store URLs from `subscriptions.txt`, hot-reloads on remote key updates, and enables auto-failover. |
| **`subscriptions.txt`** | Configuration | Plain text list of remote subscription URLs (Gist, Hiddify, Sub-Store, Clash, or raw share links) to auto-fetch and monitor. |
| **`Connect-Rotator.bat`** | Batch / Desktop | Starts the **Per-Connection Round-Robin Rotator** (every single connection exits via a different country/IP). |
| **`connect-rotator.ps1`** | PowerShell | Core kernel source-port modulo randomizer engine with TUN & rotating SOCKS5/HTTP proxy (`127.0.0.1:10808`). |
| **`Test-Rotation.bat`** | Batch / Desktop | Verifies live IP rotation by issuing 6 rapid requests and displaying the changing public IPs/countries. |
| **`test-rotation.ps1`** | PowerShell | IP rotation diagnostic and verification script. |
| **`Connect-VPN.bat`** | Batch / Desktop | Starts a **Single VPN connection** using `config.json`. Supports dragging & dropping any `.json` config onto it. |
| **`connect-vpn.ps1`** | PowerShell | Connects to a specific single configuration file in transparent TUN mode. |
| **`Clean-Configs.bat`** | Batch / Desktop | 1-Click health check: tests all nodes (16 threads, 9s delay), filters blocked countries, merges all working nodes into `config.json`. |
| **`clean-configs.ps1`** | PowerShell | Core health cleaner & consolidator engine with 16 parallel workers, 2-stage deduplication, and configurable `-TimeoutMs 9000`. |
| **`Convert-Keys.bat`** | Batch / Desktop | Interactive converter: converts `key.txt` (URLs, base64, share links) into sing-box JSON with 16 parallel threads. |
| **`convert-keys.ps1`** | PowerShell | Core key converter engine supporting subscriptions, Shadowsocks, VLESS (Reality/WS), VMess, Trojan, Hysteria 2, and TUIC. |
| **`Reset-Network.bat`** | Batch / Desktop | **Emergency 1-Click Network Clean & Restoration**: Restores Windows TCP/IP stack to clean post-reboot state (kills rogue sing-box, purges static /32 routes, clears firewall rules, disables proxy, flushes DNS & ARP). |
| **`reset-network.ps1`** | PowerShell | Core deep network cleanup engine with health & gateway verification. |
| **`Export-Normal-JSON.bat`** | Batch / Desktop | Extracts pure proxy outbounds from complex configs into clean import format `{ "outbounds": [...] }`. |
| **`export-normal-json.ps1`** | PowerShell | Core extraction engine: strips TUN, DNS, and routing bloat into a clean, normal JSON file. |
| **`Deploy-Termux.bat`** | Batch / Desktop | Deploys `termux-vpn.sh` and `config.json` to Termux Android device (`u0_a1384@192.168.1.2:8022`). |
| **`termux-vpn.sh`** | Bash / Termux | **Termux Dedicated Gateway**: Locked to user `u0_a1384`, IP `192.168.1.2`, password `rooted`. Starts mixed proxy gateway (`192.168.1.2:10808`). |
| **`install-singbox.ps1`** | PowerShell | Downloads and verifies the official `sing-box.exe` Windows amd64 core binary. |

---

## Command Reference

### 1. Load-Balanced Cluster (Recommended for Speed & Redundancy)

#### `Connect-Cluster.bat`
* **Purpose**: Automatically scans all nodes across all `config*.json` files, runs parallel ping checks, filters out Antigravity-unsupported regions (Hong Kong, China, Russia, Iran, etc.), and routes traffic through the fastest live nodes using `urltest`.
* **Features**:
  * **Dedicated AI & Antigravity Priority Pool**: Curates high-trust, Tier-1 nodes (SG, JP, US, CA, UK, DE, ES, CH, SE) and excludes dirty Anycast/CDN-fronted nodes (`172.64.*`, WeTV debug, etc.).
  * **Anti-Location-Not-Supported Session Lock**: Uses sticky 15-minute intervals and 150ms tolerance tested directly against Google AI Studio (`https://aistudio.google.com`), preventing "impossible travel" country-hopping.
  * **Strict Remote DoH for AI**: Routes all Google, Gemini, and AI domains strictly through encrypted DoH (`dns-remote-doh`), blocking local ISP DNS and EDNS Client Subnet (ECS) leaks.
  * **Windows IPv6 Leak Blocker**: Enforces `ip_version: 6 -> block` so dual-stack Google domains cannot bypass the IPv4 TUN over physical Wi-Fi.
  * **Dynamic Customer VPN Coexistence**: Detects FortiClient, Cisco AnyConnect, and GlobalProtect subnets and gateways dynamically from registry.
  * **Non-Conflicting TUN Subnet**: Operates on `198.18.0.1/30` with MTU 1400 to avoid any overlap with corporate `172.16.0.0/12`.
  * **Browser & Antigravity Protection**: Automatically rejects QUIC (UDP 443) and DoT (UDP 853) to force fast, reliable TCP TLS.
  * **IPv4-Only DNS Strategy**: Eliminates DNS64 `64:ff9b::` timeout loops on cellular/IPv4 broadband connections.
  * **VPN Hot-Reloading**: Monitors adapter changes in real-time, synchronizing routing tables automatically without restarting sing-box.
* **Usage**: Double-click from Desktop or repository folder (automatically requests Administrator elevation).

#### `connect-cluster.ps1`
* **Purpose**: PowerShell execution of the cluster engine.
* **Usage**:
  ```powershell
  # Start cluster with automatic node discovery & transparent TUN
  .\connect-cluster.ps1

  # Run in Proxy-Only mode (mixed port 10808 without creating TUN adapter)
  .\connect-cluster.ps1 -ProxyOnly

  # Run with Windows System Proxy enabled
  .\connect-cluster.ps1 -ProxyOnly -SystemProxy
  ```

---

### 2. Live Subscription Connector (Auto-Update Lifecycle & Corporate Shield)

#### `Connect-Subscription.bat`
* **Purpose**: One-click launcher for the live subscription connector. Connects directly to remote subscription URLs (Gists, Hiddify profiles, Sub-Store links) and automatically tracks daily key rotations.
* **Features**:
  * **Dual-Engine Architecture (Post-Quantum REALITY & Xray Bridge)**: Built-in support for **`xray.exe`** (v26.11.9) alongside **`sing-box.exe`**. When subscription links use modern Xray-core Reality servers requiring post-quantum hybrid key shares (`X25519MLKEM768`), the script transparently bridges them through an internal high-speed loopback bridge. This permanently eliminates the upstream `reality verification failed` error and guarantees 100% compatibility with all modern VPN seller keys!
  * **Instant-On (Fast-Connect) & Background Best-Ping Switcher**: Never waits for dozens of dead servers to time out! Features a 1.2s rapid TCP pre-check and connects immediately as soon as the **first live node is verified** (under 2 seconds). After 60 seconds of uptime, a background benchmark scans the remaining nodes and automatically upgrades the active pool to **Best-Ping URL-Test mode**, seamlessly routing your traffic through the lowest-latency server without disconnecting your session!
  * **Recursive Aggregator Resolution**: Automatically traverses nested subscription links (such as Mahsa collections, Sub-Store hubs, and Hiddify aggregators) that point to child subscription URLs.
  * **Auto-Update Lifecycle (Hiddify / Sub-Store Standard)**: Reads `profile-update-interval` (e.g. every 1 hour) and monitors your remote subscription URLs. When the VPN admin updates keys, IPs, or UUIDs on the remote server, sing-box hot-reloads the new credentials in memory with zero downtime and zero manual conversion!
  * **Corporate Shield (FortiClient & AnyConnect 100% Safe)**: Dedicated `dns-custvpn` adapter routing, corporate internal DNS rules, and process bypass ensures your corporate VPN, internal portals, and RDP sessions never drop, even if a public subscription key expires or drops.
  * **Auto-Failover Pool (Resilience Guarantee)**: Tests subscription nodes with a live handshake probe. If a remote key drops or is blocked, it automatically merges verified fallback nodes from `config*.json` into the `urltest` pool so your laptop, browser, and Antigravity never lose internet access!
  * **Transparent System TUN (`198.18.0.1/30`)**: Automatically captures system-wide traffic while keeping corporate subnets untouched.
  * **Browser Safe**: Drops QUIC/DoT to force browsers to clean TCP TLS over the proxy.
* **Usage**: Double-click `Connect-Subscription.bat` (automatically requests Administrator elevation).

#### `connect-subscription.ps1`
* **Purpose**: PowerShell execution of the subscription connector engine.
* **Parameters**:
  * `-SubscriptionFile <path>`: File containing subscription links (default: `subscriptions.txt`).
  * `-Url <link>`: Connects directly to a specific subscription URL without modifying `subscriptions.txt`.
  * `-ProxyOnly`: Runs mixed proxy (`127.0.0.1:10808`) without creating a TUN adapter.
  * `-SystemProxy`: Sets Windows system proxy to `127.0.0.1:10808`.
  * `-DisableFallbackPool`: Disables loading local fallback nodes if subscription nodes are down.
* **Usage**:
  ```powershell
  # Connect using links in subscriptions.txt (TUN Mode)
  .\connect-subscription.ps1

  # Connect directly to a specific Gist/subscription URL
  .\connect-subscription.ps1 -Url "https://gist.github.com/.../raw/ylt_onekey-stable"

  # Run in Proxy-Only mode
  .\connect-subscription.ps1 -ProxyOnly
  ```

#### `subscriptions.txt`
* **Purpose**: Plain text list of remote subscription URLs (one link per line). Lines starting with `#` are treated as comments.
* **Example**:
  ```text
  # Multip VPN - Remote Subscription Links
  https://gist.github.com/yelinntunnn09/1b074d7640dc8799a2213593a3523d44/raw/ylt_onekey-stable
  ```

---

### 3. Per-Connection Round-Robin Rotator (Full Randomizer)

#### `Connect-Rotator.bat`
* **Purpose**: Starts the **Hacker-Style Per-Connection Round-Robin Rotator**. Every single TCP connection exits through a different proxy node across different countries (Japan, Singapore, US, Canada, Germany, Spain, UK, etc.).
* **Features**:
  * **Kernel Source-Port Modulo**: Routes connections based on Windows ephemeral port allocation. Connection 1 goes to Japan, Connection 2 to Singapore, Connection 3 to the US, Connection 4 to Germany, etc.
  * **Transparent System TUN**: Automatically captures all system traffic.
  * **Local Rotating Proxy (`127.0.0.1:10808`)**: Mixed SOCKS5/HTTP proxy for curl, Python scrapers, and browser extensions.
  * **Bypasses Physical Gateway**: Safe to run alongside Customer VPNs (FortiClient, AnyConnect).
* **Usage**: Double-click `Connect-Rotator.bat` or run in terminal.

#### `Test-Rotation.bat` / `test-rotation.ps1`
* **Purpose**: Rapidly issues 6 test requests and prints the resulting IP addresses and countries in the console to visually confirm live per-connection rotation.
* **Usage**:
  ```cmd
  .\Test-Rotation.bat
  ```

---

### 4. Single VPN Connection

#### `Connect-VPN.bat`
* **Purpose**: Connects your computer to a single VPN configuration file (`config.json` by default).
* **Usage**:
  * Double-click to connect to `config.json`.
  * Drag and drop any specific `.json` file onto `Connect-VPN.bat` to connect directly to that file.

#### `connect-vpn.ps1`
* **Purpose**: Connects via PowerShell to a specific config file.
* **Usage**:
  ```powershell
  # Connect to default config.json
  .\connect-vpn.ps1

  # Connect to a specific file
  .\connect-vpn.ps1 -ConfigFile "config02.json"
  ```

---

### 5. Config Health Cleaner & Auto-Consolidator

#### `Clean-Configs.bat`
* **Purpose**: 1-Click health check and pruner. Cleans dead, expired, and Antigravity-incompatible nodes across all `config*.json` files.
* **Features**:
  * **2-Stage Deduplication**: Drops duplicate nodes by exact signature (`Get-NodeSignature`) and by resolved `Protocol://IP:Port`.
  * **16-Thread Parallel Probing**: Uses native `sing-box tools fetch` with a generous 9-second timeout to accommodate high-latency links.
  * **Consolidation**: By default, merges all surviving nodes into `config.json` and purges redundant split files.

#### `clean-configs.ps1`
* **Purpose**: PowerShell execution of the cleaner engine.
* **Parameters**:
  * `-DryRun`: Previews which nodes are alive/dead without modifying or deleting any files.
  * `-KeepSplit`: Cleans files in place without merging into `config.json`.
  * `-TargetFile <name>`: Cleans only the specified config file.
* **Usage**:
  ```powershell
  # Clean and consolidate all working nodes into config.json (Default)
  .\clean-configs.ps1

  # Preview results without changing or deleting files
  .\clean-configs.ps1 -DryRun

  # Clean files in-place without merging
  .\clean-configs.ps1 -KeepSplit

  # Clean only one specific file
  .\clean-configs.ps1 -TargetFile config.json
  ```

---

### 6. Key to JSON Converter

#### `Convert-Keys.bat`
* **Purpose**: Reads raw VPN share links from `key.txt` and converts them into sing-box config JSON.
* **Supported Protocols**: `ss://`, `vless://` (Reality, WS, gRPC), `vmess://`, `trojan://`, `hysteria2://` / `hy2://`, `tuic://`, and Base64 subscription blobs.
* **Usage**:
  * Double-click to convert `key.txt`.
  * Choose between:
    * `[1]` **Bundle Mode**: All keys saved into one file (e.g. `config05.json`).
    * `[2]` **Split Mode**: 1 file per key (`config05.json`, `config06.json`, etc.).
  * Drag and drop any `.txt` file onto `Convert-Keys.bat` to convert that file.

#### `convert-keys.ps1`
* **Purpose**: PowerShell execution of the converter engine.
* **Parameters**:
  * `-InputFile <path>`: Source text file containing links (default: `key.txt`).
  * `-OutputFile <path>`: Destination JSON file (auto-picks next available slot if omitted).
  * `-Split`: Splits each key into its own JSON file.
* **Usage**:
  ```powershell
  # Convert key.txt into a single bundled JSON file
  .\convert-keys.ps1

  # Convert key.txt into separate JSON files (1 key per file)
  .\convert-keys.ps1 -Split

  # Convert custom file to specific target
  .\convert-keys.ps1 -InputFile "my_keys.txt" -OutputFile "config.json"
  ```

---

### 7. Config to Normal JSON Converter

#### `Export-Normal-JSON.bat`
* **Purpose**: Extracts real proxy nodes from any complex sing-box configuration (such as `_singbox_cluster_run.json` or any full TUN config) and exports them into clean, standard `{ "outbounds": [ ... ] }` JSON format just like your imported `config.json`.
* **Usage**:
  * Double-click to extract the currently running cluster nodes into `normal_config.json`.
  * Drag and drop any complex sing-box JSON file onto `Export-Normal-JSON.bat` to convert it.

#### `export-normal-json.ps1`
* **Purpose**: PowerShell execution of the normal JSON extractor.
* **Parameters**:
  * `-InputFile <path>`: Source JSON config (defaults to `_singbox_cluster_run.json` or `config.json`).
  * `-OutputFile <path>`: Destination file (defaults to `normal_config.json`).
  * `-OverwriteMaster`: Directly updates `config.json` (creates a timestamped backup first).
* **Usage**:
  ```powershell
  # Extract active cluster nodes into normal_config.json
  .\export-normal-json.ps1

  # Extract from a specific file
  .\export-normal-json.ps1 -InputFile "_singbox_cluster_run.json" -OutputFile "my_normal_config.json"

  # Extract and update master config.json directly (with safety backup)
  .\export-normal-json.ps1 -OverwriteMaster
  ```

---

### 8. Emergency Network Clean & Factory Restoration (Reboot-Free)

#### `Reset-Network.bat` / `reset-network.ps1`
* **Purpose**: If a VPN session is stopped abruptly (e.g. terminal window closed without graceful Ctrl+C, or power loss), Windows may be left with orphan `/32` static routes, dead proxy settings, or hijacked DNS entries. This tool scrubs the entire Windows TCP/IP networking stack back to a clean, pristine post-reboot state in under 2 seconds **without needing to restart your computer**.
* **What It Does**:
  1. Force-terminates all running/hung `sing-box.exe` processes.
  2. Disables and removes any orphaned `wintun` / `sing-tun` virtual adapters.
  3. Sweeps and purges all lingering `/32` static bypass routes from Windows ActiveStore.
  4. Deletes all `MultipVPN*` firewall allow rules.
  5. Disables Windows Internet Proxy (WinINet) and broadcasts `InternetSetOption` to all browsers.
  6. Flushes the DNS resolver cache and resets static loopback DNS to automatic DHCP.
  7. Wipes stale ARP and NetBIOS cache bindings.
  8. Purges temporary runtime configs (`_singbox_*.json`).
  9. Tests and verifies physical gateway ping and direct internet connectivity.
  10. **Customer VPN Safe**: Preserves Cisco AnyConnect, FortiClient, and corporate subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
* **Usage**: Double-click `Reset-Network.bat` (prompts for UAC Administrator elevation) or run:
  ```powershell
  .\reset-network.ps1
  ```

---

### 9. Setup & Binary Installation

#### `install-singbox.ps1`
* **Purpose**: Downloads and unpacks the official `sing-box.exe` Windows amd64 core binary from GitHub Releases into the project folder.
* **Usage**:
  ```powershell
  .\install-singbox.ps1
  ```

---

## Technical Highlights & Coexistence Architecture

| Subsystem | Design & Implementation |
| :--- | :--- |
| **TUN Addressing** | `198.18.0.1/30` with MTU 1400. Avoids subnet conflicts with corporate VPN subnets (`172.16.0.0/12`) and prevents cellular packet fragmentation. |
| **Customer VPN Isolation** | Dynamically discovers FortiClient/AnyConnect gateway `/32` addresses and corporate subnets from the Windows Registry and routes table. Bypasses VPN processes to physical Wi-Fi. |
| **Corporate DNS Routing** | Dedicated `dns-custvpn` outbound bound to the customer VPN interface (`direct-vpn-0`). Internal corporate domains (`.corp`, `.internal`, `.lan`, single-label hostnames) are strictly routed through corporate DNS. |
| **DoH DNS over Port 443** | All public internet DNS is resolved via `https://1.1.1.1/dns-query` through the proxy tunnel, bypassing ISP DNS poisoning. |
| **QUIC & DoT Suppression** | Immediately rejects UDP 443 (QUIC) and UDP 853 (DoT) inside sing-box kernel, forcing Chromium/WebView2 browsers and Antigravity IDE to negotiate rock-solid TCP TLS. |
| **IPv4-Only Strategy** | Enforces `ipv4_only` DNS strategy to eliminate DNS64 (`64:ff9b::`) latency penalties and connection timeouts. |
