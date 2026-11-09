# Multip VPN & Load Balancer

A high-performance transparent TUN VPN and load-balancing toolkit powered by `sing-box`. It features automatic key conversion, live proxy health checks, Antigravity/Google AI policy filtering (auto-dropping Hong Kong, China, etc.), and multi-node lowest-ping clustering.

---

## Available Commands & Purpose

| Command / Script | Type | Purpose |
| :--- | :---: | :--- |
| **`Connect-Cluster.bat`** | Batch / Desktop | Starts the **Load-Balanced Cluster** (lowest-ping auto-failover across all available working nodes). |
| **`connect-cluster.ps1`** | PowerShell | Core engine for the load-balanced cluster. Discovers all nodes, filters blocked countries, and builds the TUN tunnel. |
| **`Connect-Rotator.bat`** | Batch / Desktop | Starts the **Per-Connection Round-Robin Rotator** (every single connection exits via a different country/IP). |
| **`connect-rotator.ps1`** | PowerShell | Core kernel source-port modulo randomizer engine with TUN & rotating SOCKS5/HTTP proxy (`127.0.0.1:10808`). |
| **`Test-Rotation.bat`** | Batch / Desktop | Verifies live IP rotation by issuing 6 rapid requests and displaying the changing public IPs/countries. |
| **`test-rotation.ps1`** | PowerShell | IP rotation diagnostic and verification script. |
| **`Connect-VPN.bat`** | Batch / Desktop | Starts a **Single VPN connection** using `config.json`. Supports dragging & dropping any `.json` config onto it. |
| **`connect-vpn.ps1`** | PowerShell | Connects to a specific single configuration file in transparent TUN mode. |
| **`Clean-Configs.bat`** | Batch / Desktop | 1-Click health check: tests all nodes (16 threads, 9s delay), filters blocked countries, merges all working nodes into `config.json`. |
| **`clean-configs.ps1`** | PowerShell | Core health cleaner & consolidator engine with 16 parallel workers and configurable `-TimeoutMs 9000`. |
| **`Convert-Keys.bat`** | Batch / Desktop | Interactive converter: converts `key.txt` (URLs, base64, share links) into sing-box JSON with 16 parallel threads. |
| **`convert-keys.ps1`** | PowerShell | Core key converter engine supporting subscriptions, Shadowsocks, VLESS, VMess, Trojan, Hysteria 2, and TUIC. |
| **`Reset-Network.bat`** | Batch / Desktop | **Emergency 1-Click Network Clean & Restoration**: Restores Windows TCP/IP stack to clean post-reboot state (kills rogue sing-box, purges static /32 routes, clears firewall rules, disables proxy, flushes DNS & ARP). |
| **`reset-network.ps1`** | PowerShell | Core deep network cleanup engine with health & gateway verification. |
| **`Export-Normal-JSON.bat`** | Batch / Desktop | Extracts pure proxy outbounds from complex configs into clean import format `{ "outbounds": [...] }`. |
| **`export-normal-json.ps1`** | PowerShell | Core extraction engine: strips TUN, DNS, and routing bloat into a clean, normal JSON file. |
| **`install-singbox.ps1`** | PowerShell | Downloads and verifies the official `sing-box.exe` Windows amd64 core binary. |

---

## Command Reference

### 1. Load-Balanced Cluster (Recommended for Speed & Redundancy)

#### `Connect-Cluster.bat`
* **Purpose**: Automatically scans all nodes, runs ping tests, filters out Antigravity-unsupported regions (Hong Kong, etc.), and routes traffic through the fastest live nodes using `urltest`.
* **Usage**: Double-click from Desktop or repository folder (automatically requests Administrator elevation).

#### `connect-cluster.ps1`
* **Purpose**: PowerShell execution of the cluster engine.
* **Usage**:
  ```powershell
  # Start cluster with automatic node discovery
  .\connect-cluster.ps1
  ```

---

### 2. Per-Connection Round-Robin Rotator (Full Randomizer)

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

### 3. Single VPN Connection

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
  .\connect-vpn.ps1 config04.json
  ```

---

### 3. Config Health Cleaner & Auto-Consolidator

#### `Clean-Configs.bat`
* **Purpose**:
  1. Backs up all `config*.json` files to `backups\backup_<timestamp>\`.
  2. Tests every node with a real proxy handshake and HTTP 204 fetch.
  3. Purges dead/expired keys and Antigravity-blocked countries (`HK`, `CN`, `RU`, `IR`, etc.).
  4. Deduplicates identical nodes.
  5. Merges **ALL surviving nodes into ONE master `config.json`** and cleans up secondary config files.
* **Usage**: Double-click from Desktop or repository folder.

#### `clean-configs.ps1`
* **Purpose**: Advanced PowerShell options for cleaning.
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

### 4. Key to JSON Converter

#### `Convert-Keys.bat`
* **Purpose**: Reads raw VPN share links from `key.txt` and converts them into sing-box config JSON.
* **Supported Protocols**: `ss://`, `vless://`, `vmess://`, `trojan://`, `hysteria2://` / `hy2://`, `tuic://`, and Base64 subscription blobs.
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
  * `-NoTest`: Skips live latency probing after conversion.
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

### 5. Config to Normal JSON Converter

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

### 6. Emergency Network Clean & Factory Restoration (Reboot-Free)

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

### 7. Setup & Binary Installation

#### `install-singbox.ps1`
* **Purpose**: Downloads and unpacks the official `sing-box.exe` Windows amd64 core binary from GitHub Releases into the project folder.
* **Usage**:
  ```powershell
  .\install-singbox.ps1
  ```
