# Multip VPN & Load Balancer

A high-performance transparent TUN VPN and load-balancing toolkit powered by `sing-box`. It features automatic key conversion, live proxy health checks, Antigravity/Google AI policy filtering (auto-dropping Hong Kong, China, etc.), and multi-node lowest-ping clustering.

---

## Available Commands & Purpose

| Command / Script | Type | Purpose |
| :--- | :---: | :--- |
| **`Connect-Cluster.bat`** | Batch / Desktop | Starts the **Load-Balanced Cluster** (lowest-ping auto-failover across all available working nodes). |
| **`connect-cluster.ps1`** | PowerShell | Core engine for the load-balanced cluster. Discovers all nodes, filters blocked countries, and builds the TUN tunnel. |
| **`Connect-VPN.bat`** | Batch / Desktop | Starts a **Single VPN connection** using `config.json`. Supports dragging & dropping any `.json` config onto it. |
| **`connect-vpn.ps1`** | PowerShell | Connects to a specific single configuration file in transparent TUN mode. |
| **`Clean-Configs.bat`** | Batch / Desktop | 1-Click health check: tests all nodes, filters out blocked countries, merges all working nodes into `config.json`, and deletes secondary files. |
| **`clean-configs.ps1`** | PowerShell | Core health cleaner & consolidator engine with customizable parameters (`-DryRun`, `-KeepSplit`, `-TargetFile`). |
| **`Convert-Keys.bat`** | Batch / Desktop | Interactive converter: converts `key.txt` into sing-box JSON with a choice of **Bundle (1 file)** or **Split (1 key per file)**. |
| **`convert-keys.ps1`** | PowerShell | Core key converter engine supporting Shadowsocks, VLESS, VMess, Trojan, Hysteria 2, and TUIC. |
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

### 2. Single VPN Connection

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

### 5. Setup & Binary Installation

#### `install-singbox.ps1`
* **Purpose**: Downloads and unpacks the official `sing-box.exe` Windows amd64 core binary from GitHub Releases into the project folder.
* **Usage**:
  ```powershell
  .\install-singbox.ps1
  ```
