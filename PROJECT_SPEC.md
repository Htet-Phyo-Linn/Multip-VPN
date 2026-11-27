# PROJECT SPEC: Multip VPN Cross-Platform Client (Windows First)

## 1. Executive Summary & Purpose Anchor
Multip VPN Client is an ultra-fast, cross-platform graphical application (Windows-first, extensible to macOS & Linux) designed to manage, orchestrate, and load-balance transparent TUN proxies using a dual-engine core (`sing-box` + `xray`).

### Core Mission
- Transform the existing PowerShell CLI toolchain into a robust, high-performance GUI client.
- Eliminate command-line friction for starting clusters, managing subscriptions, converting keys, scraping Telegram bot configs, and testing proxy health.
- Enforce strict safety-critical software engineering standards (NASA JPL 12 Rules) across process lifecycle, state management, and memory safety.

---

## 2. NASA JPL Safety Constraints & Quality Invariants
All client components must comply with Gerard Holzmann's NASA JPL safety rules:
1. **Control Flow:** Maximum 2 indentation levels per function. Zero recursion.
2. **Bounded Loops:** Hard loop bounds and strict timeout deadlines on all I/O, IPC socket queries, and process polling.
3. **Deterministic Lifecycle:** All sockets, child processes (`sing-box.exe`, `xray.exe`), named pipes, and temporary files MUST be tracked and cleanly terminated in `finally` blocks across all exit paths (graceful shutdown and SIGTERM/SIGINT handlers).
4. **Single Responsibility:** Functions must remain under 60 lines with exactly one clear responsibility.
5. **Fail-Closed Security:** Unhandled errors, DNS resolution failures, or gateway detection errors default to safe state (bypassing sensitive corporate subnets, never blackholing user traffic).
6. **Explicit Error Handling:** Zero empty catch blocks. All IPC, process, and file errors are explicitly typed, logged, and surfaced to the UI.

---

## 3. System Architecture

```
+-------------------------------------------------------------------------+
|                         Frontend GUI Layer                              |
|       (React / TypeScript / Tailwind CSS / Lucide Icons / Vite)        |
+-------------------------------------------------------------------------+
       |                                                    ^
       | IPC / REST / WebSocket                             | Events & State
       v                                                    |
+-------------------------------------------------------------------------+
|                         Backend Core Controller                         |
|   - Sidecar Process Supervisor (sing-box & xray lifecycle)              |
|   - Clash API / Sing-box REST Client (latency tests, group selector)    |
|   - Config & Subscription Parser (Gist, Base64, Sub-Store, Telegram)   |
|   - Network & Routing Engine (TUN mode, Wintun, corporate bypass)       |
|   - System Tray & Power Notification Daemon                             |
+-------------------------------------------------------------------------+
       |                                                    ^
       | Subprocess IPC / Stdin / Stdout                   | Health / Latency
       v                                                    v
+-----------------------------------+   +---------------------------------+
|          sing-box Core            |   |           xray Core             |
|   - Transparent TUN (198.18.0.1)  |   |   - Post-Quantum REALITY Bridge |
|   - Lowest-Ping urltest Pool      |   |   - X25519MLKEM768 Loopback     |
|   - Antigravity / YouTube Policy  |   +---------------------------------+
+-----------------------------------+
```

---

## 4. Subsystems & Technical Requirements

### 4.1. Core Engine Supervisor (Sidecar Manager)
- Spawns `sing-box.exe` and `xray.exe` as managed sidecar sub-processes.
- Automatically handles Windows UAC elevation for TUN mode (`wintun.dll` driver injection).
- Monitors daemon heartbeat; restarts crashed engines with exponential backoff (capped at 3 retries).
- Cleans up orphaned engines on startup (terminating lingering background instances).

### 4.2. Configuration & Ingestion Pipeline
- **Local Configs:** Auto-discovers `config*.json` and `vpn_file*.json`.
- **Subscription Engine:** Fetches remote subscription URLs (`subscriptions.txt`), parses Base64 / Clash / Sing-box formats, supports periodic refresh or single-fetch (`-Pause` mode).
- **Key Converter:** Parses raw share links (`ss://`, `vless://`, `vmess://`, `trojan://`, `hysteria2://`, `tuic://`) into validated sing-box schema.
- **Telegram Decrypt Scraper:** In-memory Telegram scraping engine for `@decrypt_file_vpn` with QR-code login and time-range filtering (`-d 3`).

### 4.3. Health Probe & Latency Matrix
- Concurrent multi-threaded probe (up to 16-32 workers) via `sing-box tools fetch`.
- Visual latency metrics with real-time ping updates (ms), country flags, and protocol indicators.
- One-click dead node pruning with automatic `.bak` safety backups.

### 4.4. Policy & Route Controller
- **Antigravity AI Pool:** Strict exclusion of blocked regions (`HK`, `CN`, `RU`, `IR`, `MM`, etc.) and datacenter ASNs (Atlantic.Net `AS6364`, GCP `AS396982`/`AS15169`).
- **YouTube & Streaming Pool:** Dedicated 150ms tolerance pool with sticky routing to eliminate 403 chunk drops.
- **Corporate VPN Coexistence:** Dynamically detects Cisco AnyConnect, FortiClient, and GlobalProtect adapters, excluding corporate subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) from the tunnel.
- **System Proxy & TUN Mode:** One-click toggle between Transparent TUN mode (system-wide) and Mixed SOCKS5/HTTP Proxy mode (`127.0.0.1:10808`).

---

## 5. Technology Stack Selection & Recommendation
1. **Desktop Shell:** Tauri v2 (Rust Backend + React/TypeScript Frontend)
   - *Alternative:* Electron (Node.js + React) for zero-compilation instant dev.
2. **Frontend UI:** React 19, TypeScript, Tailwind CSS, Lucide React, Shadcn/Radix UI.
3. **Core Binaries:** Bundled `sing-box.exe` (v1.14.4) + `xray.exe`.
