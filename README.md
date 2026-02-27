<!-- 
SEO Keywords: NullSec PortScan, Elixir port scanner, async port scanner, network reconnaissance,
TCP scanner, service detection, concurrent scanning, fast port scanner, pentesting tools,
bad-antics, NullSec Framework, security scanner, Elixir security tools
-->

<div align="center">

# 🔍 NullSec PortScan

### Lightning-Fast Async Port Scanner

[![Discord](https://img.shields.io/badge/🔑_GET_KEYS-x.com/AnonAntics-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://x.com/AnonAntics)
[![GitHub](https://img.shields.io/badge/GitHub-bad--antics-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/bad-antics)
[![License](https://img.shields.io/badge/License-NPS--XXX-red?style=for-the-badge)](LICENSE)

[![Elixir](https://img.shields.io/badge/Elixir-4B275F?style=for-the-badge&logo=elixir&logoColor=white)]()

```
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░ P O R T S C A N ░░░░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics
```

### 🔓 **[Join x.com/AnonAntics](https://x.com/AnonAntics)** for premium features!

</div>

---

## 🎯 Features

- ⚡ **Massively Concurrent** - Elixir/BEAM VM handles 100k+ simultaneous connections
- 🎯 **Smart Scanning** - SYN, TCP Connect, and service fingerprinting
- 📊 **Service Detection** - Banner grabbing and version identification
- 🌐 **CIDR Support** - Scan entire subnets efficiently
- 📋 **Multiple Output** - JSON, CSV, XML, and Nmap-compatible formats
- 🔥 **Rate Limiting** - Configurable packets-per-second

---

## 🚀 Installation

```bash
# Requires Elixir 1.14+
mix deps.get
mix compile
mix escript.build
./portscan --help
```

---

## 💀 Usage

```bash
# Basic scan
./portscan -t 192.168.1.1 -p 1-1000

# Full port scan with service detection
./portscan -t 192.168.1.0/24 -p 1-65535 -sV

# Fast scan (top 100 ports)
./portscan -t target.com --fast

# Output to JSON
./portscan -t 10.0.0.1 -p 22,80,443,8080 -o results.json
```

---

## ⚠️ Legal

For authorized security testing only.

---

<div align="center">

**[Discord](https://x.com/AnonAntics)** • **[GitHub](https://github.com/bad-antics)**

*Made with 💀 by bad-antics*

</div>
