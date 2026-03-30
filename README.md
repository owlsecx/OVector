# 🦉 OVector

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-informational?style=flat-square&logo=linux&logoColor=white&color=0a0c10"/>
  <img src="https://img.shields.io/badge/Category-ONetwork-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Requires-Root-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OVector** is an advanced IPv6 attack and recon framework covering host discovery, DNS enumeration, NDP-based attacks, DoS modules, vulnerability checks, and address manipulation — all from a single terminal interface.

---

> ⚠️ **AUTHORISED USE ONLY** — OVector must only be used on networks you own or have **explicit written permission** to test. Unauthorised use is illegal.

---

## 📌 Overview

OVector provides 12 modules across 4 categories, built on raw IPv6 packet crafting. Each module produces a structured result that can be exported as JSON or CSV at the end of any session.

---

## 🖥️ Modules

### 🔍 Recon

| # | Module | Description |
|---|--------|-------------|
| **1** | **alive6** | Discover alive IPv6 hosts via ICMPv6 Echo requests. Supports single address or prefix scan using Router Solicitation |
| **2** | **dnsdict6** | Enumerate IPv6 DNS records (AAAA) for a domain using a built-in wordlist or a custom file. Multi-threaded with configurable DNS server |
| **3** | **detect-new-ip6** | Monitor a network segment in real-time and alert when a new IPv6 address appears. Optional duration or unlimited with Ctrl+C |
| **4** | **trace6** | IPv6 traceroute using TCP SYN packets with configurable max hops, timeout, and destination port |

### ⚔️ Attack

| # | Module | Description |
|---|--------|-------------|
| **5** | **parasite6** | NDP Neighbour Advertisement spoofing — continuously send forged NA packets to redirect a target's traffic |
| **6** | **fake_router6** | Send rogue Router Advertisements with a custom prefix and lifetime to intercept or disrupt host routing |
| **7** | **redir6** | ICMPv6 redirect attack — force a victim to route traffic through an attacker-controlled address |

### 💣 DoS

| # | Module | Description |
|---|--------|-------------|
| **8** | **flood_router6** | Flood the network with random Router Advertisements at a configurable rate (pps) to exhaust router tables |
| **9** | **smurf6** | IPv6 smurf amplification — send spoofed ICMPv6 echo requests to a multicast/anycast amplifier with the victim as source |
| **10** | **dos-new-ip6** | Monitor a network and automatically attack any new IPv6 host attempting to join via DAD, blocking it from coming online |

### 🔬 Exploit

| # | Module | Description |
|---|--------|-------------|
| **11** | **exploit6** | Run 5 automated IPv6 vulnerability checks against a target: fragmentation handling, rogue RA acceptance, neighbour cache exhaustion, DAD DoS, and extension header bombing |

### 🛠️ Utils

| # | Module | Description |
|---|--------|-------------|
| **12** | **address6** | IPv6 address manipulation — convert MAC to link-local (EUI-64), derive MAC from link-local, generate global IPv6 from MAC + prefix, expand/compress addresses, compute solicited-node multicast |

---

## 🔬 Exploit6 — Vulnerability Checks

| Check | Severity |
|-------|----------|
| ICMPv6 Fragmentation handling | MEDIUM |
| Rogue Router Advertisement acceptance | HIGH |
| Neighbour Cache Exhaustion | MEDIUM |
| Duplicate Address Detection (DAD) DoS | MEDIUM |
| Extension Header bomb (50 chained headers) | CRITICAL |

---

## ⚙️ Requirements

- **Linux** (any modern distro)
- **Root privileges** — required for raw socket operations
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage

```bash
sudo ./OVector
```

---

## 📤 Export

After any module run, press **[E]** from the main menu to export results:

| Format | Contents |
|--------|----------|
| **JSON** | Full structured report with metadata, packets sent/received, duration, all hosts and findings |
| **CSV** | Tabular host list: IPv6, MAC, Router flag, RTT, first/last seen, packet count |
| **Both** | Exports JSON and CSV simultaneously |

Files are saved as `<module>_YYYYMMDD_HHMMSS.json / .csv`.

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad

*Tools are distributed as pre-built executables. Source code is proprietary.*
