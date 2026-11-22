# 🦉 OVector

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-OAttack%20/%20Offensive-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OVector** — Advanced IPv6 Security Research Framework

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview


OVector is an attack-surface and initial-access vector mapper that correlates exposed services, versions and misconfigurations into prioritized entry-point candidates. It aggregates reconnaissance data, matches it against a knowledge base of known weaknesses, and ranks potential vectors by exploitability and impact. It is intended for authorized penetration-testing and red-team planning.

---

## ✨ Features


- Correlates exposed services, versions and misconfigurations into candidate attack vectors
- Knowledge-base matching of known weaknesses and common entry points
- Exploitability and impact scoring to prioritize vectors
- Aggregates reconnaissance input from multiple sources
- Structured export of ranked vectors for reporting
- Offline --self-test for safe verification

---

## ⚙️ Requirements

- **Linux**
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage


```bash
./OVector
./OVector --self-test
./OVector --help
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled.s.Haddad

*Tools are distributed as pre-built executables. Source code is proprietary.*
