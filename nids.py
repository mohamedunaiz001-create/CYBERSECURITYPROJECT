#!/usr/bin/env python3
"""
================================================================
  Internship — Task 4: Network Intrusion Detection System
  Author  : Mohamed (Cybersecurity Intern)
  Engine  : Scapy + Flask live dashboard
  Usage   : sudo python3 task4_nids.py [-i INTERFACE] [-p PORT]
  ⚠  For educational / lab use only  ⚠
================================================================

Architecture:
  ┌─────────────────────────────────────────────────────┐
  │  Scapy Capture Thread  →  PacketAnalyzer            │
  │       ↓                      ↓                      │
  │  RuleEngine.match()    AlertManager.add()           │
  │       ↓                      ↓                      │
  │  ResponseEngine       alert_log.json  ←  Dashboard  │
  └─────────────────────────────────────────────────────┘

Detection Rules:
  RULE-01  Port Scan       (>10 unique dst ports / 5s from same src)
  RULE-02  SYN Flood       (>100 SYN packets / 1s from same src)
  RULE-03  ICMP Sweep      (>5 unique dst IPs via ICMP / 3s)
  RULE-04  DNS Tunneling   (hostname length > 52 chars in DNS query)
  RULE-05  SSH Brute Force (>10 conns to port 22 / 10s from same src)
  RULE-06  HTTP BruteForce (>20 conns to port 80/443 / 5s from same src)
  RULE-07  UDP Flood       (>200 UDP packets / 1s from same src)
  RULE-08  Path Traversal  (../ pattern in TCP payload)
  RULE-09  NULL Scan       (TCP packet with no flags set)
  RULE-10  XMAS Scan       (TCP FIN+PSH+URG flags set simultaneously)
"""

import argparse
import datetime
import ipaddress
import json
import logging
import os
import sys
import threading
import time
from collections import defaultdict, deque
from typing import Dict, List

# ── Dependency check ──────────────────────────────────────────────
for pkg, imp in [("scapy", "scapy.all"), ("flask", "flask")]:
    try:
        __import__(imp)
    except ImportError:
        print(f"[ERROR] {pkg} not installed. Run: pip install {pkg}")
        sys.exit(1)

from flask import Flask, jsonify, render_template_string, request as flask_req
from scapy.all import (IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR,
                        Raw, sniff, conf as scapy_conf)

# ─────────────────────────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("NIDS")

ALERT_LOG_FILE = "nids_alerts.json"

# ─────────────────────────────────────────────────────────────────
# Color helpers (terminal only)
# ─────────────────────────────────────────────────────────────────
C = {
    "RED":    "\033[91m", "YLW": "\033[93m", "GRN": "\033[92m",
    "CYN":    "\033[96m", "MAG": "\033[95m", "WHT": "\033[97m",
    "GRY":    "\033[90m", "BLD": "\033[1m",  "RST": "\033[0m",
}

SEV_COLOR = {
    "CRITICAL": C["RED"], "HIGH": C["YLW"],
    "MEDIUM":   C["MAG"], "LOW":  C["GRN"],
    "INFO":     C["CYN"],
}

def cprint(msg, color="WHT"):
    print(f"{C.get(color,'')}{msg}{C['RST']}")

# ─────────────────────────────────────────────────────────────────
# Alert Manager
# ─────────────────────────────────────────────────────────────────
class AlertManager:
    def __init__(self):
        self._alerts: List[dict] = []
        self._lock = threading.Lock()
        self.stats = defaultdict(int)

    def add(self, rule_id: str, severity: str, src_ip: str,
            dst_ip: str, proto: str, description: str,
            details: str = "", response: str = "logged"):
        alert = {
            "id":          len(self._alerts) + 1,
            "timestamp":   datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "rule_id":     rule_id,
            "severity":    severity,
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "protocol":    proto,
            "description": description,
            "details":     details,
            "response":    response,
        }
        with self._lock:
            self._alerts.append(alert)
            self.stats[rule_id] += 1
            self.stats["total"] += 1

        # Terminal output
        col = SEV_COLOR.get(severity, C["WHT"])
        print(
            f"{col}{C['BLD']}[ALERT #{alert['id']:04d}] [{severity}] {rule_id}{C['RST']}"
            f"  {C['WHT']}{src_ip}{C['RST']} → {C['YLW']}{dst_ip}{C['RST']}"
            f"  {C['GRY']}{description}{C['RST']}"
        )
        self._persist()

    def _persist(self):
        with self._lock:
            try:
                with open(ALERT_LOG_FILE, "w") as f:
                    json.dump(self._alerts, f, indent=2)
            except Exception as e:
                log.warning(f"Failed to persist alerts: {e}")

    def get_all(self):
        with self._lock:
            return list(self._alerts)

    def get_recent(self, n=50):
        with self._lock:
            return list(self._alerts[-n:])

    def get_stats(self):
        with self._lock:
            return dict(self.stats)


# ─────────────────────────────────────────────────────────────────
# Rule Engine
# ─────────────────────────────────────────────────────────────────
class RuleEngine:
    """
    Stateful rule engine. Maintains sliding time windows per source IP
    to detect volumetric and behavioral attacks.
    """
    WINDOW = 10  # max seconds to keep state

    def __init__(self, rules_file: str = "task4_rules.conf"):
        # Sliding window tracking structures
        self._tcp_dst_ports:  Dict[str, deque] = defaultdict(deque)  # src → [(ts, dport)]
        self._syn_times:      Dict[str, deque] = defaultdict(deque)  # src → [ts]
        self._icmp_dst_ips:   Dict[str, deque] = defaultdict(deque)  # src → [(ts, dip)]
        self._ssh_times:      Dict[str, deque] = defaultdict(deque)  # src → [ts]
        self._http_times:     Dict[str, deque] = defaultdict(deque)  # src → [ts]
        self._udp_times:      Dict[str, deque] = defaultdict(deque)  # src → [ts]
        self._alerted:        Dict[str, float] = {}                  # cooldown per src+rule
        self.custom_rules = self._load_rules(rules_file)
        log.info(f"Rule engine initialized — {len(self.custom_rules)} custom rules loaded")

    def _load_rules(self, path: str):
        rules = []
        if not os.path.exists(path):
            log.warning(f"Rules file '{path}' not found — using built-in rules only")
            return rules
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    rules.append(line)
        return rules

    def _cooldown(self, key: str, window: float = 10.0) -> bool:
        """Return True if this alert is in cooldown (suppress duplicates)."""
        now = time.time()
        last = self._alerted.get(key, 0)
        if now - last < window:
            return True
        self._alerted[key] = now
        return False

    def _prune(self, dq: deque, max_age: float):
        now = time.time()
        while dq and (now - dq[0][0]) > max_age:
            dq.popleft()

    def _prune_simple(self, dq: deque, max_age: float):
        now = time.time()
        while dq and (now - dq[0]) > max_age:
            dq.popleft()

    def analyze(self, packet, alerts: AlertManager):
        """Run all rules against a single packet."""
        if not packet.haslayer(IP):
            return
        src = packet[IP].src
        dst = packet[IP].dst
        now = time.time()

        # ── RULE-01: Port Scan ─────────────────────────────────────
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            dq = self._tcp_dst_ports[src]
            dq.append((now, dport))
            self._prune(dq, 5.0)
            unique_ports = len(set(p for _, p in dq))
            if unique_ports >= 10:
                key = f"RULE-01:{src}"
                if not self._cooldown(key, 8.0):
                    alerts.add("RULE-01", "HIGH", src, dst, "TCP",
                               f"Port Scan detected",
                               f"{unique_ports} unique ports probed in 5s",
                               "logged + src flagged")

        # ── RULE-02: SYN Flood ─────────────────────────────────────
        if packet.haslayer(TCP) and packet[TCP].flags & 0x02:  # SYN
            dq = self._syn_times[src]
            dq.append(now)
            self._prune_simple(dq, 1.0)
            if len(dq) > 100:
                key = f"RULE-02:{src}"
                if not self._cooldown(key, 5.0):
                    alerts.add("RULE-02", "CRITICAL", src, dst, "TCP",
                               f"SYN Flood detected",
                               f"{len(dq)} SYN packets in 1s",
                               "logged + rate limit recommended")

        # ── RULE-03: ICMP Ping Sweep ───────────────────────────────
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # echo request
            dq = self._icmp_dst_ips[src]
            dq.append((now, dst))
            self._prune(dq, 3.0)
            unique_ips = len(set(ip for _, ip in dq))
            if unique_ips >= 5:
                key = f"RULE-03:{src}"
                if not self._cooldown(key, 8.0):
                    alerts.add("RULE-03", "MEDIUM", src, dst, "ICMP",
                               f"ICMP Ping Sweep detected",
                               f"{unique_ips} unique hosts pinged in 3s",
                               "logged")

        # ── RULE-04: DNS Tunneling ─────────────────────────────────
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                qname = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
                if len(qname) > 52:
                    key = f"RULE-04:{src}:{qname[:20]}"
                    if not self._cooldown(key, 30.0):
                        alerts.add("RULE-04", "HIGH", src, dst, "DNS",
                                   f"Possible DNS Tunneling",
                                   f"Suspicious query hostname ({len(qname)} chars): {qname[:60]}...",
                                   "logged + DNS query blocked")
            except Exception:
                pass

        # ── RULE-05: SSH Brute Force ───────────────────────────────
        if packet.haslayer(TCP) and packet[TCP].dport == 22:
            if packet[TCP].flags & 0x02:  # SYN
                dq = self._ssh_times[src]
                dq.append(now)
                self._prune_simple(dq, 10.0)
                if len(dq) > 10:
                    key = f"RULE-05:{src}"
                    if not self._cooldown(key, 15.0):
                        alerts.add("RULE-05", "HIGH", src, dst, "TCP",
                                   f"SSH Brute Force attempt",
                                   f"{len(dq)} SSH connection attempts in 10s",
                                   "logged + IP block recommended")

        # ── RULE-06: HTTP Brute Force ──────────────────────────────
        if packet.haslayer(TCP) and packet[TCP].dport in (80, 443, 8080, 8443):
            if packet[TCP].flags & 0x02:
                dq = self._http_times[src]
                dq.append(now)
                self._prune_simple(dq, 5.0)
                if len(dq) > 20:
                    key = f"RULE-06:{src}"
                    if not self._cooldown(key, 10.0):
                        alerts.add("RULE-06", "MEDIUM", src, dst, "TCP",
                                   f"HTTP Brute Force / Flood",
                                   f"{len(dq)} HTTP connections in 5s",
                                   "logged")

        # ── RULE-07: UDP Flood ─────────────────────────────────────
        if packet.haslayer(UDP):
            dq = self._udp_times[src]
            dq.append(now)
            self._prune_simple(dq, 1.0)
            if len(dq) > 200:
                key = f"RULE-07:{src}"
                if not self._cooldown(key, 5.0):
                    alerts.add("RULE-07", "CRITICAL", src, dst, "UDP",
                               f"UDP Flood detected",
                               f"{len(dq)} UDP packets in 1s",
                               "logged + rate limit recommended")

        # ── RULE-08: Path Traversal in HTTP Payload ────────────────
        if packet.haslayer(Raw) and packet.haslayer(TCP):
            try:
                payload = bytes(packet[Raw]).decode(errors="replace")
                if "../" in payload or "..%2F" in payload.upper():
                    key = f"RULE-08:{src}:{dst}"
                    if not self._cooldown(key, 15.0):
                        alerts.add("RULE-08", "HIGH", src, dst, "TCP",
                                   f"Path Traversal attempt in payload",
                                   f"Payload preview: {payload[:80].strip()}",
                                   "logged + request blocked")
            except Exception:
                pass

        # ── RULE-09: NULL Scan (no flags) ──────────────────────────
        if packet.haslayer(TCP) and int(packet[TCP].flags) == 0:
            key = f"RULE-09:{src}"
            if not self._cooldown(key, 10.0):
                alerts.add("RULE-09", "MEDIUM", src, dst, "TCP",
                           f"NULL Scan detected (TCP flags=0)",
                           f"Src port {packet[TCP].sport} → dst port {packet[TCP].dport}",
                           "logged")

        # ── RULE-10: XMAS Scan (FIN+PSH+URG) ──────────────────────
        if packet.haslayer(TCP):
            flags = int(packet[TCP].flags)
            if (flags & 0x29) == 0x29:  # FIN=1, PSH=8, URG=32 → 0b101001 = 0x29
                key = f"RULE-10:{src}"
                if not self._cooldown(key, 10.0):
                    alerts.add("RULE-10", "MEDIUM", src, dst, "TCP",
                               f"XMAS Scan detected (FIN+PSH+URG)",
                               f"Src port {packet[TCP].sport} → dst port {packet[TCP].dport}",
                               "logged")


# ─────────────────────────────────────────────────────────────────
# Response Engine
# ─────────────────────────────────────────────────────────────────
class ResponseEngine:
    """
    Implements response actions for detected intrusions.
    Currently: logging, iptables blocking (optional), email notification hook.
    """
    def __init__(self, enable_block: bool = False):
        self.enable_block = enable_block
        self.blocked_ips: set = set()

    def respond(self, alert: dict):
        severity = alert.get("severity", "")
        src_ip   = alert.get("src_ip", "")

        if severity == "CRITICAL" and self.enable_block:
            self._block_ip(src_ip)

    def _block_ip(self, ip: str):
        if ip in self.blocked_ips:
            return
        try:
            ipaddress.ip_address(ip)  # validate
        except ValueError:
            return
        self.blocked_ips.add(ip)
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
        ret = os.system(cmd)
        if ret == 0:
            log.warning(f"[RESPONSE] Blocked {ip} via iptables")
        else:
            log.warning(f"[RESPONSE] iptables block for {ip} failed (need root?)")


# ─────────────────────────────────────────────────────────────────
# Dashboard HTML
# ─────────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CodeAlpha NIDS — Live Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;800&display=swap');
:root{--bg:#080d13;--s:#0d1520;--card:#111c2e;--b:#1a3050;--acc:#00e5ff;--cr:#ff3b6b;--hi:#ff7043;--md:#ffb300;--lo:#66bb6a;--inf:#42a5f5;--txt:#cde4f5;--mu:#567a9a}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:'Exo 2',sans-serif;min-height:100vh}
header{background:var(--s);border-bottom:1px solid var(--b);padding:14px 28px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.logo{font-family:'Share Tech Mono',monospace;color:var(--acc);font-size:1rem;letter-spacing:.1em}
.status{display:flex;align-items:center;gap:8px;font-family:'Share Tech Mono',monospace;font-size:.8rem;color:var(--mu)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--lo);animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;padding:22px 28px}
.stat-card{background:var(--card);border:1px solid var(--b);border-radius:8px;padding:18px;text-align:center;transition:border-color .25s}
.stat-card:hover{border-color:var(--acc)}
.stat-val{font-size:2.2rem;font-weight:800;line-height:1}
.stat-lbl{font-size:.75rem;color:var(--mu);font-family:'Share Tech Mono',monospace;margin-top:5px}
.charts{display:grid;grid-template-columns:1.4fr 1fr;gap:14px;padding:0 28px 14px}
.chart-box{background:var(--card);border:1px solid var(--b);border-radius:8px;padding:16px}
.chart-title{font-size:.8rem;color:var(--acc);font-family:'Share Tech Mono',monospace;letter-spacing:.1em;margin-bottom:12px}
canvas{max-height:200px}
.table-box{background:var(--card);border:1px solid var(--b);border-radius:8px;margin:0 28px 28px;overflow:hidden}
.table-title{padding:12px 16px;background:var(--s);font-size:.8rem;color:var(--acc);font-family:'Share Tech Mono',monospace;letter-spacing:.1em;display:flex;justify-content:space-between;align-items:center}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{background:var(--s);padding:10px 14px;text-align:left;color:var(--mu);font-weight:600;font-size:.75rem;letter-spacing:.07em;border-bottom:1px solid var(--b)}
td{padding:9px 14px;border-bottom:1px solid var(--b);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(0,229,255,.04)}
.sev{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.72rem;font-weight:700;font-family:'Share Tech Mono',monospace}
.CRITICAL{background:rgba(255,59,107,.18);color:var(--cr)}
.HIGH    {background:rgba(255,112,67,.18);color:var(--hi)}
.MEDIUM  {background:rgba(255,179,0,.15);color:var(--md)}
.LOW     {background:rgba(102,187,106,.13);color:var(--lo)}
.src-ip{font-family:'Share Tech Mono',monospace;color:#80cbc4;font-size:.8rem}
.desc{color:var(--txt)}
.details{color:var(--mu);font-size:.78rem}
.ts{color:var(--mu);font-family:'Share Tech Mono',monospace;font-size:.74rem}
.empty{text-align:center;padding:40px;color:var(--mu);font-family:'Share Tech Mono',monospace}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}.charts{grid-template-columns:1fr}}
</style>
</head><body>
<header>
  <div class="logo">CODEALPHA // NIDS — LIVE ALERT DASHBOARD</div>
  <div class="status"><div class="dot"></div><span id="status-txt">MONITORING</span>&nbsp;|&nbsp;Last update: <span id="last-upd">—</span></div>
</header>

<div class="grid">
  <div class="stat-card"><div class="stat-val" id="s-total" style="color:var(--acc)">0</div><div class="stat-lbl">TOTAL ALERTS</div></div>
  <div class="stat-card"><div class="stat-val" id="s-crit" style="color:var(--cr)">0</div><div class="stat-lbl">CRITICAL</div></div>
  <div class="stat-card"><div class="stat-val" id="s-high" style="color:var(--hi)">0</div><div class="stat-lbl">HIGH</div></div>
  <div class="stat-card"><div class="stat-val" id="s-med" style="color:var(--md)">0</div><div class="stat-lbl">MEDIUM / LOW</div></div>
</div>

<div class="charts">
  <div class="chart-box">
    <div class="chart-title">ALERT TIMELINE (last 30 alerts)</div>
    <canvas id="timelineChart"></canvas>
  </div>
  <div class="chart-box">
    <div class="chart-title">DISTRIBUTION BY RULE</div>
    <canvas id="ruleChart"></canvas>
  </div>
</div>

<div class="table-box">
  <div class="table-title">
    <span>LIVE ALERT FEED</span>
    <span id="alert-count" style="color:var(--mu)">0 alerts</span>
  </div>
  <div id="table-wrap">
    <div class="empty" id="empty-msg">⏳ Waiting for network traffic...</div>
    <table id="alert-table" style="display:none">
      <thead><tr>
        <th>#</th><th>TIMESTAMP</th><th>SEVERITY</th><th>RULE</th>
        <th>SRC → DST</th><th>DESCRIPTION</th><th>DETAILS</th>
      </tr></thead>
      <tbody id="alert-tbody"></tbody>
    </table>
  </div>
</div>

<script>
const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];

let timelineChart, ruleChart;
let lastCount = 0;

function initCharts(){
  const tCtx = document.getElementById('timelineChart').getContext('2d');
  timelineChart = new Chart(tCtx,{
    type:'bar',
    data:{labels:[],datasets:[
      {label:'CRITICAL',data:[],backgroundColor:'rgba(255,59,107,.7)'},
      {label:'HIGH',    data:[],backgroundColor:'rgba(255,112,67,.7)'},
      {label:'MEDIUM',  data:[],backgroundColor:'rgba(255,179,0,.6)'},
      {label:'LOW',     data:[],backgroundColor:'rgba(102,187,106,.6)'},
    ]},
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#567a9a',font:{size:10}}}},
      scales:{
        x:{ticks:{color:'#567a9a',font:{size:9}},grid:{color:'#1a3050'}},
        y:{ticks:{color:'#567a9a',font:{size:9}},grid:{color:'#1a3050'},beginAtZero:true}
      }
    }
  });

  const rCtx = document.getElementById('ruleChart').getContext('2d');
  ruleChart = new Chart(rCtx,{
    type:'doughnut',
    data:{labels:[],datasets:[{data:[],
      backgroundColor:['#ff3b6b','#ff7043','#ffb300','#66bb6a','#42a5f5','#ab47bc','#26c6da','#8d6e63','#78909c','#d4e157']
    }]},
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{position:'right',labels:{color:'#567a9a',font:{size:9},padding:8}}}
    }
  });
}

function updateCharts(alerts){
  // Timeline: group into buckets of 5 (last 30)
  const recent = alerts.slice(-30);
  const labels = recent.map(a => a.timestamp.split(' ')[1]);
  const sevs = ['CRITICAL','HIGH','MEDIUM','LOW'];
  const datasets = sevs.map(s => ({
    label: s,
    data: recent.map(a => a.severity === s ? 1 : 0),
    backgroundColor: s==='CRITICAL'?'rgba(255,59,107,.7)':s==='HIGH'?'rgba(255,112,67,.7)':s==='MEDIUM'?'rgba(255,179,0,.6)':'rgba(102,187,106,.6)'
  }));
  timelineChart.data.labels = labels;
  timelineChart.data.datasets = datasets;
  timelineChart.update('none');

  // Rule distribution
  const ruleCounts = {};
  alerts.forEach(a => { ruleCounts[a.rule_id] = (ruleCounts[a.rule_id]||0)+1; });
  ruleChart.data.labels = Object.keys(ruleCounts);
  ruleChart.data.datasets[0].data = Object.values(ruleCounts);
  ruleChart.update('none');
}

function renderTable(alerts){
  const tbody = document.getElementById('alert-tbody');
  const reversed = [...alerts].reverse().slice(0,100);
  tbody.innerHTML = reversed.map(a => `
    <tr>
      <td style="color:var(--mu);font-family:'Share Tech Mono',monospace">#${a.id}</td>
      <td class="ts">${a.timestamp}</td>
      <td><span class="sev ${a.severity}">${a.severity}</span></td>
      <td style="font-family:'Share Tech Mono',monospace;color:var(--acc);font-size:.78rem">${a.rule_id}</td>
      <td class="src-ip">${a.src_ip} → ${a.dst_ip}</td>
      <td class="desc">${a.description}</td>
      <td class="details">${a.details}</td>
    </tr>`).join('');
  document.getElementById('alert-table').style.display = reversed.length ? 'table' : 'none';
  document.getElementById('empty-msg').style.display  = reversed.length ? 'none' : 'block';
}

async function poll(){
  try {
    const r  = await fetch('/api/alerts');
    const data = await r.json();
    const alerts = data.alerts || [];

    document.getElementById('s-total').textContent = alerts.length;
    document.getElementById('s-crit').textContent  = alerts.filter(a=>a.severity==='CRITICAL').length;
    document.getElementById('s-high').textContent  = alerts.filter(a=>a.severity==='HIGH').length;
    document.getElementById('s-med').textContent   = alerts.filter(a=>['MEDIUM','LOW'].includes(a.severity)).length;
    document.getElementById('alert-count').textContent = `${alerts.length} alert${alerts.length!==1?'s':''}`;
    document.getElementById('last-upd').textContent = new Date().toLocaleTimeString();

    if(alerts.length !== lastCount){
      lastCount = alerts.length;
      renderTable(alerts);
      updateCharts(alerts);
    }
  } catch(e){ document.getElementById('status-txt').textContent = 'RECONNECTING...'; }
}

initCharts();
poll();
setInterval(poll, 2000);  // refresh every 2 seconds
</script>
</body></html>
"""

# ─────────────────────────────────────────────────────────────────
# Flask API
# ─────────────────────────────────────────────────────────────────
flask_app = Flask(__name__)

_alert_manager: AlertManager = None

@flask_app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@flask_app.route("/api/alerts")
def api_alerts():
    limit  = int(flask_req.args.get("limit", 0))
    alerts = _alert_manager.get_all()
    if limit:
        alerts = alerts[-limit:]
    return jsonify({"alerts": alerts, "stats": _alert_manager.get_stats()})

@flask_app.route("/api/stats")
def api_stats():
    return jsonify(_alert_manager.get_stats())

def run_flask(port: int):
    import logging as pylog
    pylog.getLogger("werkzeug").setLevel(pylog.ERROR)
    flask_app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

# ─────────────────────────────────────────────────────────────────
# Packet Capture Thread
# ─────────────────────────────────────────────────────────────────
def start_capture(interface, alert_mgr: AlertManager,
                  response_engine: ResponseEngine):
    rule_engine = RuleEngine("task4_rules.conf")
    packet_count = [0]

    def handle(packet):
        packet_count[0] += 1
        if packet_count[0] % 500 == 0:
            cprint(f"[*] {packet_count[0]} packets analyzed | "
                   f"{alert_mgr.stats.get('total',0)} alerts generated", "GRY")
        rule_engine.analyze(packet, alert_mgr)
        # Trigger response for every new alert (check last alert)
        all_alerts = alert_mgr.get_all()
        if all_alerts:
            response_engine.respond(all_alerts[-1])

    cprint(f"\n[*] Starting packet capture on: {interface or 'all interfaces'}", "CYN")
    cprint("[*] Press Ctrl+C to stop\n", "GRY")

    sniff(
        iface=interface,
        prn=handle,
        store=False,
        filter="ip or arp",
    )

# ─────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────
def banner(dash_port):
    print(f"""
{C['CYN']}{C['BLD']}
  ╔═══════════════════════════════════════════════════════╗
  ║   CodeAlpha — Network Intrusion Detection System      ║
  ║   Task 4 | Cybersecurity Internship                   ║
  ╠═══════════════════════════════════════════════════════╣
  ║  Rules  : 10 built-in  +  task4_rules.conf (custom)  ║
  ║  Dashboard : http://localhost:{dash_port:<5}                  ║
  ║  Alert log : nids_alerts.json                         ║
  ╚═══════════════════════════════════════════════════════╝
{C['RST']}""")

# ─────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────
def main():
    global _alert_manager

    parser = argparse.ArgumentParser(description="CodeAlpha NIDS — Task 4")
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface (default: all)")
    parser.add_argument("-p", "--port",      type=int, default=8080,
                        help="Dashboard port (default: 8080)")
    parser.add_argument("--block",           action="store_true",
                        help="Enable iptables auto-block for CRITICAL alerts (requires root)")
    args = parser.parse_args()

    banner(args.port)

    _alert_manager   = AlertManager()
    response_engine  = ResponseEngine(enable_block=args.block)

    # Start Flask dashboard in background thread
    dash_thread = threading.Thread(
        target=run_flask, args=(args.port,), daemon=True
    )
    dash_thread.start()
    cprint(f"[+] Dashboard running at http://localhost:{args.port}", "GRN")

    # Start packet capture (blocking — runs in main thread)
    try:
        start_capture(args.interface, _alert_manager, response_engine)
    except PermissionError:
        cprint("\n[ERROR] Root privileges required for packet capture.", "RED")
        cprint("        Run: sudo python3 task4_nids.py", "YLW")
        sys.exit(1)
    except KeyboardInterrupt:
        total = _alert_manager.stats.get("total", 0)
        cprint(f"\n\n[+] Session ended | Total alerts: {total}", "CYN")
        cprint(f"[+] Alert log saved to: {ALERT_LOG_FILE}", "GRN")
        sys.exit(0)

if __name__ == "__main__":
    main()
