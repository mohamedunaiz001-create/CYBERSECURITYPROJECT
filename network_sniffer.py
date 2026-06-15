#!/usr/bin/env python3
"""
========================================================
  Basic Network Sniffer
  Author  : Mohamed (CodeAlpha Cybersecurity Intern)
  Tool    : Scapy-based packet capture & analysis
  License : For educational purposes only
========================================================
"""

import sys
import signal
import argparse
import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, Ether
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    print("[ERROR] Scapy not found. Install with: pip install scapy")
    sys.exit(1)

# ─── ANSI Color Codes ────────────────────────────────────────────────────────
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

# ─── Global Stats ─────────────────────────────────────────────────────────────
stats = defaultdict(int)
packet_count = 0

def banner():
    print(f"""
{Color.CYAN}{Color.BOLD}
  ╔═══════════════════════════════════════════════════╗
  ║        CodeAlpha — Basic Network Sniffer          ║
  ║        Cybersecurity Internship                   ║
  ╚═══════════════════════════════════════════════════╝
{Color.RESET}""")

def get_protocol_color(proto):
    colors = {
        "TCP":   Color.GREEN,
        "UDP":   Color.BLUE,
        "ICMP":  Color.YELLOW,
        "ARP":   Color.MAGENTA,
        "DNS":   Color.CYAN,
        "HTTP":  Color.RED,
        "IPv6":  Color.WHITE,
        "OTHER": Color.GRAY,
    }
    return colors.get(proto, Color.GRAY)

def format_payload(payload_bytes, max_len=64):
    """Format raw payload as both hex and printable ASCII."""
    if not payload_bytes:
        return ""
    payload_bytes = payload_bytes[:max_len]
    hex_str   = " ".join(f"{b:02X}" for b in payload_bytes)
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in payload_bytes)
    return f"HEX : {hex_str}\n              ASCII: {ascii_str}"

def detect_protocol(packet):
    """Detect the highest-level meaningful protocol."""
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        return "HTTP"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IPv6):
        return "IPv6"
    return "OTHER"

def parse_dns(packet):
    """Extract DNS query/response details."""
    dns = packet[DNS]
    info = []
    if dns.qr == 0:  # Query
        if dns.qd:
            info.append(f"Query: {dns.qd.qname.decode(errors='replace').rstrip('.')}")
    else:             # Response
        if dns.qd:
            info.append(f"Response for: {dns.qd.qname.decode(errors='replace').rstrip('.')}")
        if dns.an:
            try:
                info.append(f"Answer: {dns.an.rdata}")
            except Exception:
                pass
    return " | ".join(info)

def parse_http(packet):
    """Extract HTTP method, host, and path."""
    info = []
    if packet.haslayer(HTTPRequest):
        req = packet[HTTPRequest]
        method = req.Method.decode(errors='replace') if req.Method else "?"
        host   = req.Host.decode(errors='replace')   if req.Host   else "?"
        path   = req.Path.decode(errors='replace')   if req.Path   else "/"
        info.append(f"{method} http://{host}{path}")
    elif packet.haslayer(HTTPResponse):
        resp = packet[HTTPResponse]
        code = resp.Status_Code.decode(errors='replace') if resp.Status_Code else "?"
        info.append(f"Response {code}")
    return " ".join(info)

def process_packet(packet):
    """Main packet handler — parse and display each captured packet."""
    global packet_count, stats

    packet_count += 1
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto     = detect_protocol(packet)
    stats[proto] += 1

    color = get_protocol_color(proto)

    # ── Layer 2: Ethernet ──────────────────────────────────────────────────
    src_mac = dst_mac = "N/A"
    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst

    # ── Layer 3: IP ────────────────────────────────────────────────────────
    src_ip = dst_ip = "N/A"
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ttl    = packet[IP].ttl
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        ttl    = packet[IPv6].hlim
    elif packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst

    # ── Layer 4: Ports ─────────────────────────────────────────────────────
    sport = dport = "-"
    flags = ""
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        raw_flags = packet[TCP].flags
        flag_map = {
            "F": "FIN", "S": "SYN", "R": "RST",
            "P": "PSH", "A": "ACK", "U": "URG"
        }
        flags = " [" + "|".join(v for k, v in flag_map.items() if k in str(raw_flags)) + "]"
    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    # ── Payload ────────────────────────────────────────────────────────────
    payload_info = ""
    if packet.haslayer(Raw):
        payload_info = format_payload(bytes(packet[Raw]))

    # ── Protocol-specific info ─────────────────────────────────────────────
    extra_info = ""
    if proto == "DNS":
        extra_info = parse_dns(packet)
    elif proto == "HTTP":
        extra_info = parse_http(packet)

    # ── Print ──────────────────────────────────────────────────────────────
    divider = f"{Color.GRAY}{'─'*70}{Color.RESET}"
    print(divider)
    print(
        f"{color}{Color.BOLD}[#{packet_count:04d}] [{timestamp}] {proto}{flags}{Color.RESET}"
    )
    print(f"  {Color.WHITE}SRC{Color.RESET}  ➜  {Color.GREEN}{src_ip}:{sport}{Color.RESET}  "
          f"  {Color.WHITE}DST{Color.RESET}  ➜  {Color.RED}{dst_ip}:{dport}{Color.RESET}")
    if src_mac != "N/A":
        print(f"  {Color.GRAY}MAC SRC: {src_mac}   MAC DST: {dst_mac}{Color.RESET}")
    if extra_info:
        print(f"  {Color.CYAN}INFO {Color.RESET}: {extra_info}")
    if payload_info:
        print(f"  {Color.YELLOW}PAYLOAD{Color.RESET}: {payload_info}")
    print(f"  {Color.GRAY}Packet size: {len(packet)} bytes{Color.RESET}")

def print_summary(signum=None, frame=None):
    """Print session statistics on exit."""
    print(f"\n\n{Color.CYAN}{Color.BOLD}{'═'*50}")
    print(f"  Session Summary  |  Total Packets: {packet_count}")
    print(f"{'═'*50}{Color.RESET}")
    for proto, count in sorted(stats.items(), key=lambda x: -x[1]):
        bar = "█" * min(count, 40)
        print(f"  {get_protocol_color(proto)}{proto:<8}{Color.RESET}  {bar}  {count}")
    print(f"{Color.CYAN}{'═'*50}{Color.RESET}\n")
    sys.exit(0)

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1 — Network Sniffer",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  sudo python3 task1_network_sniffer.py
  sudo python3 task1_network_sniffer.py -i eth0 -c 50
  sudo python3 task1_network_sniffer.py -i wlan0 -f "tcp port 80"
  sudo python3 task1_network_sniffer.py -f "udp" -c 100
        """
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to sniff on (default: auto)")
    parser.add_argument("-c", "--count",     type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter",    default=None,
                        help='BPF filter string (e.g., "tcp port 80")')
    parser.add_argument("-v", "--verbose",   action="store_true",
                        help="Enable verbose mode")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, print_summary)

    iface_str = args.interface if args.interface else "default interface"
    print(f"{Color.GREEN}[*] Starting capture on {iface_str}{Color.RESET}")
    if args.filter:
        print(f"{Color.YELLOW}[*] BPF Filter : {args.filter}{Color.RESET}")
    print(f"{Color.YELLOW}[*] Count      : {'Unlimited' if args.count == 0 else args.count}{Color.RESET}")
    print(f"{Color.GRAY}[*] Press Ctrl+C to stop and view summary{Color.RESET}\n")

    sniff(
        iface=args.interface,
        filter=args.filter,
        count=args.count,
        prn=process_packet,
        store=False,
    )

    print_summary()

if __name__ == "__main__":
    main()
