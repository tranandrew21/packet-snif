#!/usr/bin/env python3
"""
Network Packet Sniffer
------------------------------------------------------------
Captures live network traffic using Scapy, filters packets by
protocol, and logs summary details to CSV or PCAP.
Useful for network analysis, troubleshooting, and basic security monitoring.
"""

import argparse, csv, datetime as dt

# === IMPORT DEPENDENCIES ===
# Scapy is required for packet sniffing and decoding.
try:
    from scapy.all import sniff, Packet, TCP, UDP, DNS, DNSQR, IP, Raw, wrpcap
except Exception as e:
    raise SystemExit("Scapy is required. Install with: pip install scapy") from e


# === ARGUMENT PARSER ===
# Allows customization via command-line arguments (interface, protocol, count, etc.)
def parse_args():
    p = argparse.ArgumentParser(description="Network Packet Sniffer (Scapy)")
    p.add_argument("--iface", default=None, help="Interface (e.g., eth0, wlan0)")
    p.add_argument("--proto", default="all", help="tcp|udp|dns|http|all")
    p.add_argument("--count", type=int, default=0, help="Packets to capture (0=unlimited)")
    p.add_argument("--csv", default=None, help="CSV output path")
    p.add_argument("--pcap", default=None, help="PCAP output path")
    p.add_argument("--summary", action="store_true", help="Print per-packet summary")
    return p.parse_args()


# === PROTOCOL FILTER ===
# Decides whether a packet matches the protocol type specified by the user.
def proto_filter(pkt, proto):
    proto = proto.lower()
    if proto == "all":
        return True
    if proto == "tcp" and pkt.haslayer(TCP):
        return True
    if proto == "udp" and pkt.haslayer(UDP):
        return True
    if proto == "dns" and pkt.haslayer(DNS):
        return True
    if proto == "http" and pkt.haslayer(TCP):
        # Look for TCP port 80 (HTTP)
        if pkt[TCP].dport in (80,) or pkt[TCP].sport in (80,):
            return True
        # Or look for HTTP keywords in the payload
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw]).lower()
            if b"host:" in raw or b"get " in raw or b"post " in raw:
                return True
    return False


# === CONVERT PACKET TO DICTIONARY ROW ===
# Extracts readable info for logging (timestamp, IPs, ports, size, etc.)
def pkt_to_row(pkt):
    ts = dt.datetime.fromtimestamp(float(pkt.time)).isoformat(timespec="seconds")
    ip_src = pkt[IP].src if pkt.haslayer(IP) else ""
    ip_dst = pkt[IP].dst if pkt.haslayer(IP) else ""
    proto = "OTHER"
    sport = ""
    dport = ""
    length = len(pkt)
    notes = ""

    # Handle DNS packets
    if pkt.haslayer(DNS):
        proto = "DNS"
        if pkt[DNS].qd and isinstance(pkt[DNS].qd, DNSQR):
            try:
                notes = f"qname={pkt[DNS].qd.qname.decode(errors='ignore')}"
            except:
                notes = f"qname={pkt[DNS].qd.qname}"
        return {
            "timestamp": ts,
            "proto": proto,
            "src": ip_src,
            "dst": ip_dst,
            "sport": sport,
            "dport": dport,
            "length": length,
            "notes": notes,
        }

    # Handle TCP and UDP packets
    if pkt.haslayer(TCP):
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    return {
        "timestamp": ts,
        "proto": proto,
        "src": ip_src,
        "dst": ip_dst,
        "sport": sport,
        "dport": dport,
        "length": length,
        "notes": notes,
    }


# === MAIN CAPTURE FUNCTION ===
def main():
    args = parse_args()
    captured = []
    csv_file = None
    csv_writer = None

    # === INITIALIZE CSV OUTPUT ===
    if args.csv:
        csv_file = open(args.csv, "w", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(
            csv_file,
            fieldnames=["timestamp", "proto", "src", "dst", "sport", "dport", "length", "notes"],
        )
        csv_writer.writeheader()

    # === PACKET HANDLER ===
    # Called each time Scapy captures a packet.
    def handle(pkt):
        if not proto_filter(pkt, args.proto):
            return

        row = pkt_to_row(pkt)
        captured.append(pkt)

        # Print short summary if requested
        if args.summary:
            print(
                f"[{row['timestamp']}] {row['proto']} "
                f"{row['src']}:{row['sport']} -> {row['dst']}:{row['dport']} "
                f"len={row['length']} {row['notes']}"
            )

        # Write to CSV if enabled
        if csv_writer:
            csv_writer.writerow(row)

    # === START PACKET SNIFFING ===
    try:
        kw = {"prn": handle, "iface": args.iface, "store": False}
        if args.count > 0:
            kw["count"] = args.count
        sniff(**kw)
    except PermissionError:
        print("Permission error: Run this script as Administrator or with sudo privileges.")
    finally:
        # Clean up files and save PCAP if specified
        if csv_file:
            csv_file.close()
        if args.pcap and captured:
            wrpcap(args.pcap, captured)


# === SCRIPT ENTRY POINT ===
if __name__ == "__main__":
    main()
