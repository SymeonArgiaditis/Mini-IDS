from scapy.all import PcapReader
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR

from collections import defaultdict
from datetime import datetime, timezone

def format_time(timestamp):
    utc_timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)

    return utc_timestamp.strftime("%Y-%m-%d %H:%M:%S")

def record(findings, level, kind, ip, ts, evidence):
    key = (kind, ip)

    if key in findings:
        findings[key]["count"] += 1
        findings[key]["last_seen"] = ts
        findings[key]["evidence"].add(evidence)
        
        return False
    else:
        findings[key] = {
            "level": level, "kind": kind, "ip":ip,
            "first_seen": ts, "last_seen": ts, "count": 1,
            "evidence": {evidence}
        }
        return True

def check_arp(pkt, table, findings):
    ip = pkt[ARP].psrc
    arp_mac = pkt[ARP].hwsrc
    ether_mac = pkt[Ether].src if pkt.haslayer(Ether) else None

    timestamp = float(pkt.time)
    time_str = format_time(timestamp)

    if ip == "0.0.0.0":
        return

    if ether_mac and ether_mac != arp_mac:
        if record(
            findings, "WARN", "header_mismatch", ip, timestamp, 
            evidence = (ether_mac, arp_mac)
        ):
            print(
                f"[WARN] ARP header mismatch for {ip}\n"
                f"\tEthernet src: {ether_mac} | ARP hwsrc: {arp_mac} | t={time_str}\n"
            )

    known_macs = table[ip]

    if known_macs and arp_mac not in known_macs:
        print(
            f"[ALERT] Possible ARP spoofing for {ip}!\n"
            f"\tOld MAC: {known_macs} | New MAC: {arp_mac} | t={time_str}\n"
        )
        record(
            findings, "ALERT", "arp_spoofing", ip, timestamp,
            evidence = arp_mac
        )

    known_macs.add(arp_mac)

with PcapReader("sample.pcap") as pcap:
    table = defaultdict(set)
    findings = {}

    for pkt in pcap:
        if pkt.haslayer(ARP):
            check_arp(pkt, table, findings)

    print(f"ARP Table State: {dict(table)}")

print("\n--- Summary ---")
for item in findings.values():
    print(f"IP: {item['ip']}")
    print(f"Level: {item['level']}")
    print(f"Kind: {item['kind']}")
    print(f"First seen: {format_time(item['first_seen'])}")
    print(f"Last seen: {format_time(item['last_seen'])}")
    print(f"Appearances: {item['count']}")
    print("Evidence:")
    for e in sorted(item["evidence"]):
        print(f"  {e}")
    print("-" * 30)
