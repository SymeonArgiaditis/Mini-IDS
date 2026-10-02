from scapy.all import PcapReader
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR

from collections import defaultdict
from datetime import datetime, timezone

def record(findings, level, kind, ip, ts, **details):
    key = (kind, ip)

    if key in findings:
        findings[key]["count"] += 1
        findings[key]["last_seen"] = ts
    else:
        findings[key] = {
            "level": level, "kind": kind, "ip":ip,
            "first_seen": ts, "last_seen": ts, "count": 1,
            **details  
        }

def check_arp(pkt, table, findings):
    ip = pkt[ARP].psrc
    mac = pkt[ARP].hwsrc


    ether_mac = pkt[Ether].src if pkt.haslayer(Ether) else None

    timestamp = float(pkt.time)
    utc_timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    time_str = utc_timestamp.strftime("%H:%M:%S")

    if ip == "0.0.0.0":
        return

    if ether_mac and ether_mac != mac:
        print(
            f"[WARN] ARP header mismatch for {ip}\n"
            f"\tEthernet src: {ether_mac} | ARP hwsrc: {mac} | t={time_str}\n"
        )
        record(
            findings, "WARN", "header_mismatch", ip, timestamp,
            ether_mac = ether_mac, arp_mac = mac  
        )

    known_macs = table[ip]

    if known_macs and mac not in known_macs:
        print(
            f"[ALERT] Possible ARP spoofing for {ip}!\n"
            f"\tOld MAC: {known_macs} | New MAC: {mac} | t={time_str}\n"
        )
        record(
            findings, "ALERT", "arp_spoofing", ip, timestamp,
            ether_mac = ether_mac, arp_mac = mac
        )

    known_macs.add(mac)

with PcapReader("sample.pcap") as pcap:
    table = defaultdict(set)
    findings = {}

    for pkt in pcap:
        if pkt.haslayer(ARP):
            check_arp(pkt, table, findings)

    print(f"ARP Table State: {dict(table)}")

print("\n--- Summary ---")
for item in findings.values():
    print(f"IP: {item["ip"]}")
    print(f"Kind: {item["kind"]}")
    print(f"First seen: {item["first_seen"]} | Last seen: {item["last_seen"]}")
    print(f"Appearances: {item["count"]}")
    print("-" * 30)
