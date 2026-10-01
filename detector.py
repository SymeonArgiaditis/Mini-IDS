from scapy.all import PcapReader
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR

from collections import defaultdict
from datetime import datetime, timezone

def check_arp(pkt, table, alerts):
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

    known_macs = table[ip]

    if known_macs and mac not in known_macs:
        print(
            f"[ALERT] Possible ARP spoofing for {ip}!\n"
            f"\tOld MAC: {known_macs} | New MAC: {mac} | t={time_str}\n"
        )
        # We use set() to store a copy of known_macs, so it doesn't mutate later
        alerts.append((ip, set(known_macs), mac))

    known_macs.add(mac)

with PcapReader("sample.pcap") as pcap:
    table = defaultdict(set)
    alerts = []

    for pkt in pcap:
        if pkt.haslayer(ARP):
            check_arp(pkt, table, alerts)

    print(f"ARP Table State: {dict(table)}")

print("\n--- ARP Spoofing Summary ---")
for ip, previous_macs, new_mac in alerts:
    print(f"IP: {ip}")
    print(f"  Previous MAC(s): {', '.join(previous_macs)}")
    print(f"  Conflicting MAC: {new_mac}")
    print("-" * 30)
