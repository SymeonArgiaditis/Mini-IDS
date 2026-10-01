from scapy.all import PcapReader
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR

from collections import defaultdict

### Build ARP table using Hash Map ###

with PcapReader("sample.pcap") as pcap:
    table = defaultdict(set)
    alerts = []

    for pkt in pcap:
        if pkt.haslayer(ARP):
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc

            if ip == "0.0.0.0":
                continue

            # Dictionary of sets ip: set(mac1, mac2)
            old_mac = table[ip]

            if old_mac and mac not in old_mac:
                print(f"[ALERT] Possible ARP spoofing for {ip}!\n"
                      f"Old MAC: {old_mac}. New MAC: {mac}\n"
                )

                alerts.append((ip, set(old_mac), mac))

            old_mac.add(mac)

    print(f"ARP Table State: {dict(table)}")

print("\n--- ARP Spoofing Summary ---")
for ip, previous_macs, new_mac in alerts:
    print(f"IP: {ip}")
    print(f"  Previous MAC(s): {', '.join(previous_macs)}")
    print(f"  Conflicting MAC: {new_mac}")
    print("-" * 30)
