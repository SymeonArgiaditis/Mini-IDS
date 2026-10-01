from scapy.all import PcapReader
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR

from collections import defaultdict

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
            known_macs = table[ip]

            if known_macs and mac not in known_macs:
                print(f"[ALERT] Possible ARP spoofing for {ip}!\n"
                      f"Old MAC: {known_macs}. New MAC: {mac}\n"
                )

                alerts.append((ip, known_macs, mac))

            known_macs.add(mac)

    print(f"ARP Table State: {dict(table)}")

print("\n--- ARP Spoofing Summary ---")
for ip, previous_macs, new_mac in alerts:
    print(f"IP: {ip}")
    print(f"  Previous MAC(s): {', '.join(previous_macs)}")
    print(f"  Conflicting MAC: {new_mac}")
    print("-" * 30)
