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

            if (ip in table) and (table[ip] != mac):
                print(f"[ALERT] Possible ARP spoofing for {ip}!\n"
                      f"Old MAC: {table[ip]}. New MAC: {mac}\n"
                )
            else:
                table[ip].add(mac)

    print(table)
