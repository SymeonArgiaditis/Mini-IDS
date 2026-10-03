from scapy.all import PcapReader
from scapy.layers.l2 import ARP, Ether

from parsing import parse_arp
from arp import is_suspect, detect_arp, learn
from findings import record
from report import print_detection, print_summary, print_table


def process(pkt, table, findings):
    obs = parse_arp(pkt)
    ip, arp_mac, ether_mac, _ = obs

    if ip == "0.0.0.0":
        return []

    new = []
    for d in detect_arp(obs, table):
        if record(findings, d):
            new.append(d)

    # Only learn from trusted packets
    if not is_suspect(ether_mac, arp_mac):
        # Create key. Write to table
        learn(table, ip, arp_mac)

    return new


def main():
    table, findings = {}, {}

    with PcapReader("sample.pcap") as pcap:
        for pkt in pcap:
            if pkt.haslayer(ARP):
                for d in process(pkt, table, findings):
                    print_detection(d)
                
    print_table(table)
    print_summary(findings)


if __name__ == "__main__":    
    main()
