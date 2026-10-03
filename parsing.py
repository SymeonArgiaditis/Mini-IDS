from scapy.layers.l2 import ARP, Ether

def parse_arp(pkt):
    ip = pkt[ARP].psrc
    arp_mac = pkt[ARP].hwsrc
    ether_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
    timestamp = float(pkt.time)

    return ip, arp_mac, ether_mac, timestamp
