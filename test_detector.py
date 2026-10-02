from collections import defaultdict
from scapy.layers.l2 import Ether, ARP

from detector import check_arp

def make_arp(ip, arp_mac, ether_mac=None, ts=1700000000.0):
    ether_mac = ether_mac or arp_mac
    pkt = Ether(src=ether_mac) / ARP(op=2, psrc=ip, hwsrc=arp_mac)
    pkt.time = ts

    return pkt
