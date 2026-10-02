from collections import defaultdict
from scapy.layers.l2 import Ether, ARP

from detector import check_arp

def make_arp(ip, arp_mac, ether_mac=None, ts=1700000000.0):
    ether_mac = ether_mac or arp_mac
    pkt = Ether(src=ether_mac) / ARP(op=2, psrc=ip, hwsrc=arp_mac)
    pkt.time = ts

    return pkt

def test_new_mac_for_known_ip_raises_one_alert():
    table = defaultdict(set)
    findings = {}

    check_arp(make_arp("192.168.1.50", "aa:aa:aa:aa:aa:01"), table, findings)
    check_arp(make_arp("192.168.1.50", "aa:aa:aa:aa:aa:02"), table, findings)

    assert len(findings) == 1

    finding = findings[("arp_spoofing", "192.168.1.50")]
    assert finding["count"] == 1
    assert finding["evidence"] == {"aa:aa:aa:aa:aa:02"}

def test_same_mac_sent_twice_for_one_ip():
    table = defaultdict(set)
    findings = {}

    check_arp(make_arp("192.168.1.50", "aa:aa:aa:aa:aa:01"), table, findings)
    check_arp(make_arp("192.168.1.50", "aa:aa:aa:aa:aa:01"), table, findings)

    assert len(findings) == 0
    assert len(table[("192.168.1.50")]) == 1
