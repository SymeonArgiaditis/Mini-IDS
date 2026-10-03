from scapy.layers.l2 import Ether, ARP

from detector import process


def make_arp(ip, arp_mac, ether_mac=None, ts=1700000000.0):
    ether_mac = ether_mac or arp_mac
    pkt = Ether(src=ether_mac) / ARP(op=2, psrc=ip, hwsrc=arp_mac)
    pkt.time = ts

    return pkt

IP = "192.168.1.50"
MAC_1, MAC_2, MAC_3 = "aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02", "aa:aa:aa:aa:aa:03"
SPOOF_KEY = ("arp_spoofing", IP)
MISMATCH_KEY = ("header_mismatch", IP)


def run(*packets):
    table = {}
    findings = {}

    for pkt in packets:
        process(pkt, table, findings)

    return table, findings


def test_new_mac_for_known_ip_raises_one_alert():
    _, findings = run(
        make_arp(IP, MAC_1), 
        make_arp(IP, MAC_2)
    )

    assert list(findings) == [SPOOF_KEY]
    assert findings[SPOOF_KEY]["evidence"] == {MAC_2}


def test_same_mac_sent_twice_for_one_ip():
    table, findings = run(
        make_arp(IP, MAC_1), 
        make_arp(IP, MAC_1)
    )

    assert len(findings) == 0
    assert table[IP] == {MAC_1}


def test_third_mac_arriving_after_the_first_alert():
    _, findings = run(
        make_arp(IP, MAC_1),
        make_arp(IP, MAC_2),
        make_arp(IP, MAC_3)
    )

    assert findings[SPOOF_KEY]["count"] == 2
    assert findings[SPOOF_KEY]["evidence"] == {MAC_2, MAC_3}


def test_header_mismatch_packet_for_new_ip():
    table, findings = run(
        make_arp(IP, MAC_1, ether_mac=MAC_3)
    )

    assert list(findings) == [MISMATCH_KEY]
    assert findings[MISMATCH_KEY]["evidence"] == {(MAC_3, MAC_1)}
    assert IP not in table

def test_repeated_suspect_packet_that_also_conflicts():
    suspect = make_arp(IP, MAC_2, ether_mac=MAC_3)

    table, findings = run(
        make_arp(IP, MAC_1), suspect, suspect, suspect
    )

    assert set(findings) == {SPOOF_KEY, MISMATCH_KEY}
    assert findings[MISMATCH_KEY]["count"] == 3
    assert findings[SPOOF_KEY]["count"] == 3
    # Suspect MAC addresses are not saved (learned from)
    assert table[IP] == {MAC_1}
