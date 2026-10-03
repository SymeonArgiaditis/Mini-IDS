from scapy.all import PcapReader
from scapy.layers.l2 import ARP, Ether

from parsing import parse_arp
from arp import is_suspect, detect_arp, learn
from findings import record
from report import format_time


def print_detection(d):
    t = format_time(d["ts"])

    if d["kind"] == "header_mismatch":
        ether_mac, arp_mac = d["evidence"]

        print(
            f"[WARN] ARP header mismatch for {d['ip']}\n"
            f"\tEthernet src: {ether_mac} | ARP hwsrc: {arp_mac} | t={t}\n" 
        )
    elif d["kind"] == "arp_spoofing":
        print(
            f"[ALERT] Possible ARP spoofing for {d['ip']}!\n"
            f"\tOld MAC: {set(d['known_macs'])} | New MAC: {d['evidence']} | t={t}\n"
        )


def print_table(table):
    print(f"ARP Table State: {dict(table)}")


def print_summary(findings):
    print("\n--- Summary ---")
    for item in findings.values():
        print(f"IP: {item['ip']}")
        print(f"Level: {item['level']}")
        print(f"Kind: {item['kind']}")
        print(f"First seen: {format_time(item['first_seen'])}")
        print(f"Last seen: {format_time(item['last_seen'])}")
        print(f"Appearances: {item['count']}")
        print("Evidence:")
        for e in sorted(item["evidence"]):
            print(f"  {e}")
        print("-" * 30)


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
