from scapy.all import PcapReader
from scapy.layers.l2 import ARP, Ether

from datetime import datetime, timezone

def parse_arp(pkt):
    ip = pkt[ARP].psrc
    arp_mac = pkt[ARP].hwsrc
    ether_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
    timestamp = float(pkt.time)

    return ip, arp_mac, ether_mac, timestamp


def is_suspect(ether_mac, arp_mac):
    return bool(ether_mac and ether_mac != arp_mac)


def format_time(timestamp):
    utc_timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)

    return utc_timestamp.strftime("%Y-%m-%d %H:%M:%S")


def learn(table, ip, arp_mac):
    table.setdefault(ip, set()).add(arp_mac)


def record(findings, level, kind, ip, ts, evidence):
    key = (kind, ip)

    if key in findings:
        findings[key]["count"] += 1
        findings[key]["last_seen"] = ts
        findings[key]["evidence"].add(evidence)
        
        return False
    else:
        findings[key] = {
            "level": level, "kind": kind, "ip":ip,
            "first_seen": ts, "last_seen": ts, "count": 1,
            "evidence": {evidence}
        }
        return True


def check_arp(pkt, table, findings):
    ip, arp_mac, ether_mac, timestamp = parse_arp(pkt)

    if ip == "0.0.0.0":
        return

    time_str = format_time(timestamp)

    # A mismatched packet is suspect: report it, but never learn from it.
    suspect = is_suspect(ether_mac, arp_mac)

    if suspect:
        if record(
            findings, "WARN", "header_mismatch", ip, timestamp, 
            evidence = (ether_mac, arp_mac)
        ):
            print(
                f"[WARN] ARP header mismatch for {ip}\n"
                f"\tEthernet src: {ether_mac} | ARP hwsrc: {arp_mac} | t={time_str}\n"
            )
    # Read-only lookup: does not create the key if the IP is new
    known_macs = table.get(ip, set())

    if known_macs and arp_mac not in known_macs:
        if record(
            findings, "ALERT", "arp_spoofing", ip, timestamp,
            evidence = arp_mac
        ):
            print(
                f"[ALERT] Possible ARP spoofing for {ip}!\n"
                f"\tOld MAC: {known_macs} | New MAC: {arp_mac} | t={time_str}\n"
            )

    # Only learn from trusted packets
    if not suspect:
        # Create key. Write to table
        learn(table, ip, arp_mac)


def main():
    with PcapReader("sample.pcap") as pcap:
        table = {}
        findings = {}

        for pkt in pcap:
            if pkt.haslayer(ARP):
                check_arp(pkt, table, findings)

    print(f"ARP Table State: {dict(table)}")

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


if __name__ == "__main__":    
    main()
