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


def detect_arp(obs, table):
    ip, arp_mac, ether_mac, ts = obs
    detections = []

    if is_suspect(ether_mac, arp_mac):
        detections.append({
            "level": "WARN", "kind": "header_mismatch",
            "ip": ip, "ts": ts,
            "evidence": (ether_mac, arp_mac),
        })

    known_macs = table.get(ip, set())

    if known_macs and arp_mac not in known_macs:
        detections.append({
            "level": "ALERT", "kind": "arp_spoofing",
            "ip": ip, "ts": ts,
            "evidence": arp_mac,
            "known_macs": frozenset(known_macs),
        })

    return detections


def format_time(timestamp):
    utc_timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)

    return utc_timestamp.strftime("%Y-%m-%d %H:%M:%S")


def learn(table, ip, arp_mac):
    table.setdefault(ip, set()).add(arp_mac)


def record(findings, d):
    key = (d["kind"], d["ip"])

    if key in findings:
        findings[key]["count"] += 1
        findings[key]["last_seen"] = d["ts"]
        findings[key]["evidence"].add(d["evidence"])
        
        return False

    findings[key] = {
        "level": d["level"], "kind": d["kind"], "ip":d["ip"],
        "first_seen": d["ts"], "last_seen": d["ts"], "count": 1,
        "evidence": {d["evidence"]}
    }
    
    return True


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
