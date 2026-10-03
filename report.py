from datetime import datetime, timezone


def format_time(timestamp):
    utc_timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)

    return utc_timestamp.strftime("%Y-%m-%d %H:%M:%S")


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


def print_table(table):
    print(f"ARP Table State: {dict(table)}")
