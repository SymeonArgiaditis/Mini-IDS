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
