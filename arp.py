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
