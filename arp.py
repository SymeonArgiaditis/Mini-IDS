def is_suspect(ether_mac, arp_mac):
    return bool(ether_mac and ether_mac != arp_mac)
