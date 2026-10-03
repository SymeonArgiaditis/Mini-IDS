# Mini-IDS

[![Tests](https://github.com/SymeonArgiaditis/Mini-IDS/actions/workflows/tests.yml/badge.svg)](https://github.com/SymeonArgiaditis/Mini-IDS/actions/workflows/tests.yml)

A small home-network intrusion detector written in Python with [Scapy](https://scapy.net/). It reads packet captures (PCAP files), tracks which MAC address belongs to which IP, and flags ARP spoofing and suspicious ARP packets.

**Status: early development.** Only ARP analysis is implemented so far. See the [roadmap](#roadmap) for what's planned.

## What it does today

- Reads ARP packets from a PCAP file, streaming them so large captures don't have to fit in memory.
- Builds an IP → set-of-MACs table from trusted packets.
- Raises an **`ALERT` (`arp_spoofing`)** when an IP is claimed by a MAC address it hasn't been seen with before.
- Raises a **`WARN` (`header_mismatch`)** when the Ethernet source MAC and the sender MAC inside the ARP payload disagree.
- Ignores `0.0.0.0` sender addresses (ARP probes, which are normal).
- Prints each finding once, live, then ends with a summary. Repeats are counted, not reprinted.
- Records a count, first/last seen timestamps, and the evidence (the MACs involved) for every finding.
- Ships with tests that build fake ARP packets in memory, so the detector can be verified without a real attack.

## Quickstart

Requires Python 3.10 or newer.

```bash
git clone https://github.com/SymeonArgiaditis/Mini-IDS.git
cd Mini-IDS
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### Capture your own sample

The repository deliberately does **not** include a capture file (see [Privacy](#privacy)). Record your own:

1. Open [Wireshark](https://www.wireshark.org/) and start capturing on your network interface (Wi-Fi or Ethernet).
2. Let it run for a few minutes. Reconnecting a device to Wi-Fi during the capture produces extra ARP traffic.
3. Save it as `sample.pcap` in the project's root folder (File → Save As, pcap format).

Or, with tcpdump on macOS/Linux (needs sudo): `sudo tcpdump -i <interface> -w sample.pcap arp`.

### Run the detector

From the project's root folder:

```bash
python -m mini_ids
```

The detector reads `sample.pcap` from the current directory, prints findings as it goes, and finishes with a summary.

## Example output

The example below uses the fake packets from the test suite, not real traffic:

```
[WARN] ARP header mismatch for 192.168.1.50
	Ethernet src: aa:aa:aa:aa:aa:03 | ARP hwsrc: aa:aa:aa:aa:aa:02 | t=2023-11-14 22:13:20

--- Summary ---
IP: 192.168.1.50
Level: WARN
Kind: header_mismatch
First seen: 2023-11-14 22:13:20
Last seen: 2023-11-14 22:13:20
Appearances: 1
Evidence:
  ('aa:aa:aa:aa:aa:03', 'aa:aa:aa:aa:aa:02')
------------------------------
```

On a clean capture of an ordinary home network, you should see an ARP table and an empty summary.

## How detection works

ARP maps IP addresses to MAC addresses on a local network, and it has no authentication. Anyone on the network can claim "192.168.1.1 is at *my* MAC", and other devices will often believe it. That's ARP spoofing (or ARP poisoning), the basis of many man-in-the-middle attacks.

Every ARP packet carries a sender MAC in two places: the Ethernet header (who sent the frame) and the ARP payload (who the sender says the IP belongs to). An honest device writes the same MAC in both. The detector uses that in two checks:

| Finding | Level | Trigger |
|---|---|---|
| `arp_spoofing` | ALERT | An IP that already has known MACs is claimed by a new MAC |
| `header_mismatch` | WARN | Ethernet source MAC ≠ ARP sender MAC |

## Architecture

Each packet flows through four small stages, and each stage lives in its own module:

```
PCAP ──▶ parsing ──▶     cli     ──▶ findings ──▶  report
         (fields)   (reads table)    (dedupe)    (printing)
                         │
                         └──▶ learn (updates table, only after detection)
```

| Module | Responsibility |
|---|---|
| `parsing.py` | Turns a Scapy packet into plain values (IP, MACs, timestamp) |
| `arp.py` | ARP detection rules and the table-learning step |
| `findings.py` | Deduplicates and counts repeated findings |
| `report.py` | All printing and time formatting |
| `detector.py` | Wires the stages together (`process`, `main`) |

Detection never prints, and reporting never decides what is suspicious. That separation keeps each piece testable on its own and makes it straightforward to add new protocols later.

## Design decisions

- **Suspect packets are reported but never learned.** If a mismatched packet were allowed to update the table, an attacker could teach the detector their own MAC as legitimate. Established tools take a similar stance: arpwatch reports an "ethernet mismatch" as its own event type, and switches with Dynamic ARP Inspection can drop such packets.
- **A mismatch is a WARN, not an ALERT.** Some legitimate setups (proxy ARP, certain failover and virtualization configurations) can produce mismatched headers, and real spoofing tools often write matching MACs. A mismatch is a lead, not proof.
- **Order matters: detect, record, then learn.** If the table were updated first, a new MAC would already look "known" when detection ran, and no alert would ever fire.
- **Findings are keyed by `(kind, IP)`.** A repeated condition increments a counter instead of flooding the output, and the distinct MACs involved are kept in a set.
- **Raw timestamps are stored; formatting happens at display time.** Keeping the numeric value allows durations and time-based analysis later.
- **Lookups never create table entries.** An IP only enters the table when a trusted packet teaches it.

## Testing

```bash
python -m pytest -v
```

The tests construct ARP packets with Scapy, run them through the detector, and assert on the results. They cover:

- a new MAC appearing for a known IP (one alert)
- the same MAC repeating (no alert)
- a third MAC arriving after the first alert
- a header-mismatch packet for a brand-new IP (reported, not learned)
- a repeated suspect packet that also conflicts with a known MAC (counted, never learned)

No test depends on a capture file, so they run anywhere. The test suite also runs automatically on every push through GitHub Actions.

## Limitations

This is a learning project, and it is honest about what it can't do:

- **It trusts the first MAC it sees for an IP.** An attacker already poisoning the network when the capture starts is learned as legitimate. There is no persistent baseline yet.
- **Legitimate MAC changes look like attacks.** A new device taking over an IP after a DHCP lease expires, a replaced router, or a swapped network card will raise an `ALERT`.
- **MAC address randomization isn't handled.** Modern phones may use a different MAC per network, or rotate it over time, which makes a simple IP-to-MAC table noisy. Handling this properly is a roadmap item.
- **Only the first occurrence of each finding prints live.** A second, different conflicting MAC for the same IP is added to that finding's evidence and shows up in the summary, but isn't printed as it happens.
- **It analyzes captures offline.** There is no live sniffing yet, and a capture only contains what your machine could see. On a switched network that is mostly broadcasts and your own traffic.
- **ARP only.** Other protocols and attack types are out of scope for now.
- **Layer 2 only, and local only.** It says nothing about attacks beyond your own network segment.

## Roadmap

- [x] First-occurrence gating for `ALERT` output (matching the `WARN` behavior)
- [x] Separate detection from reporting
- [ ] Tests for the `0.0.0.0` filter and a smoke test for `main`
- [ ] New-device detection ("first time this IP/MAC pair appeared")
- [ ] MAC flip-flop detection (an IP alternating between MACs)
- [ ] DNS parsing, stored in SQLite
- [ ] Per-device baselines and statistical anomaly detection
- [ ] Evaluation against a public labeled dataset, with precision/recall reporting
- [ ] Comparison against Suricata or Zeek on the same traffic
- [ ] Command-line interface (file path argument, JSON report output)

## Project layout

```
Mini-IDS/
├── .github/workflows/tests.yml   # runs the tests on every push
├── mini_ids/
│   ├── __init__.py
│   ├── __main__.py               # entry point for: python -m mini_ids
│   ├── parsing.py
│   ├── arp.py
│   ├── findings.py
│   ├── report.py
│   └── cli.py
├── tests/
│   └── test_arp.py
├── pyproject.toml
├── requirements.txt
└── .gitignore
```

## Privacy

Packet captures contain real device MAC addresses, IPs, and (once DNS support lands) the domains you visit. `*.pcap` files are git-ignored, and you should never commit a capture of your own network. If you share results, use the synthetic packets from the test suite or a public dataset.

## Ethical use

Only analyze traffic from networks you own or have explicit permission to monitor.
