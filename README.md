# Advanced ARP Network Scanner

A powerful, flexible network scanner written in Python using Scapy. It supports ARP scanning, optional TCP port scanning, MAC vendor lookup, and multiple output formats.

## 🔧 Features
- Automatic network and interface detection
- ARP scanning with multi-threading
- Optional TCP port scan (top 100 ports)
- MAC vendor lookup support
- Multiple output formats: table, JSON, CSV
- Logging and progress bar

## 🚀 Requirements
- Python 3.x
- `scapy`, `netifaces`, `tqdm`, `prettytable`, `mac-vendor-lookup`

Install dependencies:
```bash
pip install scapy netifaces tqdm prettytable mac-vendor-lookup
```

## 🔍 Usage
```bash
sudo python3 advanced_arp_scanner.py --interface eth0 --port-scan --vendor --output json
```

### Example:
```bash
sudo python3 advanced_arp_scanner.py -t 192.168.1.0/24 -i eth0 --port-scan --vendor --output table
```

## 📂 Output Example
```
+---------------+-------------------+---------------------+-------------+
| IP            | MAC               | Vendor              | Open Ports  |
+---------------+-------------------+---------------------+-------------+
| 192.168.1.10  | AA:BB:CC:DD:EE:FF | Intel Corporation   | 22,80       |
+---------------+-------------------+---------------------+-------------+
```

## 🧠 Author
Fransly Dutervil | [GitHub: Qb7354vm](https://github.com/Qb7354vm)

---

> ⚠️ For ethical hacking and internal use only. Always get permission before scanning any network.
