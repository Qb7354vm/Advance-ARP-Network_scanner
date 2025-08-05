#!/usr/bin/env python
#!/usr/bin/env python3
"""
Advanced ARP Network Scanner
Features:
- Automatic interface and local network detection
- Concurrency for faster scans
- Optional TCP port scanning (top 100 ports)
- MAC vendor lookup
- Multiple output formats: table, JSON, CSV
- Progress bar & logging
"""
import os
import argparse
import logging
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import netifaces
import scapy.all as scapy
import ipaddress
from prettytable import PrettyTable
from tqdm import tqdm
try:
    from mac_vendor_lookup import VendorLookup
except ImportError:
    VendorLookup = None


def check_root():
    if os.geteuid() != 0:
        logging.error("This script requires root privileges. Please run with sudo.")
        exit(1)


def get_default_interface():
    gateways = netifaces.gateways()
    return gateways['default'][netifaces.AF_INET][1]


def get_local_network(iface):
    addrs = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
    ip = addrs['addr']
    netmask = addrs['netmask']
    cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
    return f"{ip}/{cidr}"


def parse_args():
    parser = argparse.ArgumentParser(description="Advanced ARP Network Scanner")
    parser.add_argument("-t", "--target", help="Target IP or network in CIDR notation")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-o", "--output", choices=['table', 'json', 'csv'], default='table', help="Output format")
    parser.add_argument("--timeout", type=float, default=1.0, help="ARP request timeout")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads for parallel scan")
    parser.add_argument("--port-scan", action='store_true', help="Perform TCP port scan on discovered hosts")
    parser.add_argument("--vendor", action='store_true', help="Lookup MAC vendor (requires mac_vendor_lookup library)")
    parser.add_argument("--verbose", action='store_true', help="Enable verbose logging")
    return parser.parse_args()


def arp_scan(ip, iface, timeout):
    arp_req = scapy.ARP(pdst=ip)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = ether/arp_req
    answered = scapy.srp(pkt, timeout=timeout, iface=iface, verbose=False)[0]

    results = []
    for _, resp in answered:
        results.append({'ip': resp.psrc, 'mac': resp.hwsrc})
    return results


def port_scan_ip(ip, ports):
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports


def scan_host(ip, args, vendor_lookup=None, ports=None):
    entry = {'ip': ip, 'mac': None, 'vendor': None, 'ports': []}
    # ARP probe
    res = arp_scan(ip, args.interface, args.timeout)
    if res:
        entry['mac'] = res[0]['mac']
        if args.vendor and vendor_lookup:
            try:
                entry['vendor'] = vendor_lookup.get_vendor(entry['mac'])
            except Exception:
                entry['vendor'] = 'Unknown'
        if args.port_scan and ports:
            entry['ports'] = port_scan_ip(ip, ports)
    return entry


def main():
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='[%(levelname)s] %(message)s')

    check_root()

    # Determine interface
    iface = args.interface or get_default_interface()
    logging.info(f"Using interface: {iface}")

    # Determine network
    network = args.target or get_local_network(iface)
    logging.info(f"Scanning network: {network}")

    # Prepare IP list
    try:
        ip_list = [str(ip) for ip in ipaddress.ip_network(network, strict=False).hosts()]
    except ValueError:
        logging.error("Invalid network target. Use CIDR notation, e.g., 192.168.1.0/24.")
        exit(1)

    # Initialize vendor lookup
    vendor_lookup = VendorLookup() if args.vendor and VendorLookup else None
    if args.vendor and not VendorLookup:
        logging.warning("mac_vendor_lookup library not found; skipping vendor lookup.")

    # Ports list
    ports = list(range(1, 101)) if args.port_scan else None

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_host, ip, args, vendor_lookup, ports): ip for ip in ip_list}
        for fut in tqdm(as_completed(futures), total=len(ip_list), desc="Scanning hosts"):
            res = fut.result()
            if res['mac']:
                results.append(res)

    # Output results
    if args.output == 'json':
        print(json.dumps(results, indent=2))
    else:
        table = PrettyTable()
        fields = ['IP', 'MAC']
        if args.vendor:
            fields.append('Vendor')
        if args.port_scan:
            fields.append('Open Ports')
        table.field_names = fields

        for r in results:
            row = [r['ip'], r['mac']]
            if args.vendor:
                row.append(r['vendor'] or '-')
            if args.port_scan:
                row.append(','.join(map(str, r['ports'])) or '-')
            table.add_row(row)

        if args.output == 'csv':
            print(table.get_csv_string())
        else:
            print(table)

if __name__ == '__main__':
    main()
