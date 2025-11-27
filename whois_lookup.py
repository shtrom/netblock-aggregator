#!/usr/bin/env python3
import csv
import ipaddress
import sys
from pathlib import Path
from ipwhois import IPWhois

cache_file = Path("whois_cache.csv")
cache = {}

if cache_file.exists():
    with open(cache_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            cache[row['cidr']] = row['netname']
else:
    # Create cache file with header
    with open(cache_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['cidr', 'netname'])
        writer.writeheader()

def get_netname(ip):
    ip_obj = ipaddress.ip_address(ip)
    for cidr, netname in cache.items():
        if ip_obj in ipaddress.ip_network(cidr):
            return cidr, netname

    result = IPWhois(ip).lookup_rdap()
    cidr = result.get('network', {}).get('cidr') or result.get('asn_cidr')
    netname = result.get('network', {}).get('name') or result.get('asn_description')
    cache[cidr] = netname
    with open(cache_file, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['cidr', 'netname'])
        writer.writerow({'cidr': cidr, 'netname': netname})
        f.flush()
    return cidr, netname

input_file = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin

output_writer = csv.DictWriter(sys.stdout, fieldnames=['ip', 'cidr', 'netname'])
output_writer.writeheader()

for line in input_file:
    ip = line.strip()
    cidr, netname = get_netname(ip)
    output_writer.writerow({'ip': ip, 'cidr': cidr, 'netname': netname})
