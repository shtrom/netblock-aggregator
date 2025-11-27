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

    # Handle multiple CIDR blocks separated by commas
    cidr_blocks = [block.strip() for block in cidr.split(',')]

    # Add each block to the cache
    with open(cache_file, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['cidr', 'netname'])
        for block in cidr_blocks:
            cache[block] = netname
            writer.writerow({'cidr': block, 'netname': netname})
        f.flush()

    # Find and return the specific block that contains this IP
    for block in cidr_blocks:
        if ip_obj in ipaddress.ip_network(block):
            return block, netname

    # Fallback: return first block if none match (shouldn't happen)
    return cidr_blocks[0], netname

input_file = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin

output_writer = csv.DictWriter(sys.stdout, fieldnames=['ip', 'cidr', 'netname'])
output_writer.writeheader()

for line in input_file:
    ip = line.strip()
    cidr, netname = get_netname(ip)
    output_writer.writerow({'ip': ip, 'cidr': cidr, 'netname': netname})
