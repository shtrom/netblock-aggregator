#!/usr/bin/env python3
import csv
import ipaddress
import sys
from pathlib import Path
from ipwhois import IPWhois
from ipwhois.exceptions import HTTPLookupError

cache_file = Path("whois_cache.csv")
cache = {}
error_file = Path("whois_errors.csv")

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

if not error_file.exists():
    # Create error file with header
    with open(error_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['ip', 'error'])
        writer.writeheader()

def get_netname(ip):
    ip_obj = ipaddress.ip_address(ip)
    for cidr, netname in cache.items():
        if ip_obj in ipaddress.ip_network(cidr):
            return cidr, netname

    result = None
    try:
        result = IPWhois(ip).lookup_rdap()
    except HTTPLookupError:
        # Try fallback to traditional whois lookup
        try:
            result = IPWhois(ip).lookup_whois()
        except Exception as e:
            # Both methods failed, return None to signal error
            return None, None

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

    if cidr is None or netname is None:
        # Lookup failed, append to error file
        with open(error_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['ip', 'error'])
            writer.writerow({'ip': ip, 'error': 'HTTPLookupError: Both RDAP and WHOIS lookups failed'})
        continue

    output_writer.writerow({'ip': ip, 'cidr': cidr, 'netname': netname})
