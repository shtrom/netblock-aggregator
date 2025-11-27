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
        for row in csv.reader(f):
            cache[row[0]] = row[1]

def get_netname(ip):
    ip_obj = ipaddress.ip_address(ip)
    for cidr, netname in cache.items():
        if ip_obj in ipaddress.ip_network(cidr):
            return netname

    result = IPWhois(ip).lookup_rdap()
    cidr = result.get('network', {}).get('cidr') or result.get('asn_cidr')
    netname = result.get('network', {}).get('name') or result.get('asn_description')
    cache[cidr] = netname
    with open(cache_file, 'a', newline='') as f:
        csv.writer(f).writerow([cidr, netname])
        f.flush()
    return netname

input_file = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin

for line in input_file:
    ip = line.strip()
    print(f"{ip}\t{get_netname(ip)}")
