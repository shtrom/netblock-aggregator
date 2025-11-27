#!/usr/bin/env python3
import json
import ipaddress
from pathlib import Path
from ipwhois import IPWhois

cache_file = Path("whois_cache.json")
cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}

def get_netname(ip):
    ip_obj = ipaddress.ip_address(ip)
    for cidr, netname in cache.items():
        if ip_obj in ipaddress.ip_network(cidr):
            return netname

    result = IPWhois(ip).lookup_rdap()
    cidr = result.get('network', {}).get('cidr') or result.get('asn_cidr')
    netname = result.get('network', {}).get('name') or result.get('asn_description')
    cache[cidr] = netname
    return netname

for line in open("requests_remoteIP.uniq"):
    ip = line.strip()
    print(f"{ip}\t{get_netname(ip)}")

cache_file.write_text(json.dumps(cache, indent=2))
