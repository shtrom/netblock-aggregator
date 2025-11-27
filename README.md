# netblock-aggregator

Simple script resolving IP address to CIDR ranges and NETNAME via WHOIS lookups
(with caching).

## Usage

```
pip install -r requirements.txt
./whois_lookup.py < ips.csv > ips_cidrs_netnames.csv
```

`ips.csv` is a single-column file with no headers containing one IPv4 or IPv6
per row.

## License

SPDX-License-Identifier: Apache-2.0
