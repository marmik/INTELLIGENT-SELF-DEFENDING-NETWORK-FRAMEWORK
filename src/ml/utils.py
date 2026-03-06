
import ipaddress

# ranges are much more precise than simple string prefixes; the original
# implementation was overly broad (e.g. "172." matched the entire /8) which
# led to innocent hosts being marked as "datacenter" and then receiving
# higher risk scores.  Use real CIDRs so we can keep the whitelist accurate
# and avoid false positives.

KNOWN_INFRA_CIDRS = [
    # DNS providers and public resolver blocks
    '8.8.8.0/24', '8.8.4.0/24',          # Google DNS
    '1.1.1.0/24', '1.0.0.0/24',          # Cloudflare DNS
    '4.2.2.0/24',                        # Level3

    # AWS EC2 / Cloud (comprehensive coverage)
    '4.0.0.0/8',                         # AWS (covers 4.213.25.241)
    '44.0.0.0/6',                        # AWS (covers 44.239.45.59 and similar)
    '52.0.0.0/8',                        # AWS
    '54.0.0.0/8',                        # AWS

    # Major cloud provider / CDN subnets
    '34.0.0.0/8',   # Google Cloud
    '35.0.0.0/8',   # Google Cloud
    '13.64.0.0/10', # Azure
    '20.0.0.0/7',   # Azure
    '40.0.0.0/6',   # Azure / Others

    # Apple services (17.0.0.0/8 is Apple's entire range)
    '17.0.0.0/8',
    '192.178.0.0/16', # Apple iCloud
    '45.33.0.0/16',   # Apple supporting services

    # GitHub, Fastly, Akamai, Cloudflare edge
    '185.199.108.0/22',
    '140.82.112.0/20',
    '162.158.0.0/15',

    # Google services specific ranges
    '142.250.0.0/15', '142.251.0.0/16',
    '172.217.0.0/16', '216.58.192.0/19',
]


def is_known_infra(ip_addr: str) -> bool:
    """Return ``True`` if the address belongs to a well‑known cloud/CDN
    infrastructure range.

    The previous implementation used ``startswith`` on a long list of
    prefixes; that matched far too much (``'172.'`` matched the whole 172/8)
    which caused benign hosts to be treated as datacenter traffic.  A
    concrete CIDR list makes whitelisting predictable and can be updated via
    configuration if needed.
    """
    if not ip_addr:
        return False
    try:
        ip = ipaddress.ip_address(ip_addr)
    except ValueError:
        return False
    for cidr in KNOWN_INFRA_CIDRS:
        if ip in ipaddress.ip_network(cidr):
            return True
    return False
