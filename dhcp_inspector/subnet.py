"""Expands subnet notation into the list of IP addresses to probe."""
import ipaddress

from . import config


def _expand_one(token: str) -> list[str]:
    """Expand a single CIDR, range, or address into IP strings."""
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        # .hosts() drops the network/broadcast addresses; for /31 and /32
        # there are none to drop and it can come back empty.
        return [str(h) for h in net.hosts()] or [str(net.network_address)]

    if "-" in token:
        start_text, end_text = (part.strip() for part in token.split("-", 1))
        start = ipaddress.ip_address(start_text)
        if "." not in end_text and ":" not in end_text:
            # Last-octet shorthand, e.g. 10.20.30.10-50
            end = ipaddress.ip_address(f"{start_text.rsplit('.', 1)[0]}.{end_text}")
        else:
            end = ipaddress.ip_address(end_text)
        if type(end) is not type(start):
            raise ValueError(f"Range mixes IPv4 and IPv6: {token}")
        if int(end) < int(start):
            raise ValueError(f"Range ends before it starts: {token}")
        return [str(type(start)(value)) for value in range(int(start), int(end) + 1)]

    return [str(ipaddress.ip_address(token))]


def parse_targets(text: str) -> list[str]:
    """Turn subnet text into the IPs to scan, in order and deduplicated.

    Accepts CIDRs (10.20.30.0/24), ranges (10.20.30.10-10.20.30.50 or the
    shorthand 10.20.30.10-50), and single addresses, separated by commas or
    whitespace. Raises ValueError on bad input or an over-large range.
    """
    ips: list[str] = []
    seen: set[str] = set()
    for token in text.replace(",", " ").split():
        for ip in _expand_one(token):
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)

    if not ips:
        raise ValueError("Enter a subnet, e.g. 10.20.30.0/24 or 10.20.30.1-50")

    limit = config.get_settings().max_subnet_hosts
    if len(ips) > limit:
        raise ValueError(
            f"{len(ips)} addresses exceeds the {limit}-host limit. "
            "Narrow the range, or raise the limit in Settings."
        )
    return ips
