"""Expands subnet notation into the list of IP addresses to probe."""
import ipaddress

from . import config


def _too_many(count: int, limit: int) -> ValueError:
    return ValueError(
        f"{count} addresses exceeds the {limit}-host limit. "
        "Narrow the range, or raise the limit in Settings."
    )


def _expand_one(token: str, limit: int) -> list[str]:
    """Expand a single CIDR, range, or address into IP strings.

    The size is checked before anything is built: a mistyped /8 is 16
    million addresses, and expanding them first froze the window for
    about twenty seconds before the limit message appeared.
    """
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        if net.num_addresses > limit + 2:   # +2: network and broadcast
            raise _too_many(net.num_addresses, limit)
        # .hosts() drops the network and broadcast addresses, and already
        # returns the addresses themselves for /31 and /32.
        return [str(h) for h in net.hosts()]

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
        if int(end) - int(start) + 1 > limit:
            raise _too_many(int(end) - int(start) + 1, limit)
        return [str(type(start)(value)) for value in range(int(start), int(end) + 1)]

    return [str(ipaddress.ip_address(token))]


def parse_targets(text: str) -> list[str]:
    """Turn subnet text into the IPs to scan, in order and deduplicated.

    Accepts CIDRs (10.20.30.0/24), ranges (10.20.30.10-10.20.30.50 or the
    shorthand 10.20.30.10-50), and single addresses, separated by commas or
    whitespace. Raises ValueError on bad input or an over-large range.
    """
    limit = config.get_settings().max_subnet_hosts
    ips: list[str] = []
    seen: set[str] = set()
    for token in text.replace(",", " ").split():
        for ip in _expand_one(token, limit):
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)

    if not ips:
        raise ValueError("Enter a subnet, e.g. 10.20.30.0/24 or 10.20.30.1-50")

    if len(ips) > limit:   # several tokens that are each fine can still add up
        raise _too_many(len(ips), limit)
    return ips
