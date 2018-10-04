"""Utilities for dealing with networks and addressing."""

import ipaddress
import re


def is_valid_ip_net_addr(ip: str) -> bool:
    """Return whether the address is a valid IPv4 or IPv6 network address."""
    try:
        ipaddress.ip_network(ip)
    except ValueError:
        return False

    return True


def is_valid_ip_host_addr(ip: str) -> bool:
    """Return whether the address is a valid IPv4 or IPv6 host address."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False

    return True


def is_valid_hostname(ho: str) -> bool:
    """Return whether the string is a valid hostname.

    Based on: https://stackoverflow.com/a/2532344

    """
    if len(ho) > 255:
        return False
    ho = ho.rstrip('.')
    allowed = re.compile('(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)
    return all(allowed.match(x) for x in ho.split('.'))
