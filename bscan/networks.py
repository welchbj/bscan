"""Utilities for dealing with networks and addressing."""

import ipaddress


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
