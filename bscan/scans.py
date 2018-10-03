"""Target scanning and reporting functionality."""

from collections import namedtuple

from typing import (
    Optional,
    Set)

from bscan.config import get_config_value
from bscan.errors import BscanConfigError
from bscan.io import (
    print_e_d1,
    print_i_d2,
    print_i_d3)

DetectedService = namedtuple('DetectedService', ['name', 'ports'])

UNICORNSCAN_QUICK_SCAN_TEMPLATE = 'TODO'
NMAP_QUICK_SCAN_TEMPLATE = 'TODO'


async def scan_target(target: str) -> None:
    """Run quick, thorough, and service scans on a target."""
    # run quick scan
    qs_services: Set[DetectedService] = await run_qs(target)

    # run thorough scan
    ts_services: Set[DetectedService] = await run_ts(target)

    # diff open ports between quick and thorough scans
    # TODO

    # report on scanned/unscanned ports
    # TODO

    pass


async def run_qs(target: str) -> Set[DetectedService]:
    """Run a quick scan on a target using the configured option."""
    method = get_config_value('quick-scan')
    if method == 'unicornscan':
        return await run_unicornscan_qs(target)
    else:
        return await run_nmap_qs(target)


async def run_unicornscan_qs(target: str) -> Set[DetectedService]:
    """Run a quick scan on a target via unicornscan."""
    print_i_d2(target, ': beginning unicornscan quick scan of target')
    print_i_d3(target, ': spawning subprocess `', 'TODO', '`')
    # TODO: spawn subprocess, highlight pattern matches, write to file


async def run_nmap_qs(target: str) -> Set[DetectedService]:
    """Run a quick scan on a target using Nmap."""
    # TODO
    raise NotImplementedError


async def run_ts(target: str) -> Set[DetectedService]:
    """Run a thorough scan on a target using Nmap."""
    # TODO
    raise NotImplementedError
