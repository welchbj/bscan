"""Target scanning and reporting functionality."""

import re

from asyncio import (
    ensure_future,
    gather)
from itertools import chain
from functools import partial
from typing import (
    Any,
    Coroutine,
    List,
    Pattern,
    Set,
    Tuple)

from bscan.dir_structure import (
    get_recommendations_txt_file,
    get_scan_file)
from bscan.io_console import (
    blue,
    print_i_d2,
    print_i_d3,
    print_w_d3,
    purple,
    yellow)
from bscan.models import (
    DetectedService,
    ParsedService)
from bscan.runtime import (
    add_active_target,
    get_db_value,
    proc_spawn,
    remove_active_target)


async def scan_target(target: str) -> None:
    """Run quick, thorough, and service scans on a target."""
    do_thorough = not get_db_value('quick-only')
    await add_active_target(target)

    # block on the initial quick scan
    qs_parsed_services = await run_qs(target)
    qs_unmatched_services, qs_joined_services = \
        join_services(target, qs_parsed_services)
    _print_matched_services(target, qs_joined_services)
    _print_unmatched_services(target, qs_unmatched_services)

    # schedule service scans based on qs-found ports
    qs_s_scan_cmds: List[List[str]] = \
        [js.build_scans() for js in qs_joined_services]
    qs_s_scans: List[Coroutine[Any, Any, Any]] = \
        [run_service_s(target, cmd) for cmd in chain(*qs_s_scan_cmds)]
    qs_s_scan_tasks = [ensure_future(scan) for scan in qs_s_scans]

    # block on the thorough scan, if enabled
    if do_thorough:
        ts_parsed_services: Set[ParsedService] = await run_ts(target)
    else:
        ts_parsed_services = set()
        print_i_d2(target, ': skipping thorough scan')

    # diff open ports between quick and thorough scans
    new_services: Set[ParsedService] = ts_parsed_services - qs_parsed_services
    ts_joined_services: List[DetectedService] = []
    if new_services:
        ts_unmatched_services, ts_joined_services = \
            join_services(target, new_services)
        _print_matched_services(target, ts_joined_services)
        _print_unmatched_services(target, ts_unmatched_services)
        ts_s_scan_cmds = [js.build_scans() for js in ts_joined_services]
        ts_s_scans = [run_service_s(target, cmd) for
                      cmd in chain(*ts_s_scan_cmds)]
        ts_s_scan_tasks = [ensure_future(scan) for scan in ts_s_scans]
    elif do_thorough:
        print_i_d2(target, ': thorough scan discovered no additional '
                   'services')
        ts_s_scan_tasks = []

    # write recommendations file for further manual TCP commands
    for js in chain(qs_joined_services, ts_joined_services):
        if not js.recommendations:
            continue

        with open(get_recommendations_txt_file(js.target), 'a') as f:
            fprint = partial(print, file=f, sep='')
            section_header = (
                'The following commands are recommended for service ' +
                js.name + ' running on port(s) ' + js.port_str() + ':')
            fprint(section_header)
            fprint('-'*len(section_header))
            for rec in js.build_recommendations():
                fprint(rec)
            fprint()

    # run UDP scan
    if get_db_value('udp'):
        udp_services = await run_udp_s(target)
        for service in udp_services:
            print_i_d3(
                target, ': detected service ', blue(service.name),
                ' on UDP port ', blue(str(service.port)))

    # block on any pending service scan tasks
    await gather(*chain(qs_s_scan_tasks, ts_s_scan_tasks))

    await remove_active_target(target)


async def run_qs(target: str) -> Set[ParsedService]:
    """Run a quick scan on a target via the configured method."""
    print_i_d2(target, ': beginning TCP quick scan')
    qs_config = get_db_value('quick-scan')
    cmd = qs_config.scan.format(
        target=target,
        fout=get_scan_file(target, 'tcp.quickscan.' + qs_config.name))
    services = await _parse_port_scan(target, cmd, qs_config.pattern)
    print_i_d2(target, ': finished TCP quick scan')
    return services


async def run_service_s(target: str, cmd: str) -> None:
    """Run an in-depth service scan on the specified target."""
    async for line in proc_spawn(target, cmd):
        highlight_patterns(target, line)


async def run_ts(target: str) -> Set[ParsedService]:
    """Run a thorough TCP scan on a target using the configured method."""
    print_i_d2(target, ': beginning TCP thorough scan')
    ts_config = get_db_value('thorough-scan')
    cmd = ts_config.scan.format(
        target=target,
        fout=get_scan_file(target, 'tcp.thorough.' + ts_config.name))
    services = await _parse_port_scan(target, cmd, ts_config.pattern)
    print_i_d2(target, ': finished TCP thorough scan')
    return services


async def run_udp_s(target: str) -> Set[ParsedService]:
    """Run a UDP scan on a target."""
    print_i_d2(target, ': beginning UDP scan')
    udp_config = get_db_value('udp-scan')
    cmd = udp_config.scan.format(
        target=target,
        fout=get_scan_file(target, 'udp.' + udp_config.name))
    services = await _parse_port_scan(target, cmd, udp_config.pattern)
    print_i_d2(target, ': finished UDP scan')
    return services


def join_services(target: str,
                  services: Set[ParsedService]) ->\
                  Tuple[Set[ParsedService], List[DetectedService]]:
    """Join services on multiple ports into a consolidated set.

    Returns:
        A set of unmatched services and a list of consolidated service
        matches.

    """
    defined_services = get_db_value('services')
    unmatched_services = services.copy()
    joined_services = []
    for protocol, config in defined_services.items():
        matches = [s for s in services if s.name in
                   config['nmap-service-names']]
        if matches:
            ds = DetectedService(
                protocol,
                target,
                tuple(sorted(s.port for s in matches)),
                config['scans'],
                tuple(config['recommendations']))
            joined_services.append(ds)
            unmatched_services -= set(matches)

    return unmatched_services, joined_services


def highlight_patterns(target: str, line: str) -> None:
    """Print a string with configured pattern matches highlighted in purple."""
    patterns = get_db_value('patterns')
    pos = 0
    highlighted_line = ''
    did_match = False
    for match in re.finditer(patterns, line):
        did_match = True
        highlighted_line += line[pos:match.start()]
        highlighted_line += purple(match.group(0))
        pos = match.end()

    if did_match:
        highlighted_line += line[pos:]
        print_i_d3(
            target, ': matched pattern in line `', highlighted_line, '`')


async def _parse_port_scan(
        target: str,
        cmd: str,
        pattern: Pattern) -> Set[ParsedService]:
    """Parse the output of a port scan command."""
    services = set()
    async for line in proc_spawn(target, cmd):
        highlight_patterns(target, line)
        parse_match = re.search(pattern, line)
        if parse_match:
            services.add(
                ParsedService(
                    parse_match.group('name'),
                    int(parse_match.group('port'))))
    return services


def _print_matched_services(target: str,
                            matched_services: List[DetectedService]) -> None:
    """Print information about matched services."""
    for ds in matched_services:
        print_i_d3(target, ': matched service(s) on port(s) ',
                   blue(ds.port_str()), ' to ', blue(ds.name))


def _print_unmatched_services(target: str,
                              unmatched_services: Set[ParsedService]) -> None:
    """Print information about unmatched services."""
    for ps in unmatched_services:
        print_w_d3(target, ': unable to match reported ',
                   yellow(ps.name), ' on port ', yellow(str(ps.port)),
                   ' to a configured service')
