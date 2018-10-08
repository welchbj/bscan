"""Target scanning and reporting functionality."""

import asyncio
import re

from collections import namedtuple
from functools import partial
from typing import (
    Generator,
    List,
    Set)

from bscan.config import get_config_value
from bscan.io import (
    blue,
    print_i_d2,
    print_i_d3,
    print_w_d3,
    purple)
from bscan.structure import (
    get_recommendations_txt_file,
    get_scan_file)

DetectedService = namedtuple('DetectedService', ['name', 'port'])
"""Encapsulate the data associated with a detected service."""

UNIC_QUICK_SCAN = (
    'unicornscan {target} 2>&1 | tee "{fout}"')
"""TCP connect() and SYN scans on most common ports."""

NMAP_QUICK_SCAN = (
    'nmap -vv -Pn -sC -sV --top-ports 1000 {target} -oN "{fout}" 2>&1')
"""TCP connect() scan and service discovery on most common ports."""

NMAP_TCP_SCAN = (
    'nmap -vv -Pn -sS -sC -A -p- -T4 {target} -oN "{fout}" 2>&1')
"""TCP SYN and connect() scans (aggressively) on all TCP ports."""

NMAP_UDP_SCAN = (
    'nmap -vv -Pn -sC -sV sU {target} -oN "{fout}" 2>&1')
"""UDP scan."""


async def scan_target(target: str) -> None:
    """Run quick, thorough, and service scans on a target."""
    do_thorough = not get_config_value('quick-only')

    # run quick scan
    qs_services = await run_qs(target)

    # run the ts and scans based on qs-found ports
    scans = [run_service_s(target, cmd) for
             cmd in build_scans(target, qs_services)]
    if do_thorough:
        scans.append(run_nmap_ts(target))
    else:
        print_i_d2(target, ': skipping thorough scan')
    res = await asyncio.gather(*scans)
    ts_services = res[0] if do_thorough else set()

    # diff open ports between quick and thorough scans
    new_services = ts_services - qs_services
    if new_services:
        print_i_d2(target, ': Nmap thorough scan discovered the following '
                   'additional service(s): ',
                   ', '.join([ns.name for ns in new_services]))
        scans = [run_service_s(target, cmd) for
                 cmd in build_scans(target, new_services)]
        await asyncio.gather(*scans)
    elif do_thorough:
        print_i_d2(target, ': thorough scan discovered no additional '
                   'services')

    # run UDP scan
    if get_config_value('udp'):
        udp_services = await run_udp_s(target)
        # TODO: handle UDP results

    # report on scanned/unscanned ports
    # TODO

    # write recommendations file for further manual commands
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
    print_i_d2(target, ': beginning unicornscan quick scan')
    services = set()

    unic_cmd = UNIC_QUICK_SCAN.format(
        target=target,
        fout=get_scan_file(target, 'tcp.quick.unicornscan'))
    async for line in proc_spawn(target, unic_cmd):
        match_patterns(target, line)
        if line.startswith('TCP open'):
            tokens = line.replace('[', ' ').replace(']', ' ').split()
            name = tokens[2]
            port = int(tokens[3])
            services.add(DetectedService(name, port))

    print_i_d2(target, ': finished unicornscan quick scan')
    return services


async def run_nmap_qs(target: str) -> Set[DetectedService]:
    """Run a quick scan on a target using Nmap."""
    # TODO
    raise NotImplementedError


async def run_service_s(target: str, cmd: str) -> None:
    """Run an in-depth service scan on the specified target."""
    async for line in proc_spawn(target, cmd):
        match_patterns(target, line)


async def run_nmap_ts(target: str) -> Set[DetectedService]:
    """Run a thorough TCP scan on a target using Nmap."""
    print_i_d2(target, ': beginning Nmap TCP thorough scan')
    services = set()

    nmap_cmd = NMAP_TCP_SCAN.format(
        target=target,
        fout=get_scan_file(target, 'tcp.thorough.nmap'))
    async for line in proc_spawn(target, nmap_cmd):
        match_patterns(target, line)
        tokens = line.split()
        if 'Discovered' not in line and '/tcp' in line and 'open' in tokens:
            name = tokens[2].rstrip('?')
            port = int(tokens[0].split('/')[0])
            services.add(DetectedService(name, port))

    print_i_d2(target, ': finished Nmap thorough scan')
    return services


async def run_udp_s(target: str) -> Set[DetectedService]:
    """Run a UDP scan on a target using Nmap."""
    # TODO
    raise NotImplementedError


async def proc_spawn(target: str, cmd: str) -> Generator[str, None, None]:
    """Asynchronously yield lines from stdout of a spawned subprocess."""
    print_i_d3(target, ': spawning subprocess `', cmd, '`')
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    async for line in proc.stdout:
        yield line.decode('utf-8').strip()

    exit_code = await proc.wait()
    if exit_code != 0:
        print_w_d3(target, ': subprocess `', cmd, '` exited with non-zero ',
                   'exit code of ', exit_code)


def build_scans(target: str,
                detected_services: Set[DetectedService]) -> List[str]:
    """Build scan commands from the detected services and services config."""
    cmds = []

    # TODO: refactor our protocol structure into a separate class with its
    #       own functions such as templating filling; we need to maintain an
    #       efficient way of hashing these to be able to efficiently organize
    #       them by and diff them between quick and thorough scans

    # this implementation is wildly inefficient
    wordlist = get_config_value('web-word-list')
    userlist = get_config_value('brute-user-list')
    passlist = get_config_value('brute-pass-list')
    defined_services = get_config_value('services')
    for protocol, config in defined_services.items():
        matches = [ds for ds in detected_services if
                   ds.name in config['nmap-service-names']]
        if matches:
            port_ints = sorted(ds.port for ds in matches)
            ports_str = ','.join(str(p) for p in port_ints)
            print_i_d3(target, ': matched services on port(s) ',
                       blue(ports_str), ' to ', blue(protocol), ' protocol')

            # create scan commands
            for key, cmd in config['scans'].items():
                fout = get_scan_file(target, protocol + '.' + key)
                cmd = template_replace(
                    cmd, target, fout, wordlist, userlist, passlist)
                if '<ports>' in cmd:
                    cmds.append(cmd.replace('<ports>', ports_str))
                elif '<port>' in cmd:
                    cmds.extend([cmd.replace('<port>', str(port)) for
                                 port in port_ints])
                else:
                    cmds.append(cmd)

            # write to recommendations file
            with open(get_recommendations_txt_file(target), 'a') as f:
                fprint = partial(print, sep='', file=f)
                recs = config['recommendations']
                if recs:
                    fprint('Recommendations for protocol `', protocol,
                           '` on ports ', ports_str, ':')
                    for cmd in recs:
                        cmd = template_replace(
                            cmd, target, fout, wordlist, userlist, passlist)
                        if '<ports>' in cmd:
                            fprint(cmd.replace('<ports>', ports_str))
                        elif '<port>' in cmd:
                            for port in port_ints:
                                fprint(cmd.replace('<port>', str(port)))
                        else:
                            fprint(cmd)
                    fprint()

            print_i_d2(target, ': finished configuring scans and '
                       'recommendations for protocol `', protocol, '`')

    return cmds


def template_replace(cmd_template: str, target: str, fout: str, wordlist: str,
                     userlist: str, passlist: str):
    """Replace values in a command template."""
    return (cmd_template.replace('<target>', target)
                        .replace('<fout>', fout)
                        .replace('<wordlist>', wordlist)
                        .replace('<userlist>', userlist)
                        .replace('<passlist>', passlist))


def match_patterns(target: str, line: str) -> None:
    """Print a string with matched patterns highlighted in purple."""
    patterns = get_config_value('patterns')
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

