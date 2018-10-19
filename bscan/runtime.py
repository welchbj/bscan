"""Asynchronous-access global application configuration."""

import asyncio
import os
import re
import shutil
import sys
import toml

from argparse import Namespace
from asyncio import Lock
from collections import namedtuple
from pkg_resources import resource_string
from sublemon import Sublemon
from typing import (
    Any,
    AsyncGenerator,
    Dict)

from bscan.errors import (
    BscanConfigError,
    BscanInternalError)
from bscan.io import (
    print_i_d2,
    print_i_d3,
    print_w_d3,
    dir_exists,
    file_exists,
    shortened_cmd)

db: Dict[str, Any] = dict()
lock = Lock()

_STATUS_POLL_PERIOD = 0.5

DEFAULT_WORDLIST_SEARCH_DIRS = [
    '/usr/share/wordlists/',
    '/usr/share/seclists/Passwords/']

PortScanConfig = namedtuple(
    'PortScanConfig',
    ['name', 'pattern', 'scan'])

RuntimeStats = namedtuple(
    'RuntimeStats',
    ['num_active_targets', 'num_total_subprocs'])
"""An encapsulation of system-wide running subprocess stats."""


def good_py_version() -> bool:
    """Verify that this program is being run with the expected version."""
    return sys.version_info.major >= 3 and sys.version_info.minor >= 6


def py_version_str() -> str:
    """Get the running Python version as a string."""
    return str(sys.version_info.major) + '.' + str(sys.version_info.minor)


def load_config_file(filename: str) -> str:
    """Packaged-friendly solution to loading file contents as a string."""
    try:
        raw_contents = resource_string(__name__, 'configuration/' + filename)
    except FileNotFoundError:
        raise BscanConfigError(
            'Unable to find configuration file `' + filename + '`')
    return raw_contents.decode('utf-8')


async def init_db(ns: Namespace, subl: Sublemon) -> None:
    """Init configuration from default files and command-line arguments."""
    async with lock:
        # track subprocess-management server
        db['sublemon'] = subl

        # track targets being actively scanned
        db['active-targets'] = set()

        # --brute-pass-list
        if ns.brute_pass_list is None:
            db['brute-pass-list'] = '/usr/share/wordlists/fasttrack.txt'
        else:
            db['brute-pass-list'] = ns.brute_pass_list
        if not ns.no_file_check and not file_exists(db['brute-pass-list']):
            raise BscanConfigError(
                '`--brute-pass-list` file ' + db['brute-pass-list'] +
                ' does not exist')

        # --brute-user-list
        if ns.brute_user_list is None:
            db['brute-user-list'] = (
                '/usr/share/wordlists/metasploit/namelist.txt')
        else:
            db['brute-user-list'] = ns.brute_user_list
        if not ns.no_file_check and not file_exists(db['brute-user-list']):
            raise BscanConfigError(
                '`--brute-user-list` file ' + db['brute-user-list'] +
                ' does not exist')

        # --cmd-print-width
        try:
            cmd_print_width = (80 if ns.cmd_print_width is None
                               else int(ns.cmd_print_width))
            if cmd_print_width < 5:
                raise ValueError
        except ValueError:
            raise BscanConfigError(
                'Invalid `--cmd-print-width` value specified; must be an '
                'integer greater than or equal to 5')
        db['cmd-print-width'] = cmd_print_width

        # --output-dir
        if ns.output_dir is None:
            db['output-dir'] = os.getcwd()
        else:
            db['output-dir'] = ns.output_dir
        if not dir_exists(db['output-dir']):
            raise BscanConfigError(
                '`--output-dir` directory ' + db['output-dir'] +
                ' does not exist')

        # --patterns; also loads from `configuration/patterns.txt`
        patterns = load_config_file('patterns.txt').splitlines()
        if ns.patterns is not None:
            if not ns.patterns:
                raise BscanConfigError(
                    '`--patterns` requires at least one regex pattern')
            else:
                patterns.extend(ns.patterns)
        db['patterns'] = re.compile('|'.join(patterns))

        # --no-program-check
        if not ns.no_program_check:
            not_found_progs = []
            progs = load_config_file('required-programs.txt').splitlines()
            for prog in progs:
                if shutil.which(prog) is None:
                    not_found_progs.append(prog)

            if not_found_progs:
                raise BscanConfigError(
                    'required programs ' + ', '.join(not_found_progs) +
                    ' could not be found on this system')

        # load service information from `configuration/service-scans.toml`
        db['services'] = toml.loads(load_config_file('service-scans.toml'))

        # load quick scan method configuration
        # derived from `--qs-method` + `configuration/port-scans.toml`
        port_scan_config = toml.loads(load_config_file('port-scans.toml'))
        qs_config = port_scan_config['quick']
        qs_method_name = (ns.qs_method if ns.qs_method is not None else
                          qs_config['default'])
        if qs_method_name not in qs_config or qs_method_name == 'default':
            raise BscanConfigError(
                'Invalid `--qs-method` specified: ' + str(qs_method_name))
        qs_attrs = qs_config[qs_method_name]
        db['quick-scan'] = PortScanConfig(
            qs_method_name,
            re.compile(qs_attrs['pattern']),
            qs_attrs['scan'])

        # load thorough scan method configuration
        # derived from `--ts-method` + `configuration/port-scans.toml`
        ts_config = port_scan_config['thorough']
        ts_method_name = (ns.ts_method if ns.ts_method is not None else
                          ts_config['default'])
        if ts_method_name not in ts_config or ts_method_name == 'default':
            raise BscanConfigError(
                'Invalid `--ts-method` specified: ' + str(ts_method_name))
        ts_attrs = ts_config[ts_method_name]
        db['thorough-scan'] = PortScanConfig(
            ts_method_name,
            re.compile(ts_attrs['pattern']),
            ts_attrs['scan'])

        # load udp scan method configuration
        # derived from `--udp-method` + `configuration/port-scans.toml`
        udp_config = port_scan_config['udp']
        udp_method_name = (ns.udp_method if ns.udp_method is not None else
                           udp_config['default'])
        if udp_method_name not in udp_config or udp_method_name == 'default':
            raise BscanConfigError(
                'Invalid `--udp-method` specified: ' + str(udp_method_name))
        udp_attrs = udp_config[udp_method_name]
        db['udp-scan'] = PortScanConfig(
            udp_method_name,
            re.compile(udp_attrs['pattern']),
            udp_attrs['scan'])

        # --status-interval
        try:
            db['status-interval'] = (30 if ns.status_interval is None
                                     else int(ns.status_interval))
        except ValueError:
            raise BscanConfigError(
                'Invalid `--status-interval` integer specified: ' +
                str(ns.status_interval))

        # runtime tracking of active subprocesses
        db['subprocesses'] = dict()

        # --web-word-list
        if ns.web_word_list is None:
            db['web-word-list'] = '/usr/share/dirb/wordlists/big.txt'
        else:
            db['web-word-list'] = ns.web_word_list
        if not ns.no_file_check and not file_exists(db['web-word-list']):
            raise BscanConfigError(
                '`--web-word-list` file ' + db['web-word-list'] +
                ' does not exist')

        # --quick-only
        db['quick-only'] = ns.quick_only

        # --hard
        db['hard'] = ns.hard

        # --ping-sweep
        if ns.ping_sweep:
            raise BscanConfigError(
                '`--ping-sweep` option not yet implemented')
        db['ping-sweep'] = ns.ping_sweep

        # --udp
        db['udp'] = ns.udp

        # --verbose-status
        db['verbose-status'] = ns.verbose_status


async def write_db_value(key: str, val: Any) -> None:
    """Set a database value."""
    async with lock:
        db[key] = val


def get_db_value(key: str) -> Any:
    """Retrieve a database value."""
    try:
        return db[key]
    except KeyError:
        raise BscanInternalError(
            'Attempted to access unknown database key')


async def add_active_target(target: str) -> None:
    """Add the specified target as being currently-scanned."""
    target_set = db['active-targets']
    if target in target_set:
        raise BscanInternalError(
            'Attempted to add already-active target ' + target + ' to set of '
            'actively-scanned targets')

    async with lock:
        target_set.add(target)


async def remove_active_target(target: str) -> None:
    """Remove the specified target as being currently-scanned."""
    target_set = db['active-targets']
    if target not in target_set:
        raise BscanInternalError(
            'Attempted to remove non-active target ' + target + ' from set ' +
            'of actively-scanned targets')

    async with lock:
        target_set.remove(target)


async def proc_spawn(target: str, cmd: str) -> AsyncGenerator[str, None]:
    """Asynchronously yield lines from stdout of a spawned subprocess."""
    cmd_len = get_db_value('cmd-print-width')
    subl = get_db_value('sublemon')
    print_i_d3(target, ': spawning subprocess ', shortened_cmd(cmd, cmd_len))
    sp, = subl.spawn(cmd)
    async for line in sp.stdout:
        yield line.decode('utf-8').strip()

    exit_code = await sp.wait_done()
    if exit_code != 0:
        print_w_d3(target, ': subprocess ', shortened_cmd(cmd, cmd_len),
                   ' exited with non-zero exit code of ', exit_code)


async def status_update_poller() -> None:
    """Coroutine for periodically printing updates about the scan status."""
    interval = get_db_value('status-interval')
    verbose = get_db_value('verbose-status')
    cmd_len = get_db_value('cmd-print-width')
    if interval <= 0:
        raise BscanInternalError(
            'Attempted status update polling with non-positive interval of ' +
            str(interval))

    time_elapsed = float(0)
    while True:
        await asyncio.sleep(_STATUS_POLL_PERIOD)

        stats: RuntimeStats = get_runtime_stats()
        if stats.num_active_targets < 1:
            break

        time_elapsed += _STATUS_POLL_PERIOD
        if time_elapsed >= interval:
            time_elapsed = float(0)
            msg = ('Scan status: ' + str(stats.num_total_subprocs) +
                   ' spawned subprocess(es) currently running across ' +
                   str(stats.num_active_targets) + ' target(s)')
            if verbose:
                subl = db['sublemon']
                print_i_d2(msg, ', listed below')
                for sp in subl.running_subprocesses:
                    print_i_d3(shortened_cmd(sp.cmd, cmd_len))
            else:
                print_i_d2(msg)


def get_runtime_stats() -> RuntimeStats:
    """Computer and return the runtime statistics object."""
    return RuntimeStats(
        len(db['active-targets']),
        len(db['sublemon'].running_subprocesses))
