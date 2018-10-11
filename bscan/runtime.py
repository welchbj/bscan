"""Asynchronous-access global application configuration."""

import asyncio
import re
import os
import shutil
import toml

from argparse import Namespace
from asyncio import Lock
from collections import namedtuple
from pkg_resources import resource_string
from typing import (
    Any,
    Dict,
    Set)

from bscan.errors import (
    BscanConfigError,
    BscanInternalError)
from bscan.io import (
    print_i_d2,
    dir_exists,
    file_exists)

db: Dict[str, Any] = dict()
lock = Lock()

_STATUS_POLL_PERIOD = 0.5

RuntimeStats = namedtuple(
    'RuntimeStats',
    ['num_active_targets', 'num_total_subprocs'])
"""An encapsulation of system-wide running subprocess stats."""


def load_config_file(filename: str) -> str:
    """Packaged-friendly solution to loading file contents as a string."""
    try:
        raw_contents = resource_string(__name__, 'configuration/' + filename)
    except FileNotFoundError:
        raise BscanConfigError(
            'Unable to find configuration file `' + filename + '`')
    return raw_contents.decode('utf-8')


async def init_db(ns: Namespace) -> None:
    """Init configuration from default files and command-line arguments."""
    async with lock:
        if ns.brute_pass_list is None:
            db['brute-pass-list'] = '/usr/share/wordlists/fasttrack.txt'
        else:
            db['brute-pass-list'] = ns.brute_pass_list
        if not ns.no_file_check and not file_exists(db['brute-pass-list']):
            raise BscanConfigError(
                '`--brute-pass-list` file ' + db['brute-pass-list'] +
                ' does not exist')

        if ns.brute_user_list is None:
            db['brute-user-list'] = (
                '/usr/share/wordlists/metasploit/namelist.txt')
        else:
            db['brute-user-list'] = ns.brute_user_list
        if not ns.no_file_check and not file_exists(db['brute-user-list']):
            raise BscanConfigError(
                '`--brute-user-list` file ' + db['brute-user-list'] +
                ' does not exist')

        if ns.output_dir is None:
            db['output-dir'] = os.getcwd()
        else:
            db['output-dir'] = ns.output_dir
        if not dir_exists(db['output-dir']):
            raise BscanConfigError(
                '`--output-dir` directory ' + db['output-dir'] +
                ' does not exist')

        patterns = load_config_file('patterns.txt').splitlines()
        if ns.patterns is not None:
            if not ns.patterns:
                raise BscanConfigError(
                    '`--patterns` requires at least one regex pattern')
            else:
                patterns.extend(ns.patterns)
        db['patterns'] = re.compile('|'.join(patterns))

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

        if ns.quick_scan is None or ns.quick_scan == 'unicornscan':
            db['quick-scan'] = 'unicornscan'
        elif ns.quick_scan == 'nmap':
            raise BscanConfigError(
                'Nmap quick scan not yet implemented, use `unicornscan`')
        else:
            raise BscanConfigError(
                'Invalid --quick-scan option; must be either '
                '`unicornscan` or `nmap`')

        db['services'] = toml.loads(load_config_file('services.toml'))

        try:
            interval = (30 if ns.status_interval is None
                        else int(ns.status_interval))
        except ValueError:
            raise BscanConfigError(
                'Invalid `--status-interval` integer specified: ' +
                str(ns.status_interval))
        db['status-interval'] = interval

        db['subprocesses'] = dict()

        if ns.web_word_list is None:
            db['web-word-list'] = '/usr/share/dirb/wordlists/big.txt'
        else:
            db['web-word-list'] = ns.web_word_list
        if not ns.no_file_check and not file_exists(db['web-word-list']):
            raise BscanConfigError(
                '`--web-word-list` file ' + db['web-word-list'] +
                ' does not exist')

        db['quick-only'] = ns.quick_only
        db['hard'] = ns.hard

        if ns.ping_sweep:
            raise BscanConfigError(
                '`--ping-sweep` option not yet implemented')
        db['ping-sweep'] = ns.ping_sweep

        db['udp'] = ns.udp


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


async def init_subproc_set(target: str) -> None:
    """Initialize a list for tracking subprocesses related to a target."""
    subproc_dict = db['subprocesses']
    if target in subproc_dict:
        raise BscanInternalError(
            'Attempted to initialize existing subprocess set entry for '
            'target ' + target)

    async with lock:
        subproc_dict[target] = set()


async def remove_subproc_set(target: str) -> None:
    """Remove the set of subprocesses related to a target."""
    subproc_dict = db['subprocesses']
    if target not in subproc_dict:
        raise BscanInternalError(
            'Attempted to remove non-existent subprocess set for target ' +
            target)

    async with lock:
        subproc_dict.pop(target)


async def add_running_subproc(target: str, cmd: str) -> None:
    """Add a subprocess to the set associateed with a target."""
    subproc_set = _get_subproc_set(target)
    if cmd in subproc_set:
        raise BscanInternalError(
            'Attempted to add already-running subprocess `' + cmd +
            '` for target ' + target)

    async with lock:
        subproc_set.add(cmd)


async def remove_running_subproc(target: str, cmd: str) -> None:
    """Remove a subprocess from the set associated with a target."""
    subproc_set = _get_subproc_set(target)
    if cmd not in subproc_set:
        raise BscanInternalError(
            'Attempted to remove non-existent subprocess `' + cmd +
            '` for target ' + target)

    async with lock:
        subproc_set.remove(cmd)


async def status_update_poller() -> None:
    """Coroutine for periodically printing updates about the scan status."""
    interval = get_db_value('status-interval')
    if interval <= 0:
        raise BscanInternalError(
            'Attempted status update polling with non-positive interval of ' +
            str(interval))

    time_elapsed = float(0)
    while True:
        stats: RuntimeStats = get_runtime_stats()
        if stats.num_active_targets < 1:
            break

        await asyncio.sleep(_STATUS_POLL_PERIOD)
        time_elapsed += _STATUS_POLL_PERIOD
        if time_elapsed >= interval:
            time_elapsed = float(0)
            print_i_d2(
                'Scan status: ', stats.num_total_subprocs,
                ' spawned subprocess(es) currently running across ',
                stats.num_active_targets, ' target(s)')


def get_runtime_stats() -> RuntimeStats:
    """Get the stats associated with the running subprocesses."""
    subproc_dict = db['subprocesses']
    num_active_targets = len(subproc_dict.keys())
    num_total_subprocs = sum(len(s) for _, s in subproc_dict.items())
    return RuntimeStats(
        num_active_targets,
        num_total_subprocs)


def _get_subproc_set(target: str) -> Set[str]:
    """Ensure and return  a subprocess set for a target."""
    if target not in db['subprocesses']:
        raise BscanInternalError(
            'Attempted to access uninitialized subprocess set for target ' +
            target)

    return db['subprocesses'][target]
