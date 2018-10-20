"""Asynchronous-access global application configuration."""

import asyncio

from asyncio import Lock
from collections import namedtuple
from typing import (
    Any,
    AsyncGenerator,
    Dict)

from bscan.errors import BscanInternalError
from bscan.io_console import (
    print_i_d2,
    print_i_d3,
    print_w_d3,
    shortened_cmd)

db: Dict[str, Any] = dict()
lock = Lock()

_STATUS_POLL_PERIOD = 0.5

RuntimeStats = namedtuple(
    'RuntimeStats',
    ['num_active_targets', 'num_total_subprocs'])
"""An encapsulation of system-wide running subprocess stats."""


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
