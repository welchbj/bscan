"""Asynchronous-access global application configuration."""

import re
import os
import shutil
import toml

from argparse import Namespace
from asyncio import Lock
from pkg_resources import resource_string
from typing import (
    Any,
    Dict)

from bscan.errors import (
    BscanConfigError,
    BscanInternalError)
from bscan.io import (
    dir_exists,
    file_exists)

db: Dict[str, Any] = dict()
lock = Lock()


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
