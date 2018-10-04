"""Asynchronous-access global application configuration."""

import re
import os
import toml

from argparse import Namespace
from asyncio import Lock

from bscan.errors import (
    BscanConfigError,
    BscanInternalError)
from bscan.io import (
    dir_exists,
    file_exists)


THIS_DIR = os.path.dirname(os.path.realpath(__file__))
BSCAN_BASE_DIR = os.path.dirname(THIS_DIR)
CONFIGURATION_DIR = os.path.join(BSCAN_BASE_DIR, 'configuration')
PATTERNS_FILE = os.path.join(CONFIGURATION_DIR, 'patterns.txt')
SERVICES_FILE = os.path.join(CONFIGURATION_DIR, 'services.toml')

config = dict()
lock = Lock()


async def init_config(ns: Namespace) -> None:
    """Init configuration from default files and command-line arguments."""
    async with lock:
        if ns.brute_pass_list is None:
            config['brute-pass-list'] = '/usr/share/wordlists/fasttrack.txt'
        else:
            config['brute-pass-list'] = ns.brute_pass_list
        if not ns.no_fcheck and not file_exists(config['brute-pass-list']):
            raise BscanConfigError(
                '`--brute-pass-list` file ' + config['brute-pass-list'] +
                ' does not exist')

        if ns.brute_user_list is None:
            config['brute-user-list'] = (
                '/usr/share/wordlists/metasploit/namelist.txt')
        else:
            config['brute-user-list'] = ns.brute_user_list
        if not ns.no_fcheck and not file_exists(config['brute-user-list']):
            raise BscanConfigError(
                '`--brute-user-list` file ' + config['brute-user-list'] +
                ' does not exist')

        if ns.output_dir is None:
            config['output-dir'] = os.getcwd()
        else:
            config['output-dir'] = ns.output_dir
        if not dir_exists(config['output-dir']):
            raise BscanConfigError(
                '`--output-dir` directory ' + config['output-dir'] +
                ' does not exist')

        patterns = []
        with open(PATTERNS_FILE, 'r') as f:
            for line in f:
                patterns.append(line.rstrip('\n'))
        if ns.patterns is not None:
            if not ns.patterns:
                raise BscanConfigError(
                    '`--patterns` requires at least one regex pattern')
            else:
                patterns.extend(ns.patterns)
        config['patterns'] = re.compile('|'.join(patterns))

        if ns.quick_scan is None or ns.quick_scan == 'unicornscan':
            config['quick-scan'] = 'unicornscan'
        elif ns.quick_scan == 'nmap':
            raise BscanConfigError(
                'Nmap quick scan not yet implemented, use `unicornscan`')
        else:
            raise BscanConfigError(
                'Invalid --quick-scan option; must be either '
                '`unicornscan` or `nmap`')

        with open(SERVICES_FILE, 'r') as f:
            config['services'] = toml.loads(f.read())

        if ns.web_word_list is None:
            config['web-word-list'] = '/usr/share/dirb/wordlists/big.txt'
        else:
            config['web-word-list'] = ns.web_word_list
        if not ns.no_fcheck and not file_exists(config['web-word-list']):
            raise BscanConfigError(
                '`--web-word-list` file ' + config['web-word-list'] +
                ' does not exist')

        config['quick-only'] = ns.quick_only
        config['hard'] = ns.hard

        if ns.ping_sweep:
            raise BscanConfigError(
                '`--ping-sweep` option not yet implemented')
        config['ping-sweep'] = ns.ping_sweep

        config['udp'] = ns.udp


async def write_config_value(key: str, val: object) -> None:
    """Set a configuraton value."""
    async with lock:
        config[key] = val


def get_config_value(key: str) -> object:
    """Retrieve a configuration value."""
    try:
        return config[key]
    except KeyError:
        raise BscanInternalError(
            'Attempted to access unknown configuration key')
