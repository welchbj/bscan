"""Asynchronous-access global application configuration."""

import os

from argparse import Namespace
from asyncio import Lock

from bscan.errors import (
    BscanConfigError,
    BscanInternalError)
from bscan.io import (
    print_i_d1,
    print_w_d2)


config = dict()
lock = Lock()


async def init_config(ns: Namespace) -> None:
    """Initialize the configuration from parsed command-line arguments."""
    async with lock:
        print_i_d1('Initializing configuration from command-line arguments')
        if ns.brute_pass_list is None:
            config['brute-pass-list'] = '/usr/share/wordlists/fasttrack.txt'
        else:
            config['brute-pass-list'] = ns.brute_pass_list
        # TODO: validate existence of file

        if ns.brute_user_list is None:
            config['brute-user-list'] = (
                '/usr/share/wordlists/metasploit/namelist.txt')
        else:
            config['brute-user-list'] = ns.brute_user_list
        # TODO: validate existence of file

        if ns.output_dir is None:
            config['output-dir'] = os.getcwd()
        else:
            config['output-dir'] = ns.output_dir
        # TODO: validate existence of file

        if ns.patterns is None:
            # TODO: implement this
            pass
        else:
            print_w_d2('--patterns functionality not yet implemented, '
                       'ignoring it')
        # TODO: validate pattern syntax

        if ns.quick_scan is None or ns.quick_scan == 'unicornscan':
            config['quick-scan'] = 'unicornscan'
        elif ns.quick_scan == 'nmap':
            print_w_d2('Nmap quick scan not yet implemented, overriding to '
                       'unicornscan')
            config['quick-scan'] = 'unicornscan'
        else:
            print_w_d2('Unrecognized --quick-scan option; must be either '
                       '`unicornscan` or `nmap`')
            raise BscanConfigError('Invalid --quick-scan option')
        # TODO: support for specify a file as the input source

        if ns.web_word_list is None:
            config['web-word-list'] = '/usr/share/dirb/wordlists/big.txt'
        else:
            config['web-word-list'] = ns.web_word_list
        # TODO: validate existence of file

        config['hard'] = ns.hard

        if ns.ping_sweep:
            print_w_d2('--ping-sweep option not yet implement, disabling it')
        config['ping-sweep'] = False


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
