"""Configuration initialization and handling."""

import os
import re
import shutil
import sys
import toml

from argparse import (
    Namespace)
from collections import (
    namedtuple)
from pkg_resources import (
    resource_string)
from typing import (
    Optional)

from bscan.errors import (
    BscanConfigError)
from bscan.io_console import (
    print_w_d2)
from bscan.io_files import (
    dir_exists,
    file_exists)
from bscan.runtime import (
    db,
    lock)


DEFAULT_WORDLIST_SEARCH_DIRS = [
    '/usr/share/wordlists/',
    '/usr/share/seclists/Passwords/']

PortScanConfig = namedtuple(
    'PortScanConfig',
    ['name', 'pattern', 'scan'])
"""Encapsulation of data parsed from `port-scans.toml` file."""


def good_py_version() -> bool:
    """Verify that this program is being run with the expected version."""
    return sys.version_info.major >= 3 and sys.version_info.minor >= 6


def py_version_str() -> str:
    """Get the running Python version as a string."""
    return str(sys.version_info.major) + '.' + str(sys.version_info.minor)


def load_default_config_file(filename: str) -> str:
    """Packaged-friendly method to load contents of a default config file."""
    try:
        pyinst_basedir = getattr(sys, '_MEIPASS', None)
        if pyinst_basedir is not None:
            # load configuration from PyInstaller bundle
            filepath = os.path.join(pyinst_basedir, 'configuration', filename)
            with open(filepath, 'r') as f:
                raw_contents = f.read()
        else:
            # load configuration from either Python wheel or the filesystem
            raw_contents = resource_string(
                __name__, 'configuration/' + filename).decode('utf-8')
    except FileNotFoundError:
        raise BscanConfigError(
            'Unable to find default configuration file `' + filename + '`')

    return raw_contents


def load_config_file(filename: str, base_dir: Optional[str]=None) -> str:
    """Load config file from specified base_dir, falling back on defaults."""
    if base_dir is None:
        return load_default_config_file(filename)
    elif not dir_exists(base_dir):
        print_w_d2('Specified `--output-dir` ', base_dir, ' does not exist, '
                   'falling back to default configuration file for ', filename)
        return load_default_config_file(filename)

    path = os.path.join(base_dir, filename)
    if file_exists(path):
        with open(path, 'r') as f:
            return f.read()
    else:
        print_w_d2('File ', filename, ' not found in specified `--output-dir`'
                   ', falling back to default configuration file for ',
                   filename)
        return load_default_config_file(filename)


async def init_config(ns: Namespace) -> None:
    """Init configuration from default files and command-line arguments."""
    async with lock:
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
        patterns = load_config_file(
            'patterns.txt',
            ns.config_dir).splitlines()
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
            progs = load_config_file(
                'required-programs.txt',
                ns.config_dir).splitlines()
            for prog in progs:
                if shutil.which(prog) is None:
                    not_found_progs.append(prog)

            if not_found_progs:
                raise BscanConfigError(
                    'required programs ' + ', '.join(not_found_progs) +
                    ' could not be found on this system')

        # --no-service-scans
        db['no-service-scans'] = ns.no_service_scans

        # load service information from `configuration/service-scans.toml`
        db['services'] = toml.loads(
            load_config_file('service-scans.toml', ns.config_dir))

        # load quick scan method configuration
        # derived from `--qs-method` + `configuration/port-scans.toml`
        port_scan_config = toml.loads(
            load_config_file('port-scans.toml', ns.config_dir))
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
