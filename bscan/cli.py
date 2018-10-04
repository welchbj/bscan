"""Command-line interface for `bscan`."""

import asyncio
import sys

from argparse import (
    ArgumentParser,
    Namespace,
    RawTextHelpFormatter)
from colorama import init as init_colorama
from typing import List

from bscan.config import (
    init_config)
from bscan.errors import (
    BscanConfigError,
    BscanError,
    BscanForceSkipTarget,
    BscanForceSilentExit,
    BscanSubprocessError)
from bscan.io import (
    blue,
    print_e_d1,
    print_i_d1,
    print_w_d1,
    purple,
    red,
    yellow)
from bscan.networks import (
    is_valid_hostname,
    is_valid_ip_host_addr,
    is_valid_ip_net_addr)
from bscan.scans import scan_target
from bscan.structure import create_dir_skeleton
from bscan.version import __version__


def get_parsed_args(args: List[str]=None) -> Namespace:
    """Get the parsed command-line arguments.

    Args:
        args: Arguments to use in place of ``sys.argv``.

    """
    parser = ArgumentParser(
        prog='bscan',
        usage='bscan [OPTIONS] targets',
        description=(
            " _\n"
            "| |__  ___  ___ __ _ _ __\n"
            "| '_ \/ __|/ __/ _` | '_ \\\n"
            "| |_) \__ \ (__ (_| | | | |\n"
            "|_.__/|___/\___\__,_|_| |_|\n\n"
            'An asynchronous service enumeration tool'),
        formatter_class=RawTextHelpFormatter)

    parser.add_argument(
        '--brute-pass-list',
        action='store',
        help='password list to use for brute-forcing')

    parser.add_argument(
        '--brute-user-list',
        action='store',
        help='user list to use for brute-forcing')

    parser.add_argument(
        '--hard',
        action='store_true',
        default=False,
        help='force overwrite of existing directories')

    parser.add_argument(
        '--no-fcheck',
        action='store_true',
        default=False,
        help='disable checking the presence of files such as configured\n'
             'wordlists')

    parser.add_argument(
        '--output-dir',
        action='store',
        help='the base directory in which to write output files')

    parser.add_argument(
        '--patterns',
        action='store',
        nargs='*',
        metavar='PATTERN',
        help='patterns to highlight in output text')

    parser.add_argument(
        '--ping-sweep',
        action='store_true',
        help='whether to filter hosts from a network via a ping sweep before\n'
             'more intensive scans')

    parser.add_argument(
        '--quick-only',
        action='store_true',
        default=False,
        help='whether to only run the quick scan (and not include the\n'
             'thorough scan over all ports)')

    parser.add_argument(
        '--quick-scan',
        action='store',
        default='unicornscan',
        metavar='METHOD',
        help='the method for peforming the initial port scan:\n'
             '`unicornscan` or `nmap`')

    parser.add_argument(
        '--udp',
        action='store_true',
        default=False,
        help='whether to run UDP scans')

    parser.add_argument(
        '--version',
        action='version',
        version=str(__version__),
        help='program version')

    parser.add_argument(
        '--web-word-list',
        action='store',
        type=str,
        metavar='LIST',
        help='the wordlist to use for scans')

    parser.add_argument(
        'targets',
        nargs='*',
        help='the targets and/or networks on which to perform enumeration')

    if args is None:
        args = sys.argv[1:]

    return parser.parse_args(args)


async def main(args: List[str]=None) -> int:
    """Main entry point for `bscan`'s command-line interface.

    Args:
        args: Custom arguments to override ``sys.argv``.

    Returns:
        The exit code of the program.

    """
    try:
        init_colorama()
        opts = get_parsed_args(args)
        print_i_d1('Initializing configuration from command-line arguments')
        await init_config(opts)

        # TODO: check output directory exists
        # TODO: handle patterns
        # TODO: validate web word list
        # TODO: implement ping sweep for networks

        print_i_d1('Colors: ', blue('info'), ', ', yellow('warnings'), ', ',
                   red('errors'), ', and ', purple('pattern matches'), sep='')

        if not opts.targets:
            print_e_d1('No targets specified; use `--help` to figure out what '
                       'you\'re doing')
            return 1

        # TODO: create a full list of targets from network address and
        #       --ping-sweep filtering
        targets = []
        for candidate in opts.targets:
            if is_valid_ip_host_addr(candidate):
                pass
            elif is_valid_hostname(candidate):
                pass
            elif is_valid_ip_net_addr(candidate):
                print_w_d1('Network scanning not yet supported; '
                           'skipping network: ', candidate)
                continue
            else:
                # TODO: handle host names
                print_e_d1('Unable to parse target ', candidate,
                           ', skipping it')
                continue

            try:
                create_dir_skeleton(candidate)
            except BscanForceSkipTarget as e:
                print_e_d1(e.message)
                print_e_d1(candidate, ': skipping this target')
                continue

            targets.append(candidate)

        if targets:
            print_i_d1('Kicking off scans of ', len(targets), ' targets')
            await asyncio.gather(*[scan_target(target) for target in targets])
        else:
            print_e_d1('No valid targets specified')
            return 1

        print_i_d1('Completed execution')
        return 0
    except BscanConfigError as e:
        print_e_d1('Configuration error: ', e.message)
        return 1
    except BscanSubprocessError as e:
        # TODO
        return 1
    except BscanForceSilentExit as e:
        # TODO
        return 1
    except BscanError as e:
        # TODO
        return 1
    except Exception as e:
        print_e_d1('Received unexpected exception; re-raising it.',
                   file=sys.stderr)
        raise e
