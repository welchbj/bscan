"""Command-line interface for `bscan`."""

import sys

from argparse import (
    ArgumentParser,
    Namespace,
    RawTextHelpFormatter)
from colorama import init as colorama_init
from typing import List

from bscan.errors import (
    BscanError,
    BscanInputError,
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
    is_valid_ip_host_addr,
    is_valid_ip_net_addr)
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
        '--hard',
        action='store_true',
        default=False,
        help='force overwrite of existing directories')

    parser.add_argument(
        '--patterns',
        action='store',
        nargs='*',
        metavar='PATTERN',
        help='patterns to highlight in output text')

    parser.add_argument(
        '--ping-sweep',
        action='store_true',
        help='whether to filter hosts from a network via a ping sweep before '
             'more intensive scans')

    parser.add_argument(
        '--quick-scan',
        action='store',
        default='unicornscan',
        metavar='METHOD',
        help='the method for peforming the initial port scan:\n'
             '`unicornscan` or `nmap`')

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


def main(args: List[str]=None) -> int:
    """Main entry point for `bscan`'s command-line interface.

    Args:
        args: Custom arguments to override ``sys.argv``.

    Returns:
        The exit code of the program

    """
    try:
        colorama_init()
        opts = get_parsed_args(args)
        if opts.quick_scan not in ('unicornscan', 'nmap',):
            print_e_d1('`--quick-scan` must be either `unicornscan` or `nmap`')
        elif opts.quick_scan != 'unicornscan':
            print_e_d1('The only currently supported `--quick-scan` option is '
                       '`--unicornscan`')

        # TODO: handle patterns
        # TODO: validate web word list
        # TODO: implement ping sweep for networks

        print_i_d1('Colors: ', blue('info'), ', ', yellow('warnings'), ', ',
                   red('errors'), ', and ', purple('pattern matches'), sep='')

        if not opts.targets:
            print_e_d1('No targets specified; use `--help` to figure out what '
                       'you\'re doing')

        for target in opts.targets:
            if is_valid_ip_host_addr(target):
                pass
            elif is_valid_ip_net_addr(target):
                print_w_d1('Network scanning not yet supported; '
                           'skipping network: ', target)
                continue
            else:
                print_e_d1('Unable to parse target ', target, ', skipping it')
                continue

            create_dir_skeleton(target, opts.hard)
        return 0
    except BscanInputError as e:
        # TODO
        return 1
    except BscanSubprocessError as e:
        # TODO
        return 1
    except BscanError as e:
        # TODO
        return 1
    except Exception as e:
        print_e_d1('Received unexpected exception; re-raising it.',
                   file=sys.stderr)
        raise e
