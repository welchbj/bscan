"""Command-line interface for `bscan`."""

import asyncio
import sys

from argparse import (
    ArgumentParser,
    Namespace,
    RawTextHelpFormatter)
from colorama import init as init_colorama
from sublemon import Sublemon
from typing import (
    List,
    Optional)

from bscan.config import (
    init_config,
    good_py_version,
    py_version_str)
from bscan.errors import (
    BscanConfigError,
    BscanError,
    BscanForceSkipTarget,
    BscanForceSilentExit,
    BscanInternalError,
    BscanSubprocessError)
from bscan.io_console import (
    print_color_info,
    print_e_d1,
    print_i_d1,
    print_w_d1)
from bscan.networks import (
    is_valid_hostname,
    is_valid_ip_host_addr,
    is_valid_ip_net_addr)
from bscan.scans import scan_target
from bscan.structure import create_dir_skeleton
from bscan.runtime import (
    get_db_value,
    status_update_poller,
    write_db_value)
from bscan.version import __version__


def get_parsed_args(args: Optional[List[str]]=None) -> Namespace:
    """Get the parsed command-line arguments.

    Args:
        args: Arguments to use in place of `sys.argv`.

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
            'an asynchronous service enumeration tool'),
        formatter_class=RawTextHelpFormatter)

    parser.add_argument(
        '--brute-pass-list',
        action='store',
        metavar='F',
        help='filename of password list to use for brute-forcing')

    parser.add_argument(
        '--brute-user-list',
        action='store',
        metavar='F',
        help='filename of user list to use for brute-forcing')

    parser.add_argument(
        '--cmd-print-width',
        action='store',
        metavar='I',
        help='the maximum integer number of characters allowed when printing\n'
             'the command used to spawn a running subprocess (defaults to 80)')

    parser.add_argument(
        '--config-dir',
        action='store',
        metavar='D',
        help='the base directory from which to load the configuration files;\n'
             'required configuration files missing from this directory will\n'
             'instead be loaded from the default files shipped with this\n'
             'program')

    parser.add_argument(
        '--hard',
        action='store_true',
        default=False,
        help='force overwrite of existing directories')

    parser.add_argument(
        '--max-concurrency',
        action='store',
        metavar='I',
        help='maximum integer number of subprocesses permitted to be running\n'
             'concurrently (defaults to 20)')

    parser.add_argument(
        '--no-program-check',
        action='store_true',
        default=False,
        help='disable checking the presence of required system programs')

    parser.add_argument(
        '--no-file-check',
        action='store_true',
        default=False,
        help='disable checking the presence of files such as configured\n'
             'wordlists')

    parser.add_argument(
        '--output-dir',
        action='store',
        metavar='D',
        help='the base directory in which to write output files')

    parser.add_argument(
        '--patterns',
        action='store',
        nargs='*',
        metavar='',
        help='regex patterns to highlight in output text')

    parser.add_argument(
        '--ping-sweep',
        action='store_true',
        help='enable ping sweep filtering of hosts from a network range\n'
             'before running more intensive scans')

    parser.add_argument(
        '--quick-only',
        action='store_true',
        default=False,
        help='whether to only run the quick scan (and not include the\n'
             'thorough scan over all ports)')

    parser.add_argument(
        '--qs-method',
        action='store',
        metavar='S',
        help='the method for performing the initial TCP port scan; must\n'
             'correspond to a configured port scan')

    parser.add_argument(
        '--status-interval',
        action='store',
        metavar='I',
        help='integer number of seconds to pause in between printing status\n'
             'updates; a non-positive value disables updates (defaults to 30)')

    parser.add_argument(
        '--ts-method',
        action='store',
        metavar='S',
        help='the method for performing the thorough TCP port scan; must\n'
             'correspond to a configured port scan')

    parser.add_argument(
        '--udp',
        action='store_true',
        default=False,
        help='whether to run UDP scans')

    parser.add_argument(
        '--udp-method',
        action='store',
        metavar='S',
        help='the method for performing the UDP port scan; must correspond\n'
             'to a configured port scan')

    parser.add_argument(
        '--verbose-status',
        action='store_true',
        default=False,
        help='whether to print verbose runtime status updates, based on \n'
             'frequency specified by `--status-interval` flag')

    parser.add_argument(
        '--version',
        action='version',
        version=str(__version__),
        help='program version')

    parser.add_argument(
        '--web-word-list',
        action='store',
        type=str,
        metavar='F',
        help='the wordlist to use for scans')

    parser.add_argument(
        'targets',
        nargs='*',
        help='the targets and/or networks on which to perform enumeration')

    if args is None:
        args = sys.argv[1:]

    return parser.parse_args(args)


async def main(args: Optional[List[str]]=None) -> int:
    """Main entry point for `bscan`'s command-line interface.

    Args:
        args: Custom arguments to override ``sys.argv``.

    Returns:
        The exit code of the program.

    """
    try:
        init_colorama()

        if not good_py_version():
            print_w_d1('Running with Python version ', py_version_str(),
                       'but this program is only tested with Python 3.6')

        opts = get_parsed_args(args)
        print_i_d1('Initializing configuration from command-line arguments')
        mc = opts.max_concurrency
        try:
            mc = (20 if mc is None else int(mc))
            if mc < 1:
                raise ValueError
        except ValueError:
            raise BscanConfigError(
                'Invalid `--max-concurrency` positive integer value '
                'received: ' + str(mc))

        async with Sublemon(max_concurrency=mc) as subl:
            await write_db_value('sublemon', subl)
            await init_config(opts)

            print_color_info()

            if not opts.targets:
                print_e_d1('No targets specified; use `--help` to figure '
                           'out what you\'re doing')
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

            if not targets:
                print_e_d1('No valid targets specified')
                return 1

            print_i_d1('Kicking off scans of ', len(targets), ' targets')
            tasks = [scan_target(target) for target in targets]
            if get_db_value('status-interval') > 0:
                tasks.append(status_update_poller())
            await asyncio.gather(*tasks)

            print_i_d1('Completed execution')
            return 0
    except BscanConfigError as e:
        print_e_d1('Configuration error: ', e.message)
        return 1
    except BscanForceSilentExit as e:
        return 1
    except BscanInternalError as e:
        print_e_d1('Internal error: ', e.message)
        return 1
    except BscanSubprocessError as e:
        print_e_d1('Error handling subprocess: ', e.message)
        return 1
    except BscanError as e:
        print_e_d1('This should not be reached!')
        return 1
    except Exception as e:
        print_e_d1('Received unexpected exception; re-raising it.',
                   file=sys.stderr)
        raise e
