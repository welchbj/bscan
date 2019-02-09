"""Command-line interface for the `bscan-shells` application."""

import sys

from argparse import (
    ArgumentParser,
    Namespace,
    RawTextHelpFormatter)
from typing import (
    List,
    Optional)

from bscan.errors import (
    BscanConfigError)
from bscan.networks import (
    is_valid_ip_host_addr,
    is_valid_hostname)
from bscan.shells import (
    reverse_shell_commands)
from bscan.version import (
    __version__)


def get_parsed_args(args: Optional[List[str]]=None) -> Namespace:
    """Get the parsed command-line arguments.

    Args:
        args: Arguments to use in place of `sys.argv`.

    """
    parser = ArgumentParser(
        prog='bscan-shells',
        usage='bscan-shells [OPTIONS]',
        description='bscan companion utility for generating reverse shells '
                    'commands',
        formatter_class=RawTextHelpFormatter)

    parser.add_argument(
        '--port',
        action='store',
        required=False,
        metavar='I',
        help='the port you want the reverse shell to connect back to\n'
             '(defaults to 80)')

    parser.add_argument(
        '--url-encode',
        action='store_true',
        default=False,
        help='whether to URL-encode all generated commands')

    parser.add_argument(
        '--version',
        action='version',
        version=str(__version__),
        help='program version')

    parser.add_argument(
        'target',
        action='store',
        help='the ip or host you want the reverse shell to connect back to')

    if args is None:
        args = sys.argv[1:]

    return parser.parse_args(args)


def main(args: Optional[List[str]]=None) -> int:
    """Main entry point for `bscan-shells`'s command-line interface."""
    try:
        opts = get_parsed_args(args)
        target = opts.target
        if not is_valid_ip_host_addr(target) and not is_valid_hostname(target):
            raise BscanConfigError('Invalid target specified: ' + target)

        try:
            port = (80 if opts.port is None else int(opts.port))
        except ValueError:
            raise BscanConfigError('Invalid port specified: ' + opts.port)

        if opts.url_encode:
            attr = 'url_encoded_cmd'
        else:
            attr = 'cmd'

        _cmd_iter = sorted(
            reverse_shell_commands(target, port), key=lambda c: c.name)
        for rev_shell_cmd in _cmd_iter:
            print(rev_shell_cmd.name)
            print(getattr(rev_shell_cmd, attr))
            print()

        return 0
    except BscanConfigError as e:
        print('Configuration error:', e.message, file=sys.stderr)
        return 1
    except Exception as e:
        print('Received unexpected exception; re-raising it!', file=sys.stderr)
        raise e
