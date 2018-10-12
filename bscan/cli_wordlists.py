"""Command-line interface for the `bscan-wordlists` application."""

import sys

from argparse import (
    ArgumentParser,
    Namespace,
    RawTextHelpFormatter)
from typing import (
    List,
    Optional)

from bscan.runtime import DEFAULT_WORDLIST_SEARCH_DIRS
from bscan.version import __version__
from bscan.wordlists import (
    find_wordlist,
    walk_wordlists)


def get_parsed_args(args: Optional[List[str]]=None) -> Namespace:
    """Get the parsed command-line arguments.

    Args:
        args: Arguments to use in place of `sys.argv`.

    """
    parser = ArgumentParser(
        prog='bscan-wordlists',
        usage='bscan-wordlists [OPTIONS]',
        description='bscan companion utility for listing and finding\n'
                    'wordlists on Kali Linux',
        formatter_class=RawTextHelpFormatter)

    parser.add_argument(
        '--list',
        action='store_true',
        default=False,
        help='list all findable wordlists on the system')

    parser.add_argument(
        '--find',
        action='store',
        help='find the absolute path to a wordlist via its filename')

    parser.add_argument(
        '--version',
        action='version',
        version=str(__version__),
        help='program version')

    if args is None:
        args = sys.argv[1:]

    return parser.parse_args(args)


def main(args: Optional[List[str]]=None) -> int:
    """Main entry point for `bscan-wordlists`'s command-line interface."""
    opts = get_parsed_args(args)
    if opts.list:
        walk_wordlists(DEFAULT_WORDLIST_SEARCH_DIRS)
    elif opts.find is not None:
        wordlist = find_wordlist(DEFAULT_WORDLIST_SEARCH_DIRS, opts.find)
        if wordlist is None:
            print('Unable to locate', opts.find)
        else:
            print(opts.find)
    else:
        print('specify `--list` or `--find <filename>` options')

    return 0
