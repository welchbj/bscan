"""Main entry point for the bscan program."""

import sys

from sublemon import crossplat_loop_run

from bscan.cli import (
    main as cli_main)
from bscan.cli_wordlists import (
    main as cli_wordlists_main)
from bscan.cli_shells import (
    main as cli_shells_main)


def main():
    """The function pointed to by `bscan` in console_scripts."""
    sys.exit(crossplat_loop_run(cli_main()))


def wordlists_main():
    """The function pointed to by `bscan-wordlists` in console_scripts."""
    sys.exit(cli_wordlists_main())


def shells_main():
    """The function pointed to by `bscan-shells` in console_scripts."""
    sys.exit(cli_shells_main())


if __name__ == '__main__':
    main()
