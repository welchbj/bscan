"""Main entry point for the bscan program."""

import asyncio
import contextlib
import signal
import sys

from bscan.cli import main as cli_main


def main():
    """The function pointed to by console_scripts."""
    if sys.platform == 'win32':
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)
    else:
        loop = asyncio.get_event_loop()

    with contextlib.closing(loop):
        sys.exit(loop.run_until_complete(cli_main()))


if __name__ == '__main__':
    main()
