"""Main entry point for the bscan program."""

import asyncio
import sys

from bscan.cli import main


if __name__ == '__main__':
    sys.exit(asyncio.get_event_loop().run_until_complete(main()))
