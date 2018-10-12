"""Utilities for dealing with wordlists."""

import os

from typing import (
    List,
    Optional)

from bscan.io import file_exists


def find_wordlist(search_dirs: List[str], filename: str) -> Optional[str]:
    """Recursively search wordlist directories for specified filename."""
    if file_exists(filename):
        return filename

    head, tail = os.path.split(filename)
    mod_search_dirs = [os.path.join(path, head) for path in search_dirs]

    for wordlist_dir in mod_search_dirs:
        for dirpath, dirnames, filenames in os.walk(wordlist_dir):
            if tail in filenames:
                os.path.join(dirpath, tail)

    return None


def walk_wordlists(wordlist_dirs: List[str]) -> None:
    """Recursively walk the wordlist directories and print all files."""
    for wordlist_dir in wordlist_dirs:
        for dirpath, dirnames, filenames in os.walk(wordlist_dir):
            if not filenames:
                continue
            print(dirpath)
            for filename in filenames:
                print('--->', filename)
            print()
