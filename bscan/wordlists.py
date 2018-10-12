"""Utilities for dealing with wordlists."""

import fnmatch
import os

from typing import List


def find_wordlist(wordlist_dirs: List[str], fnpattern: str) -> None:
    """Recursively search wordlist directories for a specified filename."""
    for wordlist_dir in wordlist_dirs:
        _walk_iter = os.walk(wordlist_dir, followlinks=True)
        for dirpath, dirnames, filenames in _walk_iter:
            for match in fnmatch.filter(filenames, fnpattern):
                print(os.path.join(dirpath, match))


def walk_wordlists(wordlist_dirs: List[str]) -> None:
    """Recursively walk the wordlist directories and print all files."""
    for wordlist_dir in wordlist_dirs:
        _walk_iter = os.walk(wordlist_dir, followlinks=True)
        for dirpath, dirnames, filenames in _walk_iter:
            if not filenames:
                continue
            print(dirpath)
            for filename in filenames:
                print(filename)
            print()
