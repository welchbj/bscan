"""Utilities for file and terminal I/O."""

import shutil

from colorama import (
    Fore,
    Style)
from functools import partial
from pathlib import Path


def red(s: str) -> str:
    """Add escape sequences to print a string red."""
    return Fore.RED + s + Style.RESET_ALL


def purple(s: str) -> str:
    """Add escape sequences to print a string purple."""
    return Fore.MAGENTA + s + Style.RESET_ALL


def blue(s: str) -> str:
    """Add escape sequences to print a string blue."""
    return Fore.CYAN + s + Style.RESET_ALL


def yellow(s: str) -> str:
    """Add escape sequences to print a string yellow."""
    return Fore.YELLOW + s + Style.RESET_ALL


print_i_d1 = partial(print, blue('[+] '), sep='')
print_w_d1 = partial(print, yellow('[!] '), sep='')
print_e_d1 = partial(print, red('[E] '), sep='')
print_i_d2 = partial(print, blue('  [>] '), sep='')
print_w_d2 = partial(print, yellow('  [! >]'), sep='')
print_e_d2 = partial(print, red('  [E >]'), sep='')
print_i_d3 = partial(print, blue('    --> '), sep='')
print_w_d3 = partial(print, yellow('    ! --> '), sep='')
print_e_d3 = partial(print, red('    E -->'), sep='')


def path_exists(path: str) -> bool:
    """Return whether the specified path leads to a file or directory."""
    return Path(path).exists()


def dir_exists(path: str) -> bool:
    """Return whether the specified path leads to a directory."""
    return Path(path).is_dir()


def file_exists(path: str) -> bool:
    """Return whether the specified path leads to a file."""
    return Path(path).is_file()


def remove_dir(path: str) -> None:
    """Remove a directory tree, failing silently if ``path`` does not exist."""
    shutil.rmdir(path, ignore_errors=True)


def create_dir(path: str) -> None:
    """Create a directory."""
    Path(path).mkdir()


def touch_file(path: str) -> None:
    """Touch a file."""
    Path(path).touch()
