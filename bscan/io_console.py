"""Utilities for console I/O."""

from colorama import (
    Fore,
    Style)
from functools import (
    partial)


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


def shortened_cmd(cmd: str, length: int) -> str:
    """Shorten the command to the specified length."""
    if len(cmd) + 2 <= length:
        return '`' + cmd + '`'

    return '`' + cmd[:(length-5)] + '...`'


print_i_d1 = partial(print, blue('[I] '), sep='')
print_p_d1 = partial(print, purple('[P] '), sep='')
print_w_d1 = partial(print, yellow('[W] '), sep='')
print_e_d1 = partial(print, red('[E] '), sep='')
print_i_d2 = partial(print, blue('  [I] '), sep='')
print_p_d2 = partial(print, purple('  [P] '), sep='')
print_w_d2 = partial(print, yellow('  [W] '), sep='')
print_e_d2 = partial(print, red('  [E] '), sep='')
print_i_d3 = partial(print, blue('    [I] '), sep='')
print_p_d3 = partial(print, purple('    [P] '), sep='')
print_w_d3 = partial(print, yellow('    [W] '), sep='')
print_e_d3 = partial(print, red('    [E] '), sep='')


def print_color_info():
    print_i_d1('Colors: ', blue('info'), ', ', yellow('warnings'), ', ',
               red('errors'), ', and ', purple('pattern matches'), sep='')
