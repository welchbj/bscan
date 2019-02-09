"""Utilities for loading reverse shell commands from the configuration file."""

import toml

from collections import (
    namedtuple)
from typing import (
    List)
from urllib.parse import (
    quote_plus)

from bscan.config import load_default_config_file

ReverseShellCommand = namedtuple(
    'ReverseShellCommand',
    ['name', 'cmd', 'url_encoded_cmd'])


def reverse_shell_commands(
        target: str, port: int) -> List[ReverseShellCommand]:
    """Generate reverse shell commands from default configuration."""
    rev_shell_cmds = []
    config_contents = load_default_config_file('reverse-shells.toml')
    for unparsed in toml.loads(config_contents)['shells']:
        cmd = (unparsed['cmd'].replace('<target>', target)
                              .replace('<port>', str(port)))
        parsed = ReverseShellCommand(
            unparsed['name'],
            cmd,
            quote_plus(cmd))
        rev_shell_cmds.append(parsed)
    return rev_shell_cmds
