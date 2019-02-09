"""Utilities for file I/O."""

import shutil

from pathlib import (
    Path)


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
    shutil.rmtree(path, ignore_errors=True)


def create_dir(path: str) -> None:
    """Create a directory."""
    Path(path).mkdir()


def touch_file(path: str) -> None:
    """Touch a file."""
    Path(path).touch()
