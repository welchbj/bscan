"""Utilities for getting the location of files within the structure."""

import os

from bscan.runtime import get_db_value


def get_base_dir(target: str) -> str:
    """Get the path of the base directory for a scan."""
    return os.path.join(get_db_value('output-dir'), f'{target}.bscan.d')


def get_notes_txt_file(target: str) -> str:
    """Get the path to the notes.txt file."""
    return os.path.join(get_base_dir(target), 'notes.txt')


def get_recommendations_txt_file(target: str) -> str:
    """Get the path to the recommendations.txt file."""
    return os.path.join(get_base_dir(target), 'recommendations.txt')


def get_services_dir(target: str) -> str:
    """Get the path of the services directory for a scan."""
    return os.path.join(get_base_dir(target), 'services')


def get_sploits_dir(target: str) -> str:
    """Get the path of the sploits  directory for a scan."""
    return os.path.join(get_base_dir(target), 'sploits')


def get_loot_dir(target: str) -> str:
    """Get the path of the loot directory for a scan."""
    return os.path.join(get_base_dir(target), 'loot')


def get_proof_txt_file(target: str) -> str:
    """Get the path to the proof.txt proof file."""
    return os.path.join(get_loot_dir(target), 'proof.txt')


def get_local_txt_file(target: str) -> str:
    """Get the path to the local.txt proof file."""
    return os.path.join(get_loot_dir(target), 'local.txt')


def get_bscan_summary_file(target: str) -> str:
    """Get path to the summary file for the entire scan."""
    return os.path.join(get_base_dir(target), 'summary.bscan')


def get_scan_file(target: str, scan_name: str) -> str:
    """Get path to a file for service scan output."""
    return os.path.join(get_services_dir(target), scan_name)
