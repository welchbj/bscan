"""File and terminal I/O utilies."""

import os

from bscan.errors import BscanForceSkipTarget
from bscan.io import (
    create_dir,
    path_exists,
    print_i_d1,
    print_i_d2,
    print_i_d3,
    print_w_d1,
    remove_dir,
    touch_file)
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


def create_dir_skeleton(target: str) -> None:
    """Create the directory skeleton for a target-based scan.

    Args:
        target: The singular target of the scan.

    """
    print_i_d1('Beginning creation of directory structure for target ', target)

    base_dir = get_base_dir(target)
    if path_exists(base_dir):
        if not get_db_value('hard'):
            raise BscanForceSkipTarget(
                'Base directory ' + base_dir + ' already exists, use '
                '`--hard` option to force overwrite')

        print_w_d1('Removing existing base directory ', base_dir)
        remove_dir(base_dir)

    print_i_d1('Creating base directory at ', base_dir)
    create_dir(base_dir)
    notes_file = get_notes_txt_file(target)
    print_i_d2('Creating notes.txt file at ', notes_file)
    touch_file(notes_file)
    recommendations_file = get_recommendations_txt_file(target)
    print_i_d2('Creating recommendations.txt file at ', recommendations_file)
    touch_file(recommendations_file)

    loot_dir = get_loot_dir(target)
    print_i_d2('Creating loot directory at ', loot_dir)
    create_dir(loot_dir)
    proof_file = get_proof_txt_file(target)
    print_i_d3('Creating proof.txt file at ', proof_file)
    touch_file(proof_file)
    local_file = get_local_txt_file(target)
    print_i_d3('Creating local.txt file at ', local_file)
    touch_file(local_file)

    services_dir = get_services_dir(target)
    print_i_d2('Creating services directory at ', services_dir)
    create_dir(services_dir)

    sploits_dir = get_sploits_dir(target)
    print_i_d2('Creating sploits directory at ', sploits_dir)
    create_dir(sploits_dir)

    print_i_d1('Successfully completed directory skeleton setup')
