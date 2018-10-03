"""File and terminal I/O utilies."""

import os

from bscan.config import get_config_value
from bscan.io import (
    create_dir,
    path_exists,
    print_e_d1,
    print_i_d1,
    print_i_d2,
    print_w_d1,
    remove_dir,
    touch_file)


PARENT_DIR = os.getcwd()


def get_base_dir(target: str) -> str:
    """Get the path of the base directory for a scan."""
    return os.path.join(PARENT_DIR, f'{target}.bscan.d')


def get_services_dir(target: str) -> str:
    """Get the path of the  directory for a scan."""
    return os.path.join(get_base_dir(target), 'services')


def get_sploits_dir(target: str) -> str:
    """Get the path of the  directory for a scan."""
    return os.path.join(get_base_dir(target), 'sploits')


def get_loot_dir(target: str) -> str:
    """Get the path of the loot directory for a scan."""
    return os.path.join(get_base_dir(target), 'loot')


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
        if not get_config_value('hard'):
            print_e_d1('Base directory ', base_dir, ' already exists; use '
                       '`--hard` option to force overwrite')
            return

        print_w_d1('Removing existing base directory ', base_dir)
        remove_dir(base_dir)

    print_i_d1('Creating base directory ', base_dir)
    create_dir(base_dir)

    loot_dir = get_loot_dir(target)
    print_i_d2('Creating loot directory ', loot_dir)
    create_dir(loot_dir)

    services_dir = get_services_dir(target)
    print_i_d2('Creating services directory ', services_dir)
    create_dir(services_dir)

    sploits_dir = get_sploits_dir(target)
    print_i_d2('Creating sploits directory ', sploits_dir)
    create_dir(sploits_dir)

    bscan_summary_file = get_bscan_summary_file(target)
    print_i_d2('Creating summary file ', bscan_summary_file)
    touch_file(bscan_summary_file)

    print_i_d1('Successfully completed directory skeleton setup')
