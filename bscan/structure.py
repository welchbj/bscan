"""File and terminal I/O utilies."""

import os

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
    return os.path.join(PARENT_DIR, f'{target}.bscan')


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


def get_scan_file_smb_nmap(target: str) -> str:
    """Get path to the SMB Nmap script scan output."""
    return os.path.join(get_services_dir(target), 'smb.nmap')


def get_scan_file_smb_enum4linx(target: str) -> str:
    """Get path to the SMB enum4linux scan output."""
    return os.path.join(get_services_dir(target), 'smb.enum4linux')


def get_scan_file_http_nmap(target: str) -> str:
    """Get path to the HTTP Nmap script scan output."""
    return os.path.join(get_services_dir(target), 'http.nmap')


def get_scan_file_http_nikto(target: str) -> str:
    """Get path to the HTTP Nikto scan output."""
    return os.path.join(get_services_dir(target), 'http.nikto')


def get_scan_file_http_gobuster(target: str) -> str:
    """Get path to the HTTP gobuster scan output."""
    return os.path.join(get_services_dir(target), 'http.gobuster')


def create_dir_skeleton(target: str, hard: bool) -> None:
    """Create the directory skeleton for a target-based scan.

    Args:
        target: The singular target of the scan.
        hard: Whether to force overwrite of an existing directory for the
            target.

    """
    print_i_d1('Beginning creation of directory structure for target ', target)

    base_dir = get_base_dir(target)
    if path_exists(base_dir):
        if not hard:
            print_e_d1('Base directory ', base_dir, 'already exists; use '
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

    print_i_d1('Successfully completed directory setup')
