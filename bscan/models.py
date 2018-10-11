"""Models for use in `bscan` operations."""

from collections import namedtuple
from typing import List

from bscan.runtime import get_db_value
from bscan.structure import get_scan_file

ParsedService = namedtuple(
    'ParsedService',
    ['name', 'port'])
"""A class representing a service parsed from unicornscan/nmap outout."""

_DetectedService = namedtuple(
    '_DetectedService',
    ['name', 'target', 'ports', 'scans', 'recommendations'])


class DetectedService(_DetectedService):
    """A class for encapsulating a service detected in a scan."""

    def build_scans(self) -> List[str]:
        """Build the scans to be run on this target."""
        built_scans = []
        for scan, cmd in self.scans.items():
            built_scans.extend(self._fill_template(scan, cmd))
        return built_scans

    def build_recommendations(self) -> List[str]:
        """Build the recommended commands to be run on this target."""
        built_recs = []
        for i, cmd in enumerate(self.recommendations):
            built_recs.extend(self._fill_template('rec' + str(i), cmd))
        return built_recs

    def port_str(self) -> str:
        """Build a string representing the ports open for this service."""
        return ','.join([str(p) for p in self.ports])

    def _fill_template(self, scan_name, cmd) -> List[str]:
        """Replace template parameters with values."""
        fout = get_scan_file(self.target, self.name + '.' + scan_name)
        cmd = (cmd.replace('<target>', self.target)
                  .replace('<fout>', fout)
                  .replace('<wordlist>', get_db_value('web-word-list'))
                  .replace('<userlist>', get_db_value('brute-user-list'))
                  .replace('<passlist>', get_db_value('brute-pass-list')))

        if '<ports>' in cmd:
            return [cmd.replace('<ports>', self.port_str())]
        elif '<port>' in cmd:
            return [cmd.replace('<port>', str(p)) for p in self.ports]
        else:
            return [cmd]
