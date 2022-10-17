"""This module implements a stats path subclass for Call Graphs.

See the stats module for more details.
"""
from __future__ import annotations

import os
import re
from datetime import datetime

from perun.logic.call_graph.structs import VersionState, ValidStates, TIMESTAMP_FMT
from perun.logic.stats import StatsPath


class CallGraphPath(StatsPath):
    """A representation of a Call Graph stats paths.

    Path format: sub_<cg-version-hash>_<c|d>/<conf-name>_<timestamp>.cg.bz2
        - Example: sub_c9b8cdc7_c/nightly_2022-04-30-21-22-15.cg.bz2

    The path attributes are stored for a quick comparison without the need to load the entire file.

    :ivar cg_version_hash: VCS-specific CG version hash.
    :ivar change_state: change state of the CG version.
    :ivar timestamp: timestamp associated with the Call Graph creation.
    :ivar conf_name: profiling configuration name.
    """

    __slots__ = "cg_version_hash", "change_state", "conf_name", "timestamp"

    suffix = ".cg" + StatsPath.suffix
    _format = re.compile(
        os.path.join(
            f'sub_(.*)_([{"".join(s.value for s in VersionState)}])', f"(.*)_(.*){suffix}$"
        )
    )

    def __init__(
        self,
        cg_version_hash: str,
        change_state: ValidStates,
        conf_name: str,
        timestamp: str,
        minor_version: str | None,
    ) -> None:
        """Initializer. Builds the path using the parameters.

        :param cg_version_hash: VCS-specific CG version hash.
        :param change_state: CG change state.
        :param conf_name: profiling configuration name.
        :param timestamp: timestamp in the correct format.
        :param minor_version: VCS minor version representation.
        """
        # Initialize
        super().__init__(
            f"sub_{cg_version_hash}_{change_state}",
            f"{conf_name}_{timestamp}{self.suffix}",
            minor_version=minor_version,
        )
        self.cg_version_hash: str = cg_version_hash
        self.change_state: str = change_state
        self.conf_name: str = conf_name
        self.timestamp: datetime | str
        try:
            self.timestamp = datetime.strptime(timestamp, TIMESTAMP_FMT)
        except ValueError:
            self.timestamp = timestamp

    @classmethod
    def lookup_pattern(
        cls,
        cg_version_hash: str = "*",
        change_state: ValidStates = "*",
        conf_name: str = "*",
        timestamp: str = "*",
        minor_version: str | None = None,
    ) -> CallGraphPath:
        """Call Graph path lookup glob pattern.

        This alternative constructor provides a default lookup glob strings for each path component.

        Example: a glob for lookup of CG paths only per configuration name and change state:
        ```
        lkp = CallGraphPath.lookup_pattern(conf_name=<name>, change_state=<state>)
        ```

        :param cg_version_hash: VCS-specific CG version hash.
        :param change_state: CG change state.
        :param conf_name: profiling configuration name.
        :param timestamp: timestamp in the correct format.
        :param minor_version: VCS minor version representation.

        :return: a lookup glob pattern for Call graph stats files.
        """
        return cls(cg_version_hash, change_state, conf_name, timestamp, minor_version)
