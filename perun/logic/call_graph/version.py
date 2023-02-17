"""This module implements a representation of call graph versions.

The call graph versioning is necessary to identify whether a new CG extraction has to be performed,
or if an existing CG can be reused.

Call graph versioning is somewhat more complex and the default stats VCS versioning is not
sufficient to properly represent CG versions. CG versions are identified using the following set:
 1) CG version hash (computed from the files used for call graph extraction),
 2) CG state: clean or dirty (according to the reported VCS changes of files used for extraction),
 3) collect configuration name (either supplied or computed default value),
 4) timestamp.

Note that the files dirty / clean state is determined solely from the VCS-tracked files, as
tracking changes of files outside of VCS is difficult.
"""
from __future__ import annotations
from collections.abc import Collection
from typing import TypeVar, Type

from pathlib import Path
from datetime import datetime

from perun import vcs
from perun.collect.identification import CollectCompoundId
from perun.utils.structs import VCSObjectChange, VCSChangeState
from perun.logic.call_graph.structs import TIMESTAMP_FMT, VersionState

AnyCGVersion = TypeVar("AnyCGVersion", bound="CGVersion")

# File path -> VCS hash mapping
SourcesMap = dict[Path, str]
# File path -> File change detail mapping
ChangesMap = dict[Path, "FileChangeDetail"]


class FileChangeDetail:
    """A representation of file change details.

    The details can be used to examine the change state detected for a certain file.

    :ivar file: a path to the changed file.
    :ivar file_hash: a VCS hash of the file.
    :ivar state: the change state as detected by the VCS.
    :ivar state_detail: VCS-specific details regarding the change state (e.g., status code in Git).
    :ivar new_file: new file name, if e.g., a rename was done.
    :ivar file_size: the current size of the file in bytes.
    :ivar modify_t: last modification date.
    """

    __slots__ = "file", "file_hash", "state", "state_detail", "new_file", "file_size", "modify_t"

    def __init__(
        self,
        file: Path,
        file_hash: str,
        state: VCSChangeState | None,
        state_detail: str,
        new_file: str,
        file_size: int,
        modify_time: datetime | None,
    ) -> None:
        """Initializer.

        :param file: a path to the changed file.
        :param file_hash: a VCS hash of the file.
        :param state: the change state as detected by the VCS.
        :param state_detail: VCS-specific details regarding the change state.
        :param new_file: new file name, if e.g., a rename was done.
        :param file_size: the current size of the file in bytes.
        :param modify_time: last modification date.
        """
        self.file: Path = file
        self.file_hash: str = file_hash
        self.state: VCSChangeState = VCSChangeState.NO_CHANGE if state is None else state
        self.state_detail: str = state_detail
        self.new_file: str = new_file
        self.file_size: int = file_size
        self.modify_t: datetime = datetime.now() if modify_time is None else modify_time

    @classmethod
    def from_vcs(cls, change: VCSObjectChange, file_hash: str) -> FileChangeDetail:
        """An alternative initializer that builds the change detail from a VCS report.

        :param change: a VCS change report tuple.
        :param file_hash: a VCS-specific hash of the file.

        :return: a constructed and initialized object.
        """
        file, status, status_detail = change
        file_stats = file.stat()
        return cls(
            file,
            file_hash,
            status,
            status_detail.get("code", None),
            status_detail.get("new_file", None),
            file_stats.st_size,
            datetime.fromtimestamp(file_stats.st_mtime),
        )

    def __str__(self) -> str:
        """Provides a human-readable representation of the file change detail.

        :return: a string representation.
        """
        # Empty change detail = empty string
        if self.file is None:
            return ""
        # Human readable change record
        state_detail = f"({self.state_detail})" if self.state_detail else ""
        new_file = f" -> {self.new_file}" if self.new_file else ""
        return (
            f"{str(self.file)} (VCS hash {self.file_hash}, size {self.file_size}B, "
            f"last modified {self.modify_t.strftime(TIMESTAMP_FMT)}): "
            f"{self.state.value}{state_detail}{new_file}"
        )


class CGVersion:
    """Call Graph version representation.

    :ivar cid: compound ID of the collection configuration.
    :ivar vcs_version: the VCS-specific version representation.
    :ivar _cg_version_hash: the CG version hash representation.
    :ivar sources: files used for the call graph extraction, or files that could influence the
                   resulting call graph.
    :ivar version_timestamp: timestamp of the call graph version creation.
    :ivar change_state: indicates whether the call graph is extracted from clean or dirty repo.
    :ivar changes: detailed information about VCS-detected changes of the files used for extraction.
    """

    __slots__ = (
        "cid",
        "vcs_version",
        "_cg_version_hash",
        "sources",
        "version_timestamp",
        "change_state",
        "changes",
    )

    @vcs.lookup_minor_version
    def __init__(
        self,
        compound_id: CollectCompoundId,
        minor_version: str | None,
        cg_version_hash: str | None,
        sources: SourcesMap | None,
        timestamp: datetime | None,
        change_state: VersionState | None,
        changes: ChangesMap | None,
    ) -> None:
        """Initializer.

        Use the alternative initializer to obtain a representation of the current CG version.

        :param compound_id: compound ID of the collection configuration.
        :param minor_version: the VCS-specific version representation.
        :param cg_version_hash: the CG version hash representation.
        :param sources: files used for the call graph extraction, or files that could influence the
                       resulting call graph.
        :param timestamp: timestamp of the call graph version creation.
        :param change_state: indicates whether the call graph is extracted from clean or dirty repo.
        :param changes: details about VCS-detected changes of the files used for extraction.
        """
        # The vcs lookup guarantees the minor version will be a valid string
        assert minor_version is not None
        state = change_state if change_state is not None else VersionState.CLEAN
        self.cid: CollectCompoundId = compound_id
        self.vcs_version: str = minor_version
        self._cg_version_hash: str = cg_version_hash if cg_version_hash is not None else ""
        self.sources: SourcesMap = sources if sources is not None else {}
        self.version_timestamp: datetime = timestamp if timestamp is not None else datetime.now()
        self.change_state: VersionState = state
        self.changes: ChangesMap = changes if changes is not None else {}

    def __bool__(self) -> bool:
        """Emptiness check operator.

        We consider the version object empty if it lacks the version hash.

        :return: True if the version object is not empty, False otherwise.
        """
        # A non-empty object must have a valid CG version hash
        return bool(self._cg_version_hash)

    @classmethod
    def current(
        cls: Type[AnyCGVersion], compound_id: CollectCompoundId, sources: Collection[Path]
    ) -> AnyCGVersion:
        """An alternative initializer for current CG version.

        :param compound_id: compound ID of the collection configuration.
        :param sources: files used for the call graph extraction, or files that could influence the
                        resulting call graph.

        :return: an initialized version object for the current project version.
        """
        cg_hash, sources = cls.compute_hashes(sources)
        return cls(compound_id, None, cg_hash, sources, None, *cls._compute_changes(sources))

    @property
    def cg_version_hash(self) -> str:
        """CG version hash getter.

        The version hash should be read-only.

        :return: the CG version hash.
        """
        return self._cg_version_hash

    @staticmethod
    def compute_hashes(files: Collection[Path]) -> tuple[str, SourcesMap]:
        """Computes the total hash of all files and per-file hashes.

        The total hash refers to a single VCS-specific hash for a collection of files. The total
        hash is used as a CG version hash.

        :return: the total hash, per-file hashes
        """
        return vcs.hash_objects(files)

    @staticmethod
    def _compute_changes(sources: SourcesMap) -> tuple[VersionState, ChangesMap]:
        """Obtains the change state of the repository subset and per-file change statuses.

        The reported repository change state is determined only on the basis of the provided
        sources. If the repository is actually dirty, but all of the supplied sources are clean
        (i.e., not changed according to the VCS), the resulting change state will be determined as
        clean.

        The per-file status is then determined solely on the reported VCS status of the file.

        :param sources: files and their hashes.

        :return: the repository subset change state, per-file change statuses.
        """
        changes: ChangesMap = {}
        change_state: VersionState = VersionState.CLEAN
        if sources:
            # Build the change details
            for file, status, details in vcs.status_of(sources.keys()):
                changes[file] = FileChangeDetail.from_vcs((file, status, details), sources[file])
                # Update the CG version status
                vcs_change = status not in (VCSChangeState.NOT_IN_VCS, VCSChangeState.NO_CHANGE)
                if change_state == VersionState.CLEAN and vcs_change:
                    # There is a VCS-tracked change = the CG version is dirty
                    change_state = VersionState.DIRTY
        return change_state, changes
