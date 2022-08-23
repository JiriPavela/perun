"""The module implements a collect compound ID used to uniquely identify a collection configuration.

A collect configuration generally consists of:
 1) a collect configuration name, and
 2) optimization IDs.

Multiple collect compound ID can be compared using the equivalence operator.
"""
from __future__ import annotations
from typing import ClassVar, Collection

import os
from hashlib import sha1
from pathlib import Path

from perun import vcs


class IncompleteCollectIdException(Exception):
    """Raised when the collect compound ID is not properly specified."""
    def __str__(self) -> str:
        return (f"The {CollectCompoundId.__class__.__name__} class requires the specification of "
                f"either a collect configuration name or collection files!")


class CollectCompoundId:
    """A compound identification of a collect configuration.

    :ivar conf_name: identification of the collection configuration name.
    :ivar opt_ids: a set of optimization IDs.
    :ivar files: a set of file paths that the collect is performed on (e.g., binary executable
                 files, project source files, etc.).
    """
    __slots__ = 'conf_name', 'files', 'opt_ids'

    _encoding: ClassVar[str] = 'utf-8'
    _default_collect_id: ClassVar[str] = 'id-{sha_hash}'

    def __init__(
            self, collect_config_name: str, files: set[Path], optimization_ids: set[str]
    ) -> None:
        """Initializer.

        To initialize an ID using this initializer, the configuration name and files have to be
        known and properly resolved. Otherwise, use the alternative initializer for current
        project version.

        :param collect_config_name: a collect configuration name.
        :param optimization_ids: a set of optimization IDs.
        :param files: a set of file paths that the collect is performed on (e.g., binary
                      executable files, project source files, etc.).
        """
        self.conf_name: str = collect_config_name
        self.files: set[Path] = files
        self.opt_ids: set[str] = optimization_ids if optimization_ids is not None else set()

    @classmethod
    def current(
            cls, collect_config_name: str | None, files: Path | Collection[Path] | None = None,
            optimization_ids: set[str] | None = None
    ) -> CollectCompoundId:
        """Initializes a compound ID for the current version.

        Using this alternative constructor, the configuration name and file paths are resolved:
          1. If a configuration name is not specified and file paths are provided, a default
             configuration name is computed as a SHA1 hash using the file paths relative to the
             repo working tree directory.
          2. If neither the collect name or files are provided, the IncompleteCollectIdException
             is raised.

        :param collect_config_name: a collect configuration name.
        :param optimization_ids: a set of optimization IDs.
        :param files: a collection of file paths that the collect is performed on (e.g., binary
                      executable files, project source files, etc.).
        """
        unified_files = cls._unify_paths(files)
        unified_name = cls._unify_name(collect_config_name, unified_files)
        return cls(
            unified_name,
            unified_files,
            optimization_ids if optimization_ids is not None else set()
        )

    def __eq__(self, other: object) -> bool:
        """An equivalence operator. Two collect compound IDs are considered as equal when their
        configuration names are the same.

        :param other: the other comparison operand.

        :return: True if the IDs are the same, False otherwise.
        """
        if not isinstance(other, CollectCompoundId):
            return NotImplemented
        return self.conf_name == other.conf_name

    @staticmethod
    def _unify_paths(files: Path | Collection[Path] | None) -> set[Path]:
        """Unify file paths so that they are all relative to the repository working tree directory.

        Thanks to the unification, the paths should be consistent across different ID objects.

        :param files: the file paths to unify.

        :return: the unified file paths.
        """
        # No paths given
        if files is None:
            return set()
        # Convert a single path to a collection of paths
        if isinstance(files, Path):
            files = {files}
        # Compute relative path between the `path` and the repository working tree directory
        repo_dir = vcs.get_working_tree_dir(strict=True)
        unified_paths = set()
        for path in files:
            try:
                # os' relpath cannot be substituted with pathlib's relative_to here!
                # The `path` might be outside of the repo directory, which relative_to cannot handle
                unified_paths.add(Path(os.path.relpath(path.resolve(strict=True), repo_dir)))
            except FileNotFoundError:
                # Ignore non-existing files
                continue
        return unified_paths

    @classmethod
    def _unify_name(cls, collect_config_name: str | None, files: set[Path]) -> str:
        """Computes the default collect configuration name if needed, and if possible.

        The default collect name is computed by hashing the sorted and unified file paths.

        :param collect_config_name: a collect identification.
        :param files: a set of file paths that the collect is performed on

        :return: the unified collect configuration name.
        """
        if collect_config_name:
            # Do not compute collect name if it was provided
            return collect_config_name
        if not files:
            # No paths or name given, an error
            raise IncompleteCollectIdException()
        sha_hash = sha1()
        for relative_path in sorted(files):
            sha_hash.update(str(relative_path).encode(cls._encoding))
        return cls._default_collect_id.format(sha_hash=sha_hash.hexdigest())
