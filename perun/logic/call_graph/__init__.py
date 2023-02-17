"""Implementation of Call Graph (CG) and Control Flow Graph (CFG) representations.

This package contains everything related to CG and CFG representations used in Perun, namely:
 - CG-specific Stats file paths;
 - CG versioning that combines VCS versions and relevant profiling configuration;
 - CG (CFG) extraction (reconstruction) tools that build the CG / CFG from source or binary files;
 - layered CG representation, i.e., multiple CG variants stored within a single graph structure;
 - TODO: a read-only CG view class that supports easy nodes/edges iteration or access;
 - TODO: CG and CFG comparison algorithms;
 - easy-to-use operations for file system related manipulations of stored CGs (such as saving,
   loading, lookup, ...) using the Stats module.
"""

from __future__ import annotations

from collections.abc import Sequence, Iterable
from pathlib import Path

import demandimport

from perun.utils import partition_list
from perun.collect.identification import CollectCompoundId
from perun.logic.stats import StatsFile, iter_files, iter_predecessors

from perun.logic.call_graph.structs import CGLayer, ValidStates, VersionState, TIMESTAMP_FMT
from perun.logic.call_graph.version import CGVersion
from perun.logic.call_graph.path import CallGraphPath
from perun.logic.call_graph.graphs import CallGraph, FuncCFG, CallGraphView
from perun.logic.call_graph.extractors import SupportedExtractors, extractor_factory

# Import on demand due to the circular dependency with the io module
with demandimport.enabled():
    import perun.logic.call_graph.io as cg_io


__all__ = [
    "CallGraphManager",
    "CallGraphPath",
    "CallGraph",
    "CallGraphView",
    "FuncCFG",
    "CGLayer",
    "CGVersion",
    "SupportedExtractors",
]


class CallGraphManager:
    """A manager class for CG lookup, storage, retrieval and extraction.

    This class wraps the CG representation and provides a range of operations related to CG
    lookup, storage and retrieval using the Stats module. These operations are fairly complex as
    CGs are related to both 1) VCS version (i.e., a CG is linked to a specific VCS version),
    and 2) current state of files the CG depends on (e.g., source or binary files used for
    extraction).

    The CG versioning is complicated for multiple reasons:
     A) We want to avoid repeated extraction of a CG when there were no changes.
     B) We want to be able to detect when a change happened and extract a new version of the CG.
     C) We want to identify CGs that can be compared across VCS versions, that is, while the VCS
        version is different, the configuration of CG extraction was the same.

    To solve this problem, the CG is versioned using two IDs:
     1) A hash value of the files (including their content) used for extraction. The hash value
        is obtained using the underlying VCS hashing algorithm (e.g., SHA for Git). This hash value
        changes when there are any changes in the source or binary files used for the CG extraction.
        Note that there is currently no analysis being done on whether the changes actually impact
        the resulting CG or not. We call this ID a 'CG version hash'.
     2) An ID of the extraction/profiling configuration. The ID is either a user-supplied name of
        the configuration (e.g., 'nightly-build') or a hash value computed from the file paths (!!)
        used for CG extraction. Since the hash is computed from the paths and not their contents,
        it is possible to match CGs across project versions despite the files content likely
        changing. For larger projects with extraction files being added, deleted and renamed, it
        is advised to name the configuration explicitly. We call this ID a 'configuration name'.

    To help reduce the storage space taken by the stored CGs, the manager keeps only the most recent
    CG of the same configuration name within a VCS version.

    :ivar call_graph: the actual CG representation.
    :ivar version: the CG version.
    """

    def __init__(self, call_graph: CallGraph, cg_version: CGVersion) -> None:
        """Initializer.

        :ivar call_graph: the call graph representation.
        :ivar version: the call graph version.
        """
        self.call_graph: CallGraph = call_graph
        self.version: CGVersion = cg_version

    # TODO: compound ID contains optimizations, CG contains them as well. Should we make them
    #  consistent, or can we remove the optimizations from the compound ID?
    # TODO: The two 'files' (the parameter and an attribute in compound ID) are a bit confusing.
    @classmethod
    def current(
        cls,
        compound_id: CollectCompoundId,
        files: Sequence[Path],
        extractor: SupportedExtractors = SupportedExtractors.ANGR,
    ) -> CallGraphManager:
        """Obtain a call graph for the current version.

        By current version, we mean:
         1) the VCS version (e.g., rev 8acf5...),
         2) the CG version hash (i.e., the current state of the files used for extraction),
         3) and the configuration name.

        If a CG matching the current version is not found, the method attempts to extract the CG.

        :param compound_id: the collection ID containing a valid configuration name.
        :param files: files used for the CG extraction.
        :param extractor: the CG extractor to use in case there is no CG for the current version.

        :return: an initialized CG manager containing a current version CG.
        """
        # The CG version hash corresponding to the files
        cg_version_hash, _ = CGVersion.compute_hashes(files)
        # We do not supply a change state: possibly expensive to compute and one CG version hash
        # shouldn't have both clean and dirty variant = hashing collision
        # The VCS version is implicitly HEAD
        name_pattern = CallGraphPath.lookup_pattern(
            cg_version_hash=cg_version_hash,
            conf_name=compound_id.conf_name,
        )
        saved_file = cls._select_cg(list(iter_files(name_pattern)))
        if saved_file:
            return cls.load(saved_file)
        # No saved CG file, extract it
        return cls.extract(compound_id, files, extractor)

    @classmethod
    def old(
        cls, compound_id: CollectCompoundId, change_state: ValidStates, minor_version: str
    ) -> CallGraphManager | None:
        """Obtain a call graph linked to some previous VCS version.

        The matching CG is searched only in the supplied VCS version. In order to match, the CG
        must have the same configuration name. The CG version hash is ignored.

        :param compound_id: the collection ID containing a valid configuration name.
        :param change_state: specifies whether the CG version can originate from a dirty (clean)
                             repository, or both.
        :param minor_version: the VCS version to search in.

        :return: an initialized CG manager or None if no such CG was found.
        """
        name_pattern = CallGraphPath.lookup_pattern(
            change_state=change_state, conf_name=compound_id.conf_name, minor_version=minor_version
        )
        saved_file = cls._select_cg(list(iter_files(name_pattern)))
        if saved_file:
            return cls.load(saved_file)
        return None

    @classmethod
    def extract(
        cls, compound_id: CollectCompoundId, files: Sequence[Path], extractor: SupportedExtractors
    ) -> CallGraphManager:
        """Extract a current version CG.

        :param compound_id: the collection ID containing a valid configuration name.
        :param files: files used for the CG extraction.
        :param extractor: the CG extractor to use.

        :return: an initialized CG manager with the newly extracted call graph.
        """
        # TODO: this is a bit hacky right now.
        #  Replace files and compound id with some 'Project' object after Tracer refactoring.
        main_binary, libs = None, None
        if len(files) >= 1:
            main_binary = files[0]
        if len(files) >= 2:
            libs = files[1:]
        return CallGraphManager(
            extractor_factory(extractor, main_binary, libs).extract(),
            CGVersion.current(compound_id, files),
        )

    @property
    def filepath(self) -> CallGraphPath:
        """Construct a stats file path for the CG.

        Note that the path is provided regardless if the CG is saved or not.

        :return: a stats file path corresponding to the CG.
        """
        return CallGraphPath(
            self.version.cg_version_hash,
            self.version.change_state.value,
            self.version.cid.conf_name,
            self.version.version_timestamp.strftime(TIMESTAMP_FMT),
            self.version.vcs_version,
        )

    def predecessor(self) -> StatsFile[CallGraphPath] | None:
        """Obtain a previous version of the CG (in terms of VCS versions), if it exists.

        This method traverses the VCS history and attempts to find the most recent previous VCS
        version that contains a matching CG.

        :return: a stats file with the predecessor CG, or None if there is no such predecessor.
        """
        # Only the configuration name and minor version are relevant for the predecessors lookup
        name_pattern = CallGraphPath.lookup_pattern(
            conf_name=self.version.cid.conf_name, minor_version=self.version.vcs_version
        )
        # Obtain only call graphs from the previous minor version
        for previous_cgs in iter_predecessors(name_pattern, top=1):
            return self._select_cg([StatsFile(cg) for cg in previous_cgs])
        return None

    @classmethod
    def load(cls, file: CallGraphPath | StatsFile[CallGraphPath]) -> CallGraphManager:
        """Load a CG manager specified by a path or a stats file.

        :param file: the CG file (path).

        :return: an initialized CG manager, or None if the file could not be loaded.
        """
        return cg_io.load(file)

    def save(self) -> CallGraphPath:
        """Save the current call graph.

        :return: a path to the saved file.
        """
        # Recalculate every existing layer before saving the CG
        self.call_graph.recalculate()
        cg_file = cg_io.save(self)
        # Make sure that we do not cause inconsistency = multiple redundant files
        # Find and delete CG files that store old version of the same CG
        redundant_pattern = CallGraphPath.lookup_pattern(
            change_state=self.version.change_state.value,
            conf_name=self.version.cid.conf_name,
            minor_version=self.filepath.minor_version,
        )
        for other_cg in iter_files(redundant_pattern):
            if other_cg != cg_file:
                other_cg.delete()
        return cg_file.filepath

    @staticmethod
    def _select_cg(cgs: Sequence[StatsFile[CallGraphPath]]) -> StatsFile[CallGraphPath] | None:
        """Select the most suitable CG file among multiple candidate files in the same VCS version.

        One VCS version can contain multiple CG files. Most notably, different configuration IDs
        (names) can have their own separate CG versions. However, there can also occasionally be
        multiple CG files for a single configuration name, such as one or more CG files with
        different CG version hash or different version state (i.e., clean or dirty working dir).
        Any such files, except the most recent one per each version state, are considered redundant.

        This method expects that the provided CG files are within the same VCS version and have the
        same configuration name. As such, the files should only differ in the CG version hash and/or
        the version state. Hence, there are at most two files that should be kept and the remaining
        files are considered redundant, and will be deleted.

        When both clean and dirty versions of a CG exist, this method prefers the clean version.

        :param cgs: multiple CG files with the same VCS version and configuration name.

        :return: the most suitable CG file among the provided collection of CGs.
        """
        if not cgs:
            return None
        if len(cgs) == 1:
            return cgs[0]
        # Multiple CGs, remove potential old versions
        cgs = CallGraphManager._remove_old(cgs)
        # At most one clean and one dirty version should exist.
        clean, dirty = partition_list(
            cgs, lambda v: v.filepath.change_state == VersionState.CLEAN.value
        )
        # Prefer a clean version
        if clean:
            return clean[0]
        if dirty:
            return dirty[0]
        return None

    @staticmethod
    def _remove_old(versions: Iterable[StatsFile[CallGraphPath]]) -> list[StatsFile[CallGraphPath]]:
        """Delete redundant versions of call graphs stored within the Perun storage.

        This method identifies which stored CG files are no longer needed and deletes them.
        There can be at most one CG file per (VCS version, configuration name, version state) tuple.
        When selecting what file to keep, the most recent one is selected and the remaining ones are
        deleted.

        :param versions: a collection of CG files.

        :return: filtered collection of CG files that contains no redundant file.
        """
        # First partition the files per 1) VCS version, 2) configuration name and 3) version state
        partition: dict[tuple[str, str, str], list[StatsFile[CallGraphPath]]] = {}
        for file in versions:
            f_path = file.filepath
            if not file.exist():
                continue
            assert f_path.minor_version is not None  # Existing files have a valid minor version
            partition.setdefault(
                (f_path.minor_version, f_path.conf_name, f_path.change_state), []
            ).append(file)
        # Delete any old redundant files
        for files in partition.values():
            if len(files) <= 1:
                continue
            # From the most recent date to the latest one
            files.sort(key=lambda f: f.filepath.timestamp, reverse=True)
            for file in files[1:]:
                file.delete()
        return sum(partition.values(), [])
