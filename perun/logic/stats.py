"""This module contains functions for manipulating statistics files (the so called 'stats')

Stats are basically various data or statistics that need to be stored and manipulated by other
modules, collectors, post-processors etc. The 'stats' file can be indirectly linked to a specific
profile by using the profile 'source' or 'checksum' as a template for the name of the stats file.
Or the stats file might be completely unrelated to profiles by using some custom name.

Stats files are located in the .perun/stats directory under a specific minor version since the
statistics are mostly related to some results or profiles acquired in a specific VCS version. For
storing some temporary data that are unrelated to VCS version, use the 'temp' module.

The format of the stats files is as follows:

{
    'some_ID':
    {
        stats data stored by the user
    },

    'another_ID':
    {
        some other stored data
    },

    'yet_another_ID':
    {
        ...
    }
}

where the IDs uniquely represent stored statistics within the stats file and the ID is used to
identify the data that should be manipulated by the functions.

The contents of the stats file are stored in a compressed form to reduce the memory requirements.

"""
from __future__ import annotations
import os
import json
import re
import shutil
from pathlib import Path
from typing import Generator, Any, TextIO, overload, Literal, ClassVar, TypeVar, Generic, Type, \
    Union, Iterable
from zlib import error
import bz2

import perun.logic.store as store
import perun.logic.index as index
import perun.logic.pcs as pcs
import perun.utils as utils
import perun.utils.exceptions as exceptions
import perun.utils.helpers as utils_helpers
import perun.vcs as vcs
import perun.profile.helpers as helpers
import perun.utils.log as perun_log

from perun.utils.helpers import SuppressedExceptions


# Path Type: a generic type parameter for StatsFile.
# It is used to specify / restrict the type of the underlying stats file.
PT = TypeVar('PT', bound="StatsPath")

# The following aliases are used to correctly overload the return type of StatsFile
# Alias for textual file mode in bz2
FileTextModes = Literal['rt', 'wt', 'xt', 'at']
# Alias for binary file mode in bz2
FileBinModes = Literal['r', 'rb', 'w', 'wb', 'x', 'xb', 'a', 'ab']

# Possible specification of minor versions for lookup / iteration
VersionsLookup = Union[Iterable[str], str, None]
# Unified iterable
VersionsIterable = Iterable[str]

# Match the timestamp format of the profile names
PROFILE_TIMESTAMP_REGEX = re.compile(r"(-?\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})")

# Default number of displayed records for listing stats objects
DEFAULT_STATS_LIST_TOP = 20


# TODO: This module needs a re-design. Use StatsFile and StatsPath as a temporary workaround.
# TODO: Rework index, the versions should be ordered according to the parent relation, not date.
# TODO: The stats lookup / iteration implementation is temporary, needs some more rework.

class StatsPath:
    """A class representing a stats file, or a glob, path.

    The main advantages of using a specialized path class for stats files (globs) are:
     1) Automatic validation of the input paths and globs when creating a new instance.
     2) The path internals are hidden, hence once an instance is created, the validity does not
        have to be checked every time it is passed to a function (unlike Path or path-like strings).
     3) It is possible to narrow the type of stats files by deriving from this class. This allows
        to easily restrict the lookup of stats files to a specific type just by supplying the
        appropriate subclass of StatsPath.

    The input file (glob) path is valid if:
     - is an absolute path and <repository>/.perun/stats/<minor version dir>/ is part of it,
     - is a relative path (will be concatenated to the .perun/stats/<minor version dir>/)

    The supplied path (both absolute and relative) can contain additional levels of directories
    on top of the .perun/stats/<minor version dir>/ path, e.g.: `.../<minor version dir>/a/b/file`.

    It is generally impossible to distinguish a file path from a glob, hence it is the user's
    responsibility to track which objects represent globs, and which ones represent exact paths.
    Nonetheless, objects representing file paths can be used where globs are expected, and vice
    versa (although the results will probably differ from expectations).

    When deriving from this class, make sure to properly override (if needed) the `suffix` and
    `_format` class variables, and the `from_path` class method:
      - The overridden `suffix` should contain all suffixes, including the superclass ones. An
        example of correct compound suffix definition is: `suffix = '.mysuff' + StatsPath.suffix`.
      - The `_format` should be a compiled regex pattern that matches the expected file path
        format of the derived class. It is used to construct a StatsPath instance from a Path, if
        possible. The pattern should work on both relative and absolute paths. A re.search method
        is used, hence, the regex should most likely end with '<suffix>$'. Moreover, if the
        pattern contains regex groups, they will be used as parameters for the `__init__` method.
        If the format is set to None, no checking will be done and all stats paths will be
        considered as valid. Note that the pattern doesn't have to check the validity of the name,
        only its format. The validity checks can be done in the `__init__` or `from_path` methods,
        if desired.
      - The `from_path` alternative constructor should work 'as is' for derived classes that
        can be constructed using just string parameters obtainable from the regex match. Otherwise,
        the `from_path` method should be overridden.

    :ivar _abspath: absolute file (glob) path.
    :ivar _relpath: stats file (glob) path relative to .perun/stats/<minor version dir>/.
    :ivar _version: VCS minor version that the file (glob) path is relative to.
    """
    __slots__ = '_abspath', '_relpath', '_version'
    # Compression suffix common to all stats files
    suffix: ClassVar[str] = '.bz2'
    # The format should include all of the suffixes that are used
    _format: re.Pattern[str] | None = None

    def __init__(self, *path_parts: str | Path, minor_version: str | None = None) -> None:
        """Constructor. Creates a file (glob) path from 1..N string or Path segments.

        Attempts to resolve the supplied filepath (glob) w.r.t. the supplied minor version.
        The path (glob) can refer to a file that does not exist yet. However, if the resulting path
        is outside of the .perun/stats/<version> directory, an InvalidStatsPathException is raised.

        :param path_parts: file (glob) path segments.
        :param minor_version: VCS version to link the path to.
        """
        # Check that all parts of the path were provided
        if not all(path_parts):
            raise InvalidStatsPathException(
                f'Invalid {self.__class__.__name__} from an incomplete specification: {path_parts}.'
            )
        # Make sure that the path corresponds to an appropriate stats directory
        filepath = Path(*path_parts)
        minor_dir = Path(find_minor_stats_directory(minor_version)[1])
        if filepath.is_absolute():
            # Absolute paths are allowed only if they are within the appropriate minor version dir
            if not filepath.is_relative_to(minor_dir):
                raise InvalidStatsPathException(
                    f"The stats file path '{filepath}' is not relative to the expected "
                    f"'{minor_dir}' directory."
                )
        else:
            filepath = minor_dir / filepath
        # Make sure that the (possibly derived) stats file has correct suffix(es)
        filepath = self._resolve_suffixes(filepath)
        # These attributes must never be changed directly, access them through read-only properties
        self._abspath: Path = filepath
        self._relpath: Path = filepath.relative_to(minor_dir)
        self._version: str | None = minor_version

    def __eq__(self, other: object) -> bool:
        """An equivalence operator. Two stats paths are considered equal if their absolute paths
        are the same.

        :param other: the other comparison operand.

        :return: True if the stats paths are the same, False otherwise.
        """
        if not isinstance(other, StatsPath):
            return NotImplemented
        return self.absolute == other.absolute

    @classmethod
    def from_path(cls: Type[PT], path: Path, minor_version: str | None) -> PT:
        """Constructs a StatsPath (or its subclass) from a Path object, if possible.

        The method first checks that the file path (glob) is valid w.r.t. the name format pattern.
         - If no format pattern is specified, the path is assumed to be valid.
         - If a format pattern is specified and the path fails to match, an
           InvalidStatePathException is raised.
         - If a format pattern is specified, the path is successfully matched but the match
           contains no regex groups, the path itself is used to construct the object.
         - If a format pattern is specified, the path is successfully matched and it contains
           regex groups, the matched groups are used as parameters for the object constructor.

        :param path: a stats file (glob) path to construct the object from.
        :param minor_version: VCS version to link the path to.

        :return: a constructed stats path object, if possible.
        """
        matches, match_obj = cls.matches_format(path)
        if not matches:
            # There is a pattern provided and the path does not match it
            raise InvalidStatsPathException(f"'{path}' is invalid {cls.__class__.__name__} path.")
        if match_obj is not None and match_obj.groups():
            # The provided path matches the regex and contains match groups for the constructor
            return cls(*(str(grp) for grp in match_obj.groups()), minor_version=minor_version)
        # No regex groups, use the path itself as an argument
        return cls(path, minor_version=minor_version)

    @classmethod
    def matches_format(cls, path: Path) -> tuple[bool, re.Match | None]:
        """Validates that the file (glob) path matches the format regex.

        Note that the re.search method is used, hence it is recommended to anchor the format regex
        by using the '$' at the end.

        :param path: a stats file (glob) path for format validation.

        :return: indication whether the path matches the pattern, optional regex match object.
        """
        if cls._format is None:
            return True, None
        match = cls._format.search(str(path))
        return match is not None, match

    @property
    def absolute(self) -> Path:
        """Retrieves the absolute stats file (glob) path.

        :return: the absolute stats file (glob) path.
        """
        return self._abspath

    @property
    def relative(self) -> Path:
        """Retrieves the relative stats file (glob) path.

        :return: the relative stats file (glob) path.
        """
        return self._relpath

    @property
    def minor_version(self) -> str | None:
        """Retrieves the VCS minor version linked to the path.

        :return: the VCS minor version representation.
        """
        return self._version

    def as_glob(self) -> str:
        """Retrieves the path as a glob string.

        :return: path as a glob.
        """
        return str(self._relpath)

    def _resolve_suffixes(self, path: Path) -> Path:
        """Ensures the path has correct suffixes w.r.t. the stats path class.

        Checks that the path has all of the suffixes specified in the `suffix` class variable AND
        that the base compression suffix is there.
        If not, the path is changed to contain all of the correct suffixes.

        :param path: a stats file (glob) path to resolve the suffix for.

        :return: the stats path with correct suffixes.
        """
        file_suffixes = ''.join(path.suffixes)
        if file_suffixes != self.suffix:
            # Remove suffixes one by one until there is only the file name
            while path.suffix:
                path = path.with_suffix("")
            # Now add the correct suffix for the file type
            path = path.with_suffix(self.suffix)
        # Make sure the file's last suffix is the compression suffix common to all stats files
        if path.suffix != StatsPath.suffix:
            path = path.with_suffix(path.suffix + StatsPath.suffix)
        return path


class StatsFile(Generic[PT]):
    """Generic stats file wrapper class.

    The class is parametrized by a StatsPath object or its subclasses. The path should represent
    an actual file (that might not yet exist) and not a glob.

    To actually access the stats file and manipulate its contents, use the `open` method.
    Furthermore, note that the StatsFile object can be conveniently reused for multiple
    subsequent (!) opens:

    ```
    sf = StatsFile(StatsPath('test', <minor version>))
    with sf.open('wb') as f:
        pickle.dump(<obj>, f)

    with sf.open('rb') as f:
        obj = pickle.load(f)
    ```

    :ivar filepath: a StatsPath (or its subclass) instance.
    """
    __slots__ = ('filepath',)

    write_modes: ClassVar[set[str]] = {'w', 'wb', 'wt', 'x', 'xb', 'xt', 'a', 'ab', 'at'}

    def __init__(self, filepath: PT) -> None:
        """Constructor.

        :param filepath: a StatsPath (or its subclass) instance.
        """
        if filepath.absolute.exists() and not filepath.absolute.is_file():
            # Stats path used in an actual StatsFile must be a regular file path
            raise InvalidStatsPathException(
                f"The stats file path {filepath.relative} does not point to a regular file!"
            )
        self.filepath: PT = filepath

    def __eq__(self, other: object) -> bool:
        """An equivalence operator. Two stats files are considered equal if their stats paths
        are the same.

        :param other: the other comparison operand.

        :return: True if the stats files are the same, False otherwise.
        """
        if not isinstance(other, StatsFile):
            return NotImplemented
        return self.filepath == other.filepath

    def exist(self) -> bool:
        """Checks whether a stats file corresponding to the given path exists.

        :return: True if the path corresponds to an existing file, False otherwise.
        """
        return self.filepath.absolute.exists()

    def delete(self) -> None:
        """Remove the StatsFile (if it exists) and empty directories leading up to the file.

        E.g., for a stats file path ./some_dir/another_dir/file.bz2 (relative to the minor version
        directory), the method deletes the file.bz2 and then both `another_dir` and `some_dir` if
        they become empty. If the minor version directory becomes empty as a result of the file
        deletion, it will also be deleted.
        """
        self.filepath.absolute.unlink(missing_ok=True)
        try:
            # Recursively remove empty directories (up to the <minor version dir>)
            dir_path = self.filepath.relative.parent
            while dir_path != '.':
                dir_path.rmdir()
                dir_path = dir_path.parent
            delete_version_dirs([self.filepath.minor_version], True)
        except OSError:
            return

    @overload
    def open(self, mode: FileTextModes, **bz2_kwargs: Any) -> TextIO:
        # A dummy implementation to avoid pylint no-context-manager false positive:
        # Source: https://github.com/PyCQA/pylint/issues/5273
        return bz2.open(self.filepath.absolute, mode=mode, **bz2_kwargs)

    @overload
    def open(self, mode: FileBinModes, **bz2_kwargs: Any) -> bz2.BZ2File:
        return bz2.open(self.filepath.absolute, mode=mode, **bz2_kwargs)

    def open(self, mode: FileTextModes | FileBinModes, **bz2_kwargs: Any) -> TextIO | bz2.BZ2File:
        """Open the specified stats file in the given mode.

        The stats files are stored in a bz2 compression format. The returned IO object takes care
        of the underlying incremental (de)compression, hence the IO object can be manipulated
        (written to, read from) as usual Text or Binary IO files.

        The returned object can be used standalone or as a usual IO context manager object.
        The supported modes can be found in the bz2 module documentation.

        :param mode: a mode in which to open the file (read, write, append, exclusive create, ...).
        :param bz2_kwargs: additional bz2 (de)compression parameters.

        :return: textual or binary IO object, based on the selected mode (text or binary).
        """
        # Create the stats version directory only if we attempt to write
        version, abspath = self.filepath.minor_version, self.filepath.absolute
        if mode in self.write_modes:
            version_dir = _touch_minor_stats_directory(version)
            # Create additional version sub-directories on the path
            if abspath.parent != version_dir:
                utils_helpers.touch_dir(str(abspath.parent))
        # Remove keys that are supplied as positional arguments
        for invalid_key in ('filename', 'mode'):
            bz2_kwargs.pop(invalid_key, None)
        try:
            return bz2.open(abspath, mode=mode, **bz2_kwargs)
        except FileNotFoundError as exc:
            raise StatsFileNotFoundException(abspath) from exc


def exist_any(path_glob: PT, versions: VersionsLookup = None) -> bool:
    """Checks the existence of any stats file corresponding to a glob pattern.

    If `versions` are not specified, the minor version in the path glob will be used.
    Otherwise, only the specified `versions` will be checked (the path glob version
    will be ignored).

    :param path_glob: a glob pattern to resolve.
    :param versions: if set, only the versions will be checked.

    :return: True if the glob matches at least one existing stats file, False otherwise.
    """
    for _ in iter_paths(path_glob, versions):
        return True
    return False


def iter_predecessors(path_glob: PT, top: int = 0) -> Generator[list[PT], None, None]:
    """Iterate upmost `top` previous minor versions with files matching the given glob.

    The method searches for stats files matching the glob in minor versions that precede the
    minor version associated with the `path_glob`. For each such minor version that contains at
    least one matching file, a collection of all files matching the glob will be provided.

    If `top` has a positive value, at most `top` preceding minor versions with matching files
    will be iterated.

    :param path_glob: a glob pattern to search for.
    :param top: the maximum number of predecessor versions to iterate.

    :return: collections of paths matching the glob in preceding minor versions.
    """
    cnt = 0
    # Iterate the versions previous to the one found in the glob
    versions = list_stat_versions(path_glob.minor_version)
    if not versions:
        return
    for ver_hash, _ in versions[1:]:
        ver_paths = list(iter_paths(path_glob, versions=ver_hash))
        if ver_paths:
            cnt += 1
            yield ver_paths
            # Stop the iteration if we reached the number of requested predecessors
            if 0 < top <= cnt:
                return


def iter_paths(
        path_glob: PT, versions: VersionsLookup = None, b_min: int = 0, b_max: int = -1
) -> Generator[PT, None, None]:
    """Iterates existing stats file paths conforming to the glob, path type and minor versions.

    If `versions` are not specified, the minor version in the path glob will be used.
    Otherwise, only the specified `versions` will be used (the path glob version will be ignored).

    Only valid paths corresponding to the generic path type AND the glob pattern will be iterated.
    E.g., when path_glob is an instance of a class `MyStats` that is a subclass of `StatsFile`,
    only the stats files that match the glob pattern itself and the name format of `MyStats` will
    be iterated.

    It is possible to further check the bounds of the iteration, so that when the bounds are
    violated (i.e., the number of iterated elements is not in [min, max]), an
    IteratorBoundsException is raised.

    :param path_glob: a glob pattern to filter the iterated paths.
    :param versions: if set, only file paths in the versions will be iterated.
    :param b_min: the minimum number of elements that should be present in the iterator.
    :param b_max: the maximum number of elements that should be present in the iterator.

    :return: a generator of paths matching the glob pattern and the path type format.
    """
    version_iter: VersionsIterable = _unify_versions(versions, path_glob.minor_version)
    cnt = 0
    # Iterate all of the versions
    for minor_version in version_iter:
        minor_dir = Path(find_minor_stats_directory(minor_version)[1])
        # Iterate all files in the version
        for file in minor_dir.glob(path_glob.as_glob()):
            try:
                # The constructor takes care of invalid paths.
                valid_path = path_glob.__class__.from_path(file.resolve(), minor_version)
                cnt += 1
                if 0 < b_max < cnt:
                    # Upper bound set and too many files found
                    raise exceptions.IteratorBoundsException(b_min, b_max, cnt)
                yield valid_path
            except InvalidStatsPathException:
                pass
    if cnt < b_min:
        # Lower bound set and not enough files found
        raise exceptions.IteratorBoundsException(b_min, b_max, cnt)


def iter_files(
        path_glob: PT, versions: VersionsLookup = None, b_min: int = 0, b_max: int = -1
) -> Generator[StatsFile[PT], None, None]:
    """Iterates existing stats files based on the glob and the path type.

    This function behaves similarly to the `iter_paths` function, but it transforms the stats file
    paths directly to the StatsFile objects.

    :param path_glob: a glob pattern to filter the iterated paths.
    :param versions: if set, only files in the versions will be iterated.
    :param b_min: the minimum number of elements that should be present in the iterator.
    :param b_max: the maximum number of elements that should be present in the iterator.

    :return: a generator of StatsFiles matching the glob pattern and the path type format.
    """
    yield from (StatsFile(path) for path in iter_paths(path_glob, versions, b_min, b_max))


def _unify_versions(versions: VersionsLookup, path_version: str | None) -> VersionsIterable:
    """ Unify the minor versions type so that the versions can be correctly iterated.

    In general, the minor versions can be specified as:
     1) None: refers to the `path_version` if specified, otherwise refers to HEAD,
     2) single string representing a single minor version
     3) any string iterable (sequence, iterator, ...)

    The unification process makes sure that the versions are always a correct iterable, e.g.,
    that we don't iterate over the characters in the minor version string.

    :param versions: the versions to iterate.
    :param path_version: the stats path version.

    :return: correct iterable of minor versions that can be iterated in a loop.
    """
    if versions is None:
        if path_version is None:
            return [vcs.get_minor_head()]
        return [path_version]
    if isinstance(versions, str):
        return [versions]
    return versions


def build_stats_filename_as_profile_source(profile, ignore_timestamp, minor_version=None):
    """Generate stats filename based on the 'source' property of the supplied profile,
    i.e. the stats filename will refer to the name of the profile before it was tracked.

    :param str profile: the profile identification, can be given as tag, sha value,
                        sha-path (path to tracked profile in obj) or source-name
    :param bool ignore_timestamp: if set to True, removes the 'date' component in the source name
    :param str minor_version: representation of the minor version or None for HEAD

    :return str: the generated stats filename (not path!)
    """
    profile_index_entry = helpers.find_profile_entry(profile, minor_version)
    stats_name = profile_index_entry.path
    if ignore_timestamp:
        # Remove the timestamp entry in the profile name
        stats_name = PROFILE_TIMESTAMP_REGEX.sub("", stats_name)
    if stats_name.endswith('.perf'):
        # Remove the '.perf' suffix
        stats_name = stats_name[:-5]
    return stats_name


def build_stats_filename_as_profile_sha(profile, minor_version=None):
    """Generate stats filename based on the 'SHA' property of the supplied profile,
    i.e. the stats filename will refer to the name of the profile after its tracking.

    :param str profile: the profile identification, can be given as tag, sha value,
                        sha-path (path to tracked profile in obj) or source-name
    :param str minor_version: representation of the minor version or None for HEAD

    :return str: the generated stats filename (not path!)
    """
    return helpers.find_profile_entry(profile, minor_version).checksum


def get_stats_file_path(stats_filename, minor_version=None, check_existence=False,
                        create_dir=False):
    """Create full path for the given minor version and the stats file name.

    Note: the existence of the file is checked only if the corresponding parameter is set to True.
    If set to True and the file does not exist, StatsFileNotFoundException is raised.

    Note: the corresponding minor version directory is created only if 'create_dir' is set to True.
    However, if the minor version is not valid, an exception is thrown.

    :param str stats_filename: the name of the stats file to generate the path for
    :param str minor_version: the minor version representation or None for HEAD
    :param bool check_existence: the existence of the generated path is checked if set to True
    :param bool create_dir: the minor version directory will be created if it does not exist yet

    :return str: the full path to the file under the given minor version
    """
    stats_file = os.path.join(find_minor_stats_directory(minor_version)[1],
                              os.path.basename(stats_filename.rstrip(os.sep)))
    # Create the minor version directory if requested
    if create_dir:
        _touch_minor_stats_directory(minor_version)
    # Check if the file exists
    if check_existence and not os.path.exists(stats_file):
        raise StatsFileNotFoundException(stats_file)
    return stats_file


@vcs.lookup_minor_version
def find_minor_stats_directory(minor_version):
    """ Finds the stats directory for the given minor version and checks its existence.

    :param str minor_version: the minor version representation or None for HEAD

    :return tuple: (bool representing the existence of directory, the directory path)
    """
    _, minor_dir = store.split_object_name(pcs.get_stats_directory(), minor_version)
    return os.path.exists(minor_dir), minor_dir


def add_stats(stats_filename, stats_ids, stats_contents, minor_version=None):
    """ Save some stats represented by an ID into the provided stats filename under a specific
    minor version. Creates the stats file if it does not exist yet.

    :param str stats_filename: the name of the stats file where the data will be stored
    :param list of str stats_ids: strings that serve as unique identification of the stored stats
    :param list of dict stats_contents: the stats data to save
    :param str minor_version: the minor version representation or None for HEAD

    :return str: the path to the stats file containing the stored data
    """

    stats_file = get_stats_file_path(stats_filename, minor_version, create_dir=True)
    # append: create the file if necessary, be able to read the whole file and write to the file
    _modify_stats_file(stats_file, stats_ids, stats_contents, _add_to_dict)

    return stats_file


def update_stats(stats_filename, stats_ids, extensions, minor_version=None):
    """ Updates the stats represented by an ID in the given stats filename under a specific
    minor version. The stats dictionary will be extended by the supplied extensions.

    :param str stats_filename: the name of the stats file where to update the stats
    :param list of str stats_ids: strings that serve as unique identification of the stored stats
    :param list of dict extensions: the dicts with the new / updated values
    :param str minor_version: the minor version representation or None for HEAD
    """
    stats_file = get_stats_file_path(stats_filename, minor_version, create_dir=True)
    _modify_stats_file(stats_file, stats_ids, extensions, _update_or_add_to_dict)


def get_stats_of(stats_filename, stats_ids=None, minor_version=None):
    """ Gets the stats content represented by an ID (or the whole content if stats_id is None)
    from the stats filename under a specific minor version.
    Raises StatsFileNotFoundException if the given file does not exist.

    :param str stats_filename: the name of the stats file where to search for the stats
    :param list of str stats_ids: strings that serve as unique identification of the stored stats
    :param str minor_version: the minor version representation or None for HEAD

    :return dict: the stats content of the ID (or the whole file) or empty dict in case the
                  ID was not found in the stats file
    """
    stats_file = get_stats_file_path(stats_filename, minor_version, True)

    # Load the whole stats content and filter the ID if present
    with open(stats_file, "rb") as stats_handle:
        stats_content = _load_stats_from(stats_handle)
        if stats_ids is None:
            return stats_content
        # Extract the requested stats from the contents
        return {sid: val for sid, val in stats_content.items() if sid in stats_ids}


def delete_stats(stats_filename, stats_ids, minor_version=None):
    """ Deletes the stats represented by an ID in the stats filename under a specific
    minor version. Raises StatsFileNotFoundException if the given file does not exist.

    :param str stats_filename: the name of the stats file where to delete the stats
    :param list of str stats_ids: strings that serve as unique identification of the stored stats
    :param str minor_version: the minor version representation or None for HEAD
    """
    stats_file = get_stats_file_path(stats_filename, minor_version, True)
    # We need to construct some dummy 'contents' variable
    _modify_stats_file(stats_file, stats_ids, [{} for _ in range(len(stats_ids))],
                       lambda d, sid, _: d.pop(sid, []))


def list_stats_for_minor(minor_version=None):
    """ Returns all the stats files stored under the given minor version.

    :param str minor_version: the minor version representation or None for HEAD

    :return list: all the stats file names in the minor version as tuples (file name, file size)
    """
    minor_exists, target_dir = find_minor_stats_directory(minor_version)
    if minor_exists:
        # We assume that all the files in the minor version stats directory are actually stats
        _, _, files = next(os.walk(target_dir))
        return [(file, os.stat(os.path.join(target_dir, file)).st_size) for file in files]
    return []


def list_stat_versions(from_minor=None, top=0):
    """ Returns 'top' minor versions (starting at 'from_minor') that have directories and index
     records in the '.perun/stats'. The minor versions are sorted by date from the most recent.

    :param str from_minor: starting minor version or None for HEAD
    :param int top: the number of versions to return, 0 for unlimited

    :return list: the list of lists [version checksum, version date] sorted by date
    """
    indexed_versions = _load_stats_index()
    # Get the actual length if everything is to be displayed
    top = abs(len(indexed_versions) if top == 0 else top)
    return _slice_versions(indexed_versions, from_minor, top)


def delete_stats_file(stats_filename, minor_version=None, keep_directory=False):
    """ Deletes the stats file in the stats directory of the given minor version.
    Raises StatsFileNotFoundException if the given file does not exist.

    :param str stats_filename: the name of the stats file to delete
    :param str minor_version: the minor version representation or None for HEAD
    :param bool keep_directory: do not remove the possibly empty (after the file deletion) minor
                                version directory if set to True
    """
    stats_file = get_stats_file_path(stats_filename, minor_version, True)
    os.remove(stats_file)
    if not keep_directory:
        # Delete the minor version directory if it is empty
        minor_version = minor_version or vcs.get_minor_head()
        delete_version_dirs([minor_version], True)


def get_latest(stats_filename, stats_ids=None, exclude_self=False):
    """ Fetch the content of the latest stats file named 'stats_filename' according to the
    git versions.

    :param str stats_filename: the name of the stats file
    :param list stats_ids: fetch only the specified parts of the stats file
    :param bool exclude_self: ignore the stats file in the current git version

    :return dict: selected content (IDs) of the stats file, if found
    """
    versions = list_stat_versions()
    if exclude_self and versions[0][0] == vcs.get_minor_head():
        versions = versions[1:]
    # Traverse all the version directories and try to find it
    for version, _ in versions:
        with SuppressedExceptions(StatsFileNotFoundException):
            return get_stats_of(stats_filename, stats_ids, version)
    return {}


def delete_stats_file_across_versions(stats_filename, keep_directory=False):
    """ Deletes the stats file across all the minor version directories in stats.

    :param str stats_filename: the name of the stats file to delete
    :param bool keep_directory: do not remove the possibly empty (after the file deletion) minor
                                version directory if set to True
    """
    matches = []
    # Traverse all the version directories and attempt to delete the file
    for version, _ in list_stat_versions():
        # If the file was not found in this version, simply continue
        with SuppressedExceptions(StatsFileNotFoundException):
            delete_stats_file(stats_filename, version, True)
            matches.append(version)

    # Make sure we delete only empty version directories where we actually deleted the file
    if not keep_directory:
        delete_version_dirs(matches, True)


def delete_version_dirs(minor_versions, only_empty, keep_directories=False):
    """ Deletes the given minor version directories in the stats directory.

    Based on the only_empty parameter, it may delete only those which are empty or all of them.

    :param list minor_versions: a list of minor versions whose directories should be deleted
    :param bool only_empty: deletes only those directories in 'minor_versions' which are empty
    :param bool keep_directories: do not delete the minor version directories but only their
                                  content if set to True, does nothing if 'only_empty' is also True
    """
    # Deleting only empty directories and keeping the folders at the same time doesn't make sense
    if only_empty and keep_directories:
        return

    removed_versions = []
    for version in minor_versions:
        try:
            version_dir = store.split_object_name(pcs.get_stats_directory(), version)[1]
            if keep_directories:
                # Remove only the directories and files in the version directory
                _, dirs, files = next(os.walk(version_dir))
                _delete_stats_objects([os.path.join(version_dir, directory) for directory in dirs],
                                      [os.path.join(version_dir, file) for file in files])
            else:
                # Delete the whole directory
                if not only_empty:
                    shutil.rmtree(version_dir)
                # Attempt to delete the possibly empty directory
                elif only_empty and not _delete_empty_dir(version_dir):
                    continue
                # Also delete the lower level version directory (the first SHA byte) if empty
                _delete_empty_dir(os.path.split(version_dir)[0])
                removed_versions.append(version)
        except OSError as exc:
            # Failed to delete some object, log and skip
            perun_log.msg_to_file("Stats object deletion info: {}".format(str(exc)), 0)

    # Update the index to reflect the removed version directories
    _remove_versions_from_index(removed_versions)


def reset_stats(keep_directories=False):
    """ Clears the whole stats directory and attempts to reset it into the initial state.

    :param bool keep_directories: the empty version directories are kept in the stats directory
    """
    if keep_directories:
        # Synchronize the index to make sure that we delete every minor version
        synchronize_index()
        delete_version_dirs([version for version, _ in list_stat_versions()], False, True)
        clean_stats(keep_empty=True)
    else:
        # No need to keep the version directories, simply recreate the stats directory
        stats_dir = pcs.get_stats_directory()
        shutil.rmtree(stats_dir)
        utils_helpers.touch_dir(stats_dir)


def clean_stats(keep_custom=False, keep_empty=False):
    """ Cleans the stats directory, that is:
    - synchronizes the internal state of the stats directory, i.e. the index file
    - attempts to delete all distinguishable custom files and directories (some manually created or
      custom objects may not be identified if they have the correct format, e.g. version directory
      that was created manually but has a valid version counterpart in the VCS, manually created
      files in the version directory etc.)
    - deletes all empty version directories in the stats directory

    :param bool keep_custom: the custom objects are kept in the stats directory if set to True
    :param bool keep_empty: the empty version directories are not deleted if set to True
    """
    # First synchronize the index file
    synchronize_index()
    if not keep_custom:
        # Get the custom files and directories in the stats directory
        _, custom = _get_versions_in_stats_directory()
        custom_files, custom_dirs = utils.partition_list(custom, os.path.isfile)
        # Use the reversed order to minimize the number of exceptions due to already deleted files
        _delete_stats_objects(reversed(custom_dirs), reversed(custom_files))
    if not keep_empty:
        delete_version_dirs([version for version, _ in list_stat_versions()], True)


def synchronize_index():
    """ Synchronizes the index file with the actual content of the stats directory. Should be
    needed only after some manual tampering with the directories and files in the stats directory.
    """
    indexed_versions = _load_stats_index()
    stats_versions, _ = _get_versions_in_stats_directory()
    # Delete from index all minor version records that do not have a directory in stats anymore
    indexed_versions = [version for version in indexed_versions if tuple(version) in stats_versions]
    # Add record to index for all versions in stats that do not already have one
    # Make sure the values are sorted by date and are unique by inserting all the records
    _add_versions_to_index(stats_versions + indexed_versions, [])


def _delete_stats_objects(dirs, files):
    """ Deletes stats directories and files, should be used only for deleting the content of
    directories or standalone files, not minor version directories.

    :param iterable dirs: the list of directories (paths) to delete
    :param iterable files: the list of files (paths) to delete
    """
    # Deleting directories first could cause some 'files' to be removed and raising more exceptions
    for idx, group in enumerate([files, dirs]):
        delete_func = shutil.rmtree if idx == 1 else os.remove
        for item in group:
            try:
                delete_func(item)
            except OSError as exc:
                # Possibly already deleted files or restricted permission etc., log and skip
                perun_log.msg_to_file("Stats object deletion error: {}".format(str(exc)), 0)


def _delete_empty_dir(directory_path):
    """ Deletes the directory given by the path if it is empty. If not, then nothing is done.

    :param str directory_path: path to the directory that should be deleted

    :return bool: True if the directory was deleted, False otherwise
    """
    if not os.listdir(directory_path):
        os.rmdir(directory_path)
        return True
    return False


def _add_to_dict(dictionary, sid, content):
    """ A helper function that stores the stats content in the given dict under the ID

    :param dict dictionary: the dictionary where the content will be stored
    :param str sid: a string that serves as a unique identification of the stored stats
    :param dict content: the stats data to save
    """
    dictionary[sid] = content


def _update_or_add_to_dict(dictionary, sid, extension):
    """ A helper function that updates the stats content in the given dict under the ID or creates
    the new ID with the 'extension' content if it does not exist

    :param dict dictionary: the dictionary where the content will be stored
    :param str sid: a string that serves as a unique identification of the stored stats
    :param dict extension: the stats data to save
    """
    if sid in dictionary:
        dictionary[sid].update(extension)
    else:
        _add_to_dict(dictionary, sid, extension)


@vcs.lookup_minor_version
def _touch_minor_stats_directory(minor_version):
    """ Touches the stats directories - upper (first byte of the minor version SHA) and lower (the
    rest of the SHA bytes) levels.

    :param str minor_version: the minor version representation or None for HEAD

    :return str: the full path of the minor version directory for stats
    """
    # Obtain path to the directory for the given minor version
    _, lower_level_dir = store.split_object_name(pcs.get_stats_directory(), minor_version)
    # Make an entry in the index if the minor version directory does not exist yet
    if not os.path.exists(lower_level_dir):
        _add_versions_to_index([_get_version_info(store.version_path_to_sha(lower_level_dir))])

    # Create the directory for storing statistics in the given minor version
    utils_helpers.touch_dir(lower_level_dir)
    return lower_level_dir


def _load_stats_from(stats_handle):
    """ Loads and unzips the contents of the opened stats file.

    :param file stats_handle: the handle of the stats file

    :return dict: the stats file contents
    """
    try:
        # Make sure we're at the beginning
        stats_handle.seek(0)
        return json.loads(store.read_and_deflate_chunk(stats_handle))
    except (ValueError, error):
        # Contents either empty or corrupted, init the content to empty dict
        return {}


def _save_stats_to(stats_handle, stats_records):
    """ Saves and zips the stats contents (records) to the file.

    :param file stats_handle: the handle of the stats file
    :param dict stats_records: the contents to save
    """
    # We need to rewrite the file contents, so move to the beginning and erase everything
    stats_handle.seek(0)
    stats_handle.truncate(0)
    compressed = store.pack_content(json.dumps(stats_records, indent=2).encode('utf-8'))
    stats_handle.write(compressed)


def _modify_stats_file(stats_filepath, stats_ids, stats_contents, modify_function):
    """ Modifies the contents of the given stats file by the provided modification function

    :param str stats_filepath: the path to the stats file
    :param list of str stats_ids: identifications of the stats block that are being modified
    :param list of dict stats_contents: the data to modify (add, update, ...)
    :param function modify_function: function that takes the stats contents as a parameter and
                                     modifies it accordingly
    """
    with open(stats_filepath, 'a+b') as stats_handle:
        stats_records = _load_stats_from(stats_handle)
        for idx in range(min(len(stats_ids), len(stats_contents))):
            modify_function(stats_records, stats_ids[idx], stats_contents[idx])
        _save_stats_to(stats_handle, stats_records)


def _get_version_candidates(minor_checksum, minor_date):
    """ Obtains successor minor versions that have the same date as the given minor version.

    :param str minor_checksum: the minor version checksum
    :param str minor_date: the date of the minor version

    :return list: list of successor versions as tuples: (checksum, date)
    """
    candidates = []
    # Ignore some unexpected git corruption or the end of minor version history
    with SuppressedExceptions(exceptions.VersionControlSystemException, StopIteration):
        # Start iterating the minor versions at the supplied version
        from_iter = vcs.walk_minor_versions(minor_checksum)
        # However, the first generator result is the version itself, skip it
        next(from_iter)
        successor = vcs.get_minor_version_info(next(from_iter).checksum)
        while successor.date == minor_date:
            candidates.append(successor.checksum)
            successor = vcs.get_minor_version_info(next(from_iter).checksum)
    return candidates


def _get_version_info(minor_version):
    """ Resolves the minor version and returns its checksum and date. An exception
    VersionControlSystemException is raised if the version is invalid.

    :param str minor_version: the minor version representation

    :return tuple (str, str): the minor version details (checksum, date)
    """
    vcs.check_minor_version_validity(minor_version)
    minor_version = vcs.get_minor_version_info(minor_version)
    return minor_version.checksum, minor_version.date


def _add_versions_to_index(minor_versions, index_stats=None):
    """ Adds the minor versions records to the stats index file.

    :param list minor_versions: list of minor versions (checksum, date) to add
    :param list index_stats: the content of the index file - is loaded from the file if not provided
    """
    index_stats = _load_stats_index() if index_stats is None else index_stats
    for checksum, date in minor_versions:
        # Find the correct location for inserting the new minor record, avoid duplicates
        insert_pos = _find_nearest_version(index_stats, checksum, date)
        if insert_pos == len(index_stats) or index_stats[insert_pos] != [checksum, date]:
            index_stats.insert(insert_pos, [checksum, date])
    index.save_custom_index(pcs.get_stats_index(), index_stats)


def _remove_versions_from_index(minor_versions):
    """ Removes minor versions from the index file.

    :param list minor_versions: list of minor versions (checksums) to delete
    """
    index_stats = [[checksum, date] for checksum, date in _load_stats_index()
                   if checksum not in minor_versions]
    index.save_custom_index(pcs.get_stats_index(), index_stats)


def _find_nearest_version(versions, minor_checksum, minor_date):
    """ Searches the 'versions' list in order to find a minor version record that is closest to the
    provided minor version in terms of VCS order.

    Thus either the exact record or the nearest successor of the exact minor version is found.

    :param list versions: a list of minor versions in form of tuple (checksum, date)
    :param str minor_checksum: the minor version checksum
    :param str minor_date: the date of the minor version

    :return int: the position of the nearest minor version in the 'versions' list
    """
    # Obtain the minor version and check the validity
    candidates = _get_version_candidates(minor_checksum, minor_date)
    # Traverse the versions list and try to find either the version record or its next successor
    for record_pos, (stat_checksum, stat_date) in enumerate(versions):
        # The records are sorted by date - if dates are equal, then git ordering is used
        if (minor_checksum == stat_checksum or stat_date < minor_date or
                (stat_date == minor_date and stat_checksum in candidates)):
            return record_pos
    # No result found, the exact version is not there and it has no successor
    return len(versions)


def _slice_versions(versions, from_version, top):
    """ Slice the given versions list based on the starting minor version and number of 'top'
    requested version records.

    :param list versions: the list of versions to slice
    :param str from_version: the minor version to start at
    :param int top: number of version records to take

    :return list: the versions list sliced accordingly to the parameters
    """
    try:
        # If not provided, the default start is at the HEAD
        if from_version is None:
            from_version = vcs.get_minor_head()
        from_checksum, from_date = _get_version_info(from_version)
        # The list may not contain the exact version, try to find the closest one
        slice_location = _find_nearest_version(versions, from_checksum, from_date)
        return versions[slice_location:slice_location + top]
    except exceptions.VersionControlSystemException:
        # Start from the beginning in case of some trouble with version lookup
        return versions[:top]


def _get_versions_in_stats_directory():
    """ Returns a list of minor versions that have a directory in the '.perun/stats' and a list
    of custom directories or files that were not created by the stats interface.

    :return tuple: list of minor versions (checksum, date),
                   list of custom directories and files
    """

    def dirs_generator(directory, custom_list, filter_func=None):
        """ Generator of directories contained within the 'directory'. Files or objects not passing
        the filter function are appended to the custom list.

        :param str directory: path of the base directory to scan for other directories
        :param list custom_list: list for custom objects that are not valid directories
        :param function filter_func: optional function that can filter the traversed directories

        :return generator: generator object that provides the valid directories
        """
        for item in os.listdir(directory):
            item = os.path.join(directory, item)
            # Filter out objects that are not directories or do not pass the filtering function
            if not os.path.isdir(item) or (filter_func is not None and not filter_func(item)):
                custom_list.append(item)
            # The rest should be valid directories
            else:
                yield item

    # List all the upper and lower directories
    versions, custom = [], []
    stats_dir, stats_idx = pcs.get_stats_directory(), pcs.get_stats_index()
    # The upper level of directories should represent the first SHA byte
    for upper in list(dirs_generator(stats_dir, custom, os.listdir)):
        # The lower level represents the rest of the SHA
        lower_list = list(dirs_generator(upper, custom))
        # If there are no lower level directories, then the upper directory is custom
        if not lower_list:
            custom.append(upper)
        # Check all the lower level objects
        temp_versions, temp_custom = [], []
        for lower in lower_list:
            try:
                # Construct the minor version from SHA and resolve it
                temp_versions.append(_get_version_info(store.version_path_to_sha(lower)))
                # Check the contents of the minor version stats, directories should not be allowed
                # Do not check the files as we do not really have a way to distinguish custom ones
                temp_custom.extend(list(dirs_generator(lower, [])))
            except exceptions.VersionControlSystemException:
                temp_custom.append(lower)
        # If all the objects in the upper directory are custom, delete the upper
        # Otherwise delete only the lower level objects
        if not temp_versions:
            custom.append(upper)
        else:
            versions.extend(temp_versions)
            custom.extend(temp_custom)

    # Remove the .index file from the custom list if it is present
    if stats_idx in custom:
        custom.remove(stats_idx)

    return versions, custom


def _load_stats_index():
    """ Wraps the loader of custom index files so that it would return the expected default value.

    :return list: list of records in the index file or empty list for empty index file
    """
    stats_index = index.load_custom_index(pcs.get_stats_index())
    return stats_index if stats_index else []


class StatsFileNotFoundException(Exception):
    """Raised when the looked up stats file does not exist."""
    def __init__(self, filename: Path | str) -> None:
        super().__init__("")
        self.path: Path | str = filename

    def __str__(self) -> str:
        return f"The requested stats file '{self.path}' does not exist."


class InvalidStatsPathException(Exception):
    """Raised when a stats file path is invalid.

    The exception message should clarify the reason why the path is invalid, e.g.:
     - it is not relative to the .perun/stats/<minor_version>/ directory,
     - it does not conform to the expected path pattern w.r.t. stats file type,
     - it cannot be properly constructed from the related stats file object (e.g., when empty).
    """


class StatsFilesLookupException(Exception):
    """Raised when stats file lookup fails for some reason.

    The exception message should further clarify the exact problem.
    """
