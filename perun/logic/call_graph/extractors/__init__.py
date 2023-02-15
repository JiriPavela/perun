"""A package implementing Call Graph extraction and/or reconstruction.

To handle optional package dependencies and to reduce the overhead, the package uses on-demand lazy
imports in the factory function.

This package is designed to be easily extensible with additional CG extracting / reconstruction
tools or techniques (e.g., CG reconstruction from binary or source files). Additional extractors
should be implemented in a separate sub-module that is then imported on-demand within the factory
function.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

from abc import ABC, abstractmethod
from collections.abc import Collection
from enum import Enum
from pathlib import Path

if TYPE_CHECKING:
    from perun.logic.call_graph import CallGraph


class CallGraphExtractorError(Exception):
    """Raised when the process of Call Graph extraction fails."""

    def __init__(self, extractor: SupportedExtractors, msg: str) -> None:
        """Initializer.

        :param extractor: the selected CG extractor.
        :param msg: the error message.
        """
        self.extractor: SupportedExtractors = extractor
        self.msg: str = msg

    def __str__(self) -> str:
        """Create a human-readable representation of the error.

        :return: the error message as a string.
        """
        return f"Extractor '{self.extractor.value}': {self.msg}"


class SupportedExtractors(Enum):
    """An enumeration of supported call graph extraction tools.

    - ANGR: performs CG reconstruction from a binary file and a collection of library files.
    """

    ANGR = "angr"


class CGExtractor(ABC):
    """Call Graph extractor interface.

    By default, the concrete extractor class should not perform the CG reconstruction
    immediately after its instantiation, but only after the extract method is used.

    Also note, that the extraction process should identify the CG entry point
    (e.g., the 'main' or '_start' function).

    If CFG was extracted as well, it will be stored within the CG structure.
    """

    @abstractmethod
    def extract(self, with_control_flow: bool = True) -> CallGraph:
        """The CG (and optionally CFG) extraction method.

        :param with_control_flow: True if the extractor should reconstruct the CFG as well.

        :return: the reconstructed CG, optionally containing the functions' CFGs.
        """


def extractor_factory(
    extractor: SupportedExtractors,
    binary: Path | None = None,
    libs: Collection[Path] | None = None,
) -> CGExtractor:
    """Provides an initialized CG extractor class based on the selected extractor.

    The factory method is using on-demand import of the selected extractor so that missing
    dependencies of different extractors do not cause crashes or impose unnecessary overhead.

    Note that the actually used input arguments depend on the selected extractor, that is, different
    extractors may require different parameters For example, the binary CG extractor 'angr' requires
    a path to the binary file and optionally a collection of libraries, while source code extractors
    will require a source directory path or an enumeration of source files.

    TODO: extend the signature for static CG extractors when we use one.

    :param extractor: the selected extractor.
    :param binary: a path to the main binary file to extract from.
    :param libs: paths to additional libraries to include in the CG.

    :return: an initialized extractor class.
    """
    # pylint: disable=import-outside-toplevel
    try:
        if extractor == SupportedExtractors.ANGR:
            import perun.logic.call_graph.extractors.angr_extractor as angr_module
            if binary is None:
                raise CallGraphExtractorError(extractor, "Missing required parameter `binary`.")
            return angr_module.AngrExtractor(binary, libs)
        raise NotImplementedError(f"Missing extractor implementation: {extractor.name}")
    except ImportError as exc:
        raise CallGraphExtractorError(
            extractor,
            f"The required module {exc.name} not found. "
            f"Please install the module or use a different call graph extractor.",
        ) from exc
