"""A helper module with structures, constants and enumerations commonly used by other CG modules.
"""
from __future__ import annotations
from typing import Literal

from enum import Enum

from perun.utils.structs import OrderedEnum


# Specifies a set of valid CG states - the '*' is used for glob lookup patterns.
ValidStates = Literal['c', 'd', '*']

# Timestamp format used for the CG version stats files
TIMESTAMP_FMT = '%Y-%m-%d-%H-%M-%S'


class VersionState(Enum):
    """Call graph version state enumeration.

    The Call graph version state can be either dirty or clean, depending on whether the files
    used for call graph extraction were reported as changed by the VCS.
    """
    CLEAN = 'c'
    DIRTY = 'd'


class CGFlavour(OrderedEnum):
    """Call graph flavours enumeration.

    Flavours can be understood as call graph layers, where each layer represents different source
    of call relation data. More concretely:
     - RAW flavour represents data that were gathered from a call graph extraction tool.
     - STATIC flavour corresponds to the RAW version without unreachable nodes or edges.
     - DYNAMIC flavour represents call relation data obtained from possibly multiple profiling runs.
     - MIXED flavour represents a merge of RAW and DYNAMIC flavours.
    """
    RAW = 'r'
    STATIC = 's'
    DYNAMIC = 'd'
    MIXED = 'm'

    def dep_requires(self) -> set[CGFlavour]:
        """Obtains flavours that this flavour depends on.

        Some CG flavours depend on either the existence or consistency of other flavours in the CG.
        E.g., to construct the MIXED flavour, both RAW and DYNAMIC flavours must exist and be
        consistent.

        :return: a collection of flavours that this flavour depends on.
        """
        return _CGF_REQ_MAP[self]

    def dep_changes(self) -> set[CGFlavour]:
        """Determines which flavours are dependant on this one.

        Modifying a structure of some CG flavour F can cause inconsistencies in derived (or
        dependant) flavours. Hence we provide a mapping of flavours that are affected by changes
        in each flavours.
        E.g., when changing the DYNAMIC flavour, the MIXED flavour needs to change accordingly.

        :return: a collection of flavours depending on this one.
        """
        return _CGF_CHANGE_MAP[self]


class CGExtractor(Enum):
    """An enumeration of supported call graph extraction tools."""
    ANGR = 'a'


# flavour -> {require}
_CGF_REQ_MAP: dict[CGFlavour, set[CGFlavour]] = {
    CGFlavour.RAW: set(),
    CGFlavour.STATIC: {CGFlavour.RAW},
    CGFlavour.DYNAMIC: {CGFlavour.DYNAMIC},  # Dynamic flavour iteratively builds on itself
    CGFlavour.MIXED: {CGFlavour.RAW, CGFlavour.DYNAMIC}
}

# flavour -> {depend}
_CGF_CHANGE_MAP: dict[CGFlavour, set[CGFlavour]] = {
    CGFlavour.RAW: {CGFlavour.STATIC, CGFlavour.MIXED},
    CGFlavour.STATIC: set(),
    CGFlavour.DYNAMIC: {CGFlavour.MIXED},
    CGFlavour.MIXED: set()
}
