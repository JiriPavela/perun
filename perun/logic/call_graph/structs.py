"""A helper module with structures, constants and enumerations commonly used by other CG modules.
"""
from __future__ import annotations
from typing import Literal

from enum import Enum


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


class CGFlavour(Enum):
    """Call graph flavours enumeration.

    Flavours can be understood as call graph layers, where each layer represents different source
    of call relation data. More concretely:
     - RAW flavour represents data that were gathered from a call graph extraction tool.
     - STATIC flavour corresponds to the RAW version without unreachable nodes or edges.
     - DYNAMIC flavour represents call relation data as obtained from possibly multiple runs.
     - MIXED flavour represents a merge of STATIC and DYNAMIC flavours.
    """
    RAW = 'r'
    STATIC = 's'
    DYNAMIC = 'd'
    MIXED = 'm'


class CGExtractor(Enum):
    """An enumeration of supported call graph extraction tools."""
    ANGR = 'a'
