"""This module implements serialization and deserialization of CG and CFG.

While the serialization and deserialization of CG, CFG, and any nested objects could be solved by
implementing (de)serialization methods within the classes directly, this would likely clutter the
class design with additional responsibility unrelated to its primary function.

We also deliberately separated the (de)serialization implementation from the __init__ file,
even though this created a circular dependency between the files (the circular dependency is
solved through lazy module importing). This was done to reduce the namespace pollution that would
manifest when importing directly from the call_graph package through its __init__ file.

Currently, the module implements only JSON (de)serialization. However, the resulting JSON is then
additionally compressed by the stats' module.
"""

from __future__ import annotations
from typing import Any

import json
from enum import Enum
from pathlib import Path
from datetime import datetime

import networkx as nx

from perun.utils.structs import VCSChangeState
from perun.collect.identification import CollectCompoundId
from perun.logic.stats import StatsFile

from perun.logic.call_graph import CallGraphManager
from perun.logic.call_graph.graphs import CallGraph, FuncCFG, CFGNode, CFGNodeBB, CFGNodeFunc
from perun.logic.call_graph.archs import SupportedArchs
from perun.logic.call_graph.path import CallGraphPath
from perun.logic.call_graph.version import FileChangeDetail, CGVersion
from perun.logic.call_graph.structs import (
    CFGNodeType,
    CGLayer,
    CGElementLayers,
    CGFlavour,
    VersionState,
    TIMESTAMP_FMT,
)


def save(cg_manager: CallGraphManager) -> StatsFile[CallGraphPath]:
    """Save the CG manager to a stats file.

    :param cg_manager: the CG manager object.

    :return: the stored stats file reference.
    """
    version_stats_file = StatsFile(cg_manager.filepath)
    with version_stats_file.open("wt") as cg_handle:
        json.dump(cg_manager, cg_handle, cls=CGJsonEncoder)
    return version_stats_file


def load(file: CallGraphPath | StatsFile[CallGraphPath]) -> CallGraphManager:
    """Load a CG manager from the provided path or file.

    :param file: the CG file specification.

    :return: the loaded CG manager.
    """
    if isinstance(file, CallGraphPath):
        file = StatsFile(file)
    with file.open("rt") as cg_handle:
        cg_manager: CallGraphManager = json.load(cg_handle, cls=CGJsonDecoder)
        return cg_manager


class CGJsonEncoder(json.JSONEncoder):
    """Custom JSON encoder class for encoding the CG classes."""

    def default(self, o: Any) -> Any:
        """Handle serialization of custom objects.

        For custom CG classes, we include the '_t' key into the serialized
        dictionary to recognize the class when performing deserialization.

        :param o: the object to serialize.

        :return: JSON-serialized object.
        """
        # pylint: disable=too-many-return-statements
        if isinstance(o, Enum):
            # Works only for enums that have a string as a value
            return o.value
        if isinstance(o, Path):
            return str(o)
        if isinstance(o, datetime):
            return o.strftime(TIMESTAMP_FMT)
        if isinstance(o, CollectCompoundId):
            return {"c": o.conf_name, "f": list(o.files), "o": list(o.opt_ids), "!t": "cid"}
        if isinstance(o, FileChangeDetail):
            return {
                "f": o.file,
                "h": o.file_hash,
                "s": o.state,
                "d": o.state_detail,
                "n": o.new_file,
                "fs": o.file_size,
                "m": o.modify_t,
                "!t": "fchd",
            }
        if isinstance(o, CGVersion):
            return {
                "c": o.cid,
                "v": o.vcs_version,
                "h": o.cg_version_hash,
                "s": {str(src): hsh for src, hsh in o.sources.items()},
                "t": o.version_timestamp,
                "cs": o.change_state,
                "ch": {str(file): detail for file, detail in o.changes.items()},
                "!t": "cgv",
            }
        if isinstance(o, CGLayer):
            return {
                "f": o.flavour.value if o.flavour is not None else "",
                "o": o.optimization if o.optimization is not None else "",
                "!t": "cgl",
            }
        if isinstance(o, CallGraph):
            return {
                "g": nx.adjacency_data(o.graph),
                "s": o.entry.static,
                "d": dict(o.entry.dynamic),
                "!t": "cg",
            }
        if isinstance(o, FuncCFG):
            return {
                "e": o.entrypoint,
                "a": o.architecture,
                "g": nx.adjacency_data(o.graph),
                "!t": "cfg",
            }
        if isinstance(o, CFGNode):
            return {"a": o.addr, "s": o.size, "d": o.data, "!t": f"cgn_{o.type.value}"}
        if isinstance(o, CGElementLayers):
            return {"l": list(o.layers), "!t": "cge"}
        if isinstance(o, CallGraphManager):
            return {"c": o.call_graph, "v": o.version, "!t": "cgm"}
        return super().default(o)


class CGJsonDecoder(json.JSONDecoder):
    """Custom JSON decoder class for decoding custom CG classes."""

    def __init__(self, *args: Any, **kwargs: Any):
        """Initializer.

        Registers the custom object decoding method.
        """
        super().__init__(object_hook=self.obj_hook, *args, **kwargs)

    @staticmethod
    def obj_hook(obj: Any) -> Any:
        """Implement deserialization for CG classes.

        The method uses the '_t' key to determine (a) if the JSON element is actually a custom CG
        object, and (b) the resulting class to construct using the element.

        :param obj: the object to deserialize.

        :return: either the deserialized object or the original JSON primitive.
        """
        # pylint: disable=too-many-return-statements
        if "!t" not in obj:
            return obj
        if obj["!t"] == "cid":
            return CollectCompoundId(
                collect_config_name=obj["c"],
                files={Path(file) for file in obj["f"]},
                optimization_ids=set(obj["o"]),
            )
        if obj["!t"] == "fchd":
            return FileChangeDetail(
                file=Path(obj["f"]),
                file_hash=obj["h"],
                state=VCSChangeState(obj["s"]),
                state_detail=obj.get("sd", ""),
                new_file=obj.get("n", ""),
                file_size=int(obj["fs"]),
                modify_time=datetime.strptime(obj["m"], TIMESTAMP_FMT),
            )
        if obj["!t"] == "cgv":
            return CGVersion(
                compound_id=obj["c"],
                minor_version=obj["v"],
                cg_version_hash=obj["h"],
                sources={Path(src): hsh for src, hsh in obj["s"].items()},
                timestamp=datetime.strptime(obj["t"], TIMESTAMP_FMT),
                change_state=VersionState(obj["cs"]),
                changes={Path(file): detail for file, detail in obj["ch"].items()},
            )
        if obj["!t"] == "cgl":
            return CGLayer(
                flavour=CGFlavour(obj["f"] if obj["f"] else None),
                opt=obj["o"] if obj["o"] else None,
            )
        if obj["!t"] == "cg":
            return CallGraph(
                graph=nx.adjacency_graph(obj["g"]), static_entry=obj["s"], dynamic_entry=obj["d"]
            )
        if obj["!t"] == "cfg":
            return FuncCFG(
                entrypoint=obj["e"],
                architecture=SupportedArchs(obj["a"]),
                graph=nx.adjacency_graph(obj["g"]),
            )
        if obj["!t"] == f"cgn_{CFGNodeType.BB.value}":
            return CFGNodeBB(address=obj["a"], size=obj["s"], data=obj["d"])
        if obj["!t"] == f"cgn_{CFGNodeType.FUNC.value}":
            return CFGNodeFunc(address=obj["a"], size=obj["s"], data=obj["d"])
        if obj["!t"] == "cge":
            return CGElementLayers(*obj["l"])
        if obj["!t"] == "cgm":
            return CallGraphManager(call_graph=obj["c"], cg_version=obj["v"])
        return obj
