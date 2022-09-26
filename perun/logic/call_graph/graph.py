"""The call graph implementation.

TODO: more details
"""
from __future__ import annotations

import networkx as nx

from perun.logic.call_graph.structs import CGFlavour


class CallGraph:
    """The call graph implementation.

    TODO: only a placeholder for now.
    """
    __slots__ = 'graph', 'flavours', 'opts'

    def __init__(
            self,
            graph: nx.DiGraph | None = None,
            flavours: set[CGFlavour] | None = None,
            opts: set[str] | None = None
    ) -> None:
        """Initializer.

        :param graph: the actual graph representation.
        :param flavours: the call graph flavours contained in the graph.
        :param opts: the optimization config IDs contained in the graph.
        """
        self.graph: nx.Digraph = graph if graph is not None else nx.DiGraph()
        self.flavours: set[CGFlavour] = flavours if flavours is not None else set()
        self.opts: set[str] = opts if opts is not None else set()
