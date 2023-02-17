"""This module implements Call Graph and Control Flow Graph representations.

Glossary:
    - CG flavour:
        In general, the obtained call graph of a program may not be 100% correct. The precision
        of a CG depends on the method of extraction or reconstruction. E.g., the dynamic call
        graph will clearly contain only truly reachable edges and nodes, but it will very likely
        be incomplete. On the other hand, a call graph obtained from static analysis tools may be
        more general, but over-approximate too much or completely miss some dynamic dispatch
        calls. Hence, we want to distinguish those different "flavours" of a call graph and be
        able to manipulate them individually and, to a certain degree, independently. Flavours
        thus describe the type of a call graph based on how it was obtained.

    - Optimization:
        Also sometimes called 'opt', 'opts' or 'optimization run(s)'. Optimizations, in the context
        of call graphs, refer to profiling runs that are not monitoring all of the possible function
        calls within a program, but only a selected subset of available functions. Call graphs
        obtained from optimization runs are generally less precise than call graphs obtained from
        a full profiling run, and are thus considered as a special type  of DYNAMIC flavour call
        graphs. Optimizations can have different configurations and are  distinguished using
        optimization IDs.

    - Layer:
        A combination of flavour and optimization(s) that induce a subgraph of the call graph. As
        an example, the (dynamic flavour, opt_id) tuple identify nodes and edges that are
        associated with specific dynamic optimised run(s) "opt_id", and generally form only a
        subgraph of the original call graph. As there are multiple possible interpretations for
        some combinations, the call graph implementation imposes some rules to avoid unambiguity.

    - Call graph / layers consistency:
        As nodes and edges may be inserted to, or removed from, the call graph, the different
        layers may become inconsistent, i.e., produce an invalid subgraph. In the case of
        insertion, the inconsistencies arise because certain flavours are dependent on each other
        (e.g., the Mixed layer is constructed using the Raw and Dynamic flavours). As for
        deletion, deleting certain edges or nodes may cause some - previously reachable - parts
        of a layer subgraph unreachable. To avoid expensive recalculation after every minor
        change, the call graph instead tracks which layers were modified and performs the
        recalculation only when needed.
"""
from __future__ import annotations

from collections.abc import Iterator, Iterable, Callable

import networkx as nx

from perun.logic.call_graph.structs import (
    CallGraphError,
    CGFlavour,
    CGModificationTracker,
    CGEntryPoints,
    CGLayer,
    CGLayerType,
    CGDynEntryPoints,
    CGElementLayers,
)

# Instruction name, Instruction operands
CFGInstr = tuple[str, str]
# Old name -> New name
FuncRenameMap = dict[str, str]
# Basic block equivalence comparison function
# Allows to specify different equivalence criterion when comparing two basic blocks
BlockEq = Callable[[Iterable[CFGInstr], Iterable[CFGInstr]], bool]


class FuncCFG:
    """A representation of function's Control Flow Graph (CFG).

    A CFG node represents either a basic block (BB), or a call to another function. While BBs
    contain a list of instructions, the function call nodes contain the name of the function.
    A CFG edge is oriented and represents the control flow within the graph.

    :ivar graph: the internal representation of the CFG.
    """

    __slots__ = ["graph"]

    def __init__(self, graph: nx.DiGraph | None = None) -> None:
        """Initializer.

        :param graph: a valid function CFG or None for empty graph.
        """
        self.graph: nx.DiGraph = graph if graph is not None else nx.DiGraph()

    def add_basic_block(self, block_id: int, instructions: Iterable[CFGInstr]) -> None:
        """Add new node representing a basic block with instructions to the CFG.

        :param block_id: a unique ID of the node (e.g., starting address of the basic block).
        :param instructions: a collection of the basic block instructions (e.g., ASM).
        """
        self.graph.add_node(block_id, instr=instructions)

    def add_func_call(self, block_id: int, function_name: str) -> None:
        """Add new node representing a function call to the CFG.

        :param block_id: a unique ID of the node (e.g., address of the call instruction).
        :param function_name: name of the called function.
        """
        self.graph.add_node(block_id, func=function_name)

    def add_flow(self, source: int, dest: int) -> bool:
        """Add new control flow edge to the CFG.

        Both the edge's source and destination nodes must already be in the CFG

        :param source: a unique ID of the source node.
        :param dest: a unique ID of the destination node.

        :return: False if either source or destination node are not in the graph, True otherwise.
        """
        # Don't add the flow relation if one of the nodes is missing
        if source in self.graph.nodes and dest in self.graph.nodes:
            self.graph.add_edge(source, dest)
            return True
        return False

    def compare(
        self, other: FuncCFG, renames: FuncRenameMap | None = None, block_eq: BlockEq | None = None
    ) -> bool:
        """Compare two CFGs and determine if they are equivalent.

        By default:
         1) The equivalence criterion for two basic blocks requires total equality of their
            instruction lists. For more lenient comparison, custom block equivalence function may
            be supplied.
         2) The equivalence criterion for two function call nodes requires equality of the function
            names. More accurate comparison can be achieved by supplying a mapping of function
            renames.

        # TODO: implement, add some custom pre-designed equivalence functions
        """
        raise NotImplementedError()


class CallGraph:
    """A layered representation of program's Call Graph (CG).

    A CG node represents a program function. A CG edge represents a caller-callee relation.

    The 'layered' means that each node and edge (i.e., element) contains 'meta' information that
    keep track of associated layers. There are generally multiple layers present in a CG and each
    element may be part of different layers at the same time. As such, the layered graph effectively
    represents multiple call graphs in a single graph structure.

    Apart from the meta information, each CG element may carry additional custom information (such
    as control-flow graph, CG depth level, etc.).

    The CG also contains information about the graph entry points, that is, node(s) that represent
    the top-level program function(s) where the program execution begins. Due to the layered design
    of the call graph, there may be multiple entry points:
     - The RAW and STATIC layers support only a single shared entry point.
     - The DYNAMIC (un)optimized layers support multiple entry points for each layer.
     - The MIXED layer combines both the shared entry point and dynamic entry points.

    :ivar graph: the internal representation of the CG.
    :ivar entry: entry points of the call graph.
    :ivar _modified: CG layers modification tracker used to efficiently recalculate changed layers.
    """

    __slots__ = "graph", "entry", "_modified"

    def __init__(
        self,
        graph: nx.DiGraph | None = None,
        static_entry: str | None = None,
        dynamic_entry: CGDynEntryPoints | None = None,
    ) -> None:
        """Initializer.

        :param graph: the actual graph representation.
        :param static_entry: the RAW, STATIC and MIXED shared entry point.
        :param dynamic_entry: a mapping of dynamic layer -> collection of entry points.
        """
        self.graph: nx.DiGraph = graph if graph is not None else nx.DiGraph()
        self.entry: CGEntryPoints = CGEntryPoints(self.graph, static_entry, dynamic_entry)
        self._modified: CGModificationTracker = CGModificationTracker()

    @property
    def layers(self) -> Iterator[CGLayer]:
        """Get all layers supported by the CG.

        The call graph supports those layers that are associated with at least one entry point.

        Note that the shared static entry point will report only those layers that are actually
        associated with the entry point (i.e., not all RAW, STATIC and MIXED layers may be
        provided).

        :return: a collection of layers associated with known entry points.
        """
        return self.entry.layers

    @property
    def flavours(self) -> set[CGFlavour]:
        """Get a collection of flavours supported by the CG.

        The call graph supports those flavours that are associated with at least one entry point.
        Note that for the static entry point, only the flavours actually associated with the node
        will be provided. For example, a static entry point "A" with flavours (RAW, STATIC) will
        report only those two flavours and not the MIXED flavour, despite "A" being shared for all
        three flavours.

        :return: a set of supported flavours.
        """
        return self.entry.flavours

    @property
    def optimizations(self) -> Iterator[str]:
        """Get a collection of optimization IDs supported by the CG.

        The call graph supports those optimizations that are associated with at least one entry
        point.

        :return: a collection of supported optimizations.
        """
        return self.entry.optimizations

    def add_entry_point(self, entry_point: str, layer: CGLayer) -> bool:
        """Add a new entry point for the given CG layer.

        When the provided layer is of type ALL, the entry point will be added to all layers
        currently supported by the CG.

        :param entry_point: the name of the call graph entry point (function).
        :param layer: the layer associated with the entry point.

        :return: True if the entry point was registered successfully, False otherwise.
        """
        return self.entry.add(self._modified, entry_point, layer)

    def remove_entry_point(self, entry_point: str, layer: CGLayer) -> None:
        """Remove an entry point from the given layer, if present.

        When removing entry point associated with either one of the RAW, STATIC or MIXED layer, the
        entry point will be removed from the other layers as well since the entry point is shared.
        For the layer of type ALL, the entry point will be removed from all layers in the CG.

        :param entry_point: the name of the call graph entry point (function).
        :param layer: the layer associated with the entry point.
        """
        self.entry.remove(self._modified, entry_point, layer)

    def add_functions(self, *names: str, layer: CGLayer) -> None:
        """Add functions (nodes) to the given CG layer.

        :param names: a collection of function names.
        :param layer: the CG layer.
        """
        for name in names:
            if name in self.graph.nodes:
                self.graph.nodes[name]["meta"].add(self._modified, layer)
            else:
                self.graph.add_node(name, name=name, meta=CGElementLayers(layer))
                self._modified.register(layer)

    def remove_functions(self, *names: str, layer: CGLayer) -> None:
        """Remove functions (nodes) from the given CG layer.

        Removing a function from a layer means that the graph node representing the function will
        no longer be associated with the layer, although the node itself may still be present in the
        graph structure (i.e., because it is still associated with other layers).

        When removing a function from a layer, all incoming and outgoing edges are also removed
        from the layer.

        :param names: a collection of function names.
        :param layer: the CG layer.
        """
        for name in names:
            if name not in self.graph.nodes:
                continue
            self.graph.nodes[name]["meta"].remove(self._modified, layer)
            if not self.graph.nodes[name]["meta"]:
                # The node is no longer associated with any layer
                # The node removal will also remove all connected edges
                self.graph.remove_node(name)
            else:
                # Otherwise we just have to adjust the metadata of the edges
                self.remove_call_relations(self.graph.in_edges(name), layer=layer)
                self.remove_call_relations(self.graph.out_edges(name), layer=layer)
            self.entry.remove(self._modified, name, layer)

    def add_call_relations(
        self, *from_to: tuple[str | None, str | None], layer: CGLayer, strict: bool = False
    ) -> None:
        """Add caller-callee relations (edges) to the given CG layer.

        Note that adding a CG edge to a layer will automatically add both the caller and the callee
        to the layer as well.

        The (caller, callee) input format is deliberately more lenient and allows to specify either
        the caller or the callee as None. Such pair will be ignored and no edge will be added. The
        lenient format is useful, e.g., when reconstructing a CG layer from a tool that reports some
        edges spuriously.

        :param from_to: a collection of (caller, callee) pairs representing the CG layer edge.
        :param layer: the CG layer.
        :param strict: if set to True, only call relations where both the caller and callee
                       already exist in the graph will be added to the CG.
        """
        for caller, callee in from_to:
            # The caller or callee may be supplied as None
            if caller is None or callee is None:
                continue
            if strict and (caller not in self.graph.nodes or callee not in self.graph.nodes):
                continue
            # Add the caller and/or callee nodes to the CG if needed, or update their metadata
            self.add_functions(caller, callee, layer=layer)
            if self.graph.has_edge(caller, callee):
                # The edge already exists, just update the metadata
                self.graph.edges[caller, callee]["meta"].add(self._modified, layer)
            else:
                # New edge
                self.graph.add_edge(caller, callee, meta=CGElementLayers(layer))
                self._modified.register(layer)

    def remove_call_relations(self, *from_to: tuple[str, str], layer: CGLayer) -> None:
        """Remove caller-callee relations (edges) from the given CG layer.

        Removing a CG edge from a layer will not, contrary to the add operation, remove the caller
        and the callee from the layer.

        Removing a relation from a layer means that the graph edge representing the relation will
        no longer be associated with the layer, although the edge itself may still be present in the
        graph structure (i.e., because it is still associated with other layers).

        :param from_to: a collection of (caller, callee) pairs representing the CG layer edge.
        :param layer: the CG layer.
        """
        for caller, callee in from_to:
            if not self.graph.has_edge(caller, callee):
                continue
            edge = self.graph.edges[caller, callee]
            edge["meta"].remove(self._modified, layer)
            if not edge["meta"]:
                # The edge is no longer associated with any layer and should be deleted from the CG
                self.graph.remove_edge(caller, callee)

    def add_element_data(
        self, element: str | tuple[str, str], attribute: str, data: FuncCFG | object
    ) -> bool:
        """Add additional attribute -> data mapping to a CG element (node or edge).

        Note that when the data are represented by a custom class, the (de)serialization of such
        class must be implemented in the CG (de)serialization classes.

        :param element: identification of the element (i.e., function name).
        :param attribute: attribute name that will serve as a key to retrieve the data.
        :param data: the attribute data.

        :return: True if the data was added successfully, False otherwise.
        """
        try:
            if isinstance(element, tuple):
                self.graph.edges[element[0], element[1]][attribute] = data
            else:
                self.graph.nodes[element][attribute] = data
            return True
        except KeyError:
            return False

    def get_layer_cg(self, *layers: CGLayer) -> CallGraphView:
        """Obtain a CG subgraph containing only the selected layer(s).

        The resulting CG subgraph is a static view of the CG, that is, it is not be possible to
        modify the CG and it will also not reflect any changes made to the CG in the meantime.

        :param layers: the layers that induce the CG subgraph.

        :return: a layer(s) subgraph of the CG.
        """
        layers_set = set(layers)
        if CGLayer(None) in layers_set:
            return CallGraphView(self.graph)
        self.recalculate(*layers)
        meta: CGElementLayers
        return CallGraphView(
            nx.DiGraph(
                self.graph.edge_subgraph(
                    (edge_from, edge_to)
                    for edge_from, edge_to, meta in self.graph.edges(data="meta")
                    if meta.supports_any(layers_set)
                )
            )
        )

    def recalculate(self, *layers: CGLayer) -> None:
        """Recalculate the requested CG layers.

        Recalculation is necessary when CG layers are no longer consistent due to modifications done
        to their structure (e.g., adding new functions or edges) since such modifications may change
        the reachability of some other nodes or edges.

        Note that the recalculation will be done only for the layers that actually need to be
        recalculated, and in such order that ensures the minimum number of recalculations.
        When no layers are provided, all modified layers in the call graph will be recalculated.

        Only layers that have a registered entry point can be recalculated, otherwise a
        CallGraphException is raised.

        :param layers: the CG layers to recalculate.
        """
        if not layers:
            layers = (CGLayer(None),)
        for layer in sorted(layers):
            for next_layer in self._modified.next(layer):
                self._recalculate_cg_layer(next_layer)

    def _recalculate_cg_layer(self, layer: CGLayer) -> None:
        """Recalculate a specific CG layer.

        The recalculation algorithm traverses the CG layer starting from its entry point(s). It
        keeps track of two sets: nodes to process (set A) and already visited nodes (set B). In
        each step, the algorithm selects an arbitrary node from set A, marks it as visited (i.e.,
        adds it to the set B), and investigates all outgoing edges and their target nodes. Those
        edges and nodes that are associated with the given layer are considered a part of the
        reachable CG layer, and thus the nodes are then added to the set A (nodes to process)
        unless they are already in the set B (already processed nodes).

        After this traversal, the algorithm removes the layer association from all nodes and edges
        in the CG that were not processed (i.e., were likely reachable in some previous version of
        the layer but are not reachable in the currently recalculated layer).

        When the layer has no entry point(s) or the provided layer is of type ALL, the recalculation
        fails and raises a CallGraphException.

        :param layer: the layer to recalculate.
        """
        if layer.flavour == CGFlavour.RAW:
            # Raw flavour does not need recalculation
            # However, we need to signal that the dependant flavours will need to be recalculated
            self._modified.recalculated(layer)
            return
        entry_points = self.entry.get_entry_points(layer)
        if not entry_points:
            raise CallGraphError(f"CG recalculation failed: {layer} has no entry points.")
        if layer.type == CGLayerType.ALL:
            # We need concrete layers here.
            raise CallGraphError(
                f"CG recalculation failed: {layer} is not a valid layer to recalculate."
            )
        assert layer.flavour is not None
        # The CG is generally not a DAG, so descendants() or shortest_path() won't work here.
        # We have to do our own graph traversal
        process: set[str] = entry_points
        visited: set[str] = set()
        req_layers: set[CGLayer] = {
            CGLayer(flv, layer.optimization) for flv in layer.flavour.dep_requires()
        }
        while process:
            node = process.pop()
            visited.add(node)
            self.graph.nodes[node]["meta"].add(self._modified, layer)
            for succ in self.graph.successors(node):
                # We inspect only the edges here since the layers of the edge imply the layers of
                # the nodes (i.e., edge may not support layers that the nodes do not).
                if self.graph.edges[node, succ]["meta"].supports_any(req_layers):
                    self.graph.edges[node, succ]["meta"].add(self._modified, layer)
            process |= set(self.graph.successors(node)) - visited
        unreachable_nodes = {
            attr["name"] for _, attr in self.graph.nodes(data=True) if layer in attr["meta"]
        } - visited
        self.remove_functions(*unreachable_nodes, layer=layer)
        self._modified.recalculated(layer)


# TODO: placeholder
class CallGraphView:
    # This will contain the layers CG subgraph with entry points, iteration functions, etc.
    def __init__(self, subgraph: nx.DiGraph) -> None:
        self.graph = subgraph
