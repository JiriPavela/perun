"""This module implements Call Graph and its view representations.

Glossary:
    - CG flavour:
        In general, the obtained call graph of a program may not be 100% correct. The precision
        of a CG depends on the method of extraction or reconstruction. E.g., the dynamic call
        graph will clearly contain only truly reachable edges and nodes, but it will very likely
        be incomplete. On the other hand, a call graph obtained from static analysis tools may be
        more general, but over-approximate too much or completely miss some dynamic dispatch
        calls. Hence, we want to distinguish those different "flavours" of a call graph and be
        able to manipulate them individually and, to a certain degree, independently. Flavours
        thus describe the type of call graph based on how it was obtained.

    - Optimization:
        Also sometimes called 'opt', 'opts' or 'optimization run(s)'. Optimizations, in the context
        of call graphs, refer to profiling runs that are not monitoring all the possible function
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
from collections.abc import Iterator
from typing import overload, Literal
from typing_extensions import Self

import networkx as nx

from perun.logic.call_graph.graphs.cfg import FuncCFG
from perun.logic.call_graph.graphs.cg_diff import CallGraphDiff
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

    def __contains__(self, element: str | tuple[str, str]) -> bool:
        """Node or edge membership test.

        This membership test checks for presence or absence of a node or edge in the graph
        structure regardless of their metadata.

        :param element: function name or names of source and destination functions.
        :return: ``True`` if the graph contains the node or edge, ``False`` otherwise.
        """
        if isinstance(element, tuple):
            # We're searching for a function (node)
            return element in self.graph.nodes
        # We're searching for a call edge
        return self.graph.has_edge(*element)

    def contains_func(self, function: str, *layers: CGLayer) -> bool:
        """Qualified function membership test.

        If layers are not specified, a simple membership test disregarding layers is performed
        If at least one layer is specified, the membership test will succeed if the function is in
        the CG and belongs to at least one of the specified layers.

        :param function: the function to test.
        :param layers: the layers to restrict the membership test to.
        :return: ``True`` if the function is in the CG and belongs to at least one of the layers
                 (if specified), ``False`` otherwise.
        """
        if function in self.graph.nodes:
            return not layers or self.graph.nodes[function]["meta"].layers & set(layers)
        return False

    def contains_call(self, source: str, destination: str, *layers: CGLayer) -> bool:
        """Qualified function call membership test.

        If layers are not specified, a simple membership test disregarding layers is performed
        If at least one layer is specified, the membership test will succeed if the function call
        is in the CG and belongs to at least one of the specified layers.

        :param source: the source function of the call edge (caller).
        :param destination: the destination function of the call edge (callee).
        :param layers: the layers to restrict the membership test to.
        :return: ``True`` if the call edge is in the CG and belongs to at least one of the layers
                 (if specified), ``False`` otherwise.
        """
        if self.graph.has_edge(source, destination):
            return not layers or self.graph.edges[source, destination]["meta"].layers & set(layers)
        return False

    def functions(self, *layers: CGLayer) -> Iterator[tuple[str, FuncCFG | None, CGElementLayers]]:
        """Provide the functions stored in the CG layer(s) along with their CFGs and metadata.

        :param layers: CG layers from which to provide the functions. A function is returned if it
               is associated with at least one of the specified layers. If not specified, the
               method will provide functions from all layers.
        :return: an iterator over functions associated with the CG layer(s).
        """
        _layers = set(layers)
        for func_name, node_data in self.graph.nodes.items():
            # Filter by layers, if requested
            if not layers or node_data["meta"].layers & _layers:
                yield func_name, node_data.get("cfg", None), node_data["meta"]

    def calls(self, *layers: CGLayer) -> Iterator[tuple[str, str, CGElementLayers]]:
        """Provide the call edges stored in the CG layer(s) along with their metadata.

        :param layers: CG layers to restrict the iterator to. A call edge is returned if it is
               associated with at least one of the specified layers. If not specified, the method
               will provide call edges from all layers.
        :return: an iterator over call edges associated with the CG layer(s).
        """
        _layers = set(layers)
        for source, destination, edge_data in self.graph.edges.items():
            # Filter by layers, if requested
            if not layers or edge_data["meta"].layers & _layers:
                yield source, destination, edge_data["meta"]

    def callers(self, function: str, *layers: CGLayer) -> set[str]:
        """Provide callers associated with the CG layers for the given function.

        :param function: the function for which to find its callers.
        :param layers: CG layers to restrict the search to. A caller is returned if it is
               associated with at least one of the specified layers. If not specified, the method
               will provide callers from all layers.
        :return: the function callers associated with the given layers, if specified.
        """
        _layers = set(layers)
        return {
            caller
            for caller in self.graph.predecessors(function)
            if not _layers or self.graph.edges[caller, function]["meta"].layers & _layers
        }

    def callees(self, function: str, *layers: CGLayer) -> set[str]:
        """Provide callees associated with the CG layers for the given function.

        :param function: the function for which to find its callees.
        :param layers: CG layers to restrict the search to. A callee is returned if it is
               associated with at least one of the specified layers. If not specified, the method
               will provide callees from all layers.
        :return: the function callers associated with the given layers, if specified.
        """
        _layers = set(layers)
        return {
            callee
            for callee in self.graph.successors(function)
            if not _layers or self.graph.edges[function, callee]["meta"].layers & _layers
        }

    @overload
    def get_element_data(self, element: str, attribute: Literal["cfg"]) -> FuncCFG | None:
        ...

    @overload
    def get_element_data(
        self, element: str | tuple[str, str], attribute: Literal["meta"]
    ) -> CGElementLayers | None:
        ...

    @overload
    def get_element_data(self, element: str | tuple[str, str], attribute: str) -> object | None:
        ...

    def get_element_data(
        self, element: str | tuple[str, str], attribute: str
    ) -> CGElementLayers | FuncCFG | object | None:
        """Get custom data associated with a graph element.

        :param element: function name for a node or source and destination function names for edge.
        :param attribute: the attribute under which the custom data are stored.
        :return: the custom data associated with the specified element or ``None`` if not found.
        """
        try:
            if isinstance(element, tuple):
                return self.graph.edges[element[0], element[1]][attribute]
            return self.graph.nodes[element][attribute]
        except KeyError:
            return None

    def get_cfg(self, function: str) -> FuncCFG | None:
        """Get CFG associated with the specified function.

        This function is a specialization of the :meth:`~get_element_data` that is more
        user-friendly and avoids unnecessary isinstance checks.

        :param function: function name for which to retrieve the CFG.
        :return: the function's CFG or ``None`` if not found.
        """
        func = self.graph.nodes.get(function, None)
        return None if func is None else func.get("cfg", None)

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

        The resulting CG subgraph is a static view of the CG, that is, it is not possible to
        modify the CG, and it will also not reflect any changes made to the CG in the meantime.

        :param layers: the layers that induce the CG subgraph.

        :return: a layer(s) subgraph of the CG.
        """
        return CallGraphView(self, *layers)

    def update_dynamic_from(self, source: CallGraph | CallGraphDiff) -> Self:
        """Update the current (*target*) CG with dynamic information from another (*baseline*) CG.

        In general, RAW and STATIC call graphs do not contain complete information about function
        call relations. Some of the call relations can't be statically inferred and are instead
        discovered dynamically during runtime. However, such dynamic information are usually quite
        expensive to obtain and as such, they should be reused as much as possible.

        This method attempts to identify dynamic call information form another CG that can be
        safely reused in this CG. By safely, we mean that either (a) the dynamic caller function
        has not changed between the two CG versions, or (b) if it did change, the RAW callee
        contexts of the dynamic caller function did not change (w.r.t. the identified renames).

        :param source: the *baseline* CG or a CG Diff between the *baseline* and current (*target*)
               CGs. If a *baseline* CG is provided, the CG Diff will be calculated and discarded.
        :returns: the updated *target* CG (self).
        """
        # Unify the input
        baseline: CallGraph
        cg_diff: CallGraphDiff
        baseline, cg_diff = (
            (source.cg_base, source)
            if isinstance(source, CallGraphDiff)
            else (source, source.diff(self))
        )

        dyn_layer = CGLayer(CGFlavour.DYNAMIC)
        raw_layer = CGLayer(CGFlavour.RAW)
        # Iterate over all matched functions in CG Diff
        for base_func, target_func, changed in cg_diff.iter_matches():
            if changed:
                # The function has changed, check at least its RAW callee context remained the same
                raw_callees_renamed = set(cg_diff.get_all(*baseline.callees(base_func, raw_layer)))
                if raw_callees_renamed != self.callees(target_func, raw_layer):
                    # The function and its callee ctx have changed, do not reuse dynamic information
                    continue
            # We can reuse the dynamic information: copy all dynamic call edges from this function
            edges = [
                (target_func, target_callee)
                for target_callee in cg_diff.get_all(*baseline.callees(base_func, dyn_layer))
                if target_callee is not None
            ]
            self.add_call_relations(*edges, layer=dyn_layer)
        return self

    def diff(self, target: CallGraph, *layers: CGLayer) -> CallGraphDiff:
        """Calculate the difference between this (baseline) and target CGs w.r.t. specified layers.

        The diff calculation identifies which functions are common for both CGs, functions that
        have been renamed or changed, and much more. See the :class:`~cg_diff.CallGraphDiff` for
        more details.

        :param target: the target CG.
        :param layers: CG layers to restrict the diff to. If not specified, the diff is computed
               for the RAW layer.
        :return: the computed diff of this and the other CG.
        """
        return CallGraphDiff(self, target, *layers)

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
            for successor in self.graph.successors(node):
                # We inspect only the edges here since the layers of the edge imply the layers of
                # the nodes (i.e., edge may not support layers that the nodes do not).
                if self.graph.edges[node, successor]["meta"].supports_any(req_layers):
                    self.graph.edges[node, successor]["meta"].add(self._modified, layer)
            process |= set(self.graph.successors(node)) - visited
        unreachable_nodes = {
            attr["name"] for _, attr in self.graph.nodes(data=True) if layer in attr["meta"]
        } - visited
        # TODO: this might be a problem when updating dynamic information from previous CGs!
        #       Maybe move the reachability logic to CGView creation as it is relevant for levels
        #       computation? This makes more sense imo
        self.remove_functions(*unreachable_nodes, layer=layer)
        self._modified.recalculated(layer)


# TODO: placeholder
class CallGraphView:
    # This will contain the layers CG subgraph with entry points, iteration functions, etc.
    def __init__(self, base: CallGraph, *layers: CGLayer) -> None:
        self.graph = base
