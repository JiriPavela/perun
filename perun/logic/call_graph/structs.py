"""A helper module with helper or internal classes, structures, constants and enumerations commonly
used by other CG modules.
"""

from __future__ import annotations

from typing import Literal, Union, Protocol
from collections.abc import Iterator, Set, Iterable, Sequence
from enum import Enum

import networkx as nx


from perun.utils.structs import OrderedEnum
from perun.utils.containers import InverseSetMapping


# Specifies a set of valid CG states - the '*' is used for glob lookup patterns.
ValidStates = Literal["c", "d", "*"]
# Dynamic CG entry points (i.e., top-level function of, possibly optimized, profiling run)
# Dynamic (un)optimized layers -> set of entry points
CGDynEntryPoints = Union[dict["CGLayer", Set[str]], Iterable[tuple["CGLayer", Set[str]]]]

# Instruction name, Instruction operands
CFGInstr = tuple[str, str]
# Basic block, a sequence of instructions
BasicBlock = Sequence[CFGInstr]


# Timestamp format used for the CG version stats files
TIMESTAMP_FMT = "%Y-%m-%d-%H-%M-%S"


class CallGraphError(Exception):
    """Raised when an operation on CG fails."""


class VersionState(Enum):
    """Call graph version state enumeration.

    The Call graph version state can be either dirty or clean, depending on whether the files
    used for call graph extraction were reported as changed by the VCS.
    """

    CLEAN = "c"
    DIRTY = "d"


class CFGNodeType(Enum):
    """CFG node type representation.

    The CFG supports both basic block (BB) and CALL instruction destination (function call) nodes.
    """

    BB = "b"
    FUNC = "f"


class CFGEdgeType(OrderedEnum):
    """CFG edge type representation.

    The JUMP type represents control flow change caused by a (conditional) jump instructions.
    The CONTINUE type represents the alternative control flow to the JUMP, i.e., continuation to
    the subsequent basic block.
    """

    JUMP = "j"
    CONTINUE = "c"


class BlockEq(Protocol):
    """Generic basic block equivalence comparison function.

    Allows to specify more or less strict equivalence criterion when comparing two basic blocks.
    """

    def __call__(self, block: BasicBlock, block_other: BasicBlock) -> bool:
        ...


class FuncEq(Protocol):
    """Generic equivalence criterion for function names comparison.

    The equivalence criterion is expected to be used by the CFG and/or CG equivalence checking. As
    program function names are expected to sometimes change, a correctly selected equivalence
    criterion can help achieve more precise comparison.
    """

    def __call__(self, name: str, other_name: str) -> bool:
        ...


class CGFlavour(OrderedEnum):
    """Call graph flavours enumeration.

    See the call graph glossary for more details. Currently supported flavours:
     - RAW flavour represents data that were gathered from a call graph extraction tool.
     - STATIC flavour corresponds to the RAW version without unreachable nodes or edges.
     - DYNAMIC flavour represents call relation data obtained from possibly multiple profiling runs.
     - MIXED flavour represents a merge of RAW and DYNAMIC flavours.
    """

    RAW = "r"
    STATIC = "s"
    DYNAMIC = "d"
    MIXED = "m"

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
        dependant) flavours F1, F2, ... Hence we provide a mapping of flavours that are affected
        by changes in each flavours.
        E.g., when changing the DYNAMIC flavour, the MIXED flavour needs to change accordingly.

        :return: a collection of flavours depending on this one.
        """
        return _CGF_CHANGE_MAP[self]


# flavour -> {require}
_CGF_REQ_MAP: dict[CGFlavour, set[CGFlavour]] = {
    CGFlavour.RAW: set(),
    CGFlavour.STATIC: {CGFlavour.RAW},
    CGFlavour.DYNAMIC: {CGFlavour.DYNAMIC},  # Dynamic flavour iteratively builds on itself
    CGFlavour.MIXED: {CGFlavour.RAW, CGFlavour.DYNAMIC},
}

# flavour -> {depend}
_CGF_CHANGE_MAP: dict[CGFlavour, set[CGFlavour]] = {
    CGFlavour.RAW: {CGFlavour.STATIC, CGFlavour.MIXED},
    CGFlavour.STATIC: set(),
    CGFlavour.DYNAMIC: {CGFlavour.MIXED},
    CGFlavour.MIXED: set(),
}


class CGLayerType(OrderedEnum):
    """Types of CG layers.

    The FLAVOUR type represents a layer consisting only of a single flavour (ignoring optimization).
    The OPT type represents a layer consisting of dynamic flavour and an optimization.
    The ALL type represents an abstract layer for all possible flavour and opt combinations.

    The layer types are also ordered such that FLAVOUR < OPT < ALL.
    """

    FLAVOUR = 1
    OPT = 2
    ALL = 3

    @classmethod
    def determine(cls, flavour: CGFlavour | None, opt: str | None) -> CGLayerType:
        """Alternative initializer that determines the layer type based on flavour and opt.

        Note that the initializer is rather forgiving and invalid combinations, e.g., (RAW, "opt1"),
        will always result in a valid type based on the following rules:
         - (flavour == None,              opt == None)   => ALL
         - (flavour in (None, Dynamic),   opt != None)   => OPT
         - (flavour != None,              opt == X   )   => LAYER

        :param flavour: the layer flavour.
        :param opt: the layer optimization ID or None for an unoptimized run.

        :return: a layer type object.
        """
        if flavour is None and opt is None:
            return cls.ALL
        if flavour in (CGFlavour.DYNAMIC, None) and opt is not None:
            return cls.OPT
        # The flavour is never None here
        return cls.FLAVOUR


class CGLayer:
    """A representation of CG layer.

    A layer identifies nodes and edges that generally form a subgraph of the entire call graph.
    The layers represent different versions of a call graph based on either the means of extraction
    or some properties of the graph, e.g., iterative reconstruction of the call graph across
    multiple optimized runs of a program, or the reachability property on a call graph extracted
    statically from a binary file.

    As an example, the (flavour, opt) tuple identify nodes and edges that are associated with
    specific dynamic optimised run(s) "opt_id", and generally form only a subgraph of the whole
    call graph.

    :ivar _flavour: the flavour associated with the layer.
    :ivar _opt: the optimization ID associated with the layer, if any.
    :ivar _type: the type of the layer derived from the flavour and optimization ID.
    """

    __slots__ = "_flavour", "_opt", "_type"

    def __init__(self, flavour: CGFlavour | None, opt: str | None = None) -> None:
        """Initializer.

        Invalid flavour and optimization combinations will be transformed according to the layer
        type rules so that the resulting layer object is always consistent.

        :param flavour: the layer flavour.
        :param opt: the optimization ID, if any.
        """
        layer_type = CGLayerType.determine(flavour, opt)
        if layer_type == CGLayerType.OPT:
            # Unify the two possible ways to specify flavour in optimized layer (DYNAMIC or None)
            flavour = CGFlavour.DYNAMIC
        else:
            # Unoptimized layer
            opt = None
        self._flavour: CGFlavour | None = flavour
        self._opt: str | None = opt
        self._type: CGLayerType = layer_type

    def __str__(self) -> str:
        """Provide a string representation of the layer.

        :return: the layer string representation.
        """
        return f"Layer(flavour={self._flavour}, opt={self._opt}, type={self._type.name})"

    def __hash__(self) -> int:
        """The hashing operator for layers.

        The layer type is not being used for hashing as it is deterministically derived from the
        flavour and opt. That is, two different layers with the same flavours and opts will always
        be of the same type and hence equal.

        :return: the layer hash.
        """
        return hash((self._flavour, self._opt))

    def __eq__(self, other: object) -> bool:
        """Equality operator.

        Two layers are equal if their layers and opt are equal for reasons described in the hashing
        operator.

        :param other: the other layer.

        :return: True if the layers are equal, False otherwise.
        """
        if not isinstance(other, CGLayer):
            return NotImplemented
        return self._flavour == other._flavour and self._opt == other._opt

    def __lt__(self, other: object) -> bool:
        """Less-than comparison operator.

        The layer order depends on a) layer type, b) layer flavour and c) layer opt, in this exact
        order. The actual order of different optimizations is insignificant but for the sake of
        providing a complete ordering, the opts are compared alphabetically.

        :param other: the other layer.

        :return: True if this layer is less than the other, False otherwise.
        """
        if not isinstance(other, CGLayer):
            return NotImplemented
        # Different types, one of them has to have a higher priority
        if self._type != other._type:
            return self._type < other._type
        # Same types
        if self._type == CGLayerType.FLAVOUR:
            # Compare flavours
            # They can't be None since the type would be ALL but mypy doesn't know that
            assert self._flavour is not None and other._flavour is not None
            return self._flavour < other._flavour
        if self._type == CGLayerType.OPT:
            # We don't really care about the order of opts, so we order them alphabetically
            assert self._opt is not None and other._opt is not None
            return self._opt < other._opt
        # The ALL type, it is never less than any other type
        return False

    @property
    def flavour(self) -> CGFlavour | None:
        """Get the flavour associated with the layer, if any.

        The layer should be immutable, hence the read-only property.

        :return: the layer flavour, if there is any, otherwise None.
        """
        return self._flavour

    @property
    def optimization(self) -> str | None:
        """Get the optimization associated with the layer, if any.

        The layer should be immutable, hence the read-only property.

        :return: the layer optimization, if there is any, otherwise None.
        """
        return self._opt

    @property
    def type(self) -> CGLayerType:
        """Get the layer type.

        The layer should be immutable, hence the read-only property.

        :return: the identified layer type.
        """
        return self._type


class CGModificationTracker:
    """A Helper class for tracking modifications of CG structure.

    The class tracks changes made to different CG layers, and provides a stable iterator that
    automatically resolves dependencies between layers and determines the order in which to safely
    recalculate different layers of the CG.

    :ivar _layers: a collection of tracked layers modification.
    """

    __slots__ = ["_layers"]

    def __init__(self) -> None:
        """Initializer.

        Initially, there are no tracked changes to any layer.
        """
        self._layers: set[CGLayer] = set()

    def __contains__(self, layer: CGLayer) -> bool:
        """Layer membership test.

        :param layer: the layer to test.

        :return: True if the layer is tracked as a modification, False otherwise.
        """
        return layer in self._layers

    def __bool__(self) -> bool:
        """Emptiness test.

        The Tracker is considered empty if there are no tracked layer changes.

        :return: True if the Tracker is empty, False otherwise.
        """
        return bool(self._layers)

    def register(self, *changes: CGLayer) -> CGModificationTracker:
        """Register modification of layers.

        :param changes: the modified layer(s).

        :return: the tracker object.
        """
        self._layers |= set(changes)
        return self

    def unregister(self, *changes: CGLayer) -> CGModificationTracker:
        """Unregister layer modifications.

        Mark the modifications as resolved, e.g., when the layers are once again consistent.

        :param changes: layers(s) that are no longer inconsistent.

        :return: the tracker object.
        """
        self._layers -= set(changes)
        return self

    def recalculated(self, layer: CGLayer) -> None:
        """Register that a certain layer was recalculated and resolve layer dependencies.

        When a flavour layer is recalculated and made consistent again, the recalculation should
        register dependant flavour layer(s) as modified.

        :param layer: the recalculated layer.
        """
        self._layers.discard(layer)
        if layer.type == CGLayerType.FLAVOUR:
            assert layer.flavour is not None
            self._layers |= {CGLayer(flv) for flv in layer.flavour.dep_changes()}

    def next(self, layer: CGLayer) -> Iterator[CGLayer]:
        """Get the next best layer to recalculate to get the requested layer in a consistent state.

        The next layer to recalculate is determined according to the tracked modifications, the
        flavour dependencies and the layer ordering. The parameter represent the requested layer
        and the resulting iterator provides the next best recalculation step, up to the requested
        layer itself.

        Example:
            - We want to recalculate the (MIXED, None) layer of the CG:
                self.next(CGLayer(MIXED, None))
            - The tracked modifications:
                layers == [CGLayer(DYNAMIC, "opt1"), CGLayer(RAW, None), CGLayer(DYNAMIC, "opt2")]
            - The iterator will provide the following layers to recalculate:
                1. CGLayer(RAW, None)
                2. CGLayer(MIXED, None)
            - The resulting state of registered modifications after the recalculations:
                layers == [
                    CGLayer(DYNAMIC, "opt1"),
                    CGLayer(DYNAMIC, "opt2"),
                    CGLayer(STATIC, None)      # Added because of RAW layer recalculation.
                ]

        Note that the iterator reacts to modification changes that happen during the iteration and
        will always calculate the next best step based on the current state of tracked
        modifications. This also means that repeated subsequent calls to next() will provide the
        same results if no recalculation is performed in-between.

        Example:
            - Given the modification state,
                layers == [CGLayer(DYNAMIC, "opt1"), CGLayer(RAW, None), CGLayer(DYNAMIC, "opt2")]
            - and the following sequence of calls with no recalculation in-between,
                self.next(CGLayer(MIXED, None))
                self.next(CGLayer(MIXED, None))
            - the iterator will in both cases produce the same layer to compute next:
                1. CGLayer(RAW, None)
                2. CGLayer(RAW, None)

        To make the whole CG consistent, i.e., recalculate all of its inconsistent layers, provide
        a layer of the ALL type.

        :param layer: the requested layer.

        :return: an iterator of layers that should be recalculated in the next step.
        """
        while self:
            if layer.type == CGLayerType.ALL:
                yield sorted(list(self._layers))[0]
            elif layer.type == CGLayerType.OPT:
                if layer in self:
                    yield layer
            else:
                # Flavour layer
                assert layer.flavour is not None
                # Find flavour layers that must be recalculated before this layer and check which
                # of those layers are actually tracked as changed
                required = set(CGLayer(flv) for flv in layer.flavour.dep_requires()) | {layer}
                required &= self._layers
                if not required:
                    return
                yield sorted(list(required))[0]


class CGElementLayers:
    """A representation of layers metadata for call graph (CG) elements (node and edges).

    Note that dynamic layers have a bit specific semantics here. Whenever a CG element is associated
    with an OPT layer (that is, layer with dynamic flavour and optimization ID), the element is
    automatically associated with a dynamic unoptimized layer as well. This ensures that a general
    dynamic flavour layer (i.e., CGLayer(DYNAMIC, None)) is available even if an unoptimized run was
    never actually executed.

    :ivar _layers: a collection of layers associated with the CG element.
    """

    __slots__ = ["_layers"]

    def __init__(self, *layers: CGLayer) -> None:
        """Initializer.

        :param layers: a collection of layers to associate with the CG element.
        """
        self._layers: set[CGLayer] = set(layers)

    def __contains__(self, layer: CGLayer) -> bool:
        """Membership test of a layer.

        The layer of type ALL will always be evaluated as present, thus resulting in True.

        :param layer: the layer to test.

        :return: True if the specified layer is associated with the CG element, False otherwise.
        """
        if layer.type == CGLayerType.ALL:
            return True
        return layer in self._layers

    def __bool__(self) -> bool:
        """Emptiness test.

        :return: True when the metadata have at least one layer, False otherwise.
        """
        return bool(self._layers)

    @property
    def layers(self) -> Iterator[CGLayer]:
        """Provide the layers that are associated with the CG element.

        :return: an iterator of CG element layers.
        """
        return iter(self._layers)

    @property
    def flavours(self) -> set[CGFlavour]:
        """Get unique layer flavours associated with the CG element.

        :return: the CG element flavours.
        """
        return set(layer.flavour for layer in self._layers if layer.flavour is not None)

    @property
    def optimizations(self) -> Iterator[str]:
        """Get optimizations associated with the CG element.

        :return: an iterator of CG element optimizations.
        """
        return iter(layer.optimization for layer in self._layers if layer.optimization is not None)

    def add(self, tracker: CGModificationTracker, layer: CGLayer) -> None:
        """Adds a new layer to the CG element metadata.

        If the layer is of type OPT, a DYNAMIC flavour layer will be added automatically.

        :param tracker: the CG modification tracker.
        :param layer: the layer to add.
        """
        if layer.type == CGLayerType.ALL:
            return
        if layer not in self:
            self._layers.add(layer)
            tracker.register(layer)
            if layer.type == CGLayerType.OPT:
                self.add(tracker, CGLayer(CGFlavour.DYNAMIC))

    def remove(self, tracker: CGModificationTracker, layer: CGLayer) -> None:
        """Remove a layer from the CG element metadata.

        :param tracker: the CG modification tracker.
        :param layer: the layer to remove.
        """
        if layer.type == CGLayerType.ALL:
            # Delete all layers
            tracker.register(*self._layers)
            self._layers.clear()
        if layer.type == CGLayerType.FLAVOUR and layer.flavour == CGFlavour.DYNAMIC:
            # Delete all dynamic layers (both optimized and unoptimized)
            del_layers = set(layer for layer in self._layers if layer.flavour == CGFlavour.DYNAMIC)
            tracker.register(*del_layers)
            self._layers -= del_layers
        if layer.type in (CGLayerType.OPT, CGLayerType.FLAVOUR):
            # Delete just the layer
            if layer in self:
                tracker.register(layer)
                self._layers.discard(layer)

    def supports_any(self, layers: Set[CGLayer]) -> bool:
        """Check whether the CG element is associated with at least one of the provided layers.

        If the collection of provided layers is empty or one of the provided layer is of type ALL,
        the check is automatically evaluated as True.

        :param layers: a collection of layers to check.

        :return: True if at least one matching layer is found, False otherwise.
        """
        if not layers or CGLayer(None) in layers:
            # We do not track the ALL layer in this class.
            return True
        return bool(layers & self._layers)


class CGEntryPoints:
    """A representation of call graph entry point(s).

    Call graph entry point is a node representing the program's top-level function, e.g., the 'main'
    function for C/C++ (if we ignore the libc functions such as _start or _init). In general, entry
    points are nodes where graph traversals begin.

    Our representation of call graph can have at most one static entry point and multiple dynamic
    entry points. The static entry point is expected to be obtained from the call graph extraction
    or reconstruction tool, and is the same for RAW, STATIC and MIXED flavours. The dynamic entry
    points are obtained from dynamic profiling runs and can be further attributed to different
    optimization runs.

    The MIXED layer is a bit special: it uses both the static and dynamic entry points.

    :ivar _graph_ref: a reference to the call graph object.
    :ivar _static: the RAW, STATIC and MIXED entry point.
    :ivar _dyn: a mapping of dynamic optimization run -> collection of entry points and vice versa.
    """

    __slots__ = "_graph_ref", "_static", "_dynamic"

    def __init__(
        self,
        graph_ref: nx.DiGraph,
        static: str | None = None,
        dynamic: CGDynEntryPoints | None = None,
    ) -> None:
        """Initializer.

        :param graph_ref: a reference to the call graph object.
        :param static: the RAW, STATIC and MIXED shared entry point.
        :param dynamic: a mapping of dynamic layer -> collection of entry points.
        """
        self._graph_ref: nx.DiGraph = graph_ref
        self._static: str | None = static
        # dynamic layer (optimized or not) -> set of entry points
        # entry point -> set of dynamic layers
        self._dynamic: InverseSetMapping[CGLayer, str] = InverseSetMapping(dynamic)

    def __contains__(self, entry_point: str) -> bool:
        """Entry point membership test.

        Check if the provided entry point is registered as either static or dynamic point.

        :param entry_point: the name of the call graph entry point (function).

        :return: True if the function is registered as an entry point, False otherwise.
        """
        return entry_point == self._static or self._dynamic.contains_inverse(entry_point)

    @property
    def layers(self) -> Iterator[CGLayer]:
        """Retrieve all unique layers associated with entry points.

        Note that the shared static entry point will report only those layers that are actually
        associated with the entry point (i.e., not all RAW, STATIC and MIXED layers may be
        provided).

        :return: a collection of layers associated with known entry points.
        """
        if self._static is not None:
            layer: CGLayer
            # Yield only those layers of static entry point that are actually supported.
            for layer in self._graph_ref.nodes[self._static]["meta"].layers:
                if layer.flavour != CGFlavour.DYNAMIC:
                    # Ignore dynamic layers in static entry point
                    yield layer
        yield from self._dynamic

    @property
    def flavours(self) -> set[CGFlavour]:
        """Retrieve the flavours that have entry point(s) registered.

        Note that the shared static entry point will report only the flavours that are actually
        associated with the entry point (i.e., not all RAW, STATIC and MIXED may be provided).

        :return: a set of flavours with known entry points.
        """
        supported = set()
        if self._static is not None:
            # We ignore the Dynamic flavour here - it is determined by the presence or absence of
            # dynamic entry points
            supported = self._graph_ref.nodes[self._static]["meta"].flavours - {CGFlavour.DYNAMIC}
        if self._dynamic:
            supported.add(CGFlavour.DYNAMIC)
        return supported

    @property
    def optimizations(self) -> Iterator[str]:
        """Retrieve the optimization runs that have registered entry point(s).

        :return: a collection of optimization runs with known entry points.
        """
        return (layer.optimization for layer in self._dynamic if layer.optimization is not None)

    @property
    def static(self) -> str | None:
        """Retrieve the static shared entry point.

        :return: the shared entry point, if any.
        """
        return self._static

    @property
    def dynamic(self) -> Iterable[tuple[CGLayer, set[str]]]:
        """Retrieve all dynamic (both optimized and unoptimized) entry points and their layers.

        :return: a collection of (layer, entry points).
        """
        # Pylint incorrectly doesn't recognize ItemsView from collections as iterable
        # pylint: disable-next=not-an-iterable
        return ((layer, opts) for layer, opts in self._dynamic.items())

    def add(self, tracker: CGModificationTracker, entry_point: str, layer: CGLayer) -> bool:
        """Register new entry point for the given layer.

        If the layer supports only a single entry point, the currently registered entry point will
        be overwritten. For dynamic flavour and OPT layers, the point will be added to the
        collection of entry points. For the layer of type ALL, the entry point will be added to all
        currently tracked layers.

        :param tracker: the CG modification tracker.
        :param entry_point: the name of the call graph entry point (function).
        :param layer: the layer associated with the entry point.

        :return: True if the entry point was registered successfully, False otherwise.
        """
        if entry_point not in self._graph_ref.nodes:
            return False
        if layer.type == CGLayerType.ALL:
            self._change_static_point(tracker, entry_point)
            for dyn_layer in self._dynamic:
                self._change_dynamic_point(tracker, entry_point, dyn_layer)
        elif layer.flavour == CGFlavour.DYNAMIC:
            self._change_dynamic_point(tracker, entry_point, layer)
        else:
            self._change_static_point(tracker, entry_point)
        return True

    def remove(self, tracker: CGModificationTracker, entry_point: str, layer: CGLayer) -> None:
        """Unregister an entry point for the given layer, if it exists.

        If the layer is of type ALL or the entry point does not exist in the graph anymore, remove
        all references to the entry point from all layers. Note that removing a static entry point
        will remove that shared entry point for all relevant flavour layers (i.e., RAW, STATIC and
        MIXED).

        :param tracker: the CG modification tracker.
        :param entry_point: the name of the call graph entry point (function).
        :param layer: the layer associated with the entry point.
        """
        if entry_point not in self:
            return
        if layer.type == CGLayerType.ALL or entry_point not in self._graph_ref.nodes:
            # The node has been / will be completely removed
            # Remove all references to it regardless of the flavour or opt
            if entry_point == self._static:
                self._change_static_point(tracker, None)
            if self._dynamic.contains_inverse(entry_point):
                for dyn_layer in self._dynamic.getitem_inverse(entry_point):
                    self._change_dynamic_point(tracker, entry_point, dyn_layer, remove=True)
        elif layer.type == CGLayerType.OPT or layer.flavour == CGFlavour.DYNAMIC:
            # Remove dynamic or optimization entry point
            self._change_dynamic_point(tracker, entry_point, layer, remove=True)
        elif entry_point == self._static:
            self._change_static_point(tracker, None)

    def get_entry_points(self, layer: CGLayer) -> set[str]:
        """Retrieve entry point(s) for the given CG layer.

        For layer of type ALL, all known entry points will be provided. If the dynamic flavour layer
        has no associated entry points, a collection of entry points from OPT layers will be
        provided. Also note that the method returns the current static entry point for all relevant
        layers (that is, RAW, STATIC and MIXED), even if that particular layer is currently not
        supported by the call graph.

        :param layer: a specification of the CG layer for which to obtain the entry point(s).

        :return: the entry point(s) registered for the layer, if any.
        """
        entry_points: set[str] = set()
        if layer.type == CGLayerType.ALL:
            # Get all existing entry points
            entry_points |= self._dynamic.keys(inverse=True)
            if self._static is not None:
                entry_points.add(self._static)
        elif layer.type == CGLayerType.OPT:
            # Get entry points only for a specific optimization run
            if layer in self._dynamic:
                entry_points |= self._dynamic[layer]
        elif layer.flavour in (CGFlavour.DYNAMIC, CGFlavour.MIXED):
            # Get entry pts for unopt dynamic flavour. If none, use entry pts from all opt runs.
            entry_points |= (
                self._dynamic[layer] if layer in self._dynamic else self._dynamic.keys(inverse=True)
            )
        if layer.flavour != CGFlavour.DYNAMIC and self._static is not None:
            # Static flavour entry point, if any
            entry_points.add(self._static)

        return entry_points

    def _change_static_point(self, tracker: CGModificationTracker, entry_point: str | None) -> None:
        """Set or remove a static entry point.

        The method handles changes of static entry point so that the changes are properly tracked
        by the CG modification tracker.

        :param tracker: the CG modification tracker.
        :param entry_point: the new entry point or None for entry point removal.
        """
        changed: set[CGLayer] = set()
        if self._static != entry_point:
            # We are actually changing the static entry point
            if self._static is not None and self._static in self._graph_ref.nodes:
                # Register all layers of the original entry point, if possible
                changed |= set(self._graph_ref.nodes[self._static]["meta"].layers)
        if entry_point is not None:
            # Register all layers of the new entry point
            changed |= set(self._graph_ref.nodes[entry_point]["meta"].layers)
        # Filter out dynamic layers as they are irrelevant for static entry point
        tracker.register(*[layer for layer in changed if layer.flavour != CGFlavour.DYNAMIC])
        self._static = entry_point

    def _change_dynamic_point(
        self, tracker: CGModificationTracker, entry_point: str, layer: CGLayer, remove: bool = False
    ) -> None:
        """Add or remove a dynamic entry point.

        The method handles changes of dynamic entry points so that the changes are properly tracked
        by the CG modification tracker.

        :param tracker: the CG modification tracker.
        :param layer: the layer (to be) associated with the entry point.
        :param entry_point: the entry point.
        :param remove: True if the entry point should be removed, False if it should be added.
        """
        is_in = entry_point in self._dynamic.get(layer, set())
        action = self._dynamic.remove if remove else self._dynamic.add
        # Check if we are indeed removing existing, or adding new entry point
        if (remove and is_in) or (not remove and not is_in):
            tracker.register(layer)
            action(layer, entry_point)
