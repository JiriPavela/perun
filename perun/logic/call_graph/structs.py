"""A helper module with helper or internal classes, structures, constants and enumerations commonly
used by other CG modules.

# TODO: Move to a more fitting file in the end. Perhaps the __init__.py or graph.py.
Glossary:
    - CG flavour:
        In general, the obtained call graph of a program may not be 100% correct. The precision of
        a CG depends on the method of extraction or reconstruction. E.g., the dynamic call graph
        will clearly contain only truly reachable edges and nodes, but it will very likely be
        incomplete. On the other hand, a call graph obtained from static analysis tools may be more
        general, but over-approximate too much or completely miss some dynamic dispatch calls.
        Hence, we want to distinguish those different "flavours" of a call graph and be able to
        manipulate them individually and, to a certain degree, independently. Flavours thus describe
        the type of a call graph based on how it was obtained.

    - Optimization:
        Also sometimes called 'opt', 'opts' or 'optimization run(s)'. Optimizations, in the context
        of call graphs, refer to profiling runs that are not monitoring all of the possible function
        calls within a program, but only a selected subset of available functions. Call graphs
        obtained from optimization runs are generally less precise than call graphs obtained from
        a full profiling run, and are thus considered as a special type of DYNAMIC flavour call
        graphs. Optimizations can have different configurations and are distinguished using
        optimization IDs.

    - Layer:
        A combination of flavour and optimization(s) that induce a subgraph of the call graph.
        As an example, the (dynamic flavour, opt_id) tuple identify nodes and edges that are
        associated with specific dynamic optimised run(s) "opt_id", and generally form only
        a subgraph of the original call graph. As there are multiple possible interpretations for
        some combinations, the call graph implementation imposes some rules to avoid unambiguity:
         - (flavour == None,                 opt == None)   => The complete call graph.
         - (flavour in (None, Dynamic),      opt != None)   => Dynamic optimization run "opt".
         - (flavour not in (None, Dynamic),  X          )   => Flavour layer only, no optimization.

    - Call graph / layers consistency:
        As nodes and edges may be inserted to, or removed from, the call graph, the different layers
        may become inconsistent, i.e., produce an invalid subgraph. In the case of insertion, the
        inconsistencies arise because certain flavours are dependent on each other (e.g., the Mixed
        layer is constructed using the Raw and Dynamic flavours). As for deletion, deleting certain
        edges or nodes may cause some - previously reachable - parts of a layer subgraph
        unreachable. To avoid expensive recalculation after every minor change, the call graph
        instead tracks which layers were modified and performs the recalculation only when needed.
"""
from __future__ import annotations
from typing import Literal, Iterator, AbstractSet, Optional, Collection

from enum import Enum

from perun.utils.structs import OrderedEnum


# Specifies a set of valid CG states - the '*' is used for glob lookup patterns.
ValidStates = Literal['c', 'd', '*']
# A representation of a CG layer. The Input variant facilitates more lenient input.
CGLayer = tuple["CGFlavour", Optional[str]]
CGLayerInput = tuple[Optional["CGFlavour"], Optional[str]]

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

    See the call graph glossary for more details. Currently supported flavours:
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


class CGExtractor(Enum):
    """An enumeration of supported call graph extraction tools."""
    ANGR = 'a'


class CGModificationTracker:
    """A Helper class for tracking modifications of CG structure.

    The class tracks changes with a per-flavour and per-optimization granularity, and provides a
    mutable iterator that automatically resolves dependencies between layers and determines the
    order in which to safely recalculate different layers of the CG.

    :ivar _flavours: a collection of tracked flavours modifications
    :ivar _opts: a collection of tracked optimization modifications
    """
    __slots__ = '_flavours', '_opts'

    def __init__(self) -> None:
        """Initializer.

        Initially, both the flavour and optimization tracker sets are empty.
        """
        self._flavours: set[CGFlavour] = set()
        self._opts: set[str] = set()

    def __contains__(self, item: CGFlavour | str) -> bool:
        """Membership test.

        The provided item can be either a flavour or an optimization ID. The lookup will be
        performed in both the flavour and optimization sets. Thanks to different types of flavours
        and optimization IDs, it is guaranteed that the item can't be in both sets at the same time.

        :param item: either a flavour or optimization ID.

        :return: True if the item is tracked as a modification, False otherwise.
        """
        return item in self._flavours or item in self._opts

    def __bool__(self) -> bool:
        """Emptiness test.

        The Tracker is considered empty if no layer is tracked as changed.

        :return: True if the Tracker is empty, False otherwise.
        """
        return bool(self._flavours) or bool(self._opts)

    def register(self, layer: CGLayerInput) -> CGModificationTracker:
        """Register modification of a layer.

        :param layer: the modified layer specified as a flavour and/or optimization.

        :return: the Tracker object.
        """
        flavour, opt = layer
        if flavour is not None:
            self._flavours.add(flavour)
        if opt is not None:
            self._opts.add(opt)
        return self

    def register_f(self, *flavours: CGFlavour) -> CGModificationTracker:
        """Register modification of multiple flavours.

        :param flavours: a collection of flavours that have been modified.

        :return: the Tracker object.
        """
        self._flavours |= set(flavours)
        return self

    def register_o(self, *opts: str | None) -> CGModificationTracker:
        """Register modification of multiple optimization layers.

        :param opts: a collection of optimization IDs that have been modified.

        :return: the Tracker object.
        """
        self._opts |= set(opt for opt in opts if opt is not None)
        return self

    def unregister(self, *changes: CGFlavour | str | None) -> CGModificationTracker:
        """Unregister multiple modifications.

        Mark the modifications as resolved, e.g., when the layers are once again consistent.

        :param changes: flavour(s) and/or optimizations that are no longer inconsistent.

        :return: the Tracker object.
        """
        self._flavours -= set(changes)
        self._opts -= set(changes)
        return self

    def recalculated(self, layer: CGLayerInput) -> None:
        """Register that a certain layer was recalculated and resolve layer dependencies.

        When a flavour layer is recalculated and made consistent again, the recalculation should
        trigger recalculation(s) of dependant flavour layers.

        :param layer: the recalculated layer specified as a flavour and/or optimization.
        """
        # Only flavour xor optimization layer can be recalculated at the same time. When
        # recalculating optimization, the flavour may be set to DYNAMIC, but in this case, we
        # should ignore it. Make sure to not mark both an optimization and a flavour as
        # recalculated simultaneously
        flavour, opt = layer
        if opt is not None:
            self._opts.discard(opt)
            return
        if flavour is not None:
            self._flavours.discard(flavour)
            self._flavours |= flavour.dep_changes()

    def next(
            self, flavour: CGFlavour | None, opts: AbstractSet[str] | None
    ) -> Iterator[CGLayer]:
        """Provide the next best layer to recalculate in order to obtain the specified layer.

        Here specifically, the layer can actually be specified as flavour and (optionally) a
        collection of optimization runs.

        The next layer to recalculate is determined according to the tracked modifications, the
        flavour dependencies and supplied parameters. The parameters represent the requested layer
        and the resulting iterator provides the next best recalculation step, up to the requested
        layer itself.

        Example:
            - We want to recalculate the MIXED layer of the CG:
                self.next(CGFlavour.MIXED, None)
            - The tracked modifications:
                flavours == [CGFlavour.RAW]
                opts == ["opt1", "opt2"]
            - The iterator will provide the following layers to recalculate:
                1. (CGFlavour.RAW, None)
                2. (CGFlavour.MIXED, None)
            - The resulting state of registered modifications after the recalculations:
                flavours == [CGFlavour.STATIC]  # Added because of RAW layer recalculation.
                opts == ["opt1", "opt2"]

        Note that the iterator reacts to modification changes that happen during the iteration and
        will always calculate the next best step based on the current state of tracked
        modifications. This also means that repeated subsequent calls to next() will provide the
        same results if no recalculation is performed in-between.

        Example:
            - Given the modification state,
                flavours == [CGFlavour.RAW]
                opts == ["opt1", "opt2"]
            - and the following sequence of calls with no recalculation in-between,
                self.next(CGFlavour.MIXED, None)
                self.next(CGFlavour.MIXED, None)
            - the iterator will in both cases produce the same layer to compute next:
                1. (CGFlavour.RAW, None)
                2. (CGFlavour.RAW, None)

        To make the whole CG consistent, i.e., recalculate all of its inconsistent layers, set both
        the flavour and optimization parameters to None: next(None, None).

        :param flavour: the CG flavour part of the target layer to make consistent.
        :param opts: the optimizations part of the target layer to make consistent.

        :return: an iterator of layers that should be recalculated in the next step.
        """
        while self:
            # Process everything
            if flavour is None and opts is None:
                if self._flavours:
                    yield sorted(list(self._flavours))[0], None
                elif self._opts:
                    # Pylint false positive here. The iterator will never be empty in this branch
                    # pylint: disable-next=stop-iteration-return
                    yield CGFlavour.DYNAMIC, next(iter(self._opts))
                else:
                    return
            # Specific optimization
            elif flavour in (None, CGFlavour.DYNAMIC) and opts is not None:
                modified_opts = opts & self._opts
                if modified_opts:
                    # pylint: disable-next=stop-iteration-return
                    yield CGFlavour.DYNAMIC, next(iter(modified_opts))
                else:
                    return
            # Specific flavour
            else:
                assert flavour is not None  # Help mypy here as it can't infer it
                required = (flavour.dep_requires() | {flavour}) & self._flavours
                if required:
                    yield sorted(list(required))[0], None
                else:
                    return


class CGElementLayers:
    """A representation of layers metadata for call graph (CG) elements (node and edges).

    Specifically in this class, optimization layers cannot be present in the metadata without the
    Dynamic layer. I.e., adding an optimization layer always adds the Dynamic layer unless it was
    already present. This is intentional to provide consistent and correct representation of CG
    element membership to different flavours.

    :ivar _flavours: a collection of flavour layers associated with the CG element.
    :ivar _opts: a collection of optimization layers associated with the CG element.
    """
    __slots__ = '_flavours', '_opts'

    def __init__(self, flavours: Collection[CGFlavour], opts: Collection[str] | None) -> None:
        """Initializer.

        :param flavours: a collection of CG element flavours.
        :param opts: a collection of optimization IDs associated with the CG element.
        """
        # We are deliberately using a string to achieve less memory overhead here.
        self._flavours: str = ''.join(flavour.value for flavour in flavours)
        if isinstance(opts, str):
            opts = [opts]
        self._opts: set[str] | None = None if opts is None else set(opts)

    def __contains__(self, item: CGLayerInput) -> bool:
        """Membership test of a layer.

        The left operand is expected to be a layer specification, where each element (flavour and
        opt) is optional.

        :param item: the layer specification (flavour and/or optimization ID).

        :return: True if the specified layer is associated with the CG element, False otherwise.
        """
        flavour, opt = item
        if flavour is None and opt is None:
            return True
        if flavour in (CGFlavour.DYNAMIC, None) and opt is not None:
            return self._opts is not None and opt in self._opts
        if flavour is not None:
            return flavour.value in self._flavours
        return False

    def __bool__(self) -> bool:
        """Emptiness test.

        The CG element layer metadata are considered to be empty when there are no flavours
        associated with it. We don't check the optimization as the presence of any optimization is
        mandated by the presence of the Dynamic flavour.

        :return: True when the metadata are not empty, False otherwise.
        """
        return bool(self.flavours)

    @property
    def layers(self) -> Iterator[CGLayer]:
        """Provide the layers that are associated with the CG element.

        Optimization layers are provided with a Dynamic flavour.

        :return: an iterator of CG element layers.
        """
        for char in self.flavours:
            yield CGFlavour(char), None
        if self._opts is not None:
            for opt in self._opts:
                yield CGFlavour.DYNAMIC, opt

    @property
    def flavours(self) -> set[CGFlavour]:
        """Provide the flavours associated with the CG element.

        :return: the CG element flavours.
        """
        return {CGFlavour(char) for char in self.flavours}

    @property
    def optimizations(self) -> Iterator[str]:
        """Provide the optimizations associated with the CG element.

        :return: an iterator of CG element optimizations.
        """
        if self._opts is not None:
            yield from self._opts

    def supports_any(
            self, flavours: AbstractSet[CGFlavour] | None, opts: AbstractSet[str] | None
    ) -> bool:
        """Check whether the CG element is associated with at least one flavour+opt combination.

        If any of the parameter is set to None, it is automatically resolved as satisfying the
        check. Hence, supplying (None, None) will result in True.

        :param flavours: a collection of flavours to check.
        :param opts: a collection of optimizations to check.

        :return: True if at least one combination is found, False otherwise.
        """
        # Checks that at least one flavour AND at least one opt (supplied as args) is supported
        any_opt = opts is None or (self._opts is not None and bool(self._opts & opts))
        any_flavour = flavours is None or bool(self.flavours & flavours)
        return any_opt and any_flavour

    def add(self, tracker: CGModificationTracker, layer: CGLayerInput) -> None:
        """Adds a new layer to the CG element metadata.

        :param tracker: the CG modification tracker.
        :param layer: specification of the layer to add.
        """
        flavour, opt = layer
        # Optimization layer
        if flavour in (CGFlavour.DYNAMIC, None) and opt is not None:
            if self._opts is None:
                self._opts = set()
            if opt not in self._opts:
                self._opts.add(opt)
                tracker.register_o(opt)
            flavour = CGFlavour.DYNAMIC
        # Flavour layer
        if flavour is not None and flavour.value not in self.flavours:
            self._flavours += flavour.value
            tracker.register_f(flavour)

    def remove(self, tracker: CGModificationTracker, layer: CGLayerInput) -> None:
        """Remove a layer from the CG element metadata.

        :param tracker: the CG modification tracker.
        :param layer: specification of the layer to remove.
        """
        flavour, opt = layer
        # We are removing only an optimization record. No change in the structure of the graph
        if flavour in (CGFlavour.DYNAMIC, None) and opt is not None:
            if self._opts is not None and opt in self._opts:
                self._opts.remove(opt)
                tracker.register_o(opt)
            if not self._opts:
                self._opts = None
        # We are removing a flavour
        elif flavour is not None and flavour.value in self.flavours:
            self._flavours = self._flavours.replace(flavour.value, "")
            # When dynamic flavour is removed, the optimizations are removed as well
            if flavour == CGFlavour.DYNAMIC and self._opts is not None:
                tracker.register_o(*self._opts)
                self._opts = None
            tracker.register_f(flavour)
        # We are completely removing an element (node or edge) from the graph
        elif flavour is None:
            tracker.register_f(*{CGFlavour(char) for char in self._flavours})
            self._flavours = ""
            if self._opts is not None:
                tracker.register_o(*self._opts)
                self._opts = None
