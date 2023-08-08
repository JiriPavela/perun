"""Implementation of Call Graph diff.

This implementation is aimed at identifying changes in CGs belonging to the same program in
different versions (e.g., X.Y -> X.Z). One CG version is called the *baseline* (typically belonging
to an older program version) and the second version is called *target* (typically referring to
a newer version).

The top-level idea is as follows: first we need to find out which functions in the *baseline*
version have their counterpart in the *target* version, e.g., functions from *baseline* might have
a different name in *target* or they were changed so much that it is not clear whether they are the
same function anymore. Next, for functions that have their counterpart in *target* (i.e., were
successfully *matched* in the first step), we perform detailed CFG comparison to determine which
functions have changed since the *baseline* version.

The first *matching* phase is arguably the more difficult one - due to absence of ground truth,
only heuristics may be developed for this task. Hence, we implemented multiple such heuristics
based on (a) the so-called *CFG summaries* and (b) function call contexts (i.e., sets of caller
and callee functions).
"""

from __future__ import annotations

from collections.abc import Iterator, Iterable
from typing import TYPE_CHECKING
from enum import Enum

from perun.logic.call_graph.graphs.bb_equality import EqBBRegisterBijection, eq_cache
from perun.logic.call_graph.graphs.func_equality import KnownRenames
from perun.logic.call_graph.structs import FuncEq, CGLayer, CGFlavour

if TYPE_CHECKING:
    from perun.logic.call_graph.graphs.cg import CallGraph
    from perun.logic.call_graph.graphs.cfg import FuncCFG, CFGSummary


# Function caller/callee context (a collection of function names)
Context = tuple[str, ...]
# Function name -> Caller + Callee context
FuncContexts = dict[str, tuple[Context, Context]]
# Mapping of Context -> (baseline functions, target functions) that have this context
ContextMap = dict[Context, tuple[set[str], set[str]]]
# Baseline function -> Target function that share the same unique context
UniqueContextMap = dict[str, str]


class CGDiffType(Enum):
    """Enumeration of CG types w.r.t. diff computation."""

    BASELINE = 0
    TARGET = 1


class CtxType(Enum):
    """Enumeration of function context types."""

    CALLER = 0
    CALLEE = 1


class FuncStatus(Enum):
    """Function diff status as determined during the diff computation."""

    #: the function name is only in the *target* CG version and not in *baseline*.
    NEW = "new"
    #: the function name is only in the *baseline* CG version and not in *target*.
    MISSING = "missing"
    #: the function is in both CG versions and not changed w.r.t. to the CFG equivalence criteria.
    UNCHANGED = "unchanged"
    #: the function is in both CG versions and has changed.
    CHANGED = "changed"
    #: the function is in the *baseline* CG and has been renamed.
    RENAMED = "renamed"
    #: the function is in the *target* CG and corresponds to a renamed function.
    RENAMED_INV = "renamed inverse"
    #: the function is in the *baseline* CG, has been renamed and changed.
    RENAMED_CHANGED = "renamed and changed"
    #: the function is in the *target* CG, corresponds to a renamed function and has been changed.
    RENAMED_CHANGED_INV = "renamed inverse and changed"
    #: the function name is in both CG versions but the function context and CFG summary has
    #  changed so much that none of our heuristics was able to match the *baseline* and *target*
    #  versions of the function.
    NAME_ONLY_MATCHED = "name-only matched"
    #: default value returned for untracked functions or functions that were not found in the CGs.
    UNMATCHED = "unmatched"


class CallGraphDiff:
    """The Call Graph diff representation.

    This class takes care of matching corresponding *baseline* and *target* functions (see module
    docstring for more info), determining their status and identifying the actually changed
    functions.

    The diff is computed w.r.t the provided layers. If no layers are provided, the RAW layer is
    selected as default. This corresponds to the intended usage of CG diff which is to (a) detect
    functions that have changed since the previous version, and (b) identify unchanged sub-graphs
    so that corresponding dynamic CG information from the *baseline* can be re-used in *target*.

    :ivar cg_base: the *baseline* CG version. Usually refers to CG of some older stable program
          version that has already been profiled.
    :ivar cg_target: the *target* CG version. Usually refers to CG of a new program version that
          has no dynamic information.
    :ivar layers: the layers for which the CG diff was computed.
    :ivar missing_names: function names that are in the *baseline* but not in the *target* version
          and are not renamed.
    :ivar new_names: function names that are in the *target* but not in the *baseline* version and
          are not renamed.
    :ivar matches: function names that are in both *baseline* and *target* versions and were
          matched using one of the matching heuristics.
    :ivar renames: function rename mapping from *baseline* to *target* names.
    :ivar renames_inv: inverse function rename mapping from *target* to *baseline* names.
    :ivar name_only_matches: function names that are in both *baseline* and *target* versions but
          were not successfully matched using any of the matching heuristics. This indicates likely
          a significant change in the function's CFG and call context.
    :ivar unmatched_base: functions from the *baseline* version that have not been matched yet.
          Used mainly during the diff computation.
    :ivar unmatched_target: function from the *target* version that have not been matched yet.
          Used mainly during the diff computation.
    :ivar changed_functions: functions that are considered as changed in the *target* CG version
          based on the CFG comparison. The comparison is done on the ``matches``, ``renames`` and
          ``name_only_matches``.

    Note that ``missing_names``, ``new_names``, ``matches``, ``renames``, ``renames_inv`` and
    ``name_only_matches`` are all disjunctive. On the other hand, ``changed_functions`` can contain
    functions from ``matches``, ``renames`` and ``name_only_matches``.
    """

    __slots__ = (
        "cg_base",
        "cg_target",
        "layers",
        "missing_names",
        "new_names",
        "matches",
        "renames",
        "renames_inv",
        "name_only_matches",
        "unmatched_base",
        "unmatched_target",
        "changed_functions",
    )

    def __init__(self, cg_base: CallGraph, cg_target: CallGraph, *layers: CGLayer) -> None:
        """Initializer.

        Initializes the CG diff object and computes the actual diff. Hence, instantiating a new
        object is potentially very costly.

        :param cg_base: CG *baseline* version.
        :param cg_target: CG *target* version.
        :param layers: the layers for which the diff will be computed. If not specified, the RAW
               layer will be used by default.
        """
        self.cg_base: CallGraph = cg_base
        self.cg_target: CallGraph = cg_target
        self.layers: set[CGLayer] = set(layers) if layers else {CGLayer(CGFlavour.RAW)}
        # These attributes should be useful long-term
        self.missing_names: set[str] = set()
        self.new_names: set[str] = set()
        self.matches: set[str] = set()
        self.renames: dict[str, str] = {}
        self.renames_inv: dict[str, str] = {}
        self.name_only_matches: set[str] = set()
        self.unmatched_base: set[str] = set()
        self.unmatched_target: set[str] = set()
        self.changed_functions: set[str] = set()
        # Compute the diff now
        summaries = CGDiffSummaries()
        summaries.summary_matches(self)
        summaries.summary_renames_unique(self)
        contexts = CGDiffContexts(self)
        contexts.unique_context_matches(self)
        summaries.summary_renames_exclusive(self)
        contexts.context_matches(self)
        contexts.subset_context_matches(self)
        # Update the name-only matched functions
        self.name_only_matches = self.unmatched_base & self.unmatched_target
        self.unmatched_base -= self.name_only_matches
        self.unmatched_target -= self.name_only_matches
        # Create an inverted rename map
        self.renames_inv = {name_to: name_from for name_from, name_to in self.renames.items()}
        # Detect which functions have actually changed
        self._detect_changes()

    def __getitem__(self, func: str) -> str:
        """Get the corresponding *target* name for the *baseline* function name, if it exists.

        When supplied a function name from *baseline*, the method provides the corresponding
        name in *target*, if it has been found. The name may be the same (in case a same-name match
        or name-only match has been found) or different in case of renames.

        :param func: the *baseline* function name.
        :return: the corresponding *target* function name.
        :raise: KeyError if the *baseline* name does not exist or a match has not been found.
        """
        if func in self.matches or func in self.name_only_matches:
            return func
        # This will raise KeyError indicating that we don't have a match for the name
        return self.renames[func]

    def get(self, func: str) -> str | None:
        """Get the corresponding *target* name for the *baseline* function name, if it exists.

        This method is the same as __getitem__, however, it does not raise KeyError in case of
        missing match. Instead, a special return value is provided.

        :param func: the *baseline* function name.
        :return: the corresponding *target* function name or None if not found.
        """
        try:
            return self[func]
        except KeyError:
            return None

    def function_status(self, func: str) -> FuncStatus:
        """Determines the function diff status.

        Note that the function may be in *baseline*, *target* or in both.

        For more detailed description of the individual diff states, see the FuncStatus class.

        :param func: the function name.
        :return: the function diff status.
        """
        status = FuncStatus.UNMATCHED
        if func in self.matches:
            status = FuncStatus.CHANGED if func in self.changed_functions else FuncStatus.CHANGED
        elif func in self.renames:
            status = (
                FuncStatus.RENAMED_CHANGED if func in self.changed_functions else FuncStatus.RENAMED
            )
        elif func in self.renames_inv:
            status = (
                FuncStatus.RENAMED_CHANGED_INV
                if self.renames_inv[func] in self.changed_functions
                else FuncStatus.RENAMED_INV
            )
        elif func in self.new_names:
            status = FuncStatus.NEW
        elif func in self.missing_names:
            status = FuncStatus.MISSING
        elif func in self.name_only_matches:
            status = FuncStatus.NAME_ONLY_MATCHED
        return status

    def add_match(self, func: str, func_target: str) -> None:
        """Register a matched function.

        The matched function can either have the same or a different name.

        :param func: the function name in *baseline*.
        :param func_target: the function name in *target*.
        """
        if func == func_target:
            self.matches.add(func)
        else:
            # The function was renamed, the names are not new and missing anymore
            self.renames[func] = func_target
            self.missing_names.remove(func)
            self.new_names.remove(func_target)
        # Update the unmatched sets
        self.unmatched_base.discard(func)
        self.unmatched_target.discard(func_target)

    def add_missing_func(self, func: str) -> None:
        """Register a function whose name is only in the *baseline* and not *target*.

        :param func: the function name in *baseline*.
        """
        self.missing_names.add(func)
        self.unmatched_base.add(func)

    def add_new_func(self, func: str) -> None:
        """Register a function whose name is only in the *target* and not *baseline*.

        :param func: the function name in *target*.
        """
        self.new_names.add(func)
        self.unmatched_target.add(func)

    def add_unmatched(self, func: str, cg_type: CGDiffType) -> None:
        """Register a function that has not been matched in the given CG type yet.

        :param func: the function name.
        :param cg_type: the *baseline* or *target* CG.
        """
        if cg_type == CGDiffType.BASELINE:
            self.unmatched_base.add(func)
        else:
            self.unmatched_target.add(func)

    def add_unmatched_pair(self, func: str, func_target: str) -> None:
        """Register a function pair that has not been matched yet.

        :param func: the function name in *baseline*.
        :param func_target: the function name in *target*.
        """
        self.unmatched_base.add(func)
        self.unmatched_target.add(func_target)

    def _detect_changes(self) -> None:
        """Detect changed functions based on the current state of the known matches and renames.

        A function is considered to be changed if a CFG comparison w.r.t. the selected function
        and basic block criterion fails (i.e., the comparison returns False).
        """
        # The function equality should take renames into account
        func_eq = KnownRenames(self.renames)
        for func in self.matches | self.renames.keys() | self.name_only_matches:
            func_target = self.renames.get(func, func)
            cfg_base, cfg_target = self.cg_base.get_cfg(func), self.cg_target.get_cfg(func_target)
            if cfg_base is None or cfg_target is None:
                # If a CFG is missing in baseline or target CG, the function is automatically
                # considered to be changed
                self.changed_functions.add(func)
            else:
                # Otherwise compare the CFGs and decide if a change happened or not
                block_eq = eq_cache[cfg_base.architecture, EqBBRegisterBijection]
                if not cfg_base.is_equal(cfg_target, func_eq, block_eq):
                    self.changed_functions.add(func)


class CGDiffSummaries:
    """A helper class that encapsulates summary-related matching heuristics.

    A CFG summary is a collection of simple characteristics about a CFG that allow us to quickly
    determine if CFGs are similar or not. It is not possible to determine if CFGs are equal using
    just the summaries, however, it is possible to quickly determine the opposite, i.e., if CFGs
    are surely different.

    In the context of CG function mapping, the summaries are used in various heuristics to quickly
    identify matching functions based on (unique, exclusive) summary equivalence.

    :ivar rename_summaries: a mapping between CFG summaries and functions in *baseline* and
          *target* that have this summary. The mapping will contain only functions that are
          candidates for renames, i.e., don't have their name counterpart in the other CG.
    """

    __slots__ = ["rename_summaries"]

    def __init__(self) -> None:
        """Initializer."""
        # Summary -> {CG baseline functions}, {CG target functions}
        self.rename_summaries: dict[CFGSummary, tuple[set[str], set[str]]] = {}

    def summary_matches(self, diff: CallGraphDiff) -> None:
        """CG matching heuristic that matches functions with the same *extended summaries*.

        *Extended summaries* are CFG summaries extended with function names. This means that
        functions from *baseline* and *target* that have the same name and equal summaries will
        be matched. Functions that have the same name but different summaries will be registered
        as unmatched, and functions that do not have a name counterpart in the other (*baseline* or
        *target*) CG will be registered as rename candidates.

        :param diff: a CG diff object.
        """
        # For every function in the baseline CG, we want to find function with the same name in
        # the target CG. If such function exists, we compare their summaries.
        for func, cfg, _ in diff.cg_base.functions(*diff.layers):
            # Checks if the function exists in the target CG and if it matches the layers
            if not diff.cg_target.contains_func(func, *diff.layers):
                # There is no such function in the target CG.
                diff.add_missing_func(func)
                self._new_summary_candidate(func, CGDiffType.BASELINE, cfg)
            else:
                # Both CGs contain the function. Check if CFGs are available and compare summaries
                cfg_target = diff.cg_target.get_cfg(func)
                if cfg is not None and cfg_target is not None and cfg.summary == cfg_target.summary:
                    diff.add_match(func, func)
                    continue
                diff.add_unmatched_pair(func, func)
        # Identify functions from the target CG whose names do not apper in the baseline CG.
        for func_target, cfg_target, _ in diff.cg_target.functions(*diff.layers):
            if not diff.cg_base.contains_func(func_target, *diff.layers):
                diff.add_new_func(func_target)
                self._new_summary_candidate(func_target, CGDiffType.TARGET, cfg_target)

    def summary_renames_unique(self, diff: CallGraphDiff) -> None:
        """CG matching heuristic for renamed functions with the same *unique* summaries.

        This heuristic identifies summaries that are unique for a pair of new and missing functions
        (that is, functions from *baseline* or *target* that don't have their name counterpart in
        the other CG.).

        :param diff: a CG diff object.
        """
        # We iterate over a copy of the summaries (since some elements may be deleted from the
        # summaries during the iteration) and obtain the base and target functions on-demand to
        # lower the memory footprint
        for summary in list(self.rename_summaries.keys()):
            funcs_base, funcs_target = self.rename_summaries[summary]
            if len(funcs_base) == len(funcs_target) == 1:
                func, func_other = next(iter(funcs_base)), next(iter(funcs_target))
                # We know that the functions are new/missing, as only those are stored in the
                # rename summary mapping
                diff.add_match(func, func_other)
                self._matched_summary_candidate(summary, func, func_other)

    def summary_renames_exclusive(self, diff: CallGraphDiff) -> None:
        """CG matching heuristic for renamed functions with the same *exclusive* summaries.

        The heuristic attempts to find renames based on summary and CFG equality. For summaries
        that are common for multiple *baseline* and *target* functions, we compare every *baseline*
        CFG with every *target* function and identify exclusive matches: the only pair of
        *baseline* and *target* functions that have matching summaries and CFGs.

        This heuristic is iterative, repeating the process until no new rename is found.

        :param diff: a CG diff object.
        """
        # TODO: This implementation can be optimized. Currently, all of the functions are compared
        #  repeatedly in each iteration. Instead of comparing everything again, we could compare
        #  only the summaries that contain function(s) affected by the previous iteration.
        func_eq = KnownRenames(diff.renames)
        original_renames = -1
        while original_renames != len(diff.renames):
            # Repeat until there is no new rename found
            original_renames = len(diff.renames)
            for summary in list(self.rename_summaries.keys()):
                # Iterate through all unmatched summaries (i.e., rename candidates)
                funcs_base, funcs_target = self.rename_summaries[summary]
                if len(funcs_target) < 1:
                    # There is nothing to compare the baseline functions with
                    continue
                # We need the list as we're updating the base and target sets
                for func_base, func_target in list(
                    _exclusive_cfg_match(diff, funcs_base, funcs_target, func_eq)
                ):
                    # An exclusive rename match has been found
                    diff.add_match(func_base, func_target)
                    self._matched_summary_candidate(summary, func_base, func_target)

    def _new_summary_candidate(self, func: str, cg_type: CGDiffType, cfg: FuncCFG | None) -> None:
        """Register a new rename candidate and its summary.

        :param func: the function name.
        :param cg_type: the CG version type.
        :param cfg: the function's CFG.
        """
        if cfg is not None:
            self.rename_summaries.setdefault(cfg.summary, (set(), set()))[cg_type.value].add(func)

    def _matched_summary_candidate(
        self, summary: CFGSummary, func_base: str, func_target: str
    ) -> None:
        """Remove a successfully matched rename from the summary rename candidates.

        :param summary: the CFG summary of the matched functions.
        :param func_base: the function's *baseline* name.
        :param func_target: the function's *target* name.
        """
        summary_base, summary_target = self.rename_summaries[summary]
        summary_base.remove(func_base)
        summary_target.remove(func_target)
        if not summary_base and not summary_target:
            del self.rename_summaries[summary]


class CGDiffContexts:
    """A helper class that encapsulates call context-related matching heuristics.

    By call context, we mean caller and callee contexts as extracted from the call graphs.
    Call context equality or similarity can nicely complement heuristics based on CFG summaries.

    :ivar contexts: mapping of function names to caller/callee context for baseline and target CGs.
    :ivar context_maps: mapping of caller/callee contexts to baseline/target functions that have
          the same context.
    :ivar unique_context_maps: mapping of caller/callee contexts to unique pairs of
          baseline + target functions that are the only functions having that particular context.
    """

    __slots__ = "contexts", "context_maps", "unique_context_maps"

    def __init__(self, diff: CallGraphDiff) -> None:
        """Initializer.

        Populates the context maps for future use by the individual heuristics.

        :param diff: a CG diff object.
        """
        # CG type -> (baseline func -> (caller, callee) ctx, target func -> (caller, callee) ctx)
        self.contexts: tuple[FuncContexts, FuncContexts] = ({}, {})
        # (Caller, Callee ctx) -> ((baseline funcs, target funcs), (baseline funcs, target funcs))
        self.context_maps: tuple[ContextMap, ContextMap] = ({}, {})
        # (Caller, Callee ctx) -> ((baseline -> target), (baseline -> target))
        self.unique_context_maps: tuple[UniqueContextMap, UniqueContextMap] = ({}, {})
        # Populate the contexts
        for unmatched, cg_type, graph, exclude in [
            (diff.unmatched_base, CGDiffType.BASELINE, diff.cg_base, diff.missing_names),
            (diff.unmatched_target, CGDiffType.TARGET, diff.cg_target, diff.new_names),
        ]:
            # Register the caller/callee contexts
            for name in unmatched:
                # We can do 'exclude' instead of 'exclude and not renamed' as it doesn't change the
                # result and is computationally cheaper
                self._add_contexts(
                    name,
                    cg_type,
                    tuple(sorted(graph.callers(name, *diff.layers) - exclude)),
                    tuple(sorted(graph.callees(name, *diff.layers) - exclude)),
                )
        self._classify_contexts()

    def unique_context_matches(self, diff: CallGraphDiff) -> None:
        """CG matching heuristic for (renamed) functions with a unique caller and callee context.

        Functions with a unique context are considered a match if they have the same name or their
        name is different, but they are both rename candidates (i.e., they don't have a name
        counterpart in the other CG).

        :param diff: a CG diff object.
        """
        callers_map, callees_map = self.unique_context_maps
        for func in callers_map.keys() & callees_map.keys():
            # The function has unique caller and callee contexts
            callers_target_func, callees_target_func = callers_map[func], callees_map[func]
            if callers_target_func != callees_target_func:
                # The baseline function is the same, but the corresponding target caller and callee
                # contexts belong to two different functions
                continue
            if func != callers_target_func and (
                func not in diff.missing_names or callers_target_func not in diff.new_names
            ):
                # We have matching unique callers and callees contexts with different function names
                # To be a rename, the functions must be from the missing and new names
                continue
            # Both the caller and callee contexts are unique and the functions are matching
            diff.add_match(func, callers_target_func)
            self._matched_unique_context(func)

    def context_matches(self, diff: CallGraphDiff) -> None:
        """CG matching heuristic for functions with matching contexts and matching names.

        This heuristic attempts to find matches by searching for baseline and target function pairs
        that have the same names and caller + callee contexts.

        :param diff: a CG diff object.
        """
        caller_ctx, callee_ctx = self.context_maps
        # Sets of functions that have matching baseline and target names and caller/callee contexts
        ctx_matches = (
            set().union(*(base_f & target_f for base_f, target_f in caller_ctx.values())),
            set().union(*(base_f & target_f for base_f, target_f in callee_ctx.values())),
        )
        for match in ctx_matches[CtxType.CALLER.value] & ctx_matches[CtxType.CALLEE.value]:
            # We match all functions that satisfy the context and name equality for
            # both the caller and callee context
            diff.add_match(match, match)
            ctx_matches[CtxType.CALLER.value].remove(match)
            ctx_matches[CtxType.CALLEE.value].remove(match)
        # All remaining unmatched functions are stored in unique context structure for the next
        # heuristic
        for ctx_type in CtxType:
            for func in ctx_matches[ctx_type.value]:
                self._add_unique_context(func, func, ctx_type)

    def subset_context_matches(self, diff: CallGraphDiff) -> None:
        """CG matching heuristic for functions with the same name and similar contexts.

        By context similarity, we refer to functions that have equal caller but different callee,
        or equal callee but different caller contexts. Moreover, the different contexts must
        satisfy the subset relation of baseline < target or vice versa.

        The intuition behind this heuristic is that functions are often called from new call sites
        (functions) or the function themselves call new functions as a result of e.g., refactoring.

        :param diff: a CG diff object.
        """
        for ctx_t, ctx_opposite in [
            (CtxType.CALLER, CtxType.CALLEE),
            (CtxType.CALLEE, CtxType.CALLER),
        ]:
            # The algorithm can be mirrored for caller/callee contexts
            for func, func_target in list(self.unique_context_maps[ctx_t.value].items()):
                if func != func_target:
                    # Non-matching names, skip
                    continue
                # Base and target caller/callee (ctx_opposite) contexts
                # That is, for CALLEE, we get CALLER base and CALLER target contexts
                ctx_base = self.contexts[CGDiffType.BASELINE.value][func][ctx_opposite.value]
                ctx_target = self.contexts[CGDiffType.TARGET.value][func_target][ctx_opposite.value]
                if ctx_base <= ctx_target or ctx_target <= ctx_base:
                    # The different context satisfies the subset relation
                    diff.add_match(func, func_target)
                    del self.unique_context_maps[ctx_t.value][func]

    def _classify_contexts(self) -> None:
        """Identify unique contexts and remove partially empty context records.

        Partially empty context records (i.e., baseline or target function set is empty) will never
        lead to any match.
        """
        # Repeat for both caller and callee contexts
        for ctx_type in CtxType:
            # Help the type checker here
            ctx: Context
            funcs_base: set[str]
            funcs_target: set[str]
            for ctx in list(self.context_maps[ctx_type.value].keys()):
                # For each context, check the cardinality of the functions associated with it
                funcs_base, funcs_target = self.context_maps[ctx_type.value][ctx]
                if len(funcs_base) == len(funcs_target) == 1:
                    # We found a unique context
                    self._add_unique_context(funcs_base.pop(), funcs_target.pop(), ctx_type)
                    del self.context_maps[ctx_type.value][ctx]
                elif len(funcs_base) < 1 or len(funcs_target) < 1:
                    # We found a partially empty context
                    del self.context_maps[ctx_type.value][ctx]

    def _add_contexts(
        self, func: str, cg_type: CGDiffType, caller_ctx: Context, callee_ctx: Context
    ) -> None:
        """Register contexts for the given function and CG type.

        :param func: name of the function.
        :param cg_type: the type of the CG.
        :param caller_ctx: the caller context.
        :param callee_ctx: the callee context.
        """
        self.context_maps[CtxType.CALLER.value].setdefault(caller_ctx, (set(), set()))[
            cg_type.value
        ].add(func)
        self.context_maps[CtxType.CALLEE.value].setdefault(callee_ctx, (set(), set()))[
            cg_type.value
        ].add(func)
        self.contexts[cg_type.value][func] = (caller_ctx, callee_ctx)

    def _add_unique_context(self, func: str, func_target: str, ctx_type: CtxType) -> None:
        """Register the given function pair as having a unique context.

        :param func: the function's baseline name.
        :param func_target: the function's target name.
        :param ctx_type: the context type which is unique.
        """
        if func not in self.unique_context_maps[ctx_type.value]:
            self.unique_context_maps[ctx_type.value][func] = func_target

    def _matched_unique_context(self, func_base: str) -> None:
        """Unregister a unique context record for the given function.

        :param func_base: the function's baseline name.
        """
        del self.unique_context_maps[CtxType.CALLER.value][func_base]
        del self.unique_context_maps[CtxType.CALLEE.value][func_base]


def _exclusive_cfg_match(
    diff: CallGraphDiff, funcs_base: Iterable[str], funcs_target: Iterable[str], func_eq: FuncEq
) -> Iterator[tuple[str, str]]:
    """A helper function that searches for exclusive CFG matches among the provided functions.

    The function iterates over the provided base and target functions and compares the CFGs.
    If for each base function only a single target function has a matching CFG, we found an
    exclusive match.

    :param diff: the CG diff object.
    :param funcs_base: the base functions for which we are looking for an exclusive match.
    :param funcs_target: the target functions among which to search for an exclusive match.
    :param func_eq: a function equivalence criterion.

    :return: pairs of base and target functions that form exclusive matches.
    """
    for func_base in funcs_base:
        # Compare CFGs of each base functions with all target functions' CFG
        cfg_base = diff.cg_base.get_cfg(func_base)
        if cfg_base is None:
            continue
        block_eq = eq_cache[cfg_base.architecture, EqBBRegisterBijection]
        exclusive_match: str | None = None
        # Check for an exclusive match
        for func_target in funcs_target:
            # Iterate through all the target functions and try to find equal CFGs
            cfg_target = diff.cg_target.get_cfg(func_target)
            if cfg_target is None:
                continue
            if cfg_base.is_equal(cfg_target, func_eq, block_eq):
                if exclusive_match is not None:
                    # Multiple target CFGs matching the base CFG, fast fail
                    exclusive_match = None
                    break
                exclusive_match = func_target
        # If we found an exclusive match, return it
        if exclusive_match is not None:
            yield func_base, exclusive_match
