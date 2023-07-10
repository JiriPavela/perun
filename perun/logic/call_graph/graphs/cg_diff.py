from __future__ import annotations

from typing import TYPE_CHECKING, Literal
from enum import Enum

from perun.logic.call_graph.graphs.bb_equality import EqBBRegisterBijection
from perun.logic.call_graph.graphs.func_equality import KnownRenames
from perun.logic.call_graph.archs import architectures

if TYPE_CHECKING:
    from perun.logic.call_graph.graphs.cg import CallGraph
    from perun.logic.call_graph.graphs.cfg import FuncCFG, CFGSummary
    from perun.logic.call_graph.structs import BlockEq, FuncEq


Context = tuple[str, ...]
FuncContexts = dict[str, tuple[Context, Context]]
ContextMap = dict[Context, tuple[set[str], set[str]]]
UniqueContextMap = dict[str, str]


class CGDiffType(Enum):
    BASELINE = 0
    TARGET = 1


class CtxType(Enum):
    CALLER = 0
    CALLEE = 1


class CGDiffSummaries:
    __slots__ = ["rename_summaries"]

    def __init__(self) -> None:
        # Summary -> {CG_base functions}, {CG_target functions}
        self.rename_summaries: dict[CFGSummary, tuple[set[str], set[str]]] = {}

    def summary_matches(self, diff: CallGraphDiff) -> None:
        # For every function in the baseline CG, we want to find function with the same name in
        # the target CG. If such function exists, we compare their summaries.
        for func, cfg, _ in diff.cg_base.functions:
            if func not in diff.cg_target:
                # There is no such function in the target CG.
                diff.add_missing_func(func)
                self._new_summary_candidate(func, CGDiffType.BASELINE, cfg)
            else:
                # Both CGs contain the function. Check if CFGs are available and compare summaries
                cfg_target = diff.cg_target.get_cfg(func)
                if cfg is not None and cfg_target is not None:
                    if cfg.summary == cfg_target.summary:
                        diff.add_match(func, func)
                    else:
                        diff.add_unmatched_pair(func, func)
                elif cfg is not None:
                    diff.add_unmatched(func, CGDiffType.BASELINE)
                elif cfg_target is not None:
                    diff.add_unmatched(func, CGDiffType.TARGET)
        # Identify functions from the target CG whose names do not apper in the baseline CG.
        for func_target, cfg_target, _ in diff.cg_target.functions:
            if func_target not in diff.cg_base:
                diff.add_new_func(func_target)
                self._new_summary_candidate(func_target, CGDiffType.TARGET, cfg_target)

    def summary_renames_unique(self, diff: CallGraphDiff) -> None:
        # We iterate over a copy of the summaries (since some elements may be deleted from the
        # summaries during the iteration) and obtain the base and target functions on-demand to
        # lower the memory footprint
        for summary in list(self.rename_summaries.keys()):
            funcs_base, funcs_target = self.rename_summaries[summary]
            if len(funcs_base) == len(funcs_target) == 1:
                func, func_other = next(iter(funcs_base)), next(iter(funcs_target))
                diff.add_match(func, func_other)
                self._matched_summary_candidate(summary, func, func_other)

    def summary_renames_exclusive(self, diff: CallGraphDiff) -> None:
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
                for func in list(funcs_base):
                    # Compare CFGs of all base functions with all target functions
                    cfg_base = diff.cg_base.get_cfg(func)
                    if cfg_base is None:
                        continue
                    # TODO: Make a cache that stores prepared comparisons based on the architecture
                    block_eq = EqBBRegisterBijection(architectures[cfg_base.architecture])
                    cfg_match = _exclusive_cfg_match(
                        diff.cg_target, funcs_target, cfg_base, func_eq, block_eq
                    )
                    if cfg_match:
                        diff.add_match(func, cfg_match)
                        self._matched_summary_candidate(summary, func, cfg_match)

    def _new_summary_candidate(
        self, func: str, cg_type: CGDiffType, cfg: FuncCFG | None
    ) -> None:
        if cfg is not None:
            self.rename_summaries.setdefault(cfg.summary, (set(), set()))[cg_type.value].add(func)

    def _matched_summary_candidate(
        self, summary: CFGSummary, func_base: str, func_target: str
    ) -> None:
        summary_base, summary_target = self.rename_summaries[summary]
        summary_base.remove(func_base)
        summary_target.remove(func_target)
        if not summary_base and not summary_target:
            del self.rename_summaries[summary]


class CGDiffContexts:
    __slots__ = "contexts", "context_maps", "unique_context_maps"

    def __init__(self, diff: CallGraphDiff) -> None:
        # Function name -> Caller ctx, Callee ctx
        self.contexts: tuple[FuncContexts, FuncContexts] = ({}, {})
        # Context -> {CG functions}, {CG_other functions}
        self.context_maps: tuple[ContextMap, ContextMap] = ({}, {})
        # Unique context (only one function): CG function -> CG_target function
        self.unique_context_maps: tuple[UniqueContextMap, UniqueContextMap] = ({}, {})
        # Populate the contexts
        for unmatched, cg_type, graph, exclude in [
            (diff.unmatched_base, CGDiffType.BASELINE, diff.cg_base, diff.missing_names),
            (diff.unmatched_target, CGDiffType.TARGET, diff.cg_target, diff.new_names)
        ]:
            for name in unmatched:
                # We can do 'exclude' instead of 'exclude and not renamed' as it doesn't change the
                # result and is computationally cheaper
                self._add_contexts(
                    name,
                    cg_type,
                    tuple(sorted(set(graph.graph.predecessors(name)) - exclude)),
                    tuple(sorted(set(graph.graph.successors(name)) - exclude))
                )
        self._classify_contexts()

    def _classify_contexts(self) -> None:
        for ctx_type in CtxType:
            ctx: Context
            funcs_base: set[str]
            funcs_target: set[str]
            for ctx in list(self.context_maps[ctx_type.value].keys()):
                funcs_base, funcs_target = self.context_maps[ctx_type.value][ctx]
                if len(funcs_base) == len(funcs_target) == 1:
                    self._add_unique_context(funcs_base.pop(), funcs_target.pop(), ctx_type)
                    del self.context_maps[ctx_type.value][ctx]
                elif len(funcs_base) < 1 or len(funcs_target) < 1:
                    del self.context_maps[ctx_type.value][ctx]

    def unique_context_matches(self, diff: CallGraphDiff) -> None:
        callers_map, callees_map = self.unique_context_maps
        for func in callers_map.keys() & callees_map.keys():
            # The function has unique caller and callee contexts
            callers_target_func, callees_target_func = callers_map[func], callees_map[func]
            if callers_target_func != callees_target_func:
                # The corresponding target caller and callee contexts belong to two different
                # functions
                continue
            if func != callers_target_func and func not in diff.missing_names and callers_target_func not in diff.new_names:
                # We have matching unique callers and callees contexts with different function names
                # To be a rename, the functions must be from the missing and new names
                continue
            diff.add_match(func, callers_target_func)
            self._matched_unique_context(func)

    def exclusive_context_matches(self, diff: CallGraphDiff) -> None:
        caller_ctx, callee_ctx = self.context_maps
        # Sets of functions that have matching base and target name, caller/callee contexts and
        # no CFG match with any other function with the same context.
        ctx_matches = (_exclusive_context(diff, caller_ctx), _exclusive_context(diff, callee_ctx))
        for match in ctx_matches[CtxType.CALLER.value] & ctx_matches[CtxType.CALLEE.value]:
            diff.add_match(match, match)
            ctx_matches[CtxType.CALLER.value].remove(match)
            ctx_matches[CtxType.CALLEE.value].remove(match)
        for ctx_type in CtxType:
            for func in ctx_matches[ctx_type.value]:
                self._add_unique_context(func, func, ctx_type)

    def subset_context_matches(self, diff: CallGraphDiff) -> None:
        for ctx_t, ctx_opposite in [
            (CtxType.CALLER, CtxType.CALLEE), (CtxType.CALLEE, CtxType.CALLER)
        ]:
            for func, func_target in list(self.unique_context_maps[ctx_t.value].items()):
                if func != func_target:
                    continue
                # Base and target caller/callee (ctx_opposite) contexts
                # That is, for CALLER, we get CALLER base and CALLER target contexts
                ctx_base = self.contexts[CGDiffType.BASELINE.value][func][ctx_opposite.value]
                ctx_target = self.contexts[CGDiffType.TARGET.value][func_target][ctx_opposite.value]
                if ctx_base <= ctx_target or ctx_target <= ctx_base:
                    diff.add_match(func, func_target)
                    del self.unique_context_maps[ctx_t.value][func]

    def _add_contexts(
        self,
        func: str,
        cg_t: CGDiffType,
        caller_ctx: tuple[str, ...],
        callee_ctx: tuple[str, ...],
    ) -> None:
        self.context_maps[CtxType.CALLER.value].setdefault(caller_ctx, (set(), set()))[cg_t.value].add(func)
        self.context_maps[CtxType.CALLEE.value].setdefault(callee_ctx, (set(), set()))[cg_t.value].add(func)
        self.contexts[cg_t.value][func] = (caller_ctx, callee_ctx)

    def _add_unique_context(self, func: str, func_target: str, ctx_type: CtxType) -> None:
        if func not in self.unique_context_maps[ctx_type.value]:
            self.unique_context_maps[ctx_type.value][func] = func_target

    def _matched_unique_context(self, func_base: str) -> None:
        del self.unique_context_maps[CtxType.CALLER.value][func_base]
        del self.unique_context_maps[CtxType.CALLEE.value][func_base]


class CallGraphDiff:
    __slots__ = (
        "cg_base", "cg_target", "missing_names", "new_names", "matches", "renames",
        "unmatched_base", "unmatched_target", "changed_functions"
    )

    def __init__(self, cg_base: CallGraph, cg_target: CallGraph) -> None:
        self.cg_base: CallGraph = cg_base
        self.cg_target: CallGraph = cg_target
        # These attributes should be useful long-term
        self.missing_names: set[str] = set()
        self.new_names: set[str] = set()
        self.matches: set[str] = set()
        self.renames: dict[str, str] = {}
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
        contexts.exclusive_context_matches(self)
        contexts.subset_context_matches(self)
        self.detect_changes()

    @property
    def only_name_match(self) -> set[str]:
        return self.unmatched_base & self.unmatched_target

    def add_match(self, func: str, func_target: str) -> None:
        if func == func_target:
            self.matches.add(func)
        else:
            self.renames[func] = func_target
        self.unmatched_base.discard(func)
        self.unmatched_target.discard(func_target)

    def add_missing_func(self, func: str) -> None:
        self.missing_names.add(func)
        self.unmatched_base.add(func)

    def add_new_func(self, func: str) -> None:
        self.new_names.add(func)
        self.unmatched_target.add(func)

    def add_unmatched(self, func: str, cg_type: CGDiffType) -> None:
        if cg_type == CGDiffType.BASELINE:
            self.unmatched_base.add(func)
        else:
            self.unmatched_target.add(func)

    def add_unmatched_pair(self, func: str, func_target: str) -> None:
        self.unmatched_base.add(func)
        self.unmatched_target.add(func_target)

    def do_diff(self) -> CallGraphDiff:
        # diff_state = CGDiffState()
        summaries = CGDiffSummaries()
        summaries.summary_matches(self)
        # self.summary_matches(diff_state, summaries)
        print(f"|Base functions| = {len(self.cg_base.graph)}")
        print(f"|Target functions| = {len(self.cg_target.graph)}")
        print(f"|Missing names| = {len(self.missing_names)}")
        print(f"|New names| = {len(self.new_names)}")
        print("======= Matching names and footprints")
        print(f"  |Matches| = {len(self.matches)}")
        print(f"  |Renames| = {len(self.renames)}")
        print(f"  |Unmatched base| = {len(self.unmatched_base)}")
        print(f"  |Unmatched target| = {len(self.unmatched_target)}")
        summaries.summary_renames_unique(self)
        # self.summary_renames_unique(diff_state, summaries)
        print("======= Renames based on matching unique footprints")
        print(f"  |Matches| = {len(self.matches)}")
        print(f"  |Renames| = {len(self.renames)}")
        print(f"  |Unmatched base| = {len(self.unmatched_base)}")
        print(f"  |Unmatched target| = {len(self.unmatched_target)}")
        contexts = CGDiffContexts(self)
        contexts.unique_context_matches(self)
        # self._prepare_contexts(diff_state, contexts)
        # self.unique_context_matches(diff_state, contexts)
        print("======= Matching unique contexts (matching names or renames)")
        print(f"  |Matches| = {len(self.matches)}")
        print(f"  |Renames| = {len(self.renames)}")
        print(f"  |Unmatched base| = {len(self.unmatched_base)}")
        print(f"  |Unmatched target| = {len(self.unmatched_target)}")
        summaries.summary_renames_exclusive(self)
        # self.summary_renames_exclusive(diff_state, summaries)
        print("======= Renames based on matching exclusive footprints")
        print(f"  |Matches| = {len(self.matches)}")
        print(f"  |Renames| = {len(self.renames)}")
        print(f"  |Unmatched base| = {len(self.unmatched_base)}")
        print(f"  |Unmatched target| = {len(self.unmatched_target)}")
        contexts.exclusive_context_matches(self)
        # self.exclusive_context_matches(diff_state, contexts)
        print("======= Matching names and exclusive contexts")
        print(f"  |Matches| = {len(self.matches)}")
        print(f"  |Renames| = {len(self.renames)}")
        print(f"  |Unmatched base| = {len(self.unmatched_base)}")
        print(f"  |Unmatched target| = {len(self.unmatched_target)}")
        contexts.subset_context_matches(self)
        # self.subset_context_matches(diff_state, contexts)
        print("======= Matching names and matching unique/exclusive context + context subset")
        print(f"  |Matches| = {len(self.matches)}")
        print(f"  |Renames| = {len(self.renames)}")
        print(f"  |Unmatched base| = {len(self.unmatched_base)}")
        print(f"  |Unmatched target| = {len(self.unmatched_target)}")
        self.detect_changes()
        print("======= Changes detection")
        print(f"  |Changes| = {len(self.changed_functions)}")
        return self

    def detect_changes(self) -> None:
        func_eq = KnownRenames(self.renames)
        for func in self.matches | self.renames.keys() | self.only_name_match:
            func_target = self.renames.get(func, func)
            cfg_base, cfg_target = self.cg_base.get_cfg(func), self.cg_target.get_cfg(func_target)
            if cfg_base is None or cfg_target is None:
                self.changed_functions.add(func)
            else:
                block_eq = EqBBRegisterBijection(architectures[cfg_base.architecture])
                if not cfg_base.is_equal(cfg_target, func_eq, block_eq):
                    self.changed_functions.add(func)


def _exclusive_context(diff: CallGraphDiff, ctx_map: ContextMap) -> set[str]:
    no_cfg_matches: set[str] = set()
    func_eq = KnownRenames(diff.renames)
    for funcs_base, funcs_target in ctx_map.values():
        for func_common in funcs_base & funcs_target:
            cfg_base = diff.cg_base.get_cfg(func_common)
            if cfg_base is None:
                continue
            block_eq = EqBBRegisterBijection(architectures[cfg_base.architecture])
            cfg_match = _exclusive_cfg_match(
                diff.cg_target, funcs_target - {func_common}, cfg_base, func_eq, block_eq
            )
            if not cfg_match:
                # There is no other function with the same context that has a matching CFG
                no_cfg_matches.add(func_common)
    return no_cfg_matches


def _exclusive_cfg_match(
    cg_target: CallGraph, funcs: set[str], cfg: FuncCFG, func_eq: FuncEq, block_eq: BlockEq
) -> str | Literal[False] | None:
    cfg_match: str | None = None
    for func_target in funcs:
        # Iterate through all the target functions and try to find equal CFGs
        cfg_target = cg_target.get_cfg(func_target)
        if cfg_target is None:
            continue
        if cfg.is_equal(cfg_target, func_eq, block_eq):
            if cfg_match is not None:
                # Multiple target CFGs matching the base CFG, fast fail
                return False
            cfg_match = func_target
    # A single or no CFG matches found
    return cfg_match
