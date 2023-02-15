"""Binary files CG and CFG extractor module using the Angr tool: https://github.com/angr/angr."""
from __future__ import annotations

from pathlib import Path
from typing import Collection

import angr

from perun.logic.call_graph.extractors import CGExtractor
from perun.logic.call_graph.structs import CGFlavour, CGLayer
from perun.logic.call_graph.graphs import CallGraph, FuncCFG


# Address -> normalized name
# The normalized name is a function name without optimization attributes (.cold, .constprop, etc.)
AngrFunctionsMap = dict[int, str]


class AngrExtractor(CGExtractor):
    """The Angr extractor class.

    Performs CG and CFG extraction (using a single Angr analysis) from a binary file and libraries.

    Note that the analysis can be quite expensive and time-consuming for large projects. Moreover,
    the binary CG analysis is generally quite imprecise and will likely require some additional
    dynamic CG information from program runs to obtain a sufficiently precise CG.

    :ivar main_binary: the main binary executable file.
    :ivar libs: additional libraries, if provided.
    :ivar angr_cfg: the CFG information obtained from the Angr analysis.
    :ivar _functions_map: an internal 'function address -> function name' mapping.
    """

    __slots__ = "main_binary", "libs", "angr_cfg", "_functions_map"

    def __init__(self, binary: Path, libs: Collection[Path] | None) -> None:
        """Initializer.

        :param binary: the main binary executable file.
        :param libs: additional libraries to include in the CG (CFG) reconstruction.
        """
        self.main_binary: Path = binary
        self.libs: list[Path] = list(libs) if libs is not None else []
        self.angr_cfg: angr.analyses.CFGFast | None = None
        self._functions_map: AngrFunctionsMap = {}

    def extract(self, with_control_flow: bool = True) -> CallGraph:
        """The CG (and optionally CFG) extraction method.

        :param with_control_flow: True if the extractor should reconstruct the CFG as well.

        :return: the reconstructed CG, optionally containing the functions' CFGs.
        """
        proj: angr.Project = angr.Project(
            str(self.main_binary),
            load_options={"auto_load_libs": False, "force_load_libs": map(str, self.libs)},
        )
        if self.angr_cfg is None:
            # Angr analyses are plugins and mypy can't properly detect their existence
            self.angr_cfg = proj.analyses.CFGFast(normalize=True)  # type: ignore
        self._extract_valid_functions()
        call_graph: CallGraph = self._build_call_graph()
        if with_control_flow:
            self._build_control_flow(call_graph)
        return call_graph

    def _extract_valid_functions(self) -> None:
        """Obtain valid user-defined functions in the reconstructed CFG.

        The Angr CFG may contain:
         1) a number of auxiliary or artificial functions created / obtained during the analysis;
         2) and optimized versions of the user-defined functions (e.g., .constprop, .cold).

        Hence this method filters out such functions and creates the internal 'address -> name'
        mapping.
        """
        assert self.angr_cfg is not None
        analyzed_binaries = [lib.name for lib in self.libs] + [self.main_binary.name]
        # Obtain relevant CG functions
        func: angr.knowledge_plugins.Function
        external_functions: set[str] = set()
        local_functions: set[tuple[int, str]] = set()
        for func in self.angr_cfg.kb.functions.values():
            # Default name indicates that the function does not have any obtainable user-supplied
            # name, it is thus very likely some generated artificial function.
            if func.is_default_name:
                continue
            if func.binary_name not in analyzed_binaries:
                external_functions.add(func.name)
                continue
            local_functions.add((func.addr, func.name))
        for func_addr, func_name in local_functions:
            # The local function is only a stub
            if func_name in external_functions:
                continue
            optimized_func = func_name.split(".")
            if len(optimized_func) > 1:
                func_name = optimized_func[0]
            # There are some artificial functions starting with '.'
            if func_name:
                self._functions_map[func_addr] = func_name

    def _build_call_graph(self) -> CallGraph:
        """Using the CFG analysis and the function mapping, this method constructs the actual CG.

        :return: the reconstructed call graph.
        """
        assert self.angr_cfg is not None
        call_graph = CallGraph()
        raw_layer = CGLayer(CGFlavour.RAW)
        # Add function nodes
        for func_name in self._functions_map.values():
            call_graph.add_functions(func_name, layer=raw_layer)
        # Connect the CG functions according to the call relation
        caller: int
        callee: int
        for caller, callee in self.angr_cfg.kb.callgraph.edges():
            if caller not in self._functions_map or callee not in self._functions_map:
                continue
            call_graph.add_call_relations(
                (self._functions_map[caller], self._functions_map[callee]), layer=raw_layer
            )
        # We assume the entry point is always main, as anything before it is likely
        # domain/platform/compiler-specific.
        # Using the angr project entry point may also not work properly as there are functions
        # from, e.g., libc and other libraries where the caller-callee relation may not be detected.
        call_graph.add_entry_point("main", raw_layer)
        return call_graph

    def _build_control_flow(self, call_graph: CallGraph) -> None:
        """Enhances the extracted CG with CFGs of individual functions.

        :param call_graph: the reconstructed CG.
        """
        assert self.angr_cfg is not None
        for func_addr in self._functions_map:
            # For every function in our CG, we create a separate CFG
            cfg = FuncCFG()
            func = self.angr_cfg.kb.functions.get_by_addr(func_addr)
            # Get the function's basic blocks (BB)
            local_blocks: dict[int, angr.Block] = {block.addr: block for block in func.blocks}
            for block_node in func.transition_graph.nodes:
                # Match the function's transition graph nodes with the obtained BBs
                block = local_blocks.get(block_node.addr, None)
                if block is not None:
                    cfg.add_basic_block(
                        block.addr, [(i.insn.mnemonic, i.insn.op_str) for i in block.capstone.insns]
                    )
                elif isinstance(block_node, angr.knowledge_plugins.Function):
                    # The CFG may contain function call nodes, register them
                    cfg.add_func_call(block_node.addr, block_node.name)
                else:
                    # Regular basic block node
                    cfg.add_basic_block(block_node.addr, [])
            # Add the control flow edges based on the transition graph
            for source, dest in func.transition_graph.edges:
                cfg.add_flow(source.addr, dest.addr)
            # Register the CFG with the CG function node
            call_graph.add_element_data(func.name, "cfg", cfg)
