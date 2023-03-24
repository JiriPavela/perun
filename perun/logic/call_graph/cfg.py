"""This module implements a representation of function's Control Flow Graph (CFG).

That is, in our representation, each CFG models only the control flow of a specific function and
not the whole program. Interprocedurality can be achieved in combination with a Call Graph where
each function has a link to its corresponding CFG.
"""
from __future__ import annotations
from typing import Generic, TypeVar, Any, overload
from collections.abc import Iterator
from abc import ABC, abstractmethod
from itertools import zip_longest

import networkx as nx

from perun.logic.call_graph.archs import SupportedArchs
from perun.logic.call_graph.structs import BasicBlock, BlockEq, CFGNodeType, CFGEdgeType


# CFG Function block rename mapping: old name -> New name
FuncRenameMap = dict[str, str]
# CFG node equivalence cache. The tuple contains addresses of blocks that are equivalent despite
# possibly different address values.
# TODO: consider making it a dictionary with True / False values => it is more general
CFGNodeCache = dict[tuple[int, int], bool]


# Type variables for CFG node representation
T = TypeVar("T", BasicBlock, str)
T_co = TypeVar("T_co", BasicBlock, str, covariant=True)

# We can't use bound="CFGNode[T]" and Any is a known workaround:
# https://github.com/python/mypy/issues/11910
CFGNodeT = TypeVar("CFGNodeT", bound="CFGNode[Any]")
CFGNodeT1 = TypeVar("CFGNodeT1", bound="CFGNode[Any]")
CFGNodeT2 = TypeVar("CFGNodeT2", bound="CFGNode[Any]")

# Type variable for default value
DefT = TypeVar("DefT")


class CFGNode(ABC, Generic[T_co]):
    """CFG node abstract representation.

    The node needs to know its address, size and data (e.g., instructions in a basic block).

    :ivar addr: the node's address.
    :ivar size: the node size in bytes.
    :ivar data: the node data.
    """

    __slots__ = "addr", "size", "data"

    def __init__(self, address: int, size: int, data: T_co) -> None:
        """Initializer.

        :param address: the node's address.
        :param size: the node size in bytes.
        :param data: the node data.
        """
        self.addr: int = address
        self.size: int = size
        self.data: T_co = data

    def __str__(self) -> str:
        """String representation of a CFG node.

        :return: the string representation.
        """
        return f"CFG node {hex(self.addr)} (size: {self.size}): {self.data}"

    @property
    @abstractmethod
    def type(self) -> CFGNodeType:
        """Obtain the CFG node type.

        Must be overridden in subclasses to properly reflect the concrete type.

        :return: the node type.
        """

    @abstractmethod
    def is_equal(self, other: CFGNodeT, **kwargs: Any) -> bool:
        """Equality check.

        We use a custom function instead of __eq__ since the equality check may support various
        degrees of comparison leniency for some node types.

        :param other: the other node to compare.
        :param kwargs: additional comparison parameters.

        :return: True if the nodes are perceived as equal, False otherwise.
        """
        if not isinstance(other, CFGNode):
            return False
        return self.data == other.data

    def next_block(self) -> int:
        """Compute address of the expected subsequent node in memory.

        This is important when determining the type of a CFG edge. Note that the address may in
        fact be invalid as there may be no node on this address.

        :return: expected address of the next CFG node in memory.
        """
        return self.addr + self.size


class CFGNodeBB(CFGNode[BasicBlock]):
    """Basic block CFG node.

    A basic block is a straight-line code sequence with no branches in (apart from the entry point)
    and no branches out (apart from the exit point). This basic block representation contains a
    sequence of instructions and their operands. To save space, the basic block itself does not
    contain information about the architecture (important when working with the instructions or
    operands) which is stored in the CFG instead.
    """

    def __init__(self, address: int, size: int, data: BasicBlock) -> None:
        """Basic block initializer.

        :param address: the node's address.
        :param size: the node size in bytes.
        :param data: the sequence of instructions and their operands.
        """
        super().__init__(address, size, data)

    def __str__(self) -> str:
        """String representation of the basic block node.

        :return: the string representation.
        """
        return f"CFG basic block {hex(self.addr)} (size: {self.size}):\n\t" + "\n\t".join(
            f"{name} {operators}" for name, operators in self.data
        )

    @property
    def type(self) -> CFGNodeType:
        """The node type.

        :return: the basic block node type identification.
        """
        return CFGNodeType.BB

    def is_equal(self, other: CFGNodeT, block_eq: BlockEq | None = None, **kwargs: Any) -> bool:
        """Equality check for basic blocks.

        Since perfect equality is rather unlikely unless comparing the same objects, the comparison
        can be made less strict by providing custom equivalence criterion (e.g., comparing only
        instructions and not their operands).

        :param other: the other CFG node.
        :param block_eq: custom equivalence criterion. If not provided, perfect equivalence will
                         be tested instead.
        :param kwargs: additional parameters (useful for potential subclassing).

        :return: True if the basic blocks are considered equivalent (possibly under the equivalence
                 criterion), False otherwise.
        """
        if not isinstance(other, CFGNodeBB):
            return False
        if block_eq is None:
            return self.data == other.data
        return block_eq(self.data, other.data)


class CFGNodeFunc(CFGNode[str]):
    """Function CFG node.

    A special function node that models the destination of CALL instruction. This node type makes
    sense in CFGs that focus on a single function and not the whole program. This also makes it
    easier to match the CALL destination when addresses change.
    """

    def __init__(self, address: int, size: int, data: str) -> None:
        """Function node initializer.

        :param address: the node's address.
        :param size: the node size in bytes.
        :param data: name of the destination function.
        """
        super().__init__(address, size, data)

    def __str__(self) -> str:
        """String representation of the function node.

        :return: the string representation.
        """
        return f"CFG function {hex(self.addr)} (size: {self.size}):\n\t{self.data}"

    @property
    def type(self) -> CFGNodeType:
        """The node type.

        :return: the function node type identification.
        """
        return CFGNodeType.FUNC

    def is_equal(
        self, other: CFGNodeT, renames: FuncRenameMap | None = None, **kwargs: Any
    ) -> bool:
        """Equality check for function nodes.

        Since function names can change throughout the program development, the equality checking
        should take that into account. Hence the checking can be made less strict when rename
        mapping is provided.

        :param other: the other CFG node.
        :param renames: functions rename mapping.
        :param kwargs: additional parameters (useful for potential subclassing).

        :return: True if the function nodes are considered equivalent, False otherwise.
        """
        if not isinstance(other, CFGNodeFunc):
            return False
        if renames:
            return self.data == renames.get(other.data, other.data)
        return self.data == other.data


class CFGEdge:
    """CFG oriented edge representation.

    These edge objects are not directly used in the CFG representation, but rather as a helper
    structure when traversing of comparing CFGs.

    :ivar source: the source node.
    :ivar dest: the destination node.
    :ivar type: the type of the edge.
    """

    __slots__ = "source", "dest", "type"

    def __init__(self, source: CFGNodeT1, dest: CFGNodeT2, edge_type: CFGEdgeType) -> None:
        """Initializer.

        :param source: the source node.
        :param dest: the destination node.
        :param edge_type: the type of the edge.
        """
        self.source = source
        self.dest = dest
        self.type = edge_type

    def __str__(self) -> str:
        """Edge string representation.

        :return: the edge string representation.
        """
        return f"CFG edge {hex(self.source.addr)}  --- {self.type} --->  {hex(self.dest.addr)}"

    def __lt__(self, other: object) -> bool:
        """The < comparison operator.

        An implementation of this comparison operator is needed to properly sort CFG edges. The
        ordering is designed as follows:
            1) the source addresses are compared. If they are the same,
            2) the edge types are compared based on their ordering. If they are the same,
            3) the destination addresses are compared.

        A key idea behind this ordering is that basic blocks can generally have up to several
        outgoing JUMP destinations but at most one fall-through (CONTINUE) edge at all times.
        So given the same source basic block, JUMP edges will be sorted by their destination
        addresses and if the block has a CONTINUE edge, that edge will be at the top.

        :param other: the other CFG edge we are comparing to.

        :return: True if this edge is less than the other edge, False otherwise.
        """
        if not isinstance(other, CFGEdge):
            return NotImplemented
        return (self.source.addr, self.type, self.dest.addr) < (
            other.source.addr,
            other.type,
            other.dest.addr,
        )

    def is_equal(
        self,
        other: CFGEdge,
        renames: FuncRenameMap | None = None,
        block_eq: BlockEq | None = None,
        cache: CFGNodeCache | None = None,
    ) -> bool:
        """Edges equality check.

        Two edges are considered as equal if they are of the same type and their source and
        destination nodes are equal. Given the CFG nodes support more lenient equality checks, the
        edge equality checking takes that into account and accepts the necessary parameters to
        delegate the equivalence checking of nodes.

        As multiple edges can have the same source or destination nodes, this equivalence checking
        supports caching.

        :param other: the other edge.
        :param renames: functions rename mapping.
        :param block_eq: custom equivalence criterion for nodes comparison.
        :param cache: the nodes comparison cache.

        :return: True if the edges can be considered equal, False otherwise.
        """
        # Fast fail if the edge types are different
        if self.type != other.type:
            return False
        # Obtain cached node equality if possible
        src_cache, dest_cache = False, False
        if cache is not None:
            src_cache = cache.get((self.source.addr, other.source.addr), False)
            dest_cache = cache.get((self.dest.addr, other.dest.addr), False)
        # Compare the uncached nodes
        src_eq = src_cache or self.source.is_equal(other.source, renames=renames, block_eq=block_eq)
        dst_eq = dest_cache or self.dest.is_equal(other.dest, renames=renames, block_eq=block_eq)
        # Update the cache if possible
        if cache is not None:
            cache[(self.source.addr, other.source.addr)] = src_eq
            cache[(self.dest.addr, other.dest.addr)] = dst_eq
        return src_eq and dst_eq


class FuncCFG:
    """A representation of function's Control Flow Graph (CFG).

    The common CFG representation models basic blocks as nodes and control flow changes
    between the basic blocks as edges. The representation we use is slightly modified to
    facilitate easier comparison and iteration of CFGs. Specifically, we add Function nodes
    to the graph. Such nodes represent the destination of CALL instructions.

    :ivar _entrypoint: address of the CFG entry node.
    :ivar _architecture: CPU architecture. Required for correct CFG and BB analysis.
    :ivar graph: the internal representation of the CFG.
    """

    __slots__ = ["_entrypoint", "_architecture", "graph"]

    def __init__(
        self, entrypoint: int, architecture: SupportedArchs, graph: nx.DiGraph | None = None
    ) -> None:
        """Initializer.

        :param entrypoint: address of the CFG entry node.
        :param architecture: CPU or instructions architecture.
        :param graph: a valid function CFG or None for empty graph.
        """
        self._entrypoint: int = entrypoint
        self._architecture: SupportedArchs = architecture
        self.graph: nx.DiGraph = graph if graph is not None else nx.DiGraph()

    def __iter__(self) -> Iterator[CFGEdge]:
        """CFG iteration.

        The iteration produces CFG edges in a deterministic order dictated by our traversal
        algorithm.

        The traversal starts in the entrypoint node and continues through the highest-priority
        outgoing edge in the current node. The edge priority is determined by the edge ordering.
        In general, the CONTINUE edges have highest priority since it is guaranteed that there can
        be no more than one such outgoing edge from a single node. Whenever the traversal reaches
        a node that has no outgoing edge, or the destination node has already been visited, the
        traversal backtracks to the previous node and its remaining outgoing edges.

        :return: iterator of CFG edges in a deterministic order.
        """
        edge_stack: list[CFGEdge] = []
        visited: set[int] = set()

        while edge_stack or not visited:
            if not visited:
                # This is the first iteration: we start with the CFG entry point
                current_node = self.graph.nodes[self._entrypoint]["details"]
            else:
                # Subsequent iterations: get the next edge in LIFO order
                current_edge = edge_stack.pop()
                yield current_edge
                # Skip the successor if it has already been visited. Otherwise expand its edges.
                if current_edge.dest.addr in visited:
                    continue
                current_node = current_edge.dest
            # Expand the successor by obtaining its outgoing edges
            visited.add(current_node.addr)
            edge_stack.extend(
                sorted(
                    CFGEdge(
                        self.graph.nodes[current_node.addr]["details"],
                        self.graph.nodes[successor]["details"],
                        self.graph.edges[current_node.addr, successor]["type"],
                    )
                    for successor in self.graph.successors(current_node.addr)
                )
            )

    def __contains__(self, element: int | tuple[int, int]) -> bool:
        """Membership test of node or edge.

        :param element: node's address or addresses of the edge's source and destination nodes.

        :return: True if the item is in the CFG, False otherwise.
        """
        if isinstance(element, int):
            return element in self.graph.nodes
        return self.graph.has_edge(*element)

    @overload
    def __getitem__(self, item: int) -> CFGNode[T]:
        ...

    @overload
    def __getitem__(self, item: tuple[int, int]) -> CFGEdge:
        ...

    def __getitem__(self, element: int | tuple[int, int]) -> CFGNode[T] | CFGEdge:
        """Get CFG node or edge if they are in the CFG.

        If the requested item is not in the CFG, a KeyError is raised.

        :param element: node's address or addresses of the edge's source and destination nodes.

        :return: the node or edge object.
        """
        if isinstance(element, int):
            return self.graph.nodes[element]["details"]
        return CFGEdge(
            self.graph.nodes[element[0]]["details"],
            self.graph.nodes[element[1]]["details"],
            self.graph.edges[element]["type"],
        )

    @overload
    def get(self, element: int) -> CFGNode[T] | None:
        ...

    @overload
    def get(self, element: int, default: DefT) -> CFGNode[T] | DefT:
        ...

    @overload
    def get(self, element: tuple[int, int]) -> CFGEdge | None:
        ...

    @overload
    def get(self, element: tuple[int, int], default: DefT) -> CFGEdge | DefT:
        ...

    def get(
        self, element: int | tuple[int, int], default: DefT | None = None
    ) -> CFGNode[T] | CFGEdge | DefT | None:
        """Get CFG node or edge if they exist, default otherwise.

        This method never raises KeyError and instead returns the default value if the node or edge
        were not found.

        :param element: node's address or addresses of the edge's source and destination nodes.
        :param default: the default value to return if no such element was found.

        :return: the node or edge object, or the default value if the object was not found.
        """
        if isinstance(element, int):
            return self.graph.nodes.get(element, default)["details"]
        if self.graph.has_edge(*element):
            return CFGEdge(
                self.graph.nodes[element[0]]["details"],
                self.graph.nodes[element[1]]["details"],
                self.graph.edges[element]["type"],
            )
        return default

    @property
    def entrypoint(self) -> int:
        """Get the entrypoint node address.

        :return: the entrypoint node address.
        """
        return self._entrypoint

    @property
    def architecture(self) -> SupportedArchs:
        """Get the CPU architecture of the CFG basic blocks.

        :return: CPU architecture of the basic blocks' assembly.
        """
        return self._architecture

    def add_node(self, node_data: CFGNode[T]) -> None:
        """Add a new CFG node.

        The actual node can be any subclass of the CFGNode class, e.g., a basic block, function
        block, etc.

        :param node_data: the node details (e.g., basic block disassembly or function name).
        """
        self.graph.add_node(node_data.addr, details=node_data)

    def add_flow(self, source: int, dest: int, edge_type: CFGEdgeType | None = None) -> bool:
        """Add a new control flow edge to the CFG.

        Both the edge's source and destination nodes must already be in the CFG.

        :param source: address of the source node.
        :param dest: address of the destination node.
        :param edge_type: flow edge type. The type will be automatically inferred if not provided.

        :return: False if either source or destination node are not in the graph, True otherwise.
        """
        # Don't add the flow relation if one of the nodes is missing
        if source in self.graph.nodes and dest in self.graph.nodes:
            if edge_type is None:
                # No edge type specified, guess the type
                edge_type = (
                    CFGEdgeType.CONTINUE
                    if self.graph.nodes[source]["details"].next_block() == dest
                    else CFGEdgeType.JUMP
                )
            self.graph.add_edge(source, dest, type=edge_type)
            return True
        return False

    def is_equal(
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

        :param other: the other CFG.
        :param renames: the function rename mapping.
        :param block_eq: the block equivalence criterion function.

        :return: True if the CFGs are considered equal under the provided name mappings and
                 equivalence function, False otherwise.
        """
        # Basic property checks (graph order and nodes degree).
        if not nx.faster_could_be_isomorphic(self.graph, other.graph):
            return False
        # Edge by edge detailed comparison
        edge: CFGEdge | None
        other_edge: CFGEdge | None
        cache: CFGNodeCache = {}
        for edge, other_edge in zip_longest(self, other):
            if (
                edge is None
                or other_edge is None
                or not edge.is_equal(other_edge, renames=renames, block_eq=block_eq, cache=cache)
            ):
                return False
        return True
