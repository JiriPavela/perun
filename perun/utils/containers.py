"""A collection of custom generic "container" structures.

The container structures in this module should adhere to several rules to make them easy-to-use for
other Perun developers:
    1) The containers should be generic. If possible, make as few assumptions about the data types
       the container should operate on. if some strong assumptions about the types are made, make
       sure to properly explain them.
    2) The container should support a sensible range of operations (insert, search, delete,
       iterate, etc.) that make the container sufficiently general.
    3) Try to make the operations behave as expected (e.g., __getitem__ not removing container
       elements) and adhere to the expected return types or conventions, when possible.
       See: https://docs.python.org/3/reference/datamodel.html#emulating-container-types
    4) The containers should be properly type annotated and should pass mypy checks.
    5) The container itself and its operations should be properly documented.
"""

from __future__ import annotations
from collections import deque
from typing import Optional, TypeVar, Generic, Sequence, ItemsView, Generator, overload, \
    ValuesView, KeysView, Callable

# Key, Value type variables
KT = TypeVar("KT")
VT = TypeVar("VT")
# Default value type for methods that support arbitrary default values
DefT = TypeVar("DefT")


# HierarchicalMap-specific type aliases
HMapIter = Generator[tuple[deque[KT], Optional[VT]], None, None]


class HierarchicalMap(Generic[KT, VT]):
    """A tree-like recursive hierarchical mapping structure.

    HierarchicalMap can be seen as a generalization of a dictionary, where key is a sequence
    of multiple sub-keys, e.g., ['usr', 'local', 'bin'] and values can have a hierarchical
    representation.

    Note that each sub-key:
        1) must be hashable (as with other mappings), and
        2) is expected to be of the same type (not enforced, just expected by the type checking
           engine). For mixed-type keys (e.g., [1, 'str']), use Union[Type1, Type2, ...] as KT.

    Each sub-key is then represented by a nested HierarchicalMap node.
    E.g., for keys ['usr', 'local', 'bin'], ['usr', 'lib']:

        HierarchicalMap {
            'usr': HierarchicalMap {
               'local': HierarchicalMap {
                   'bin': HierarchicalMap {}
               }
               'lib': HierarchicalMap {}
            }
        }

    Each HierarchicalMap node can also hold a value (a root data element). Note that the `None`
    value represents an empty node data.
    E.g, to specify values for (1) a root, (2) ['usr'] and (3) ['etc', 'passwd']:

        ```
        root: HierarchicalMap[str, int] = HierarchicalMap(1)
        root[['usr',]] = 2
        root[['etc', 'passwd']] = 3
        ```

    which leads to the following HierarchicalMap:

        []: HierarchicalMap(value = 1)
        |___ ['usr']: HierarchicalMap(value = 2)
        |___ ['etc']: HierarchicalMap(value = None)
           |___ ['etc', 'passwd'] = HierarchicalMap(value = 3)

    The HierarchicalMap structure supports the following operations:
        1) key's node lookup,
            - via the [] operator
            - via the get method with possible default node or value
        2) key: value insertion,
            - single value via the [] operator
            - recursive insertion to all successor nodes (transitively) of the selected node
        3) deletion of nodes (except the root),
            - via the del operator
            - via the pop operator with possible default value
        4) data retrieval from the selected node,
        5) membership test (even for partial keys),
        6) length computation (number of all nodes),
        7) iteration (key: value pairs),
            - of all the nodes
            - of only leaf nodes
        8) key, value and item views (only of the leaf nodes),
            - The views are created from copies of the (key, value) pairs, and thus are not dynamic
              and do not reflect changes made to the structure (as views would normally do, e.g.,
              in dict). This is because HierarchicalMap cannot be subclassed as proper Mapping.
        9) successors fetch,
        10) removing all elements from the map.

    The operations can be performed both directly on the root node, or on any (internal, leaf) node
    of the HierarchicalMap (which are conveniently returned by the getter methods).
    Note that due to mostly recursive implementation, RecursionError may occur for too deep
    HierarchicalMaps.
    """
    __slots__ = '_nested', '_data'

    def __init__(self, root_data: VT | None) -> None:
        """Constructor.

        :param root_data: value associated with the node. None for empty value.
        """
        self._nested: dict[KT, HierarchicalMap[KT, VT]] = {}
        self._data: VT | None = root_data

    def __getitem__(self, item: Sequence[KT]) -> HierarchicalMap[KT, VT]:
        """Node getter.

        Raises KeyError when a sub-key is not found in the respective node.

        :param item: a sequence of sub-keys.

        :return: node (internal or leaf) corresponding to the given key, if found.
        """
        # If we run out of keys, return the Node itself
        if not item:
            return self
        # Get the next nested node based on the first key item and delegate the rest to the node
        return self._nested[item[0]][item[1:]]

    def __setitem__(self, key: Sequence[KT], value: VT | None) -> None:
        """Value setter.

        Note that the setter by-default inserts new HierarchicalMap nodes for sub-keys not in the
        Map. The new node value is propagated from the current node to .

        This is consistent with the expected behaviour (e.g., setter for a single dict).

        :param key: a sequence of sub-keys.
        :param value: the value to assign to the node identified by the key.
        """
        # No more keys, we have reached the node
        if not key:
            self._data = value
        else:
            # Get the next nested node (create it if necessary) based on the first key item
            # Delegate the rest to the node
            self._nested.setdefault(key[0], HierarchicalMap(self._data))[key[1:]] = value

    def __delitem__(self, key: Sequence[KT]) -> None:
        """Deletes node represented by the key sequence.

        If the node is internal, the existing successors are not directly deleted, but become
        effectively unreachable from the root node.

        Raises KeyError when a sub-key is not found in the respective node or when attempting to
        delete the node itself (e.g., `del node`).

        :param key: a sequence of sub-keys.
        """
        # We can't delete this exact node, as it may be mapped by it's predecessor
        if not key:
            raise KeyError
        if len(key) == 1:
            # Delegate to dict delete
            del self._nested[key[0]]
        else:
            # Delegate to node delete
            del self._nested[key[0]][key[1:]]

    def __contains__(self, item: Sequence[KT]) -> bool:
        """Membership test of a key sequence.

        :param item: a sequence of sub-keys.

        :return: boolean value representing the presence, or absence, of the key in the map.
        """
        try:
            self[item]
        except KeyError:
            return False
        return True

    def __len__(self) -> int:
        """Computes the number of all map nodes.

        :return: a number of internal and leaf nodes in the map.
        """
        return len(self._nested) + sum(len(succ) for succ in self._nested.values())

    def __iter__(self) -> HMapIter:
        """Iterates the (key, value) pairs in the map.

        The iterator will iterate over all (key, value) pairs, including those in the internal
        nodes. There were some performance considerations that result in:

            1) Contrary to how mapping iterators usually work, values are also provided when
               iterating HierarchicalMap. Accessing the key's value would otherwise require
               additional dictionary lookup (hashing) for every sub-key.
            2) The key sequence is stored as deque due to its O(1) prepend operation. Deque can
               be easily converted to other Sequence types.

        :return: a generator of all (key, value) pairs in the map.
        """
        # The node itself
        yield deque(), self._data
        # The successors
        yield from self.iter_successors(HierarchicalMap.__iter__)

    @property
    def data(self) -> VT | None:
        """Node value access.

        Read-only property is used to enforce the consistency of data hierarchy.
        Thus, the value can be updated either by the [] operator or insertion, with no recursive
        propagation or possible recursive propagation, respectively.

        :return: the value associated with the node, or None if empty.
        """
        return self._data

    def insert(
            self, key: Sequence[KT], value: VT | None,
            recursive: bool = False, overwrite: bool = True, strict: bool = False
    ) -> None:
        """Customizable insertion operation of a (key, value) pair.

        The insertion can:
            1) insert the value only to the node specified by the key, or also recursively to the
               node's (transitive) successors,
            2) overwrite the current node value or set the value only if the node(s) value is empty
               (applies also to the recursive insertion),
            3) insert missing sub-key nodes with values propagated from their parents (as done by
               the __setitem__) or raise KeyError if the key is not yet in the map.

        With the default `recursive`, `overwrite` and `strict` settings, the method behaves the
        same as the [] setter operator.

        :param key: a sequence of sub-keys.
        :param value: the value to assign.
        :param recursive: select recursive mode (see point 1).
        :param overwrite: select if already set values should be overwritten (see point 2).
        :param strict: select if missing sub-keys should be added as well (see point 3).
        """
        # We are still looking for the node
        if key:
            if strict:
                candidate = self._nested[key[0]]
            else:
                candidate = self._nested.setdefault(key[0], HierarchicalMap(self._data))
            candidate.insert(key[1:], value, overwrite, recursive, strict)
        # We have found the node we are looking for
        else:
            # Update the value if possible
            if self._data is None or overwrite:
                self._data = value
            # Start propagating the value to successor nodes if requested
            if recursive:
                for node in self._nested.values():
                    node.insert(key, value, overwrite, recursive, strict)

    @overload
    def get(self, key: Sequence[KT]) -> HierarchicalMap[KT, VT] | None: ...

    @overload
    def get(
            self, key: Sequence[KT], default: DefT | HierarchicalMap[KT, VT]
    ) -> DefT | HierarchicalMap[KT, VT] | None: ...

    def get(
            self, key: Sequence[KT], default: DefT | HierarchicalMap[KT, VT] | None = None
    ) -> DefT | HierarchicalMap[KT, VT] | None:
        """Node getter with possible default value.

        If `default` is not given, its value is None. This getter never raises KeyError.

        :param key: a sequence of sub-keys.
        :param default: the default value to use when the key is not in the map.

        :return: the node associated with the key, or the default value.
        """
        try:
            return self[key]
        except KeyError:
            return default

    @overload
    def pop(self, key: Sequence[KT]) -> HierarchicalMap[KT, VT] | None: ...

    @overload
    def pop(
            self, key: Sequence[KT], default: DefT | HierarchicalMap[KT, VT]
    ) -> DefT | HierarchicalMap[KT, VT] | None: ...

    def pop(
            self, key: Sequence[KT], default: DefT | HierarchicalMap[KT, VT] | None = None
    ) -> DefT | HierarchicalMap[KT, VT] | None:
        """Return node associated with the key and delete it from the map, if found.

        If key is in the map, return the node associated with the key and remove the node from
        the map. If key is not in the map and a `default` is given, return the default value.
        Otherwise, raise KeyError.

        :param key: a sequence of sub-keys.
        :param default: the default value to use when the key is not in the map.

        :return: the node associated with the key, or the default value.
        """
        node = self.get(key)
        # Node not found OR the key is an empty sequence (the node cannot pop itself)
        if node is None or self is node:
            if default is None:
                raise KeyError(key)
            return default
        # Delete the node from the mapping and return it
        del self[key]
        return node

    def clear(self) -> None:
        """Remove all nodes from the map.

        The value of the root node is set to empty and all successor nodes are removed.
        """
        self._data = None
        self._nested.clear()

    def keys(self) -> KeysView[Sequence[KT]]:
        """Provides the keys of leaf nodes in the map.

        Please see the class docstring. The returned View is made from a copy of the nodes, and
        thus is not dynamic and does not update automatically, as would be expected.

        :return: a non-dynamic and non-updating keys view.
        """
        return {tuple(key): value for key, value in self.iter_leaves()}.keys()

    def values(self) -> ValuesView[VT | None]:
        """Provides the values of leaf nodes in the map.

        Please see the class docstring. The returned View is made from a copy of the nodes, and
        thus is not dynamic and does not update automatically, as would be expected.

        :return: a non-dynamic and non-updating values view.
        """
        return {tuple(key): value for key, value in self.iter_leaves()}.values()

    def items(self) -> ItemsView[Sequence[KT], VT | None]:
        """Provides the (key, value) pairs of leaf nodes in the map.

        Please see the class docstring. The returned View is made from a copy of the nodes, and
        thus is not dynamic and does not update automatically, as would be expected.

        :return: a non-dynamic and non-updating items view.
        """
        return {tuple(key): value for key, value in self.iter_leaves()}.items()

    def successors(self) -> ItemsView[KT, HierarchicalMap[KT, VT]]:
        """Provides the node's immediate successors.

        This allows custom iteration over the whole map, if needed. Note that the returned View
        object is dynamic and updates when changes are made to the map.

        :return: a dynamic items view of the node's immediate successors.
        """
        return self._nested.items()

    def iter_leaves(self) -> HMapIter:
        """Iterates the (key, value) pairs of the leaf nodes in the map.

        Contrary to the class __iter__ method, this iterator excludes internal nodes.

        :return: a generator of (key, value) pairs of leaf nodes in the map.
        """
        # Yield values only from the leaf nodes
        if not self._nested:
            yield deque(), self._data
        else:
            yield from self.iter_successors(HierarchicalMap.iter_leaves)

    def iter_successors(self, iterator: Callable[[HierarchicalMap], HMapIter]) -> HMapIter:
        """Helper function for customizable recursive successors iteration.

        Allows to specify custom successor iterator to, e.g., exclude or include internal nodes,
        filter empty nodes, etc.

        :param iterator: custom iterator callable with possible node filters.

        :return: a generator of (key, value) pairs of (possibly filtered) nodes in the map.
        """
        for node_key, node in self._nested.items():
            for key_sequence, value in iterator(node):
                key_sequence.insert(0, node_key)
                yield key_sequence, value
