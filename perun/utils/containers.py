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

from typing import Optional, TypeVar, Generic, Literal, overload
from collections import deque
from collections.abc import (
    Sequence,
    Generator,
    Callable,
    Iterable,
    Iterator,
    Mapping,
    KeysView,
    ValuesView,
    ItemsView,
)

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

    :ivar _nested: a collection of child nodes.
    :ivar _data: the data associated with this node.
    """

    __slots__ = "_nested", "_data"

    def __init__(self, root_data: VT | None) -> None:
        """Initializer.

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
        self,
        key: Sequence[KT],
        value: VT | None,
        recursive: bool = False,
        overwrite: bool = True,
        strict: bool = False,
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
    def get(self, key: Sequence[KT]) -> HierarchicalMap[KT, VT] | None:
        ...

    @overload
    def get(
        self, key: Sequence[KT], default: DefT | HierarchicalMap[KT, VT]
    ) -> DefT | HierarchicalMap[KT, VT] | None:
        ...

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
    def pop(self, key: Sequence[KT]) -> HierarchicalMap[KT, VT] | None:
        ...

    @overload
    def pop(
        self, key: Sequence[KT], default: DefT | HierarchicalMap[KT, VT]
    ) -> DefT | HierarchicalMap[KT, VT] | None:
        ...

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


class InverseSetMapping(Generic[KT, VT]):
    """Mapping of key -> set[value] and their inverse, value -> set[key], for fast lookups.

    Inverse set mapping is designed for use-cases when a key needs to be associated with more than
    one value and efficient manipulation with both key -> values and value -> keys associations is
    required. This container encapsulates the especially tedious task of enforcing consistency
    between the normal and inverse mappings in the case of adding or removing elements. We denote
    the mapping key -> set[values] as _normal_ and value -> set[keys] as _inverse_.

    Due to the typing limitations (or in some cases, strictness), the complementary normal+inverse
    methods are implemented in the following styles:
     1) dunder methods: __getitem__ -> getitem_inverse, __setitem__ -> setitem_inverse, ...
     2) methods with generic parameter(s): method(key: KT, ...) -> method_inverse(value: VT, ...)
        - It is not possible to elegantly narrow the types within the methods' implementation
        (even when using overloads) as they are generic.
     3) methods with no generic parameter: method(inverse: bool)

    Note that:
     1) both key and value types must be hashable, as they are held in sets in the mappings;
     2) directly manipulating (adding or removing some elements) the sets of keys or values returned
        by some of the methods (e.g., __getitem__) is discouraged, as the sets represent the actual
        mapping values and their manipulation would break the container consistency - the returned
        sets are not copies or views since the transformation could be costly;
     3) the container does not directly inherit from the MutableMapping generic type (due to
        strictness of its interface types) but still implements all of the necessary MutableMapping
        methods (and some additional ones).

    :ivar _mapping: the normal mapping of key -> values.
    :ivar _inv_mapping: the inverse mapping of value -> keys.
    """

    __slots__ = "_mapping", "_inv_mapping"

    def __init__(
        self,
        values: Mapping[KT, Iterable[VT]] | Iterable[tuple[KT, Iterable[VT]]] | None = None,
    ) -> None:
        """Initializer.

        param values: key -> values associations used to initialize the mapping.
        """
        self._mapping: dict[KT, set[VT]] = {}
        self._inv_mapping: dict[VT, set[KT]] = {}
        # Populate the mappings
        if values:
            self.update(values)

    def __contains__(self, key: KT) -> bool:
        """Key membership test.

        :param key: the key to test.
        """
        return key in self._mapping

    def contains_inverse(self, value: VT) -> bool:
        """Value membership test.

        :param value: the value to test.
        """
        return value in self._inv_mapping

    def __getitem__(self, key: KT) -> set[VT]:
        """Obtain values associated with the key.

        Raises a KeyError if the key is not in the normal mapping.

        :param key: the key.

        :return: a collection of values associated with the key.
        """
        return self._mapping[key]

    def getitem_inverse(self, value: VT) -> set[KT]:
        """Obtain keys associated with the value.

        Raises a KeyError if the value is not in the inverse mapping.

        :param value: the value.

        :return: a collection of keys associated with the value.
        """
        return self._inv_mapping[value]

    def __setitem__(self, key: KT, values: set[VT]) -> None:
        """Overwrite values associated with the key.

        Note that the values will not be added to the current values associated with the key but
        will overwrite them! This is consistent with how dictionary __setitem__ works.

        :param key: the key.
        :param values: the new values that should be associated with the key.
        """
        del self[key]
        for value in values:
            self.add(key, value)

    def setitem_inverse(self, value: VT, keys: set[KT]) -> None:
        """Overwrite keys associated with the value.

        Note that the keys will not be added to the current keys associated with the value but
        will overwrite them!

        :param value: the value.
        :param keys: the new keys that should be associated with the value.
        """
        self.delitem_inverse(value)
        for key in keys:
            self.add(key, value)

    def add(self, key: KT, value: VT) -> None:
        """Add new key to value association.

        This operation adds new key -> value and value -> key association instead of overwriting
        the existing ones.

        :param key: the key.
        :param value: the value to associate with the key.
        """
        self._mapping.setdefault(key, set()).add(value)
        self._inv_mapping.setdefault(value, set()).add(key)

    def __delitem__(self, key: KT) -> None:
        """Deletes the key entry from the normal mapping.

        The values associated with the key will not be deleted if they are still associated with
        some other key(s) in the mapping.

        Raises a KeyError if the key is not in the mapping.

        :param key: the key to delete.
        """
        self._delete_entries(key, self[key])
        del self._mapping[key]

    def delitem_inverse(self, value: VT) -> None:
        """Deletes the value entry from the inverse mapping.

        The keys associated with the value will not be deleted if they are still associated with
        some other value(s) in the mapping.

        Raises a KeyError if the value is not in the mapping.

        :param value: the value to delete.
        """
        self._delete_entries_inverse(value, self.getitem_inverse(value))
        del self._inv_mapping[value]

    def remove(self, key: KT, value: VT) -> None:
        """Remove the key -> value association from both mappings.

        The key and/or value will be completely removed from the mapping if they are not associated
        with any other value or key.

        :param key: the key.
        :param value: the associated value.
        """
        if key not in self or value not in self[key]:
            return
        # Remove the key-value association from both mappings
        self._mapping[key].discard(value)
        self._inv_mapping[value].discard(key)
        # Remove the mappings' entries if they became empty
        if not self._mapping[key]:
            del self._mapping[key]
        if not self._inv_mapping[value]:
            del self._inv_mapping[value]

    def __iter__(self) -> Iterator[KT]:
        """Iterate normal mapping keys.

        Similarly to Mapping, this method is pretty much an alias to .keys() with the slight
        difference in return types.

        :return: an iterator of keys in the normal mapping.
        """
        return iter(self.keys())

    def iter_inverse(self) -> Iterator[VT]:
        """Iterate inverse mapping keys.

        :return: an iterator of keys in the inverse mapping.
        """
        return iter(self.keys(inverse=True))

    def __len__(self) -> int:
        """Provides the number of unique keys in the normal mapping.

        :return: the number of unique keys in the normal mapping.
        """
        return len(self._mapping)

    def len_inverse(self) -> int:
        """Provides the number of unique keys in the inverse mapping.

        :return: the number of unique values in the inverse mapping.
        """
        return len(self._inv_mapping)

    def __eq__(self, other: object) -> bool:
        """Equivalence operator.

        Two mappings are considered equal if their normal mapping is equal. The inverse mappings
        are not compared as their equality is implied by the internal mapping equality, unless
        there is an inconsistency between the internal maps.

        :param other: the compared object.
        """
        if not isinstance(other, InverseSetMapping):
            return NotImplemented
        return self._mapping == other._mapping

    @overload
    def keys(self, inverse: Literal[True]) -> KeysView[VT]:
        ...

    @overload
    def keys(self, inverse: Literal[False] = False) -> KeysView[KT]:
        ...

    def keys(self, inverse: bool = False) -> KeysView[KT] | KeysView[VT]:
        """Provides a dictionary view of the normal or inverse mapping keys.

        :param inverse: specifies the view source: False = normal mapping, True = inverse mapping.

        :return: dictionary view of normal or inverse mapping keys.
        """
        if inverse:
            return self._inv_mapping.keys()
        return self._mapping.keys()

    @overload
    def values(self, inverse: Literal[True]) -> ValuesView[set[KT]]:
        ...

    @overload
    def values(self, inverse: Literal[False] = False) -> ValuesView[set[VT]]:
        ...

    def values(self, inverse: bool = False) -> ValuesView[set[VT]] | ValuesView[set[KT]]:
        """Provides a dictionary view of the normal or inverse mapping values.

        :param inverse: specifies the view source: False = normal mapping, True = inverse mapping.

        :return: dictionary view of normal or inverse mapping values (sets of keys or values).
        """
        if inverse:
            self._inv_mapping.values()
        return self._mapping.values()

    @overload
    def items(self, inverse: Literal[True]) -> ItemsView[VT, set[KT]]:
        ...

    @overload
    def items(self, inverse: Literal[False] = False) -> ItemsView[KT, set[VT]]:
        ...

    def items(self, inverse: bool = False) -> ItemsView[KT, set[VT]] | ItemsView[VT, set[KT]]:
        """Provides a dictionary view of the normal or inverse mapping items.

        :param inverse: specifies the view source: False = normal mapping, True = inverse mapping.

        :return: dictionary view of normal or inverse mapping items.
        """
        if inverse:
            return self._inv_mapping.items()
        return self._mapping.items()

    @overload
    def get(self, key: KT) -> set[VT] | None:
        ...

    @overload
    def get(self, key: KT, default: set[VT] | DefT) -> set[VT] | DefT:
        ...

    def get(self, key: KT, default: set[VT] | DefT | None = None) -> set[VT] | DefT | None:
        """Obtain the values associated with the key or default if the key is not in the mapping.

        Never raises a KeyError.

        :param key: the key.
        :param default: the default value if key is not in the normal mapping.

        :return: a set of values associated with the key, or the default value.
        """
        return self._mapping.get(key, default)

    @overload
    def get_inverse(self, value: VT) -> set[KT] | None:
        ...

    @overload
    def get_inverse(self, value: VT, default: set[KT] | DefT) -> set[KT] | DefT:
        ...

    def get_inverse(
        self, value: VT, default: set[KT] | DefT | None = None
    ) -> set[KT] | DefT | None:
        """Obtain the keys associated with the value or default if the value is not in the mapping.

        Never raises a KeyError.

        :param value: the value.
        :param default: the default value if value is not in the inverse mapping.

        :return: a set of keys associated with the value, or the default value.
        """
        return self._inv_mapping.get(value, default)

    @overload
    def pop(self, key: KT) -> set[VT] | None:
        ...

    @overload
    def pop(self, key: KT, default: set[VT] | DefT) -> set[VT] | DefT:
        ...

    def pop(self, key: KT, default: set[VT] | DefT | None = None) -> set[VT] | DefT:
        """Pop (key, values) pair from the mapping.

        If key is in the normal mapping, remove it and return its values, else return default.
        If default is not given and key is not in the normal mapping, a KeyError is raised.

        :param key: the key.
        :param default: the default value if key is not in the normal mapping.

        :return: a set of values associated with the key, or the default value.
        """
        try:
            values = self[key]
            del self[key]
            return values
        except KeyError as exc:
            if default is None:
                raise exc
            return default

    @overload
    def pop_inverse(self, value: VT) -> set[KT] | None:
        ...

    @overload
    def pop_inverse(self, value: VT, default: set[KT] | DefT) -> set[KT] | DefT:
        ...

    def pop_inverse(self, value: VT, default: set[KT] | DefT | None = None) -> set[KT] | DefT:
        """Pop (value, keys) pair from the mapping.

        If value is in the inverse mapping, remove it and return the set of associated keys, else
        return default. If default is not given and value is not in the inverse mapping, a KeyError
        is raised.

        :param value: the value.
        :param default: the default value if value is not in the inverse mapping.

        :return: a set of keys associated with the value, or the default value.
        """
        try:
            keys = self.getitem_inverse(value)
            self.delitem_inverse(value)
            return keys
        except KeyError as exc:
            if default is None:
                raise exc
            return default

    @overload
    def popitem(self, inverse: Literal[True]) -> tuple[VT, set[KT]]:
        ...

    @overload
    def popitem(self, inverse: Literal[False] = False) -> tuple[KT, set[VT]]:
        ...

    def popitem(self, inverse: bool = False) -> tuple[KT, set[VT]] | tuple[VT, set[KT]]:
        """Pop next (key, values) or (value, keys) pair from the mapping in LIFO order.

        If the mapping is empty, calling popitem() raises a KeyError.

        :param inverse: specifies the mapping to pop the next item from:
                        False = normal mapping, True = inverse mapping.

        :return: the next (key, values) or (value, keys) pair according to LIFO order.
        """
        if not inverse:
            # Popitem from the normal mapping
            key, values = self._mapping.popitem()
            self._delete_entries(key, values)
            return key, values
        # Popitem from the inverse mapping
        value, keys = self._inv_mapping.popitem()
        self._delete_entries_inverse(value, keys)
        return value, keys

    def clear(self) -> None:
        """Remove all keys and values from the mapping."""
        self._mapping.clear()
        self._inv_mapping.clear()

    def update(
        self,
        mapping: Mapping[KT, Iterable[VT]]
        | InverseSetMapping[KT, VT]
        | Iterable[tuple[KT, Iterable[VT]]],
    ) -> None:
        """Update the mapping with key -> values from the other mapping, overwriting existing keys.

        :param mapping: the other mapping to update from.
        """
        if not mapping:
            return
        iterable: ItemsView[KT, Iterable[VT]] | Iterable[tuple[KT, Iterable[VT]]] = (
            mapping.items() if isinstance(mapping, (Mapping, InverseSetMapping)) else mapping
        )
        # Mypy seems to give up here and infers both key and value as Any
        key: KT
        value: Iterable[VT]
        for key, value in iterable:
            self[key] = set(value)

    @overload
    def setdefault(self, key: KT, default: Iterable[VT]) -> set[VT]:
        ...

    @overload
    def setdefault(self, key: KT, default: None = None) -> None:
        ...

    def setdefault(self, key: KT, default: Iterable[VT] | None = None) -> set[VT] | None:
        """Return values associated with key, if any, or insert key -> default and return default.

        This method behaves slightly differently from the dictionary setdefault. Namely, if default
        is None, no item is inserted since None is not a valid value in the normal mapping (however,
        set[None] is, under the condition that it satisfies the value type).

        :param key: the key.
        :param default: the default value if key is not in the normal mapping.

        :return: values associated with the (possibly newly added) key or None if default is None.
        """
        try:
            return self[key]
        except KeyError:
            if default is None:
                return None
            self[key] = set(default)
            return self[key]

    @overload
    def setdefault_inverse(self, value: VT, default: Iterable[KT]) -> set[KT]:
        ...

    @overload
    def setdefault_inverse(self, value: VT, default: None = None) -> None:
        ...

    @overload
    def setdefault_inverse(self, value: VT, default: Iterable[KT] | None = None) -> set[KT] | None:
        ...

    def setdefault_inverse(self, value: VT, default: Iterable[KT] | None = None) -> set[KT] | None:
        """Return keys associated with value, if any, or insert value -> default and return default.

        This method behaves slightly differently from the dictionary setdefault. Namely, if default
        is None, no item is inserted since None is not a valid value in the inverse mapping
        (however, set[None] is, under the condition that it satisfies the key type).

        :param value: the value.
        :param default: the default value if value is not in the inverse mapping.

        :return: keys associated with the (possibly newly added) value or None if default is None.
        """
        try:
            return self.getitem_inverse(value)
        except KeyError:
            if default is None:
                return None
            self.setitem_inverse(value, set(default))
            return self.getitem_inverse(value)

    def _delete_entries(self, key: KT, values: Iterable[VT]) -> None:
        """Remove any key associations from the inverse mapping.

        :param key: key that should be removed from the inverse mapping.
        :param values: values that are associated with the key.
        """
        for value in values:
            # Remove all values-key associations from the inverse mapping
            self._inv_mapping[value].discard(key)
            if not self._inv_mapping[value]:
                # Remove the inverse mapping entry if it became empty
                del self._inv_mapping[value]

    def _delete_entries_inverse(self, value: VT, keys: Iterable[KT]) -> None:
        """Remove any value associations from the mapping.

        :param value: value that should be removed from the normal mapping.
        :param keys: keys that are associated with the value.
        """
        for key in keys:
            # Remove the key-values associations from the mapping
            self._mapping[key].discard(value)
            if not self._mapping[key]:
                # Remove the mapping key entry if it became empty
                del self._mapping[key]
