"""This module implements various function name equivalence criteria for CFG comparison."""
from __future__ import annotations

from collections.abc import ItemsView
from typing import Literal


# Equality criteria classes usually have only the __call__ public method, this is by design.
# pylint: disable=too-few-public-methods


class KnownRenames:
    """A strict equivalence criterion that, however, allows to specify known renames.

    Two function names are considered equal when their names match, or they correspond to a known
    rename (known name mapping). The name mapping is fixed, i.e., not updated throughout the
    equivalence checking of a CFG.

    :ivar known: known renames mapping.
    """

    __slots__ = ["known"]

    def __init__(self, known_renames: dict[str, str]) -> None:
        """Initializer.

        :param known_renames: old name -> new name mapping.
        """
        self.known: dict[str, str] = known_renames

    def __call__(self, name: str, other_name: str) -> bool:
        """Make the objects callable, so they can be used as equivalence criterion function.

        :param name: first operand of the name comparison.
        :param other_name: second operand of the name comparison.

        :return: True if the names are considered equal, False otherwise.
        """
        return self.known.get(name, name) == other_name


class AdaptiveRenames(KnownRenames):
    """A more lenient comparison based on both known and unknown name renames.

    Two function names are considered as equal when either:
      - their names match exactly,
      - their names correspond to a known rename mapping, or
      - their names are in the *missing* and *new* name sets, respectively.

    As a byproduct of CFG comparison, this object will also construct a mapping of potential
    renames that were observed.

    :ivar missing: function names that are in the first CFG but not in the second.
    :ivar new: functions names that are in the second CFG but not in the first.
    :ivar _candidate_renames: a mapping of potential renames observed during the comparison.
    """

    __slots__ = "missing", "new", "_candidate_renames"

    def __init__(
        self, known_renames: dict[str, str], missing_names: set[str], new_names: set[str]
    ) -> None:
        """Initializer.

        :param known_renames: known renames mapping.
        :param missing_names: function names that are in the first CFG but not in the second.
        :param new_names: functions names that are in the second CFG but not in the first.
        """
        super().__init__(known_renames)
        self.missing: set[str] = missing_names
        self.new: set[str] = new_names
        self._candidate_renames: dict[str, set[str]] = {}

    def __call__(self, name: str, other_name: str) -> bool:
        """Make the objects callable, so they can be used as equivalence criterion function.

        :param name: first operand of the name comparison.
        :param other_name: second operand of the name comparison.

        :return: True if the names are considered equal, False otherwise.
        """
        if super().__call__(name, other_name):
            # A known rename or identical names
            return True
        if name in self.missing:
            self._candidate_renames.setdefault(name, set()).add(other_name)
            # True if the names are in missing and new
            # False if it is only in new -> not a rename, but a different called function.
            return other_name in self.new
        return False

    def rename_candidates(self) -> ItemsView[str, set[str]]:
        """Provide a view of rename candidates.

        :return: a view of rename candidate mapping 'old name' -> 'new names'
        """
        return self._candidate_renames.items()


def eq_func_ignore_names(_: str, __: str) -> Literal[True]:
    """A permissive function name equivalence criterion.

    Every two compared function names are evaluated as equal.

    :return: True for all compared names.
    """
    return True
