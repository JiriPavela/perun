""" This module takes care of pairing USDT probes similarly to how function probes are
automatically paired as (function call, function return).

However, the process is a bit more complicated with USDT, as there is no implicit call
or return. Thus, we pair the probes according to a set of prepared pairing conventions.
Note that the user can also explicitly specify which probes are to be paired, and such
pairing has a precedence over the automated pairing.

Currently, USDT probes are paired according to their name suffixes:

        beginning suffixes      |      ending suffixes
    ============================================================
    - <name><delimiter>begin      : <name><delimiter>end
    - <name><delimiter>entry      : <name><delimiter>return
    - <name><delimiter>start      : <name><delimiter>finish
    - <name><delimiter>create     : <name><delimiter>destroy
    - <name><delimiter>construct  : <name><delimiter>deconstruct

     beginning suffix classes  |  ending suffix classes
    ==========================================
    ==================
    1) {begin, entry, start}   : {end, return, finish}
    2) {create, construct}     : {destroy, deconstruct}

The pairing algorithm works in three steps:
    1) First, if there is a probe <name> with no delimiter and beginning suffix (called "simple")
       AND no variant of the <name> with any delimiter and beginning suffix
       AND at least one <name> probe with a delimiter and ending suffix,
       THEN we pair the simple <name> probe with a random <name><delimiter><ending suffix> probe.
       E.g.: {simple, simple__end, simple__return} -> {pair(simple, simple__end)}

    2) Next, we construct so called "direct pairs", i.e., probe pairs with exact match of
       beginning and ending suffixes.
       E.g.: {direct_begin, direct_construct, direct_end, direct_deconstruct} ->
             {pair(direct_begin, direct_end), pair(direct_construct, direct_deconstruct}

    3) Lastly, we construct so called "related pairs", i.e. probe pairs where beginning and
       ending suffixes are in the same class.
       E.g.: {related-entry, related-finish, related-construct, related-destroy} ->
             {pair(related-entry, related-finish), pair(related-construct, related-destroy)}
"""
from __future__ import annotations

import re

from typing import Dict, AbstractSet, Tuple, Optional, Generator, Callable
from perun.collect.trace.probes import UsdtMap, ProbeUsdt


# lowercase suffix -> Probe
SuffixMap = Dict[str, ProbeUsdt]
# probe_name -> delimiter -> lowercase suffix -> Probe
ProbeMap = Dict[str, Dict[str, SuffixMap]]
# [probe_name, delimiter, suffix]
# In the case of "simple" probe, we do not have delimiter and suffix: [probe_name, None, None]
MapKey = Tuple[str, Optional[str], Optional[str]]
# Callable type for direct and related pairing functions
PairSuffixBy = Callable[[AbstractSet, str], str]


class Suffixes:
    """ Class that encapsulates the <name><delimiter><suffix> representation of probes as well as
    implements the pairing algorithm.

    :ivar _suffix_map: Mapping of <name><delimiter><suffix> -> <probe>
    :ivar _suffix_less_map: Mapping of <name> -> <probe>
    """
    __slots__ = '_suffix_map', '_suffix_less_map'

    # Direct suffix pairs
    _SUFFIX_DIRECT = {
        'begin': 'end',
        'entry': 'return',
        'start': 'finish',
        'create': 'destroy',
        'construct': 'deconstruct'
    }
    # Related suffix classes
    _SUFFIX_CLASS_1 = {'end', 'return', 'finish'}
    _SUFFIX_CLASS_2 = {'destroy', 'deconstruct'}
    # Related suffixes pairs
    _SUFFIX_RELATED = {
        'begin': _SUFFIX_CLASS_1,
        'entry': _SUFFIX_CLASS_1,
        'start': _SUFFIX_CLASS_1,
        'create': _SUFFIX_CLASS_2,
        'construct': _SUFFIX_CLASS_2
    }
    # The set of supported delimiter characters between probe and its suffix
    # Note that the actual delimiter can consist of multiple such characters, e.g.: '__', '--'
    _SUFFIX_DELIMITERS = ('_', '-')
    _SEPARATOR = re.compile(f"[{''.join(_SUFFIX_DELIMITERS)}]+")
    # Complete list of supported suffixes
    _SUFFIXES = list(_SUFFIX_DIRECT.keys()) + list(_SUFFIX_DIRECT.values())

    def __init__(self) -> None:
        """ Constructor, initialize new empty instance
        """
        self._suffix_map: ProbeMap = {}
        self._suffix_less_map: SuffixMap = {}

    def __setitem__(self, key: MapKey, value: ProbeUsdt) -> None:
        """ Set either the <name> -> Probe or <name><delimiter><suffix> -> <probe> mapping
        based on the key value, i.e.:
        - [name, None, None] is suffix-less mapping
        - [name, delimiter, suffix] is suffix mapping

        :param key: the mapping key
        :param value: the mapped probe object
        """
        name, lc_suffix, delimiter = key
        if lc_suffix is None or delimiter is None:
            self._suffix_map.setdefault(name, {})
            self._suffix_less_map[name] = value
        else:
            self._suffix_map.setdefault(name, {}).setdefault(lc_suffix, {})[delimiter] = value

    def __getitem__(self, key: MapKey) -> ProbeUsdt:
        """ Get the probe object mapped under the key. Similarly to the __setitem__ method, the
        key can have some fields specified as None.

        :param key: the key under which the probe object is stored

        :return: the mapped probe object
        """
        name, suffix, delimiter = key
        if suffix is None or delimiter is None:
            return self._suffix_less_map[name]
        return self._suffix_map[name][suffix][delimiter]

    def __contains__(self, key: str) -> bool:
        """ Check whether the probe map contains any records under the probe <name>.

        :param key: probe <name> without <delimiter> and <suffix>

        :return: the boolean result of the check
        """
        return key in self._suffix_map

    def __iter__(self) -> Generator[SuffixMap, None, None]:
        """ Iterates only the suffix mapping of the probe map.
        I.e., for each <name>, only the <suffix> -> <probe> mapping is provided

        :return: generator object that provides the mappings
        """
        return (suffixes for delim in self._suffix_map.values() for suffixes in delim.values())

    def add_probe(self, probe: ProbeUsdt) -> None:
        """ Adds the provided probe into the internal mapping structures. Already paired
        probes are ignored.

        :param probe: the <probe> object
        """
        # Ignore probes that are already paired!
        if probe.is_paired():
            return
        # Iterate the suffixes and check if the probe name ends with one of them
        suffix = re.split(self._SEPARATOR, probe.name.lower())[-1]
        if suffix in self._SUFFIXES:
            name = probe.name[:-len(suffix)]
            # Store the delimiter, recall that the delimiter can also be '__', '--', etc.
            delimiter = ''
            while name[-1] in self._SUFFIX_DELIMITERS:
                delimiter = name[-1] + delimiter
                name = name[:-1]
            self[name, delimiter, suffix] = probe
            return
        # No known suffix is found, add the probe as suffix-less
        self[probe.name, None, None] = probe

    def pair(self) -> None:
        """ The three-step pairing algorithm as described in the module docstring.
        """
        self._pair_simple()
        for suffixes in self:
            self._pair_suffixed(suffixes, self._find_direct_pair)
            self._pair_suffixed(suffixes, self._find_related_pair)

    def _pair_simple(self) -> None:
        """ Pair all "simple" probes.
        """
        # Probes in the suffix-less mapping are candidates for the "simple" probes
        for probe in self._suffix_less_map.values():
            # However, we still need to check if only ending suffixes exist
            pair_probe = self._find_simple_pair(probe.name)
            if pair_probe is not None:
                probe.set_pair(pair_probe)

    def _pair_suffixed(self, suffixes: SuffixMap, pair_by: PairSuffixBy) -> None:
        """ Pair suffixed probes according to the supplied pairing function. Generally,
        the pairing function is expected to obtain either direct or related pair probe.

        :param suffixes: a collection of <name> suffixes with mapped probes
        :param pair_by: a function that obtains suitable pair probe
        """
        # Iterate available beginning suffixes
        for begin in suffixes.keys() & self._SUFFIX_DIRECT.keys():
            suffix_pair = pair_by(suffixes.keys(), begin)
            if suffix_pair in suffixes:
                # Suitable pair probe found, pair the probes and delete the already paired suffixes
                suffixes[begin].set_pair(suffixes[suffix_pair])
                del suffixes[begin]
                del suffixes[suffix_pair]

    def _find_simple_pair(self, probe_name: str) -> Optional[ProbeUsdt]:
        """ Identify suitable pair probe for simple suffix-less <name> probe, if available.
        Such pair probe must have only ending suffixes and in this case, a random suffix
        is selected.

        :param probe_name: simple probe <name>

        :return: a suitable pair probe for the provided simple probe, if found
        """
        # Find probe name that is associated only with ending suffixes
        # Use random ending suffix to pair with the probe
        if probe_name in self:
            for delimiter, suffixes in self._suffix_map[probe_name].items():
                # There are suffixes and none of them is a starting one
                if suffixes and not suffixes.keys() & self._SUFFIX_DIRECT.keys():
                    return self[probe_name, delimiter, next(iter(suffixes))]
        # No suitable pair probe found
        return None

    def _find_direct_pair(self, suffixes: AbstractSet, begin_suffix: str) -> str:
        """ Identify direct pair probe, if any.

        :param suffixes: a set of available probe suffixes
        :param begin_suffix: the beginning suffix to pair

        :return: a suitable direct pair suffix if found, otherwise empty string
        """
        ending = self._SUFFIX_DIRECT[begin_suffix]
        return ending if ending in suffixes else ''

    def _find_related_pair(self, suffixes: AbstractSet, begin_suffix: str) -> str:
        """ Identify related pair probe, if any.

        :param suffixes: a set of available probe suffixes
        :param begin_suffix: the beginning suffix to pair

        :return: a suitable related pair suffix if found, otherwise empty string
        """
        endings = self._SUFFIX_RELATED[begin_suffix] & suffixes
        return next(iter(endings)) if endings else ''


def pair_usdt(probes: UsdtMap) -> None:
    """ Automatically pair USDT probes according to the pairing conventions described in the
    module docstring. User-specified pairing is kept as-is.

    :param  probes: a collection of USDT probes that should be paired
    """
    # Build the suffix representation
    suffixed_probes = Suffixes()
    for probe in probes.values():
        suffixed_probes.add_probe(probe)
    # Pair the probes
    suffixed_probes.pair()
