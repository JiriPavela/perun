"""Module implementing relevant properties of different CPU architectures.

Some architecture properties are necessary for basic block equality checking, such as CPU registers,
all possible JUMP instructions, etc.

To obtain instances of concrete architectures, use the global architecture manager that provides
architecture objects from the provided names
"""
from __future__ import annotations

from enum import Enum
from abc import ABC, abstractmethod


class SupportedArchs(Enum):
    """Currently supported CPU architectures."""

    X86_64 = "x86_64"

    @classmethod
    def from_name(cls, name: str) -> SupportedArchs:
        """Get an enumeration member from a name.

        This method should support all known names of a particular CPU architecture. If the
        supplied name is not known, a NotImplementedError exception will be raised.

        :param name: architecture name.

        :return: the corresponding enumeration member.
        """
        name_map = {
            "x86_64": "x86_64",
            "x86-64": "x86_64",
            "x64": "x86_64",
            "amd64": "x86_64",
        }
        try:
            canonical_name = name_map[name.lower()]
            return cls(canonical_name)
        except KeyError as exc:
            raise NotImplementedError(
                f"Currently unsupported or unknown architecture {name}"
                f" (select from {set(name_map.keys())})."
            ) from exc

    def as_object(self) -> ArchInfo:
        """Obtain the actual architecture object from the enumeration member.

        :return: the corresponding architecture object.
        """
        if self == SupportedArchs.X86_64:
            return ArchX8664()
        raise NotImplementedError(f"Missing implementation for architecture {self.name}.")


class ArchInfo(ABC):
    """The abstract representation of a CPU architecture.

    The individual attributes have a read-only access to prevent unintentional modification.

    :ivar _arch: architecture identification
    :ivar _jump_instr: all known jump instructions
    :ivar _gp_registers: basic general-purpose registers
    :ivar _gp_registers_ext: extended general-purpose registers
    """

    __slots__ = "_arch", "_jump_instr", "_gp_registers_basic", "_gp_registers_ext", "_gp_registers"

    @abstractmethod
    def __init__(self) -> None:
        """Initializer.

        This method is abstract by design, as this is where all the attributes should be
        initialized based on the actual architecture specifics.
        """
        self._arch: SupportedArchs
        self._jump_instr: set[str]
        self._gp_registers_basic: set[str]
        self._gp_registers_ext: set[str]
        self._gp_registers: set[str]

    @property
    def arch(self) -> SupportedArchs:
        """Get the architecture identification.

        :return: the architecture identification.
        """
        return self._arch

    @property
    def jumps(self) -> set[str]:
        """Get the architecture's known jump instructions.

        :return: all known jump instructions for this architecture.
        """
        return self._jump_instr

    @property
    def gp_registers_basic(self) -> set[str]:
        """Get the architecture's basic general purpose registers.

        :return: the basic general purpose registers.
        """
        return self._gp_registers_basic

    @property
    def gp_registers_ext(self) -> set[str]:
        """Get the architecture's extended general purpose registers, if any.

        For example, MMX, AVX or SSE instructions for x86_64.

        :return: the extended general purpose registers.
        """
        return self._gp_registers_ext

    @property
    def gp_registers(self) -> set[str]:
        """Get the architecture's complete set of general purpose registers.

        :return: all general purpose registers.
        """
        return self._gp_registers


class ArchX8664(ArchInfo):
    """x86_64 architecture representation."""

    def __init__(self) -> None:
        self._arch = SupportedArchs.X86_64
        self._jump_instr = {
            # fmt: off
            "call", "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jnle", "jnl", "jl", "jle",
            "jnge", "jng", "ja", "jae", "jnbe", "jnb", "jb", "jbe", "jnae", "jna", "jxcz", "jc",
            "jnc", "jo", "jno", "jp", "jpe", "jnp", "jpo", "js", "jns",
        }
        self._gp_registers_basic = self._build_gp_registers()
        self._gp_registers_ext = self._build_extended_gp_registers()
        self._gp_registers = self._gp_registers_basic | self._gp_registers_ext

    @staticmethod
    def _build_gp_registers() -> set[str]:
        """Generate the collection of x86_64 basic general purpose registers.

        Due to the number of available registers and their variants, we generate the entire
        collection instead of manually enumerating them.

        :return: basic general purpose registers represented as strings.
        """
        registers: set[str] = set()
        reg_classes: dict[str, list[str]] = {
            "basic": ["ax", "bx", "cx", "dx"],
            "ptr_idx": ["sp", "bp", "si", "di"],
            "segment": ["ss", "cs", "ds", "es", "fs", "gs"],
            "prefix": ["r", "e", ""],
            "suffix": ["l", "h"],
            "r64b-post": ["", "d", "w", "b"],
        }

        # Create basic registers and their 64b, 32b, 16b and high / low 8b variants:
        for reg in reg_classes["basic"]:
            # Rrr, Err, rr
            registers |= {f"{pre}{reg}" for pre in reg_classes["prefix"]}
            # rL, rH
            registers |= {f"{reg[0]}{post}" for post in reg_classes["suffix"]}

        # Create index and pointer registers with their 64b, 32b, 16b and low 8b variants:
        for reg in reg_classes["ptr_idx"]:
            # Rrr, Err, rr
            registers |= {f"{pre}{reg}" for pre in reg_classes["prefix"]}
            # rrL
            registers.add(f'{reg}{reg_classes["suffix"][0]}')

        # Add segment registers as-is
        registers |= set(reg_classes["segment"])

        # Create additional GP registers and their 64b, 32b, 16b and low 8b variants:
        # 64b register variants R8-R15
        start64, end64 = 8, 15
        for idx in range(start64, end64 + 1):
            registers |= {f"r{str(idx)}{post}" for post in reg_classes["r64b-post"]}
        return registers

    @staticmethod
    def _build_extended_gp_registers() -> set[str]:
        """Generate the collection of x86_64 extended general purpose registers.

        Similarly to the basic GP registers, we don't enumerate the registers manually.

        :return: extended general purpose registers represented as strings.
        """
        registers: set[str] = set()

        # Create the MMX registers:
        start_mmx, end_mmx = 0, 8
        for idx in range(start_mmx, end_mmx + 1):
            registers |= {f"mm{str(idx)}"}

        # Create the AVX registers and their 256b, 128b (SSE) and high / low 64b variants
        start_avx, end_avx = 0, 15
        for idx in range(start_avx, end_avx + 1):
            # ymmX (256b), ymmXhx (high 128b)
            registers |= {f"ymm{idx}{suffix}" for suffix in ["", "hx"]}
            # xmmX (128b), xmmXlq (low 64b), xmmXhq (high 64b)
            registers |= {f"xmm{idx}{suffix}" for suffix in ["", "lq", "hq"]}
        return registers


class ArchManager:
    """Architecture manager class.

    It is recommended to obtain concrete architecture instances through the manager class, as it
    ensures the instances will be singletons.

    :ivar _archs: the name -> instance mapping.
    """

    __slots__ = ["_archs"]

    def __init__(self) -> None:
        """Initializer."""
        self._archs: dict[SupportedArchs, ArchInfo] = {}

    def __contains__(self, item: SupportedArchs) -> bool:
        """Membership test.

        :return: True if a concrete architecture is already instantiated, False otherwise.
        """
        return item in self._archs

    def __getitem__(self, item: SupportedArchs) -> ArchInfo:
        """Get architecture instance.

        :param item: the requested architecture.

        :return: the corresponding architecture instance.
        """
        try:
            return self._archs[item]
        except KeyError:
            # The architecture is not instantiated yet
            return self._archs.setdefault(item, item.as_object())


# An architecture manager instance that behaves like a singleton
architectures = ArchManager()
