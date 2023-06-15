"""This module implements various basic block equivalence criteria used for CFG comparison."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Callable, ClassVar
from abc import ABC, abstractmethod

import re

from perun.logic.call_graph.structs import BasicBlock
from perun.logic.call_graph.archs import ArchInfo


# Equality criteria classes usually have only the __call__ public method, this is by design.
# pylint: disable=too-few-public-methods


def eq_bb_length(block: BasicBlock, other_block: BasicBlock) -> bool:
    """A basic equality criterion that compares only the number of BB instructions.

    :param block: a basic block.
    :param other_block: the other basic block to compare.

    :return: True if the blocks are to be considered equal under this criterion, False otherwise.
    """
    return len(block) == len(other_block)


def eq_bb_instructions(block: BasicBlock, other_block: BasicBlock) -> bool:
    """An equality criterion that compares equality of BB instructions but not their operands.

    :param block: a basic block.
    :param other_block: the other basic block to compare.

    :return: True if the blocks are to be considered equal under this criterion, False otherwise.
    """
    # Make sure that the number of instruction matches
    if not eq_bb_length(block, other_block):
        return False
    # Make sure that the instructions (without operands) match
    return all(instr == other_instr for (instr, _), (other_instr, _) in zip(block, other_block))


class ArchBasedEq(ABC):
    """An abstract base class for equality criteria that require architecture specification.

    :cvar _operands_split_re: delimiters used in the disassembly operands specification.
    :ivar arch: the CPU architecture context used for identification of jump/call instructions.
    """

    __slots__ = ["arch"]

    _operands_split_re: ClassVar[re.Pattern[str]] = re.compile(r"([\s,:+*\-\[\]]+)")

    def __init__(self, arch: ArchInfo) -> None:
        """Initializer.

        :param arch: the CPU architecture context.
        """
        self.arch: ArchInfo = arch

    @abstractmethod
    def __call__(self, block: BasicBlock, block_other: BasicBlock) -> bool:
        ...

    def _eq_operand_parts(
        self, op_parts: Sequence[str], op_parts_other: Sequence[str], register_map: dict[str, str]
    ) -> bool:
        """Compare operand parts.

        Operand part can be a register, constant, address, offset, ...
        For registers, we attempt to build a bijection to cover potentially different register
        allocation.

        :param op_parts: operand parts.
        :param op_parts_other: the other operand parts.
        :param register_map: bijection mapping of registers.

        :return: True if the operand parts are equal, False otherwise.
        """
        if len(op_parts) != len(op_parts_other):
            # Different number of operand parts
            return False
        for op_part, op_part_other in zip(op_parts, op_parts_other):
            if op_part in self.arch.gp_registers and op_part_other in self.arch.gp_registers:
                # Both operand parts are registers -> check / update bijection
                previous_mapping = register_map.get(op_part, op_part_other)
                if register_map.setdefault(op_part, op_part_other) != previous_mapping:
                    # The register mapping is not a bijection
                    return False
            elif op_part != op_part_other:
                # Otherwise simply compare the operand parts
                return False
        return True

    def _split_operand(
        self, operand: str, op_filter: Callable[[str], bool] | None = None
    ) -> list[str]:
        """Split operand(s) into parts such as registers, offsets, constants, addresses, etc.

        :param operand: the string representation of operand.
        :param op_filter: an optional filter for operand parts.

        :return: the extracted operand parts.
        """
        return [
            expr
            for expr in re.split(self._operands_split_re, operand)
            if op_filter is None or op_filter(expr)
        ]


class EqBBOperands(ArchBasedEq):
    """An equality criterion that compares equality of BB instructions and their operands.

    Note that the criterion ignores operands of jump and call instructions as the addresses in
    operands can change despite the destination being the same. The destination can be compared
    on the level of graph topology.
    """

    def __call__(self, block: BasicBlock, block_other: BasicBlock) -> bool:
        """Make the objects callable, so they can be used like a function.

        :param block: a basic block.
        :param block_other: the other basic block.

        :return: True if the blocks are considered equal under this criterion, False otherwise.
        """
        if not eq_bb_length(block, block_other):
            return False
        # Also check that the op-codes and operands match
        for (inst, operands), (inst_other, operands_other) in zip(block, block_other):
            if inst != inst_other or (inst not in self.arch.jumps and operands != operands_other):
                return False
        return True


class EqBBRegisterBijection(ArchBasedEq):
    """This criterion compares equality of BB instructions and registers usage.

    While the instructions in the two basic blocks must match exactly, the operands comparison is
    a bit more lenient. Two basic blocks BB and BB' are considered equivalent iff the sequences of
    instructions in BB and BB' are the same and there exists a bijection f: BB_reg -> BB'_reg
    between the registers used in instructions' operands. This ensures that a different allocation
    of registers is ignored when comparing two basic blocks.
    """

    def __call__(self, block: BasicBlock, block_other: BasicBlock) -> bool:
        """Make the objects callable, so they can be used like a function.

        :param block: a basic block.
        :param block_other: the other basic block.

        :return: True if the blocks are considered equal under this criterion, False otherwise.
        """
        # Make sure that the number of instruction matches
        if not eq_bb_length(block, block_other):
            return False
        # Compare the basic block on a per-instruction basis
        register_map: dict[str, str] = {}
        for (instr, operands), (instr_other, operands_other) in zip(block, block_other):
            if instr != instr_other:
                # The basic blocks have different instructions
                return False
            # Obtain the registers present in operands of both basic blocks
            registers = self._split_operand(operands, lambda expr: expr in self.arch.gp_registers)
            registers_other = self._split_operand(
                operands_other, lambda expr: expr in self.arch.gp_registers
            )
            # Try to build a bijection
            if not self._eq_operand_parts(registers, registers_other, register_map):
                return False
        return True


class EqBBOperandsRegisterBijection(ArchBasedEq):
    """More strict variant of the register bijection equality criterion.

    This criterion is a combination of the registers bijection and operands matching criteria.
    That is, the criterion compares the following:
      1) equality of instructions and their ordering,
      2) bijection of registers in operands, and
      3) equality of other operands parts (constants, offsets, etc.).
    Note that jump addresses are not compared as is the case with operands matching criterion.
    """

    def __call__(self, block: BasicBlock, block_other: BasicBlock) -> bool:
        """Make the objects callable, so they can be used like a function.

        :param block: a basic block.
        :param block_other: the other basic block.

        :return: True if the blocks are considered equal under this criterion, False otherwise.
        """
        # Make sure that the number of instruction matches
        if not eq_bb_length(block, block_other):
            return False
        # Compare the basic block on a per-instruction basis
        register_map: dict[str, str] = {}
        for (instr, operands), (instr_other, operands_other) in zip(block, block_other):
            if instr != instr_other:
                # The basic blocks have different number of instructions
                return False
            if instr in self.arch.jumps:
                # We do not compare jump addresses
                return True
            # Compare the operand parts
            if not self._eq_operand_parts(
                self._split_operand(operands), self._split_operand(operands_other), register_map
            ):
                return False
        return True
