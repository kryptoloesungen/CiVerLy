"""
Various utility functions / shared code across all different analysis types / optimisation problems.
"""

from functools import cache
from itertools import product
from dataclasses import dataclass, field
from typing import Any
from typing import TYPE_CHECKING
from typing_extensions import Literal
import numpy as np


#
from sage.crypto.sbox import SBox


#
from .. import model_options as MO
from ..component import Component, LinearLayer_CVL, SBox_CVL

#
from .core import EncodingContext
from .milp.core import MILPContext

# [ Standalone ]---------------------------------------------------- *)

Bit = Literal[0, 1]


def _get_divide_factor(component: Component, options: MO.MODEL_OPTIONS):
    return component.wordsize if options.granularity == MO.GRANULARITY.WORDWISE else 1


def int_to_bits(integer: int, width: int) -> tuple[int, ...]:
    return list(int(bit) for bit in f"{integer:0{width}b}")


def bits_to_int(bits: tuple[int, ...]) -> int:
    return int("".join(str(x) for x in bits), base=2)


def type_name(obj: Any) -> str:
    return type(obj).__name__


# [ All those damn tables ]----------------------------------------- *)


def _identity_table(width: int) -> tuple[int]:
    return tuple(range(width))


def _rotation_table(width: int, degree: int) -> tuple[int]:
    return tuple(range((-degree) % width, width)) + tuple(range((-degree) % width))


def _wordcoarse_perm_table(table, wc: int) -> tuple[int]:
    return tuple(wc * table[i] + j for i in range(len(table)) for j in range(wc))


# [ Utilities for probabilistic transitions ]----------------------- *)


@dataclass(frozen=True, slots=True)
class WeightedTransition:
    bits: tuple[Bit, ...]
    # Example for a 2 -> 1 relation:
    #     bits = (1, 0, 1) -> read (1, 0) -> (1,)

    metric: int
    # weight associated with the transition
    #
    # using 'metric' (weight, probability, correlation),
    # although it should probs be 'weight'


@dataclass(frozen=True, slots=True)
class WeightedTransitions:
    # All permitted input/output transitions,
    # together with their metrics.
    transitions: tuple[WeightedTransition, ...]

    # normaliser / scaler used to convert transition metrics
    # into objective weights
    #
    # typical expression everywhere:
    #     weight = -log2(metric / normaliser)
    #
    # e.g. for n-bit S-Box is 2^n
    normalizer: int


@cache
def _weighted_transition_rel(
    transition_table: tuple[int, ...], input_sz: int, output_sz: int
) -> WeightedTransitions:
    """nil"""

    def _get_bits(i, o):
        return (*int_to_bits(i, input_sz), *int_to_bits(o, output_sz))

    iN = 1 << input_sz
    oN = 1 << output_sz

    transitions = tuple(
        WeightedTransition(_get_bits(i, o), int(transition_table[i][o]))
        for i in range(iN)
        for o in range(oN)
        if transition_table[i][o] > 0
    )

    return WeightedTransitions(transitions, int(transition_table[0][0]))


# [ Parity and Linear Layer utils ]--------------------------------- *)


@dataclass(frozen=True, slots=True)
class ParityEquation:
    """indices of all variables in one XOR equation

    assuminig flat local namespace:
        [IN..., OUT...] = [0, ... , |IN| - 1, |IN|, ... , |OUT| - 1]

    Example:
        variables = (0, 2, 5), rhs = 0

    means:
        VAR[0] XOR VAR[2] XOR VAR[5] = 0
    """

    variables: tuple[int, ...]

    # right hand side
    rhs: Bit = 0


# ----------------------------------------------------------------- *)


def _linear_layer_equations(matrix, IN, OUT) -> tuple[ParityEquation, ...]:
    equations = tuple(
        # parity equation to exclude assignments with odd HW (hence, rhs = 0)
        ParityEquation(
            (
                *tuple(IN[i] for i, entry in enumerate(row) if entry == 1),
                OUT[row_index],
            ),
            rhs=0,
        )
        for row_index, row in enumerate(matrix)
    )

    return equations


# ----------------------------------------------------------------- *)


def _build_differential_equations(component: LinearLayer_CVL, ctx: EncodingContext):
    return _linear_layer_equations(component.binary_matrix, ctx.IN, ctx.OUT)


def _build_linear_equations(component: LinearLayer_CVL, ctx: EncodingContext):
    return _linear_layer_equations(component.binary_matrix.transpose(), ctx.OUT, ctx.IN)


build_eq_t = Literal[
    _build_differential_equations,
    _build_linear_equations,
]

# ----------------------------------------------------------------- *)


def _parity_violating_assignments(n: int, rhs: int) -> np.ndarray:
    """Lovely website about error-correction: https://errorcorrectionzoo.org/c/parity_check

    Single-parity check code gives us exactly the binary vectors that we can interpret as
    integers with even parity.

    Using a generator matrix : G = [I_{n - 1} | allones] where allones = (1 1 1 ... 1)^t
    it is clear that for any u in F_2^{n-1}:
            uG = (u1, u2, ..., u_{n-1}, XOR(ui))

    We want all u's with parity that violates XOR(ui) = rhs, i.e. all u's that satisfy XOR(ui) = 1 - rhs

    An inductive procedure:
    1. start with a vector u{k} of dimension k
    2. define the next vector u{k + 1} as u{k}G + (1 - r)e_{k + 1} where e_{k + 1} is a standard unit

    Basically, we are taking ints with 1, 2, ..., n - 1 bits, shifting them left and XORing 1 - rhs
    to the shifted int to get a result with a desired parity.

    """

    if n == 0:
        if rhs == 1:  # <=> 1 - rhs == 0
            return 0
        raise ValueError("No satisfying assignments exist n == 0 and rhs == 0.")

    # all possible u's up to 2^{n-1} - 1 (since max overall is 2^n - 1 and we shift left by 1)
    Us = np.arange(1 << (n - 1), dtype=int)

    # lshift by 1 and xor a bit to get correct parity
    parities = (np.bitwise_count(Us) & 1).astype(int) ^ (1 - rhs)
    Us = (Us << 1) | parities

    # transform ints to bit-vectors
    shifts = np.arange(n - 1, -1, -1, dtype=int)
    return ((Us[:, None] >> shifts) & 1).astype(int).tolist()


# ----------------------------------------------------------------- *)
