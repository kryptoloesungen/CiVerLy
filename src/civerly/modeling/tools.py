"""
Encoding specific functions.

Several components have encodings which are similar / identical.
This file groups together functions which are specific to the encoding
of such identical relations.

"""

from functools import cache
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from typing_extensions import Literal

if TYPE_CHECKING:
    from .. import model_options as MO



# [ Simple Tables ]------------------------------------------------- *)

def _identity_table(width: int) -> tuple[int]:
    return tuple(range(width))


def _rotation_table(width: int, degree: int) -> tuple[int]:
    return tuple(range((-degree) % width, width)) + tuple(range((-degree) % width))



# [ Utilities for probabilistic transitions ]----------------------- *)

Bit = Literal[0, 1]


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
    sbox_table: tuple[int, ...], analysis: MO.CRYPTANALYSIS
) -> WeightedTransitions:
    """nil"""

    from sage.crypto.sbox import SBox
    from .utils import _transition_table, int_to_bits

    sbox = SBox(list(sbox_table))
    table = _transition_table(sbox, analysis)

    # input/output width
    iw = sbox.input_size()
    ow = sbox.output_size()

    def _get_bits(i, o):
        return (*int_to_bits(i, iw), *int_to_bits(o, ow))

    transitions = tuple(
        WeightedTransition(_get_bits(i, o), int(table[i][o]))
        for i in range(1 << iw)
        for o in range(1 << ow)
        if table[i][o] > 0
    )

    return WeightedTransitions(iw, ow, transitions, int(table[0][0]))
