from typing import Any
from ..model_options import CRYPTANALYSIS
from .relation import (
    PermutationRelation,
    WeightedTransition,
    WeightedTransitionRelation,
)

from functools import cache
from sage.crypto.sbox import SBox

# [ vocab ]--------------------------------------------------------- *)
# metric: probability or correlation or weight, 
#         whatever is appropriate in the context
#
# rel: relation
#
# ----------------------------------------------------------------- *)

def int_to_bits(integer: int, width: int) -> tuple[int, ...]:
    return tuple(int(bit) for bit in f"{integer:0{width}b}")


def bits_to_int(bits: tuple[int, ...]) -> int:
    return int("".join(str(x) for x in bits), base=2)


def type_name(obj: Any) -> str:
    return type(obj).__name__


def _transition_table(sbox: SBox, analysis: CRYPTANALYSIS):
    """nil"""

    match analysis:
        case CRYPTANALYSIS.DIFFERENTIAL:
            return sbox.difference_distribution_table()
        case CRYPTANALYSIS.LINEAR:
            # use LAT instead of DDT
            return [
                [abs(int(entry * len(sbox))) for entry in row]
                for row in sbox.linear_approximation_table("correlation")
            ]
        case _:
            raise ValueError()


# [ rel utils ]---------------------------------------------------- *)


def _identity_rel(width: int) -> PermutationRelation:
    """nil"""
    return PermutationRelation(tuple(range(width)))


def _rotation_rel(width: int, degree: int) -> PermutationRelation:
    """nil"""
    table = tuple(range((-degree) % width, width)) + tuple(range((-degree) % width))
    return PermutationRelation(table)


# ----------------------------------------------------------------- *)


@cache
def _weighted_transition_rel_from_table(
    table: tuple[tuple[int, ...], ...],
) -> WeightedTransitionRelation:
    """nil"""

    # neat trick that, 
    # I can only be too embarassed to say,
    # I just learned after five years of working
    # with stupid sboxes when the the input / output 
    # sizes are not given
    input_width = (len(table) - 1).bit_length()
    output_width = (len(table[0]) - 1).bit_length()

    transitions = tuple(
        WeightedTransition(
            # bits
            (*int_to_bits(i, input_width), *int_to_bits(o, output_width)),
            # metric
            table[i][o],
        )
        for i in range(len(table))
        for o in range(len(table[i]))
        if table[i][o] > 0
    )

    return WeightedTransitionRelation(
        input_width, output_width, transitions, table[0][0]
    )

# ----------------------------------------------------------------- *)

@cache
def _weighted_transition_rel(
    sbox_table: tuple[int, ...], analysis: CRYPTANALYSIS
) -> WeightedTransitionRelation:
    """nil"""

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

    return WeightedTransitionRelation(iw, ow, transitions, int(table[0][0]))


# [ # AND rel stuff ]---------------------------------------------- *)
# precomputation for the ANDs, since this never changes


_AND_DIFFERENTIAL_TABLE = (
    (4, 0),
    (2, 2),
    (2, 2),
    (2, 2),
)

_AND_LINEAR_TABLE = (
    (4, 2),
    (0, 2),
    (0, 2),
    (0, 2),
)

AND_DIFFERENTIAL_REL = _weighted_transition_rel_from_table(_AND_DIFFERENTIAL_TABLE)
AND_LINEAR_REL = _weighted_transition_rel_from_table(_AND_LINEAR_TABLE)
